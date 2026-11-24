#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Merges pre-built x64 and arm64 MSIX slices into a unified Microsoft Store
    .msixbundle (strict makeappx.exe bundle, zero /nv), wraps .msixbundle and
    .appxsym debug symbol archives into a deterministic .msixupload archive,
    validates via tools/verify-msix-artifact.py, and emits LF SHA256SUMS
    (ADR 0016, ADR 0020).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$X64Msix,

    [Parameter(Mandatory = $true)]
    [string]$Arm64Msix,

    [Parameter()]
    [string]$X64Symbols = "",

    [Parameter()]
    [string]$Arm64Symbols = "",

    [Parameter()]
    [string]$OutputDir = "",

    [Parameter()]
    [switch]$StoreMode,

    [Parameter()]
    [switch]$AllowTestIdentity,

    [Parameter()]
    [switch]$SkipUploadPackage,

    [Parameter()]
    [switch]$SkipVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-SourceDateEpoch {
    $raw = [System.Environment]::GetEnvironmentVariable("SOURCE_DATE_EPOCH")
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [int64]1760000000
    }
    [int64]$parsed = 0
    if (
        -not [int64]::TryParse(
            $raw.Trim(),
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -lt 315532800 -or $parsed -gt 4354819199
    ) {
        throw "Invalid SOURCE_DATE_EPOCH '$raw'. Expected integer UNIX seconds in 315532800..4354819199 (1980-01-01 to 2107-12-31 UTC)."
    }
    return $parsed
}

function Assert-MsixVersionQuad {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter()]
        [switch]$RequireStoreRules
    )

    if ($Value -notmatch '\A[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\z') {
        throw "Invalid bundle -Version '$Value'. Expected four-part numeric version (Major.Minor.Build.Revision)."
    }
    $parts = $Value.Split('.')
    $nums = @()
    foreach ($part in $parts) {
        if ($part.Length -gt 1 -and $part.StartsWith('0')) {
            throw "Invalid bundle -Version '$Value': leading zeros are not permitted in version component '$part'."
        }
        [int]$num = 0
        if (-not [int]::TryParse($part, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$num) -or $num -lt 0 -or $num -gt 65535) {
            throw "Invalid bundle -Version '$Value': each component must be in 0..65535 (got '$part')."
        }
        $nums += $num
    }
    if ($RequireStoreRules) {
        if ($nums[0] -lt 1) {
            throw "Invalid Store bundle -Version '$Value': Microsoft Store requires Major >= 1 (1..65535)."
        }
        if ($nums[3] -ne 0) {
            throw "Invalid Store bundle -Version '$Value': Microsoft Store requires Revision == 0."
        }
    }
}

function Assert-ZipMagic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found: $Path"
    }
    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    $info = Get-Item -LiteralPath $fullPath
    if ($info.Length -lt 4) {
        throw "$Label is truncated (< 4 bytes): $fullPath"
    }
    $buf = [byte[]]::new(4)
    $fs = [System.IO.File]::OpenRead($fullPath)
    try {
        $read = $fs.Read($buf, 0, 4)
        if ($read -ne 4 -or $buf[0] -ne 0x50 -or $buf[1] -ne 0x4B -or $buf[2] -ne 0x03 -or $buf[3] -ne 0x04) {
            throw "$Label is not a valid ZIP/OPC archive (expected PK\x03\x04 magic): $fullPath"
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Assert-AppxSymArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Assert-ZipMagic -Path $Path -Label $Label
    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    Add-Type -AssemblyName System.IO.Compression
    $fs = [System.IO.File]::OpenRead($fullPath)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $pdbCount = 0
            $seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $forbiddenExts = @(".pfx", ".p12", ".cer", ".snk", ".key", ".pem", ".pvk", ".pepk", ".jks", ".keystore", ".msix", ".appx", ".msixbundle", ".exe", ".dll")
            foreach ($entry in $zip.Entries) {
                $name = $entry.FullName
                if ([string]::IsNullOrWhiteSpace($name)) {
                    throw "$Label contains an empty ZIP entry name."
                }
                foreach ($ch in $name.ToCharArray()) {
                    $cp = [int]$ch
                    if ($cp -lt 0x20 -or $cp -gt 0x7E) {
                        throw ('{0} contains non-ASCII or control character (U+{1:X4}) in ZIP entry name.' -f $Label, $cp)
                    }
                }
                if ($name -cne $name.Trim()) {
                    throw "$Label contains leading or trailing whitespace in entry '$name'."
                }
                if ($name.StartsWith(".")) {
                    throw "$Label contains hidden dotfile entry '$name'."
                }
                if ($name.Contains("/") -or $name.Contains("\") -or $name.Contains(":")) {
                    throw "$Label contains nested, trailing-slash, or unsafe path entry '$name' (flat root .pdb files only)."
                }
                if (-not $seenNames.Add($name)) {
                    throw "$Label contains duplicate or case-colliding entry '$name'."
                }
                $lower = $name.ToLowerInvariant()
                foreach ($badExt in $forbiddenExts) {
                    if ($lower.EndsWith($badExt)) {
                        throw "$Label contains forbidden entry '$name'."
                    }
                }
                if (-not $lower.EndsWith(".pdb")) {
                    throw "$Label contains non-PDB entry '$name'."
                }
                if ($entry.Length -le 0) {
                    throw "$Label contains empty PDB entry '$name'."
                }
                $pdbCount++
            }
            if ($pdbCount -lt 1) {
                throw "$Label contains zero .pdb symbol entries."
            }
            $requiredPdbs = @("totaldrop-winui.pdb", "totaldrop_windows_ffi.pdb", "totaldrop_explorer_ext.pdb")
            $missingPdbs = @($requiredPdbs | Where-Object { -not $seenNames.Contains($_) })
            if ($missingPdbs.Count -gt 0) {
                throw "$Label is missing required PDB symbol(s): $($missingPdbs -join ', ')."
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter()]
        [string]$PreferredArch = "x64"
    )

    $archOrder = if ($PreferredArch -eq "arm64") { @("arm64", "x64") } else { @("x64", "arm64") }

    # Self-contained strict ASCII 4-part numeric version sorter (zero external helpers).
    $sortDirsByVersionDesc = {
        param(
            [AllowNull()]
            [AllowEmptyCollection()]
            [System.IO.DirectoryInfo[]]$Dirs,

            [bool]$AllowPrerelease
        )

        $rx = if ($AllowPrerelease) {
            '\A([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?\z'
        } else {
            '\A([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\z'
        }
        $ranked = [System.Collections.Generic.List[object]]::new()
        foreach ($d in @($Dirs)) {
            if ($null -eq $d) {
                continue
            }
            $name = [string]$d.Name
            $isNum = 0
            [uint64]$v0 = 0
            [uint64]$v1 = 0
            [uint64]$v2 = 0
            [uint64]$v3 = 0
            $isStable = 0
            if ($name -cmatch $rx) {
                $ok0 = [uint64]::TryParse($Matches[1], [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v0)
                $ok1 = [uint64]::TryParse($Matches[2], [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v1)
                $ok2 = [uint64]::TryParse($Matches[3], [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v2)
                $ok3 = [uint64]::TryParse($Matches[4], [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v3)
                if ($ok0 -and $ok1 -and $ok2 -and $ok3) {
                    $isNum = 1
                    $isStable = if ($AllowPrerelease -and $Matches.ContainsKey(5) -and -not [string]::IsNullOrEmpty($Matches[5])) { 0 } else { 1 }
                }
            }
            if ($isNum -eq 0 -and -not $AllowPrerelease) {
                continue
            }
            $ranked.Add([PSCustomObject]@{
                Dir      = $d
                IsNum    = $isNum
                V0       = $v0
                V1       = $v1
                V2       = $v2
                V3       = $v3
                IsStable = $isStable
                Name     = $name
            })
        }
        $sorted = @(
            $ranked | Sort-Object -Property @(
                @{ Expression = { $_.IsNum };    Descending = $true },
                @{ Expression = { $_.V0 };       Descending = $true },
                @{ Expression = { $_.V1 };       Descending = $true },
                @{ Expression = { $_.V2 };       Descending = $true },
                @{ Expression = { $_.V3 };       Descending = $true },
                @{ Expression = { $_.IsStable }; Descending = $true },
                @{ Expression = { $_.Name };     Descending = $true }
            )
        )
        $result = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new()
        foreach ($item in $sorted) {
            $result.Add($item.Dir)
        }
        return $result.ToArray()
    }

    $kitBinRoots = [System.Collections.Generic.List[string]]::new()
    $winSdkDir = [System.Environment]::GetEnvironmentVariable("WindowsSdkDir")
    if (-not [string]::IsNullOrWhiteSpace($winSdkDir)) {
        $kitBinRoots.Add((Join-Path $winSdkDir "bin"))
    }
    foreach ($pfVar in @("ProgramFiles(x86)", "ProgramFiles")) {
        $pfRoot = [System.Environment]::GetEnvironmentVariable($pfVar)
        if (-not [string]::IsNullOrWhiteSpace($pfRoot)) {
            $kitBinRoots.Add((Join-Path $pfRoot "Windows Kits\10\bin"))
        }
    }

    $winSdkVer = [System.Environment]::GetEnvironmentVariable("WindowsSDKVersion")
    if (-not [string]::IsNullOrWhiteSpace($winSdkVer)) {
        $winSdkVer = $winSdkVer.Trim().TrimEnd('\', '/')
    }

    foreach ($kitsBin in $kitBinRoots) {
        if (-not (Test-Path -LiteralPath $kitsBin)) {
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace($winSdkVer) -and $winSdkVer -cmatch '\A[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\z') {
            foreach ($arch in $archOrder) {
                $envCandidate = Join-Path $kitsBin "$winSdkVer\$arch\$ToolName"
                if (Test-Path -LiteralPath $envCandidate) {
                    return $envCandidate
                }
            }
        }
        $rawVersionDirs = @(Get-ChildItem -LiteralPath $kitsBin -Directory -ErrorAction SilentlyContinue)
        $versionDirs = @(& $sortDirsByVersionDesc -Dirs $rawVersionDirs -AllowPrerelease $false)
        foreach ($vDir in $versionDirs) {
            foreach ($arch in $archOrder) {
                $candidate = Join-Path $vDir.FullName "$arch\$ToolName"
                if (Test-Path -LiteralPath $candidate) {
                    return $candidate
                }
            }
        }
    }

    $nugetEnv = [System.Environment]::GetEnvironmentVariable("NUGET_PACKAGES")
    $userProfileEnv = [System.Environment]::GetEnvironmentVariable("USERPROFILE")
    $nugetRoot = ""
    if (-not [string]::IsNullOrWhiteSpace($nugetEnv)) {
        $nugetRoot = $nugetEnv
    } elseif (-not [string]::IsNullOrWhiteSpace($userProfileEnv)) {
        $nugetRoot = Join-Path $userProfileEnv ".nuget\packages"
    }
    if (-not [string]::IsNullOrWhiteSpace($nugetRoot)) {
        $btRoot = Join-Path $nugetRoot "microsoft.windows.sdk.buildtools"
        if (Test-Path -LiteralPath $btRoot) {
            $rawPkgDirs = @(Get-ChildItem -LiteralPath $btRoot -Directory -ErrorAction SilentlyContinue)
            $pkgDirs = @(& $sortDirsByVersionDesc -Dirs $rawPkgDirs -AllowPrerelease $true)
            foreach ($pkgDir in $pkgDirs) {
                $binRoot = Join-Path $pkgDir.FullName "bin"
                if (-not (Test-Path -LiteralPath $binRoot)) { continue }
                $rawSdkDirs = @(Get-ChildItem -LiteralPath $binRoot -Directory -ErrorAction SilentlyContinue)
                $sdkDirs = @(& $sortDirsByVersionDesc -Dirs $rawSdkDirs -AllowPrerelease $false)
                foreach ($sdkDir in $sdkDirs) {
                    foreach ($arch in $archOrder) {
                        $candidate = Join-Path $sdkDir.FullName "$arch\$ToolName"
                        if (Test-Path -LiteralPath $candidate) {
                            return $candidate
                        }
                    }
                }
            }
        }
    }

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Required Windows SDK tool '$ToolName' not found in Windows Kits 10, NuGet BuildTools, or PATH."
}

function Resolve-PythonCommand {
    $candidates = @(
        @{ Exe = "python3"; PrefixArgs = @() },
        @{ Exe = "python";  PrefixArgs = @() },
        @{ Exe = "py";      PrefixArgs = @("-3") }
    )

    foreach ($cand in $candidates) {
        $cmds = @(Get-Command $cand.Exe -All -CommandType Application -ErrorAction SilentlyContinue)
        foreach ($cmd in $cmds) {
            $src = [string]$cmd.Source
            if ([string]::IsNullOrWhiteSpace($src)) {
                continue
            }
            # Skip Windows 11 Microsoft Store App Execution Alias stubs (%LOCALAPPDATA%\Microsoft\WindowsApps\python*.exe).
            if ($src -match '(?i)[\\/]Microsoft[\\/]WindowsApps[\\/]python[^\\/]*\.exe$') {
                continue
            }
            $probeArgs = @($cand.PrefixArgs) + @(
                "-c",
                "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}'); raise SystemExit(0 if sys.version_info >= (3, 10) else 2)"
            )
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $verOut = (& $src @probeArgs 2>$null | Out-String).Trim()
                $probeExit = $LASTEXITCODE
            }
            catch {
                $probeExit = -1
                $verOut = ""
            }
            finally {
                $ErrorActionPreference = $prevEap
            }
            if ($probeExit -eq 0) {
                return [PSCustomObject]@{
                    Executable = $src
                    PrefixArgs = @($cand.PrefixArgs)
                    Version    = $verOut
                }
            }
        }
    }

    throw "Python >= 3.10 is required to run tools/verify-msix-artifact.py (checked python3, python, and py -3, skipping WindowsApps Store alias stubs)."
}

function New-DeterministicZipArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$EntryMap,

        [Parameter(Mandatory = $true)]
        [int64]$EpochSeconds
    )

    Add-Type -AssemblyName System.IO.Compression
    $sortedNames = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $EntryMap.Keys) {
        $sortedNames.Add([string]$key)
    }
    $sortedNames.Sort([System.StringComparer]::Ordinal)

    # Use UTC DateTimeOffset directly so ZIP DOS timestamps are timezone-independent.
    $zipTimestamp = [System.DateTimeOffset]::FromUnixTimeSeconds($EpochSeconds)
    $tmpPath = "$DestinationPath.$PID.tmp"
    if (Test-Path -LiteralPath $tmpPath) {
        Remove-Item -LiteralPath $tmpPath -Force
    }
    try {
        $fs = [System.IO.File]::Open($tmpPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $archive = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
            try {
                foreach ($entryName in $sortedNames) {
                    $sourceFile = (Resolve-Path -LiteralPath ([string]$EntryMap[$entryName])).Path
                    $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                    $entry.LastWriteTime = $zipTimestamp
                    $entry.ExternalAttributes = 0
                    $srcStream = [System.IO.File]::OpenRead($sourceFile)
                    try {
                        $dstStream = $entry.Open()
                        try {
                            $srcStream.CopyTo($dstStream)
                        }
                        finally {
                            $dstStream.Dispose()
                        }
                    }
                    finally {
                        $srcStream.Dispose()
                    }
                }
            }
            finally {
                $archive.Dispose()
            }
        }
        finally {
            $fs.Dispose()
        }
        [System.IO.File]::SetLastWriteTimeUtc($tmpPath, $zipTimestamp.UtcDateTime)
        [System.IO.File]::Move($tmpPath, $DestinationPath, $true)
        [System.IO.File]::SetLastWriteTimeUtc($DestinationPath, $zipTimestamp.UtcDateTime)
    }
    catch {
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

$SourceDateEpoch = Resolve-SourceDateEpoch
$EpochUtc = [System.DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch).UtcDateTime

Assert-MsixVersionQuad -Value $Version -RequireStoreRules:$StoreMode

$ScriptDir = $PSScriptRoot
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $ScriptDir "..")).Path

Assert-ZipMagic -Path $X64Msix -Label "x64 MSIX"
Assert-ZipMagic -Path $Arm64Msix -Label "arm64 MSIX"
$ResolvedX64Msix = (Resolve-Path -LiteralPath $X64Msix).Path
$ResolvedArm64Msix = (Resolve-Path -LiteralPath $Arm64Msix).Path
if ($ResolvedX64Msix.Equals($ResolvedArm64Msix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "X64Msix and Arm64Msix must point to two distinct architecture MSIX archives."
}

$ResolvedOutDir = if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    Join-Path $RepoRoot "dist\store"
} else {
    $OutputDir
}
New-Item -ItemType Directory -Force -Path $ResolvedOutDir | Out-Null
$ResolvedOutDir = (Resolve-Path -LiteralPath $ResolvedOutDir).Path

$preferredMakeAppxArch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64) {
    "arm64"
} else {
    "x64"
}
$MakeAppxExe = Resolve-WindowsKitTool -ToolName "makeappx.exe" -PreferredArch $preferredMakeAppxArch
Write-Host "==> [bundle 1/3] Packing unified x64+arm64 bundle with strict makeappx.exe (no /nv)..."
Write-Host "    MakeAppx: $MakeAppxExe"

$OutBundleName = "TotalDrop-${Version}.msixbundle"
$OutBundle = Join-Path $ResolvedOutDir $OutBundleName
$BundleInputDir = Join-Path ([System.IO.Path]::GetTempPath()) ("totaldrop-bundle-$PID-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $BundleInputDir | Out-Null
try {
    $StagedX64 = Join-Path $BundleInputDir "TotalDrop_${Version}_x64.msix"
    $StagedArm64 = Join-Path $BundleInputDir "TotalDrop_${Version}_arm64.msix"
    Copy-Item -LiteralPath $ResolvedX64Msix -Destination $StagedX64 -Force
    Copy-Item -LiteralPath $ResolvedArm64Msix -Destination $StagedArm64 -Force
    [System.IO.File]::SetLastWriteTimeUtc($StagedX64, $EpochUtc)
    [System.IO.File]::SetLastWriteTimeUtc($StagedArm64, $EpochUtc)

    & $MakeAppxExe bundle /o /bv $Version /d $BundleInputDir /p $OutBundle
    if ($LASTEXITCODE -ne 0) {
        throw "makeappx.exe bundle failed with exit code $LASTEXITCODE"
    }
    [System.IO.File]::SetLastWriteTimeUtc($OutBundle, $EpochUtc)
}
finally {
    if (Test-Path -LiteralPath $BundleInputDir) {
        Remove-Item -LiteralPath $BundleInputDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$OutUploadName = "TotalDrop-${Version}.msixupload"
$OutUpload = Join-Path $ResolvedOutDir $OutUploadName
if (-not $SkipUploadPackage) {
    Write-Host "==> [bundle 2/3] Packing deterministic Partner Center archive $OutUploadName..."
    if ([string]::IsNullOrWhiteSpace($X64Symbols) -or [string]::IsNullOrWhiteSpace($Arm64Symbols)) {
        throw "Both -X64Symbols and -Arm64Symbols (.appxsym archives) are required to build .msixupload (or pass -SkipUploadPackage)."
    }
    Assert-AppxSymArchive -Path $X64Symbols -Label "x64 symbols archive"
    Assert-AppxSymArchive -Path $Arm64Symbols -Label "arm64 symbols archive"
    $ResolvedX64Sym = (Resolve-Path -LiteralPath $X64Symbols).Path
    $ResolvedArm64Sym = (Resolve-Path -LiteralPath $Arm64Symbols).Path
    if ($ResolvedX64Sym.Equals($ResolvedArm64Sym, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "X64Symbols and Arm64Symbols must point to two distinct architecture .appxsym archives."
    }
    $x64SymHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ResolvedX64Sym).Hash.ToLowerInvariant()
    $arm64SymHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ResolvedArm64Sym).Hash.ToLowerInvariant()
    if ($x64SymHash -eq $arm64SymHash) {
        throw "X64Symbols and Arm64Symbols have identical SHA-256 ($x64SymHash); refusing duplicate architecture symbols."
    }

    # Wrap ONLY the unified .msixbundle + per-arch .appxsym archives (zero bare .msix, zero signing keys).
    $uploadEntries = @{
        $OutBundleName                       = $OutBundle
        "TotalDrop_${Version}_arm64.appxsym" = $ResolvedArm64Sym
        "TotalDrop_${Version}_x64.appxsym"   = $ResolvedX64Sym
    }
    New-DeterministicZipArchive -DestinationPath $OutUpload -EntryMap $uploadEntries -EpochSeconds $SourceDateEpoch
} else {
    Write-Host "==> [bundle 2/3] Skipping .msixupload assembly (-SkipUploadPackage)."
}

if (-not $SkipVerify) {
    Write-Host "==> [bundle 3/3] Deep-verifying unified bundle & upload package via tools/verify-msix-artifact.py..."
    $verifyArgs = @(
        (Join-Path $RepoRoot "tools\verify-msix-artifact.py"),
        "--bundle", $OutBundle,
        "--expected-version", $Version
    )
    if (-not $SkipUploadPackage) {
        $verifyArgs += @("--msixupload", $OutUpload)
    }
    if ($StoreMode) {
        $verifyArgs += "--store-mode"
        if ($AllowTestIdentity) {
            $verifyArgs += "--allow-test-identity"
        }
    }
    $pythonCmd = Resolve-PythonCommand
    Write-Host "    Python:   $($pythonCmd.Executable) ($($pythonCmd.Version))"
    $allVerifyArgs = @($pythonCmd.PrefixArgs) + $verifyArgs
    & $pythonCmd.Executable @allVerifyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "tools/verify-msix-artifact.py failed with exit code $LASTEXITCODE"
    }
}

$ArtifactsToHash = [System.Collections.Generic.List[string]]::new()
$ArtifactsToHash.Add($OutBundleName)
if (-not $SkipUploadPackage) {
    $ArtifactsToHash.Add($OutUploadName)
}
$ArtifactsToHash.Sort([System.StringComparer]::Ordinal)

$ChecksumLines = [System.Collections.Generic.List[string]]::new()
foreach ($artName in $ArtifactsToHash) {
    $artPath = Join-Path $ResolvedOutDir $artName
    $hashHex = (Get-FileHash -Algorithm SHA256 -LiteralPath $artPath).Hash.ToLowerInvariant()
    $ChecksumLines.Add("$hashHex  $artName")
}
$ChecksumsPath = Join-Path $ResolvedOutDir "SHA256SUMS"
[System.IO.File]::WriteAllText(
    $ChecksumsPath,
    ($ChecksumLines -join "`n") + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "==> Built Store bundle: $OutBundle"
if (-not $SkipUploadPackage) {
    Write-Host "==> Built Partner Center upload package: $OutUpload"
}
Write-Host "==> Wrote checksums: $ChecksumsPath"
