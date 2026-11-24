#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Headless Windows CI E2E test orchestrator for TotalDrop for Windows (Full M1-M4).
    Executes all 60 windows-ci tests (22 M1 + 8 M2 + 21 M3 + 9 M4) with zero interactive
    WinUI windows and zero live production network connections.
.NOTES
    - Test T3-04 (LoopbackRelayTransferTests) requires external Architecture A loopback
      server binaries supplied via absolute paths in TOTALDROP_TEST_RENDEZVOUS_BIN and
      TOTALDROP_TEST_RELAY_BIN (or prebuilt in a sibling totaldrop-servers checkout).
    - Firewall lifecycle tests (T1-F21-03, T2-F21-05, T3-17, T4-10) and T3-13
      (powercfg /requests) require elevated Administrator privileges on Windows.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("M1", "M2", "M3", "M4", "All")]
    [string]$Milestone = "All",

    [Parameter()]
    [string]$MsixPath = "",

    [Parameter()]
    [string]$Arm64MsixPath = "",

    [Parameter()]
    [string]$BundlePath = "",

    [Parameter()]
    [string]$MsixUploadPath = "",

    [Parameter()]
    [string]$RuntimeDepMsix = "",

    [Parameter()]
    [string]$X64ExtDll = "",

    [Parameter()]
    [string]$BundleVersion = "1.0.1.0",

    [Parameter()]
    [switch]$SkipBuild,

    [Parameter()]
    [string]$ResultsJson = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$Results = [ordered]@{}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter()][string[]]$Arguments = @()
    )
    [void](Get-Command -Name $FilePath -ErrorAction Stop)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $global:LASTEXITCODE = 0
        $out = (& $FilePath @Arguments 2>&1 | Out-String)
        $rc = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
    return [PSCustomObject]@{
        ExitCode = $rc
        Output   = $out
    }
}

function Resolve-PythonExe {
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $candidates = @(Get-Command -Name "python3", "python" -CommandType Application -All -ErrorAction SilentlyContinue)
    foreach ($cand in $candidates) {
        $src = [string]$cand.Source
        if ([string]::IsNullOrWhiteSpace($src)) {
            continue
        }
        if ($src -match '(?i)\\Microsoft\\WindowsApps\\') {
            continue
        }
        if (-not $seen.Add($src)) {
            continue
        }
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
            continue
        }
        $probe = Invoke-NativeCapture -FilePath $src -Arguments @(
            "-B", "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 2)"
        )
        if ($probe.ExitCode -eq 0) {
            return $src
        }
    }
    throw "Required Python >= 3.11 executable not found on PATH (excluding Microsoft\WindowsApps stubs)."
}

function Sort-VersionDirsDesc {
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.IO.DirectoryInfo[]]$Dirs,

        [bool]$AllowPrerelease = $false,

        [bool]$AllowThreePart = $false
    )

    $rx = if ($AllowThreePart) {
        if ($AllowPrerelease) {
            '\A([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:-([0-9A-Za-z.-]+))?\z'
        } else {
            '\A([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\z'
        }
    } else {
        if ($AllowPrerelease) {
            '\A([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?\z'
        } else {
            '\A([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\z'
        }
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
            $ok3 = $true
            if ($Matches.ContainsKey(4) -and -not [string]::IsNullOrEmpty($Matches[4])) {
                $ok3 = [uint64]::TryParse($Matches[4], [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v3)
            }
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

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter()]
        [string]$PreferredArch = ""
    )

    if ([string]::IsNullOrWhiteSpace($PreferredArch)) {
        $isArm64Host = ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64)
        $PreferredArch = if ($isArm64Host) { "arm64" } else { "x64" }
    }
    $archOrder = if ($PreferredArch -eq "arm64") { @("arm64", "x64") } else { @("x64", "arm64") }

    # 1. WindowsSdkDir and installed Windows 10/11 SDK roots
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
                if (Test-Path -LiteralPath $envCandidate -PathType Leaf) {
                    return $envCandidate
                }
            }
        }
        $rawVersionDirs = @(Get-ChildItem -LiteralPath $kitsBin -Directory -ErrorAction SilentlyContinue)
        $versionDirs = @(Sort-VersionDirsDesc -Dirs $rawVersionDirs -AllowPrerelease $false -AllowThreePart $false)
        foreach ($vDir in $versionDirs) {
            foreach ($arch in $archOrder) {
                $candidate = Join-Path $vDir.FullName "$arch\$ToolName"
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return $candidate
                }
            }
        }
    }

    # 2. Restored NuGet Microsoft.Windows.SDK.BuildTools package
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
        if (Test-Path -LiteralPath $btRoot -PathType Container) {
            $rawPkgDirs = @(Get-ChildItem -LiteralPath $btRoot -Directory -ErrorAction SilentlyContinue)
            $pkgDirs = @(Sort-VersionDirsDesc -Dirs $rawPkgDirs -AllowPrerelease $true -AllowThreePart $true)
            foreach ($pkgDir in $pkgDirs) {
                $binRoot = Join-Path $pkgDir.FullName "bin"
                if (-not (Test-Path -LiteralPath $binRoot -PathType Container)) { continue }
                $rawSdkDirs = @(Get-ChildItem -LiteralPath $binRoot -Directory -ErrorAction SilentlyContinue)
                $sdkDirs = @(Sort-VersionDirsDesc -Dirs $rawSdkDirs -AllowPrerelease $false -AllowThreePart $false)
                foreach ($sdkDir in $sdkDirs) {
                    foreach ($arch in $archOrder) {
                        $candidate = Join-Path $sdkDir.FullName "$arch\$ToolName"
                        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                            return $candidate
                        }
                    }
                }
            }
        }
    }

    # 3. Ambient PATH fallback
    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Required Windows SDK tool '$ToolName' not found in Windows Kits 10, NuGet BuildTools, or PATH."
}

function Resolve-DumpBinExe {
    $isArm64 = ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64)
    $binSubpaths = if ($isArm64) {
        @("Hostarm64\arm64", "Hostarm64\x64", "Hostx64\arm64", "Hostx64\x64")
    } else {
        @("Hostx64\x64", "Hostx64\arm64", "Hostarm64\arm64", "Hostarm64\x64")
    }

    # 1. Probe vswhere.exe under both ProgramFiles(x86) and ProgramFiles
    $vswhereCandidates = [System.Collections.Generic.List[string]]::new()
    foreach ($pfVar in @("ProgramFiles(x86)", "ProgramFiles")) {
        $pfRoot = [System.Environment]::GetEnvironmentVariable($pfVar)
        if (-not [string]::IsNullOrWhiteSpace($pfRoot)) {
            $cand = Join-Path $pfRoot "Microsoft Visual Studio\Installer\vswhere.exe"
            if ((Test-Path -LiteralPath $cand -PathType Leaf) -and -not $vswhereCandidates.Contains($cand)) {
                $vswhereCandidates.Add($cand)
            }
        }
    }

    $installPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($vswhere in $vswhereCandidates) {
        foreach ($queryArgs in @(
            @("-latest", "-products", "*", "-prerelease", "-property", "installationPath"),
            @("-products", "*", "-prerelease", "-sort", "-property", "installationPath")
        )) {
            $res = Invoke-NativeCapture -FilePath $vswhere -Arguments $queryArgs
            if ($res.ExitCode -eq 0) {
                foreach ($line in ($res.Output -split '\r?\n')) {
                    $trimmed = $line.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($trimmed) -and -not $installPaths.Contains($trimmed)) {
                        $installPaths.Add($trimmed)
                    }
                }
            }
        }
    }

    foreach ($installPath in $installPaths) {
        $msvcRoot = Join-Path $installPath "VC\Tools\MSVC"
        if (-not (Test-Path -LiteralPath $msvcRoot -PathType Container)) { continue }
        $rawToolsets = @(Get-ChildItem -LiteralPath $msvcRoot -Directory -ErrorAction SilentlyContinue)
        $sortedToolsets = @(Sort-VersionDirsDesc -Dirs $rawToolsets -AllowPrerelease $true -AllowThreePart $true)
        foreach ($ts in $sortedToolsets) {
            foreach ($sub in $binSubpaths) {
                $cand = Join-Path $ts.FullName "bin\$sub\dumpbin.exe"
                if (Test-Path -LiteralPath $cand -PathType Leaf) {
                    return $cand
                }
            }
        }
    }

    # 2. VCToolsInstallDir environment variable (if running inside VS Dev Shell)
    $vcToolsDir = [System.Environment]::GetEnvironmentVariable("VCToolsInstallDir")
    if (-not [string]::IsNullOrWhiteSpace($vcToolsDir)) {
        foreach ($sub in $binSubpaths) {
            $cand = Join-Path $vcToolsDir "bin\$sub\dumpbin.exe"
            if (Test-Path -LiteralPath $cand -PathType Leaf) {
                return $cand
            }
        }
    }

    # 3. Ambient PATH fallback
    $cmd = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    throw "dumpbin.exe not found via vswhere.exe (ProgramFiles(x86)/ProgramFiles), VCToolsInstallDir, or PATH."
}

$script:CachedMakePriExe = ""
$script:CachedMakeAppxExe = ""
$script:CachedDumpBinExe = ""

function Get-MakePriExe {
    if ([string]::IsNullOrWhiteSpace($script:CachedMakePriExe)) {
        $script:CachedMakePriExe = Resolve-WindowsKitTool -ToolName "MakePri.exe"
    }
    return $script:CachedMakePriExe
}

function Get-MakeAppxExe {
    if ([string]::IsNullOrWhiteSpace($script:CachedMakeAppxExe)) {
        $script:CachedMakeAppxExe = Resolve-WindowsKitTool -ToolName "makeappx.exe"
    }
    return $script:CachedMakeAppxExe
}

function Get-DumpBinExe {
    if ([string]::IsNullOrWhiteSpace($script:CachedDumpBinExe)) {
        $script:CachedDumpBinExe = Resolve-DumpBinExe
    }
    return $script:CachedDumpBinExe
}

function Resolve-PosixSh {
    $cmd = Get-Command sh -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    foreach ($cand in @(
        "C:\Program Files\Git\bin\sh.exe",
        "C:\Program Files\Git\usr\bin\sh.exe"
    )) {
        if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
    }
    throw "POSIX sh executable not found on PATH or Git for Windows."
}

function Resolve-ExistingAbsolutePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required $Label not found at '$Path'."
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Strip-AppxFootprintFiles {
    param(
        [Parameter(Mandatory = $true)][string]$StageDir
    )
    foreach ($fp in @("AppxBlockMap.xml", "[Content_Types].xml", "AppxSignature.p7x", "AppxMetadata")) {
        $fpPath = Join-Path $StageDir $fp
        if (Test-Path -LiteralPath $fpPath) {
            Remove-Item -LiteralPath $fpPath -Recurse -Force
        }
    }
}

function Read-EntryBytesFromZip {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$EntryName
    )
    $fullPath = Resolve-ExistingAbsolutePath -Path $ZipPath -Label "ZIP/MSIX archive"
    Add-Type -AssemblyName System.IO.Compression
    $targetNorm = $EntryName.Replace('\', '/')
    $fs = [System.IO.File]::OpenRead($fullPath)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $match = $null
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName.Replace('\', '/').Equals($targetNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $match = $entry
                    break
                }
            }
            if ($null -eq $match) {
                return $null
            }
            $es = $match.Open()
            try {
                $ms = [System.IO.MemoryStream]::new()
                try {
                    $es.CopyTo($ms)
                    return ,$ms.ToArray()
                }
                finally {
                    $ms.Dispose()
                }
            }
            finally {
                $es.Dispose()
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

function Read-MsixManifestMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$MsixFile
    )
    $bytes = Read-EntryBytesFromZip -ZipPath $MsixFile -EntryName "AppxManifest.xml"
    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        throw "MSIX archive '$MsixFile' does not contain AppxManifest.xml"
    }
    $doc = [System.Xml.XmlDocument]::new()
    $doc.XmlResolver = $null
    $readerSettings = [System.Xml.XmlReaderSettings]::new()
    $readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $readerSettings.XmlResolver = $null
    $ms = [System.IO.MemoryStream]::new($bytes)
    try {
        $reader = [System.Xml.XmlReader]::Create($ms, $readerSettings)
        try {
            $doc.Load($reader)
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $ms.Dispose()
    }
    $nsm = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
    $nsm.AddNamespace("appx", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $idNode = $doc.SelectSingleNode("/appx:Package/appx:Identity", $nsm)
    if ($null -eq $idNode) {
        throw "AppxManifest.xml in '$MsixFile' is missing /Package/Identity"
    }
    $identityName = [string]$idNode.GetAttribute("Name")
    $arch = ([string]$idNode.GetAttribute("ProcessorArchitecture")).ToLowerInvariant()
    $ver = [string]$idNode.GetAttribute("Version")
    if ([string]::IsNullOrWhiteSpace($identityName) -or [string]::IsNullOrWhiteSpace($arch)) {
        throw "AppxManifest.xml in '$MsixFile' has incomplete Identity attributes (Name='$identityName', ProcessorArchitecture='$arch')"
    }
    $appNode = $doc.SelectSingleNode("/appx:Package/appx:Applications/appx:Application", $nsm)
    $exeName = if ($null -ne $appNode -and -not [string]::IsNullOrWhiteSpace($appNode.GetAttribute("Executable"))) {
        [string]$appNode.GetAttribute("Executable")
    } else {
        "totaldrop-winui.exe"
    }
    $depNode = $doc.SelectSingleNode("/appx:Package/appx:Dependencies/appx:PackageDependency[@Name='Microsoft.WindowsAppRuntime.1.8']", $nsm)
    $rtMinRaw = if ($null -ne $depNode -and -not [string]::IsNullOrWhiteSpace($depNode.GetAttribute("MinVersion"))) {
        [string]$depNode.GetAttribute("MinVersion")
    } else {
        "8000.994.2142.0"
    }
    return [PSCustomObject]@{
        IdentityName      = $identityName
        Architecture      = $arch
        Version           = $ver
        Executable        = $exeName
        RuntimeMinVersion = [version]$rtMinRaw
    }
}

$script:DotnetTestsBuilt = $false

function Ensure-DotnetTestsBuilt {
    if ($script:DotnetTestsBuilt) {
        return
    }
    $uiDir = Join-Path $RepoRoot "ui-winui3-fluent2"
    $builtDll = Join-Path $uiDir "TotalDrop.WinUI.Tests\bin\Release\net10.0\TotalDrop.WinUI.Tests.dll"
    if ($SkipBuild) {
        if (-not (Test-Path -LiteralPath $builtDll -PathType Leaf)) {
            throw "-SkipBuild was specified, but prebuilt test assembly is missing: $builtDll"
        }
        $script:DotnetTestsBuilt = $true
        return
    }
    Push-Location $uiDir
    try {
        & dotnet build "TotalDrop.WinUI.Tests\TotalDrop.WinUI.Tests.csproj" -c Release
        if ($LASTEXITCODE -ne 0) {
            throw "Upfront dotnet build TotalDrop.WinUI.Tests failed with exit $LASTEXITCODE"
        }
        $script:DotnetTestsBuilt = $true
    }
    finally {
        Pop-Location
    }
}

function Invoke-DotnetTestFiltered {
    param(
        [Parameter(Mandatory = $true)][string]$Filter
    )
    Ensure-DotnetTestsBuilt
    $uiDir = Join-Path $RepoRoot "ui-winui3-fluent2"
    Push-Location $uiDir
    try {
        & dotnet test "TotalDrop.WinUI.Tests\TotalDrop.WinUI.Tests.csproj" -c Release --no-build --filter $Filter --blame-hang-timeout 2m --verbosity minimal
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet test filter '$Filter' failed with exit $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-E2ETest {
    param(
        [Parameter(Mandatory = $true)][string]$TestId,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    try {
        $detail = & $Body
        $Results[$TestId] = @{ status = "PASS"; detail = ([string]$detail) }
        Write-Host "[PASS] $TestId : $detail"
    }
    catch {
        $Results[$TestId] = @{ status = "FAIL"; detail = $_.Exception.Message }
        Write-Host "[FAIL] $TestId : $($_.Exception.Message)" -ForegroundColor Red
    }
}

$PythonExe = Resolve-PythonExe
$WorkTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("totaldrop-win-e2e-" + $PID + "-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $WorkTemp | Out-Null

$SavedFfiDllPath = $env:TOTALDROP_FFI_DLL_PATH
$SavedExtDllPath = $env:TOTALDROP_EXPLORER_EXT_DLL

try {
    if ($BundleVersion -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\z') {
        throw "Invalid -BundleVersion '$BundleVersion': expected strict 4-part numeric quad (e.g. 1.0.1.0)."
    }

    $ExpectedArtifactName = (& $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --root $RepoRoot --arch x64 --resolve-recipe).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ExpectedArtifactName)) {
        throw "Failed to resolve artifact_name from subplatforms/msix/x86_64/RECIPE.toml"
    }

    if ([string]::IsNullOrWhiteSpace($MsixPath)) {
        $MsixPath = Join-Path $RepoRoot ("dist\" + $ExpectedArtifactName)
    }

    $RunM1 = ($Milestone -eq "M1" -or $Milestone -eq "All")
    $RunM2 = ($Milestone -eq "M2" -or $Milestone -eq "All")
    $RunM3 = ($Milestone -eq "M3" -or $Milestone -eq "All")
    $RunM4 = ($Milestone -eq "M4" -or $Milestone -eq "All")

    $PubOutDir = Join-Path $WorkTemp "publish-win-x64"
    $UnpackedDir = Join-Path $WorkTemp "unpacked-msix"
    $PriDumpPath = Join-Path $WorkTemp "pri-dump.xml"
    $FfiDll = Join-Path $RepoRoot "target\x86_64-pc-windows-msvc\release\totaldrop_windows_ffi.dll"
    $ExtDll = Join-Path $RepoRoot "target\x86_64-pc-windows-msvc\release\totaldrop_explorer_ext.dll"

    if ($RunM1) {
        # T1-F05-02: PowerShell AST parse + ambient RUSTFLAGS restoration around build-x64.ps1
        Invoke-E2ETest "T1-F05-02" {
            $buildScript = Join-Path $RepoRoot "target-x86_64\build-x64.ps1"
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -ne 0) {
                throw "PowerShell AST parse errors in build-x64.ps1: $($parseErrors -join '; ')"
            }
            if (-not $SkipBuild) {
                $childCmd = @"
`$ErrorActionPreference = 'Stop'
`$env:RUSTFLAGS = '-C debuginfo=2'
& '$buildScript' -SelfSignEphemeral
if (`$env:RUSTFLAGS -ne '-C debuginfo=2') {
    throw "Caller RUSTFLAGS not restored: got '`$(`$env:RUSTFLAGS)'"
}
"@
                & pwsh -NoProfile -Command $childCmd
                if ($LASTEXITCODE -ne 0) { throw "build-x64.ps1 -SelfSignEphemeral failed with exit $LASTEXITCODE" }
                "AST 0 errors; build-x64.ps1 -SelfSignEphemeral succeeded and restored caller RUSTFLAGS"
            }
            else {
                "AST 0 errors; build-x64.ps1 invocation skipped via -SkipBuild"
            }
        }

        # T1-F02-03: Clean .NET 10 Native AOT publish with zero warnings
        Invoke-E2ETest "T1-F02-03" {
            if (-not (Test-Path -LiteralPath $FfiDll -PathType Leaf)) {
                throw "Missing compiled x64 FFI DLL at $FfiDll"
            }
            New-Item -ItemType Directory -Force -Path $PubOutDir | Out-Null
            Push-Location (Join-Path $RepoRoot "ui-winui3-fluent2")
            try {
                & dotnet publish "TotalDrop.WinUI.csproj" `
                    -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true `
                    -p:WindowsAppSDKSelfContained=false -p:TreatWarningsAsErrors=true -o $PubOutDir
                if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit $LASTEXITCODE" }
            }
            finally {
                Pop-Location
            }
            "dotnet publish -r win-x64 PublishAot=true TreatWarningsAsErrors=true exited 0"
        }

        # T1-F02-04 & T1-F02-05: PE32+ Native AOT purity & RT_GROUP_ICON/RT_ICON resources
        Invoke-E2ETest "T1-F02-04" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $PubOutDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "verify_pe_hardening.py failed on publish output" }
            "PE32+ AMD64 Native AOT purity and staged totaldrop_windows_ffi.dll verified"
        }
        Invoke-E2ETest "T1-F02-05" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $PubOutDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "RT_GROUP_ICON/RT_ICON resource check failed" }
            "RT_GROUP_ICON (14) and RT_ICON (3) resources verified in totaldrop-winui.exe"
        }

        # T2-F02-01: Missing totaldrop_windows_ffi.dll MUST fail dotnet publish loudly with exact csproj diagnostic
        Invoke-E2ETest "T2-F02-01" {
            $isoRoot = Join-Path $WorkTemp "missing-dll-copy"
            $isoUi = Join-Path $isoRoot "ui-winui3-fluent2"
            New-Item -ItemType Directory -Force -Path $isoUi | Out-Null
            Get-ChildItem -LiteralPath (Join-Path $RepoRoot "ui-winui3-fluent2") -Force |
                Where-Object { $_.Name -notin @("bin", "obj", "TotalDrop.WinUI.Tests") } |
                ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $isoUi -Recurse -Force }
            $isoOut = Join-Path $WorkTemp "missing-dll-out"
            Push-Location $isoUi
            try {
                $pubRes = Invoke-NativeCapture -FilePath "dotnet" -Arguments @(
                    "publish", (Join-Path $isoUi "TotalDrop.WinUI.csproj"),
                    "-r", "win-x64", "-c", "Release", "-p:Platform=x64",
                    "-p:PublishAot=true", "-p:WindowsAppSDKSelfContained=false", "-o", $isoOut
                )
            }
            finally {
                Pop-Location
            }
            if ($pubRes.ExitCode -eq 0) {
                throw "dotnet publish unexpectedly succeeded when totaldrop_windows_ffi.dll was missing!"
            }
            if ($pubRes.Output -notmatch 'Native Rust FFI DLL not found') {
                throw "dotnet publish failed without expected csproj diagnostic 'Native Rust FFI DLL not found' (rc=$($pubRes.ExitCode)): $($pubRes.Output)"
            }
            "dotnet publish failed loudly (exit $($pubRes.ExitCode)) with 'Native Rust FFI DLL not found'"
        }

        # T2-F02-04: 3 CLR/JIT/apphost contamination mutations rejected
        Invoke-E2ETest "T2-F02-04" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $PubOutDir --arch x64 --milestone M1 --self-test-mutations
            if ($LASTEXITCODE -ne 0) { throw "T2-F02-04 CLR/apphost mutation self-test failed" }
            "All CLR/apphost contamination mutations rejected by verify_pe_hardening.py"
        }

        # T1-F05-03: Strict makeappx.exe unpack of RECIPE-resolved MSIX
        Invoke-E2ETest "T1-F05-03" {
            if (-not (Test-Path -LiteralPath $MsixPath -PathType Leaf)) { throw "MSIX not found: $MsixPath" }
            $makeAppxExe = Get-MakeAppxExe
            & $makeAppxExe unpack /o /p $MsixPath /d $UnpackedDir
            if ($LASTEXITCODE -ne 0) { throw "makeappx.exe unpack failed with exit $LASTEXITCODE" }
            foreach ($req in @("AppxManifest.xml", "AppxBlockMap.xml", "resources.pri", "totaldrop-winui.exe", "totaldrop_windows_ffi.dll")) {
                if (-not (Test-Path -LiteralPath (Join-Path $UnpackedDir $req) -PathType Leaf)) {
                    throw "Unpacked MSIX missing $req"
                }
            }
            "makeappx.exe unpack verified SHA-256 blockmap and unpacked all required payloads"
        }

        # T1-F04-03, T1-F04-04, T1-F04-05: resources.pri magic/size + MakePri dump 35 locales & qualifiers
        Invoke-E2ETest "T1-F04-03" {
            $priFile = Join-Path $UnpackedDir "resources.pri"
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --check-pri-file $priFile
            if ($LASTEXITCODE -ne 0) { throw "resources.pri magic/size verification failed" }
            "resources.pri > 4096 bytes with exact b'mrm_pri2' header"
        }
        Invoke-E2ETest "T1-F04-04" {
            $makePriExe = Get-MakePriExe
            & $makePriExe dump /if (Join-Path $UnpackedDir "resources.pri") /of $PriDumpPath /dt detailed /o
            if ($LASTEXITCODE -ne 0) { throw "MakePri.exe dump failed with exit $LASTEXITCODE" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "pri.xml 35-language completeness check failed" }
            "All 35 canonical BCP-47 languages verified in dumped pri.xml"
        }
        Invoke-E2ETest "T1-F04-05" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "pri.xml asset qualifier check failed" }
            "Scale (100..400), TargetSize (16..256), UNPLATED, and LIGHTUNPLATED verified in pri.xml"
        }

        # T2-F04-04: 0-byte and FAKEPRI! stub rejected
        Invoke-E2ETest "T2-F04-04" {
            $zeroPri = Join-Path $WorkTemp "zero.pri"
            $fakePri = Join-Path $WorkTemp "fake.pri"
            [System.IO.File]::WriteAllBytes($zeroPri, @())
            [System.IO.File]::WriteAllBytes($fakePri, [System.Text.Encoding]::ASCII.GetBytes("FAKEPRI!" + ("x" * 5000)))
            $resZero = Invoke-NativeCapture -FilePath $PythonExe -Arguments @(
                "-B", (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py"), "--check-pri-file", $zeroPri
            )
            if ($resZero.ExitCode -eq 0) { throw "0-byte PRI unexpectedly passed" }
            $resFake = Invoke-NativeCapture -FilePath $PythonExe -Arguments @(
                "-B", (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py"), "--check-pri-file", $fakePri
            )
            if ($resFake.ExitCode -eq 0) { throw "FAKEPRI! stub unexpectedly passed" }
            "0-byte and non-mrm_pri2 stub resources.pri rejected"
        }

        # T2-F04-05: 34-locale zh-Hant removal in MakePri + duplicate <Resource Language="tr"/> check
        Invoke-E2ETest "T2-F04-05" {
            $makePriExe = Get-MakePriExe
            $badStage = Join-Path $WorkTemp "pri-34-stage"
            Copy-Item -LiteralPath $UnpackedDir -Destination $badStage -Recurse -Force
            Strip-AppxFootprintFiles -StageDir $badStage
            Remove-Item -LiteralPath (Join-Path $badStage "resources.pri") -Force -ErrorAction SilentlyContinue
            $stringsDst = Join-Path $badStage "Strings"
            Copy-Item -LiteralPath (Join-Path $RepoRoot "ui-winui3-fluent2\Strings") -Destination $stringsDst -Recurse -Force
            Remove-Item -LiteralPath (Join-Path $stringsDst "locales.json") -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $stringsDst "zh-Hant") -Recurse -Force
            $manPath = Join-Path $badStage "AppxManifest.xml"
            $manText = Get-Content -LiteralPath $manPath -Raw
            Set-Content -LiteralPath $manPath -Value ($manText -replace '<Resource Language="zh-Hant"\s*/>', '') -NoNewline
            $badCfg = Join-Path $WorkTemp "bad-priconfig.xml"
            $badPri = Join-Path $badStage "resources.pri"
            $badDump = Join-Path $WorkTemp "bad-pri.xml"
            & $makePriExe createconfig /cf $badCfg /dq lang-en /o /pv 10.0.0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri createconfig failed in T2-F04-05 with exit $LASTEXITCODE" }
            [xml]$px = Get-Content -LiteralPath $badCfg -Raw
            $pkgNode = $px.SelectSingleNode("/resources/packaging")
            if ($null -ne $pkgNode) { [void]$px.resources.RemoveChild($pkgNode) }
            $px.Save($badCfg)
            & $makePriExe new /pr $badStage /cf $badCfg /mn $manPath /of $badPri /o | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri new failed in T2-F04-05 with exit $LASTEXITCODE" }
            & $makePriExe dump /if $badPri /of $badDump /dt detailed /o | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri dump failed in T2-F04-05 with exit $LASTEXITCODE" }
            $res34 = Invoke-NativeCapture -FilePath $PythonExe -Arguments @(
                "-B", (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py"), "--pri-dump", $badDump
            )
            if ($res34.ExitCode -eq 0 -or $res34.Output -notmatch "34 != 35" -or $res34.Output -notmatch "zh-Hant") {
                throw "34-locale PRI dump without zh-Hant was not caught with '34 != 35' and 'zh-Hant': $($res34.Output)"
            }

            $dupRepo = Join-Path $WorkTemp "dup-tr-repo"
            & git clone --local --no-hardlinks -q $RepoRoot $dupRepo
            if ($LASTEXITCODE -ne 0) { throw "git clone failed in T2-F04-05 with exit $LASTEXITCODE" }
            $dupMan = Join-Path $dupRepo "target-x86_64\Package.x64.appxmanifest"
            $dupText = Get-Content -LiteralPath $dupMan -Raw
            $dupText = $dupText -replace '(<Resource Language="tr" />)', "`$1`n    <Resource Language=`"tr`" />"
            Set-Content -LiteralPath $dupMan -Value $dupText -NoNewline
            $resDup = Invoke-NativeCapture -FilePath $PythonExe -Arguments @(
                "-B", (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py"), "--milestone", "M1", "--root", $dupRepo
            )
            if ($resDup.ExitCode -eq 0 -or $resDup.Output -notmatch "tr") {
                throw "Duplicate <Resource Language='tr'/> was not caught: $($resDup.Output)"
            }
            "34-locale PRI dump missing zh-Hant and duplicate tr manifest resource both caught"
        }

        # T1-F05-04: PE32+ oracle + dumpbin.exe cross-check on unpacked totaldrop_windows_ffi.dll
        Invoke-E2ETest "T1-F05-04" {
            $unpackedFfi = Join-Path $UnpackedDir "totaldrop_windows_ffi.dll"
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $UnpackedDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "verify_pe_hardening.py failed on unpacked MSIX" }
            $dumpBinExe = Get-DumpBinExe
            $dumpOut = (& $dumpBinExe /headers /loadconfig /imports /exports $unpackedFfi) -join "`n"
            if ($LASTEXITCODE -ne 0) { throw "dumpbin.exe failed with exit $LASTEXITCODE" }
            foreach ($tok in @("8664", "Dynamic base", "NX compatible", "High Entropy Virtual Addresses", "totaldrop_win_version_json")) {
                if ($dumpOut -notmatch [regex]::Escape($tok)) {
                    throw "dumpbin output missing expected token '$tok'"
                }
            }
            if ($dumpOut -match "vcruntime140|msvcp140|concrt140|vcomp140|ucrtbased") {
                throw "dumpbin detected forbidden dynamic/debug CRT import"
            }
            "PE32+ oracle and dumpbin.exe corroborated hardening, +crt-static, and M1 exports"
        }

        # T1-F05-05: AppxSignature.p7x CN=TotalDrop + SHA-256 + SHA256SUMS + zero key residue
        Invoke-E2ETest "T1-F05-05" {
            $sig = Get-AuthenticodeSignature -FilePath $MsixPath
            if ($null -eq $sig.SignerCertificate) {
                throw "MSIX has no Authenticode signer certificate (status=$($sig.Status))"
            }
            if ($sig.SignerCertificate.Subject -ne "CN=TotalDrop") {
                throw "Unexpected Authenticode signer subject: $($sig.SignerCertificate.Subject)"
            }
            if ($sig.SignerCertificate.SignatureAlgorithm.FriendlyName -notmatch 'sha256') {
                throw "Unexpected Authenticode signature algorithm: $($sig.SignerCertificate.SignatureAlgorithm.FriendlyName)"
            }
            if ($sig.Status -ne "Valid" -and -not ($sig.Status -eq "UnknownError" -and $sig.StatusMessage -match "not trusted|root certificate|untrusted")) {
                throw "Unexpected Authenticode signature status: $($sig.Status) ($($sig.StatusMessage))"
            }
            $distDir = Split-Path -Parent $MsixPath
            $sumsPath = Join-Path $distDir "SHA256SUMS"
            if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { throw "Missing $sumsPath" }
            $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $MsixPath).Hash.ToLowerInvariant()
            $sumsText = Get-Content -LiteralPath $sumsPath -Raw
            if ($sumsText -notmatch "$actualHash\s+$([regex]::Escape((Split-Path -Leaf $MsixPath)))") {
                throw "SHA256SUMS does not match $MsixPath ($actualHash)"
            }
            $leaks = @(Get-ChildItem -LiteralPath $RepoRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.FullName -notmatch '\\\.git\\' -and
                    $_.Extension -in @(".pfx", ".p12", ".cer", ".snk", ".key", ".pem", ".pvk", ".jks", ".keystore", ".pepk")
                })
            if ($leaks.Count -gt 0) { throw "Signing key residue found in repo: $($leaks.FullName -join ', ')" }
            "CN=TotalDrop SHA-256 signature, SHA256SUMS, and zero key residue verified"
        }

        # T1-F06-04: OPC/MSIX validator + subplatforms/msix/x86_64/verify.sh
        Invoke-E2ETest "T1-F06-04" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") `
                --msix $MsixPath --arch x64 --milestone M1 --expect-signed --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "verify_msix_opc.py failed on signed MSIX" }
            $distDir = Split-Path -Parent $MsixPath
            $shExe = Resolve-PosixSh
            & $shExe (Join-Path $RepoRoot "subplatforms\msix\x86_64\verify.sh") $distDir
            if ($LASTEXITCODE -ne 0) { throw "subplatforms/msix/x86_64/verify.sh failed" }
            "Signed MSIX passed OPC/ZIP, ANSI paths, PRI dump, and subplatform verify.sh"
        }

        # T2-F05-02: Strict makeappx.exe pack (no /nv) non-vacuity control + rejects missing StoreLogo & missing exe
        Invoke-E2ETest "T2-F05-02" {
            $makeAppxExe = Get-MakeAppxExe
            $makePriExe = Get-MakePriExe

            # (0) Non-vacuity control: unmodified footprint-stripped copy MUST pack cleanly
            $stageControl = Join-Path $WorkTemp "control-stage-valid"
            Copy-Item -LiteralPath $UnpackedDir -Destination $stageControl -Recurse -Force
            Strip-AppxFootprintFiles -StageDir $stageControl
            $ctrlRes = Invoke-NativeCapture -FilePath $makeAppxExe -Arguments @(
                "pack", "/o", "/h", "SHA256", "/d", $stageControl, "/p", (Join-Path $WorkTemp "control-valid.msix")
            )
            if ($ctrlRes.ExitCode -ne 0) {
                throw "Non-vacuity control failed: footprint-stripped unpacked MSIX did not pack cleanly (rc=$($ctrlRes.ExitCode)): $($ctrlRes.Output)"
            }

            # (a) Strip footprints first, delete all StoreLogo.scale-*.png, regenerate unified resources.pri
            $stageA = Join-Path $WorkTemp "bad-stage-logo"
            Copy-Item -LiteralPath $UnpackedDir -Destination $stageA -Recurse -Force
            Strip-AppxFootprintFiles -StageDir $stageA
            Get-ChildItem -LiteralPath (Join-Path $stageA "Assets") -Filter "StoreLogo.scale-*.png" | Remove-Item -Force
            Remove-Item -LiteralPath (Join-Path $stageA "resources.pri") -Force -ErrorAction SilentlyContinue
            $stageAStrings = Join-Path $stageA "Strings"
            Copy-Item -LiteralPath (Join-Path $RepoRoot "ui-winui3-fluent2\Strings") -Destination $stageAStrings -Recurse -Force
            Remove-Item -LiteralPath (Join-Path $stageAStrings "locales.json") -Force -ErrorAction SilentlyContinue
            $cfgA = Join-Path $WorkTemp "pri-a.xml"
            & $makePriExe createconfig /cf $cfgA /dq lang-en /o /pv 10.0.0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri createconfig failed in T2-F05-02 with exit $LASTEXITCODE" }
            [xml]$priXmlA = Get-Content -LiteralPath $cfgA -Raw
            $pkgNodeA = $priXmlA.SelectSingleNode("/resources/packaging")
            if ($null -ne $pkgNodeA) { [void]$priXmlA.resources.RemoveChild($pkgNodeA) }
            $priXmlA.Save($cfgA)
            & $makePriExe new /pr $stageA /cf $cfgA /mn (Join-Path $stageA "AppxManifest.xml") /of (Join-Path $stageA "resources.pri") /o | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri new failed in T2-F05-02 with exit $LASTEXITCODE" }
            Remove-Item -LiteralPath $stageAStrings -Recurse -Force
            $resA = Invoke-NativeCapture -FilePath $makeAppxExe -Arguments @(
                "pack", "/o", "/h", "SHA256", "/d", $stageA, "/p", (Join-Path $WorkTemp "bad-logo.msix")
            )
            if ($resA.ExitCode -eq 0) {
                throw "makeappx.exe pack unexpectedly succeeded with missing StoreLogo!"
            }
            if ($resA.Output -match '0x80080200|80080200|AppxBlockMap|Content_Types|AppxSignature|footprint') {
                throw "makeappx.exe pack failed due to footprint residue instead of missing StoreLogo: $($resA.Output)"
            }
            if ($resA.Output -notmatch 'StoreLogo|Logo') {
                throw "makeappx.exe pack failure did not reference missing StoreLogo (rc=$($resA.ExitCode)): $($resA.Output)"
            }

            # (b) Strip footprints and delete totaldrop-winui.exe
            $stageB = Join-Path $WorkTemp "bad-stage-exe"
            Copy-Item -LiteralPath $UnpackedDir -Destination $stageB -Recurse -Force
            Strip-AppxFootprintFiles -StageDir $stageB
            Remove-Item -LiteralPath (Join-Path $stageB "totaldrop-winui.exe") -Force
            $resB = Invoke-NativeCapture -FilePath $makeAppxExe -Arguments @(
                "pack", "/o", "/h", "SHA256", "/d", $stageB, "/p", (Join-Path $WorkTemp "bad-exe.msix")
            )
            if ($resB.ExitCode -eq 0) {
                throw "makeappx.exe pack unexpectedly succeeded with missing totaldrop-winui.exe!"
            }
            if ($resB.Output -match '0x80080200|80080200|AppxBlockMap|Content_Types|AppxSignature|footprint') {
                throw "makeappx.exe pack failed due to footprint residue instead of missing totaldrop-winui.exe: $($resB.Output)"
            }
            if ($resB.Output -notmatch 'totaldrop-winui\.exe') {
                throw "makeappx.exe pack failure did not reference missing totaldrop-winui.exe (rc=$($resB.ExitCode)): $($resB.Output)"
            }
            "Non-vacuity control packed cleanly; strict makeappx.exe pack rejected missing StoreLogo and missing totaldrop-winui.exe"
        }

        # T2-F05-03: 4 PE32+ binary mutations on unpacked totaldrop_windows_ffi.dll
        Invoke-E2ETest "T2-F05-03" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $UnpackedDir --arch x64 --milestone M1 --self-test-mutations
            if ($LASTEXITCODE -ne 0) { throw "T2-F05-03 PE32+ mutation self-test failed" }
            "All 4 PE32+ CRT/CET/DependentLoadFlags/NX+HEVA mutations rejected"
        }

        # T2-F05-04: Corrupt 1 byte inside totaldrop_windows_ffi.dll in copied MSIX -> unpack fails
        Invoke-E2ETest "T2-F05-04" {
            $makeAppxExe = Get-MakeAppxExe
            $tampered = Join-Path $WorkTemp "tampered.msix"
            Copy-Item -LiteralPath $MsixPath -Destination $tampered -Force
            $tamperPy = @"
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p, 'r') as zin:
    items = [(info, zin.read(info.filename)) for info in zin.infolist()]
with zipfile.ZipFile(p, 'w') as zout:
    for info, data in items:
        if info.filename == 'totaldrop_windows_ffi.dll':
            b = bytearray(data)
            b[len(b) // 2] ^= 0x01
            data = bytes(b)
        zout.writestr(info, data)
"@
            & $PythonExe -B -c $tamperPy $tampered
            if ($LASTEXITCODE -ne 0) { throw "Failed to craft tampered MSIX copy" }
            $unpackRes = Invoke-NativeCapture -FilePath $makeAppxExe -Arguments @(
                "unpack", "/o", "/p", $tampered, "/d", (Join-Path $WorkTemp "tampered-out")
            )
            if ($unpackRes.ExitCode -eq 0) { throw "makeappx.exe unpack did not catch 1-byte DLL tampering!" }
            "makeappx.exe unpack rejected 1-byte tampered DLL via AppxBlockMap SHA-256 mismatch"
        }

        # T2-F05-05: Execute real build-x64.ps1 -SelfSignEphemeral try/finally on forced signtool failure + synthetic key-leak scanner
        Invoke-E2ETest "T2-F05-05" {
            # (a) AST-verify and execute build-x64.ps1's verbatim if ($SelfSignEphemeral) { ... try { ... } finally { ... } } block
            $buildScript = Join-Path $RepoRoot "target-x86_64\build-x64.ps1"
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -ne 0) {
                throw "PowerShell AST parse errors in build-x64.ps1: $($parseErrors -join '; ')"
            }
            $resolveFnMatches = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Resolve-WindowsKitTool"
            }, $true))
            if ($resolveFnMatches.Count -ne 1) {
                throw "Expected exactly 1 Resolve-WindowsKitTool function in build-x64.ps1, found $($resolveFnMatches.Count)"
            }
            $resolveFnAst = $resolveFnMatches[0]

            $signIfMatches = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.IfStatementAst] -and
                    $node.Clauses.Count -gt 0 -and
                    $node.Clauses[0].Item1.Extent.Text -match '\$SelfSignEphemeral'
            }, $true))
            if ($signIfMatches.Count -ne 1) {
                throw "Expected exactly 1 if (`$SelfSignEphemeral) signing block in build-x64.ps1, found $($signIfMatches.Count)"
            }
            $signIfAst = $signIfMatches[0]
            if ($signIfAst.Extent.Text -notmatch '\$EffectivePublisher' -or $signIfAst.Extent.Text -notmatch '\$OutMsix') {
                throw "build-x64.ps1 if (`$SelfSignEphemeral) signing block drifted from expected `$EffectivePublisher/`$OutMsix contract"
            }

            $tryAst = $signIfAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.TryStatementAst]
            }, $true)
            if ($null -eq $tryAst) {
                throw "build-x64.ps1 if (`$SelfSignEphemeral) is missing a try/finally block"
            }
            if ($tryAst.Body.Extent.Text -notmatch 'New-SelfSignedCertificate' -or $tryAst.Body.Extent.Text -notmatch 'SignToolExe|signtool') {
                throw "build-x64.ps1 ephemeral signing try block missing New-SelfSignedCertificate or signtool invocation"
            }
            if ($null -eq $tryAst.Finally -or
                $tryAst.Finally.Extent.Text -notmatch 'Remove-Item' -or
                $tryAst.Finally.Extent.Text -notmatch 'Cert:\\CurrentUser\\My\\') {
                throw "build-x64.ps1 ephemeral signing finally block missing Cert:\CurrentUser\My\ Remove-Item cleanup"
            }

            $beforeThumbs = @(Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq "CN=TotalDrop" } | Select-Object -ExpandProperty Thumbprint)
            $isoSignDir = Join-Path $WorkTemp "build-x64-sign-fail"
            New-Item -ItemType Directory -Force -Path $isoSignDir | Out-Null
            $roMsix = Join-Path $isoSignDir "readonly.msix"
            Copy-Item -LiteralPath $MsixPath -Destination $roMsix -Force
            Set-ItemProperty -LiteralPath $roMsix -Name IsReadOnly -Value $true

            $isoSignScript = Join-Path $isoSignDir "build-x64-signing-stage.ps1"
            $isoScriptBody = @(
                'param([Parameter(Mandatory = $true)][string]$OutMsix, [switch]$SelfSignEphemeral, [string]$EffectivePublisher = "CN=TotalDrop")',
                'Set-StrictMode -Version Latest',
                '$ErrorActionPreference = "Stop"',
                $resolveFnAst.Extent.Text,
                $signIfAst.Extent.Text
            ) -join "`n"
            Set-Content -LiteralPath $isoSignScript -Value $isoScriptBody -Encoding utf8NoBOM

            try {
                $signRes = Invoke-NativeCapture -FilePath "pwsh" -Arguments @(
                    "-NoProfile", "-File", $isoSignScript,
                    "-OutMsix", $roMsix, "-SelfSignEphemeral", "-EffectivePublisher", "CN=TotalDrop"
                )
            }
            finally {
                Set-ItemProperty -LiteralPath $roMsix -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
            }
            if ($signRes.ExitCode -eq 0) {
                throw "Isolated build-x64.ps1 -SelfSignEphemeral signing stage unexpectedly succeeded on read-only MSIX"
            }
            if ($signRes.Output -notmatch 'signtool\.exe sign failed with exit code') {
                throw "Isolated build-x64.ps1 -SelfSignEphemeral aborted before signtool.exe failure (rc=$($signRes.ExitCode)): $($signRes.Output)"
            }

            $afterThumbs = @(Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq "CN=TotalDrop" } | Select-Object -ExpandProperty Thumbprint)
            $leakedThumbs = @($afterThumbs | Where-Object { $_ -notin $beforeThumbs })
            if ($leakedThumbs.Count -ne 0) {
                foreach ($lt in $leakedThumbs) {
                    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$lt" -Force -ErrorAction SilentlyContinue
                }
                throw "build-x64.ps1 -SelfSignEphemeral leaked ephemeral CN=TotalDrop cert thumbprints: $($leakedThumbs -join ', ')"
            }
            $isoLeaks = @(Get-ChildItem -LiteralPath $isoSignDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @(".pfx", ".p12", ".cer", ".snk", ".key", ".pem", ".pvk", ".jks", ".keystore", ".pepk") })
            if ($isoLeaks.Count -gt 0) {
                throw "build-x64.ps1 -SelfSignEphemeral left key/cert files on disk: $($isoLeaks.FullName -join ', ')"
            }

            # (b) Synthetic leak files caught by verify_static_contracts.py
            $leakRepo = Join-Path $WorkTemp "leak-repo"
            & git clone --local --no-hardlinks -q $RepoRoot $leakRepo
            if ($LASTEXITCODE -ne 0) { throw "git clone failed in T2-F05-05 with exit $LASTEXITCODE" }
            foreach ($fname in @("leak.pfx", "secret.p12", "dev.snk", "test.cer")) {
                $f = Join-Path $leakRepo $fname
                Set-Content -LiteralPath $f -Value "synthetic-secret"
                $resLeak = Invoke-NativeCapture -FilePath $PythonExe -Arguments @(
                    "-B", (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py"), "--milestone", "M1", "--root", $leakRepo
                )
                Remove-Item -LiteralPath $f -Force
                if ($resLeak.ExitCode -eq 0 -or $resLeak.Output -notmatch [regex]::Escape($fname)) {
                    throw "Signing-material scanner missed $fname"
                }
            }
            "Real build-x64.ps1 -SelfSignEphemeral signtool failure left 0 leaked certs and 0 key files; all 4 forbidden signing extensions caught"
        }

        # T3-14: Headless native C ABI DLL LoadLibraryW/GetProcAddress smoke
        Invoke-E2ETest "T3-14" {
            $smokePy = @"
import ctypes, json, sys
lib = ctypes.CDLL(sys.argv[1])
lib.totaldrop_win_version_json.restype = ctypes.c_void_p
lib.totaldrop_win_string_free.argtypes = [ctypes.c_void_p]
ptr = lib.totaldrop_win_version_json()
assert ptr
raw = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
lib.totaldrop_win_string_free(ptr)
v = json.loads(raw)
assert v['app_version'] == '0.1.0-beta.1' and v['core_version'] == '0.2.0-beta.5' and v['msix_version'] == '0.1.1.0', v
"@
            & $PythonExe -B -c $smokePy (Join-Path $UnpackedDir "totaldrop_windows_ffi.dll")
            if ($LASTEXITCODE -ne 0) { throw "Headless ctypes.CDLL smoke test failed" }
            "Headless native C ABI loader invoked totaldrop_win_version_json and string_free cleanly"
        }

        # T3-15 & T4-06: End-to-end assets + PRI + strict MSIX + PE forensic audit
        Invoke-E2ETest "T3-15" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\render-windows-assets.py") --check
            if ($LASTEXITCODE -ne 0) { throw "render-windows-assets.py --check failed" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_assets_kose.py") --out-dir (Join-Path $UnpackedDir "Assets")
            if ($LASTEXITCODE -ne 0) { throw "verify_assets_kose.py failed on unpacked Assets" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "pri.xml check failed" }
            "Assets, MakePri 35-locale/unplated dump, and strict MSIX unpack verified together"
        }
        Invoke-E2ETest "T4-06" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") `
                --msix $MsixPath --arch x64 --milestone M1 --expect-signed --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "T4-06 MSIX OPC/PRI audit failed" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $UnpackedDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "T4-06 PE hardening audit failed" }
            "Full M1 x64 MSIX forensic audit passed"
        }
    }

    if ($RunM2) {
        $M2PubDir = Join-Path $WorkTemp "publish-m2-win-x64"
        $M2BuildOk = $false
        $M2BuildErr = ""
        try {
            if (-not (Test-Path -LiteralPath $FfiDll -PathType Leaf)) {
                if ($SkipBuild) {
                    throw "-SkipBuild was specified, but missing x64 FFI DLL at $FfiDll"
                }
                $savedRustFlags = $env:RUSTFLAGS
                $savedEncodedRustFlags = $env:CARGO_ENCODED_RUSTFLAGS
                Push-Location $RepoRoot
                try {
                    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
                    Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
                    & cargo build --config (Join-Path $RepoRoot "target-x86_64\cargo-config.toml") `
                        --target x86_64-pc-windows-msvc -p totaldrop-windows-ffi --release --locked
                    if ($LASTEXITCODE -ne 0) { throw "cargo build totaldrop-windows-ffi failed" }
                }
                finally {
                    if ($null -ne $savedRustFlags) {
                        $env:RUSTFLAGS = $savedRustFlags
                    }
                    else {
                        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
                    }
                    if ($null -ne $savedEncodedRustFlags) {
                        $env:CARGO_ENCODED_RUSTFLAGS = $savedEncodedRustFlags
                    }
                    else {
                        Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
                    }
                    Pop-Location
                }
            }
            if (Test-Path -LiteralPath (Join-Path $PubOutDir "totaldrop-winui.exe") -PathType Leaf) {
                $M2PubDir = $PubOutDir
            }
            else {
                New-Item -ItemType Directory -Force -Path $M2PubDir | Out-Null
                Push-Location (Join-Path $RepoRoot "ui-winui3-fluent2")
                try {
                    & dotnet publish "TotalDrop.WinUI.csproj" `
                        -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true `
                        -p:WindowsAppSDKSelfContained=false -p:TreatWarningsAsErrors=true -o $M2PubDir
                    if ($LASTEXITCODE -ne 0) { throw "M2 dotnet publish failed with exit $LASTEXITCODE" }
                }
                finally {
                    Pop-Location
                }
            }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $M2PubDir --arch x64 --milestone M2
            if ($LASTEXITCODE -ne 0) { throw "M2 PE32+ 24-export verification failed" }
            $M2BuildOk = $true
        }
        catch {
            $M2BuildErr = $_.Exception.Message
        }

        foreach ($uiId in @("T1-F10-05", "T1-F11-05", "T1-F12-05")) {
            Invoke-E2ETest $uiId {
                if (-not $M2BuildOk) { throw "M2 Native AOT build failed: $M2BuildErr" }
                & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --milestone M2 --root $RepoRoot
                if ($LASTEXITCODE -ne 0) { throw "verify_static_contracts.py --milestone M2 failed" }
                & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --check-m2-ui-audit --root $RepoRoot
                if ($LASTEXITCODE -ne 0) { throw "M2 UI page audit failed for $uiId" }
                "M2 Native AOT publish (0 warnings, 24 exports) + $uiId UI static contract verified"
            }
        }

        $env:TOTALDROP_FFI_DLL_PATH = Resolve-ExistingAbsolutePath -Path $FfiDll -Label "x64 FFI DLL"

        foreach ($entry in @(
            @("T1-F12-01", "T1_F12_01"),
            @("T1-F12-02", "T1_F12_02"),
            @("T2-F12-01", "T2_F12_01"),
            @("T2-F12-02", "T2_F12_02"),
            @("T3-04", "T3_04")
        )) {
            $tid = $entry[0]
            $flt = $entry[1]
            Invoke-E2ETest $tid {
                Invoke-DotnetTestFiltered -Filter "Category!=WindowsCI&FullyQualifiedName~$flt"
                "Headless .NET 10 TotalDrop.WinUI.Tests ($flt) passed"
            }
        }
    }

    if ($RunM3) {
        $M3PubDir = Join-Path $WorkTemp "publish-m3-win-x64"

        if (-not (Test-Path -LiteralPath $FfiDll -PathType Leaf) -or -not (Test-Path -LiteralPath $ExtDll -PathType Leaf)) {
            if ($SkipBuild) {
                throw "-SkipBuild was specified, but missing x64 DLL(s): FfiDll='$FfiDll', ExtDll='$ExtDll'"
            }
            $savedRf = $env:RUSTFLAGS
            $savedErf = $env:CARGO_ENCODED_RUSTFLAGS
            Push-Location $RepoRoot
            try {
                Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
                Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
                & cargo build --config (Join-Path $RepoRoot "target-x86_64\cargo-config.toml") `
                    --target x86_64-pc-windows-msvc -p totaldrop-windows-ffi -p totaldrop-explorer-ext --release --locked
                if ($LASTEXITCODE -ne 0) { throw "M3 cargo build failed with exit $LASTEXITCODE" }
            }
            finally {
                if ($null -ne $savedRf) { $env:RUSTFLAGS = $savedRf } else { Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue }
                if ($null -ne $savedErf) { $env:CARGO_ENCODED_RUSTFLAGS = $savedErf } else { Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue }
                Pop-Location
            }
        }

        $env:TOTALDROP_FFI_DLL_PATH = Resolve-ExistingAbsolutePath -Path $FfiDll -Label "x64 FFI DLL"
        $env:TOTALDROP_EXPLORER_EXT_DLL = Resolve-ExistingAbsolutePath -Path $ExtDll -Label "x64 Explorer COM DLL"

        # T1-F16-01: PE32+ + dumpbin oracle on totaldrop_explorer_ext.dll
        Invoke-E2ETest "T1-F16-01" {
            New-Item -ItemType Directory -Force -Path $M3PubDir | Out-Null
            if (Test-Path -LiteralPath (Join-Path $PubOutDir "totaldrop-winui.exe") -PathType Leaf) {
                Get-ChildItem -LiteralPath $PubOutDir -Force |
                    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $M3PubDir -Recurse -Force }
            }
            else {
                Push-Location (Join-Path $RepoRoot "ui-winui3-fluent2")
                try {
                    & dotnet publish "TotalDrop.WinUI.csproj" `
                        -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true `
                        -p:WindowsAppSDKSelfContained=false -p:TreatWarningsAsErrors=true -o $M3PubDir
                    if ($LASTEXITCODE -ne 0) { throw "M3 dotnet publish failed with exit $LASTEXITCODE" }
                }
                finally {
                    Pop-Location
                }
            }
            Copy-Item -LiteralPath $ExtDll -Destination $M3PubDir -Force
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $M3PubDir --arch x64 --milestone M3
            if ($LASTEXITCODE -ne 0) { throw "M3 verify_pe_hardening.py failed" }
            $dumpBinExe = Get-DumpBinExe
            $dumpExt = (& $dumpBinExe /headers /loadconfig /imports /exports $ExtDll) -join "`n"
            if ($LASTEXITCODE -ne 0) { throw "dumpbin.exe failed on totaldrop_explorer_ext.dll" }
            foreach ($tok in @("8664", "Dynamic base", "NX compatible", "High Entropy Virtual Addresses", "DllGetClassObject", "DllCanUnloadNow")) {
                if ($dumpExt -notmatch [regex]::Escape($tok)) { throw "dumpbin missing '$tok' in totaldrop_explorer_ext.dll" }
            }
            if ($dumpExt -match "vcruntime140|msvcp140|ucrtbased") { throw "forbidden CRT import in totaldrop_explorer_ext.dll" }
            "x64 totaldrop_explorer_ext.dll verified (PE32+ 0x8664, CETCOMPAT, 0x800, +crt-static, COM exports, RT_GROUP_ICON 101)"
        }

        # 8 COM DLL tests via e2e_com_harness.rs loading compiled totaldrop_explorer_ext.dll
        foreach ($comEntry in @(
            @("T1-F16-02", "t1_f16_02"),
            @("T1-F16-04", "t1_f16_04"),
            @("T1-F16-05", "t1_f16_05"),
            @("T2-F16-01", "t2_f16_01"),
            @("T2-F16-04", "t2_f16_04"),
            @("T2-F16-05", "t2_f16_05"),
            @("T3-09", "t3_09"),
            @("T4-07", "t4_07")
        )) {
            $tid = $comEntry[0]
            $flt = $comEntry[1]
            Invoke-E2ETest $tid {
                Push-Location $RepoRoot
                try {
                    & cargo test --locked -p totaldrop-explorer-ext --test e2e_com_harness -- $flt --nocapture
                    if ($LASTEXITCODE -ne 0) { throw "e2e_com_harness filter '$flt' failed with exit $LASTEXITCODE" }
                }
                finally { Pop-Location }
                "In-proc COM harness ($flt) against compiled totaldrop_explorer_ext.dll passed"
            }
        }

        # Headless Windows-native .NET 10 M3 tests
        foreach ($winDotnet in @(
            @("T1-F17-04", "T1_F17_04"),
            @("T1-F18-04", "T1_F18_04"),
            @("T1-F20-02", "T1_F20_02"),
            @("T2-F20-01", "T2_F20_01"),
            @("T1-F21-04", "T1_F21_03"),
            @("T3-10", "T3_10")
        )) {
            $tid = $winDotnet[0]
            $flt = $winDotnet[1]
            Invoke-E2ETest $tid {
                Invoke-DotnetTestFiltered -Filter "Category=WindowsCI&FullyQualifiedName~$flt"
                if ($tid -eq "T1-F21-04") {
                    Invoke-DotnetTestFiltered -Filter "Category=WindowsCI&FullyQualifiedName~T1_F21_04"
                }
                if ($tid -eq "T3-10") {
                    Invoke-DotnetTestFiltered -Filter "Category=WindowsCI&FullyQualifiedName~T2_F17_06"
                }
                "Headless Windows-native .NET 10 test ($tid / $flt) passed"
            }
        }

        # T1-F19-05: M3 Native AOT publish + strict MSIX pack containing ToastNotificationActivation & ExeServer
        Invoke-E2ETest "T1-F19-05" {
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --milestone M3 --root $RepoRoot
            if ($LASTEXITCODE -ne 0) { throw "M3 static contract check failed" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --msix $MsixPath --arch x64 --milestone M3 --expect-signed
            if ($LASTEXITCODE -ne 0) { throw "M3 MSIX OPC/Toast/Firewall check failed" }
            "M3 Native AOT publish & strict MSIX with ToastNotificationActivation + ExeServer verified"
        }

        # T3-13: WakeLock + cooperative shutdown + powercfg /requests zero residual check
        Invoke-E2ETest "T3-13" {
            Invoke-DotnetTestFiltered -Filter "Category=WindowsCI&FullyQualifiedName~T1_F20_02"
            Push-Location $RepoRoot
            try {
                & cargo test --locked -p totaldrop-windows-ffi --test e2e_ipc_shutdown_m3 -- t1_f20_03_cooperative_shutdown_under_800ms --nocapture
                if ($LASTEXITCODE -ne 0) { throw "t1_f20_03 cooperative shutdown failed" }
            }
            finally { Pop-Location }
            $pwrRes = Invoke-NativeCapture -FilePath "powercfg.exe" -Arguments @("/requests")
            if ($pwrRes.ExitCode -ne 0) {
                throw "powercfg /requests failed with exit $($pwrRes.ExitCode) (Administrator privileges required): $($pwrRes.Output)"
            }
            if ($pwrRes.Output -match "totaldrop-winui\.exe|TotalDrop Windows E2E transfer|TotalDrop") {
                throw "Residual TotalDrop powercfg /requests entry found after shutdown: $($pwrRes.Output)"
            }
            "WakeLock, cooperative shutdown (<800ms), and powercfg /requests (exit 0, zero TotalDrop residual) verified"
        }

        # StrictMode-safe O(1) CIM firewall rule matcher (never accesses nonexistent .Package on MSFT_NetFirewallRule)
        $GetMatchingFirewallRules = {
            param(
                [Parameter(Mandatory = $true)][string]$PackageName,
                [Parameter()][string]$PackageFamilyName = "",
                [Parameter()][string]$ExecutableName = "totaldrop-winui.exe"
            )
            $dedup = [ordered]@{}
            $addRule = {
                param(
                    [Parameter(Mandatory = $true)]$Map,
                    [Parameter(Mandatory = $true)]$RuleObj
                )
                if ($null -eq $RuleObj) { return }
                $key = if ($null -ne $RuleObj.PSObject.Properties["InstanceID"] -and -not [string]::IsNullOrWhiteSpace([string]$RuleObj.InstanceID)) {
                    [string]$RuleObj.InstanceID
                } elseif ($null -ne $RuleObj.PSObject.Properties["Name"] -and -not [string]::IsNullOrWhiteSpace([string]$RuleObj.Name)) {
                    [string]$RuleObj.Name
                } else {
                    [string]$RuleObj.GetHashCode()
                }
                if (-not $Map.Contains($key)) {
                    $Map[$key] = $RuleObj
                }
            }

            $escapedPkg = [regex]::Escape($PackageName)
            $escapedPfn = if (-not [string]::IsNullOrWhiteSpace($PackageFamilyName)) { [regex]::Escape($PackageFamilyName) } else { "" }
            $escapedExe = [regex]::Escape($ExecutableName)

            $allRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)
            foreach ($rule in $allRules) {
                $disp = if ($null -ne $rule.PSObject.Properties["DisplayName"]) { [string]$rule.DisplayName } else { "" }
                $rname = if ($null -ne $rule.PSObject.Properties["Name"]) { [string]$rule.Name } else { "" }
                $matched = ($disp -match "TotalDrop" -or $rname -match "TotalDrop" -or
                    $disp -match $escapedPkg -or $rname -match $escapedPkg -or
                    (-not [string]::IsNullOrEmpty($escapedPfn) -and ($disp -match $escapedPfn -or $rname -match $escapedPfn)))
                if ($matched) {
                    & $addRule -Map $dedup -RuleObj $rule
                }
            }

            $allAppFilters = @(Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)
            foreach ($af in $allAppFilters) {
                $prog = if ($null -ne $af.PSObject.Properties["Program"]) { [string]$af.Program } else { "" }
                $pkgVal = ""
                if ($null -ne $af.PSObject.Properties["Package"] -and $null -ne $af.Package) {
                    $pkgVal = (@($af.Package) -join " ")
                }
                $afMatched = ($prog -match "TotalDrop" -or $prog -match $escapedExe -or
                    $pkgVal -match "TotalDrop" -or $pkgVal -match $escapedPkg -or
                    (-not [string]::IsNullOrEmpty($escapedPfn) -and $pkgVal -match $escapedPfn))
                if ($afMatched) {
                    $assocRules = @(Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $af -ErrorAction SilentlyContinue)
                    foreach ($ar in $assocRules) {
                        & $addRule -Map $dedup -RuleObj $ar
                    }
                }
            }

            return @($dedup.Values)
        }

        # Helper for ephemeral MSIX install / firewall inspection / uninstall lifecycle
        $TestFirewallLifecycle = {
            param([bool]$MultiCycle)
            $resolvedMsix = Resolve-ExistingAbsolutePath -Path $MsixPath -Label "M3 MSIX"
            $manifestMeta = Read-MsixManifestMetadata -MsixFile $resolvedMsix
            $sig = Get-AuthenticodeSignature -FilePath $resolvedMsix
            if ($null -eq $sig.SignerCertificate) { throw "MSIX is not signed; ephemeral cert required for Add-AppxPackage" }
            $cert = $sig.SignerCertificate

            $depPaths = @()
            if (-not [string]::IsNullOrWhiteSpace($RuntimeDepMsix)) {
                $depPaths = @(Resolve-ExistingAbsolutePath -Path $RuntimeDepMsix -Label "WindowsAppRuntime dependency MSIX")
            }
            else {
                $installedRt = @(Get-AppxPackage -Name "Microsoft.WindowsAppRuntime.1.8" -ErrorAction SilentlyContinue |
                    Where-Object {
                        ([string]$_.Architecture).ToLowerInvariant() -eq $manifestMeta.Architecture -and
                        ([version]$_.Version -ge $manifestMeta.RuntimeMinVersion)
                    })
                if ($installedRt.Count -eq 0) {
                    $nugetEnv = [System.Environment]::GetEnvironmentVariable("NUGET_PACKAGES")
                    $userProfileEnv = [System.Environment]::GetEnvironmentVariable("USERPROFILE")
                    $nugetRoot = if (-not [string]::IsNullOrWhiteSpace($nugetEnv)) {
                        $nugetEnv
                    } elseif (-not [string]::IsNullOrWhiteSpace($userProfileEnv)) {
                        Join-Path $userProfileEnv ".nuget\packages"
                    } else {
                        ""
                    }
                    $ridSegment = if ($manifestMeta.Architecture -eq "arm64") { "win10-arm64" } else { "win10-x64" }
                    $discoveredRt = ""
                    if (-not [string]::IsNullOrWhiteSpace($nugetRoot)) {
                        foreach ($pkgFolder in @("microsoft.windowsappsdk.runtime", "microsoft.windowsappsdk")) {
                            $pkgRoot = Join-Path $nugetRoot $pkgFolder
                            if (-not (Test-Path -LiteralPath $pkgRoot -PathType Container)) { continue }
                            $rawVerDirs = @(Get-ChildItem -LiteralPath $pkgRoot -Directory -ErrorAction SilentlyContinue)
                            $verDirs = @(Sort-VersionDirsDesc -Dirs $rawVerDirs -AllowPrerelease $true -AllowThreePart $true)
                            foreach ($verDir in $verDirs) {
                                $directCand = Join-Path $verDir.FullName "tools\MSIX\$ridSegment\Microsoft.WindowsAppRuntime.1.8.msix"
                                if (Test-Path -LiteralPath $directCand -PathType Leaf) {
                                    $discoveredRt = $directCand
                                    break
                                }
                                $fallbackCand = @(Get-ChildItem -LiteralPath $verDir.FullName -Recurse -File -Filter "Microsoft.WindowsAppRuntime.1.8.msix" -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Directory.Name -eq $ridSegment }) | Select-Object -First 1
                                if ($null -ne $fallbackCand) {
                                    $discoveredRt = $fallbackCand.FullName
                                    break
                                }
                            }
                            if (-not [string]::IsNullOrWhiteSpace($discoveredRt)) { break }
                        }
                    }
                    if ([string]::IsNullOrWhiteSpace($discoveredRt)) {
                        throw "Microsoft.WindowsAppRuntime.1.8 ($($manifestMeta.Architecture) >= $($manifestMeta.RuntimeMinVersion)) is not installed and was not found in NuGet cache; pass -RuntimeDepMsix."
                    }
                    $depPaths = @((Resolve-Path -LiteralPath $discoveredRt).Path)
                }
            }

            $addedStores = @()
            try {
                Get-AppxPackage -Name $manifestMeta.IdentityName -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

                foreach ($storeName in @("TrustedPeople", "Root")) {
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, "LocalMachine")
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    try {
                        if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
                            $store.Add($cert)
                            $addedStores += $storeName
                        }
                    }
                    finally { $store.Close() }
                }

                $addParams = @{ Path = $resolvedMsix; ForceApplicationShutdown = $true }
                if ($depPaths.Count -gt 0) {
                    $addParams["DependencyPath"] = $depPaths
                }
                Add-AppxPackage @addParams
                if ($MultiCycle) {
                    $reinstallParams = $addParams.Clone()
                    $reinstallParams["ForceUpdateFromAnyVersion"] = $true
                    Add-AppxPackage @reinstallParams
                }

                $installedPkg = @(Get-AppxPackage -Name $manifestMeta.IdentityName -ErrorAction SilentlyContinue)
                $pkgFamilyName = if ($installedPkg.Count -gt 0) { [string]$installedPkg[0].PackageFamilyName } else { "" }

                $rules = @(& $GetMatchingFirewallRules -PackageName $manifestMeta.IdentityName -PackageFamilyName $pkgFamilyName -ExecutableName $manifestMeta.Executable)
                if ($rules.Count -ne 1) { throw "Expected exactly 1 TotalDrop firewall rule after install, found $($rules.Count)" }
                $r = $rules[0]
                if ([string]$r.Direction -ne "Inbound") { throw "Firewall rule Direction=$($r.Direction) != Inbound" }
                if ([string]$r.Profile -ne "Private") { throw "Firewall rule Profile=$($r.Profile) != Private" }
                $pf = @($r | Get-NetFirewallPortFilter -ErrorAction Stop)
                if ($pf.Count -ne 1 -or [string]$pf[0].Protocol -ne "UDP") {
                    throw "Firewall rule expected single UDP PortFilter, got count=$($pf.Count), protocol=$(if ($pf.Count -gt 0) { $pf[0].Protocol } else { 'none' })"
                }

                Get-AppxPackage -Name $manifestMeta.IdentityName -ErrorAction SilentlyContinue | Remove-AppxPackage
                $postRules = @(& $GetMatchingFirewallRules -PackageName $manifestMeta.IdentityName -PackageFamilyName $pkgFamilyName -ExecutableName $manifestMeta.Executable)
                if ($postRules.Count -ne 0) { throw "Orphaned TotalDrop firewall rules remained after uninstall: $($postRules.Count)" }
            }
            finally {
                Get-AppxPackage -Name $manifestMeta.IdentityName -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
                foreach ($storeName in $addedStores) {
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, "LocalMachine")
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    try {
                        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                        foreach ($c in $existing) { $store.Remove($c) }
                    }
                    finally { $store.Close() }
                }
            }
        }

        Invoke-E2ETest "T1-F21-03" { & $TestFirewallLifecycle $false; "Installed M3 MSIX, verified 1 Inbound/UDP/Private rule, uninstalled with 0 residual rules/certs" }
        Invoke-E2ETest "T2-F21-05" { & $TestFirewallLifecycle $true; "Multi-cycle install/re-install (-ForceUpdateFromAnyVersion) kept exact 1 Private UDP rule (0 duplicates) and cleaned up 100%" }
        Invoke-E2ETest "T3-17" {
            # Verify source app.manifest longPathAware=true via strict XML reader
            $appManPath = Resolve-ExistingAbsolutePath -Path (Join-Path $RepoRoot "ui-winui3-fluent2\app.manifest") -Label "app.manifest"
            $amDoc = [System.Xml.XmlDocument]::new()
            $amDoc.XmlResolver = $null
            $amSettings = [System.Xml.XmlReaderSettings]::new()
            $amSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
            $amSettings.XmlResolver = $null
            $amFs = [System.IO.File]::OpenRead($appManPath)
            try {
                $amReader = [System.Xml.XmlReader]::Create($amFs, $amSettings)
                try { $amDoc.Load($amReader) } finally { $amReader.Dispose() }
            }
            finally { $amFs.Dispose() }
            $amNsm = [System.Xml.XmlNamespaceManager]::new($amDoc.NameTable)
            $amNsm.AddNamespace("ws", "http://schemas.microsoft.com/SMI/2016/WindowsSettings")
            $lpNode = $amDoc.SelectSingleNode("//ws:longPathAware", $amNsm)
            if ($null -eq $lpNode -or $lpNode.InnerText.Trim() -cne "true") {
                throw "ui-winui3-fluent2/app.manifest missing <ws:longPathAware>true</ws:longPathAware>"
            }

            # Verify packaged executable embeds RT_MANIFEST with longPathAware=true directly from MSIX
            $resolvedMsix = Resolve-ExistingAbsolutePath -Path $MsixPath -Label "M3 MSIX"
            $meta = Read-MsixManifestMetadata -MsixFile $resolvedMsix
            $exeBytes = Read-EntryBytesFromZip -ZipPath $resolvedMsix -EntryName $meta.Executable
            if ($null -eq $exeBytes -or $exeBytes.Length -eq 0) {
                throw "MSIX '$resolvedMsix' missing packaged executable '$($meta.Executable)'"
            }
            $exeText = [System.Text.Encoding]::UTF8.GetString($exeBytes)
            if ($exeText -notmatch '<longPathAware\b[^>]*>\s*true\s*</longPathAware>') {
                throw "Packaged executable '$($meta.Executable)' inside MSIX does not embed <longPathAware>true</longPathAware> RT_MANIFEST"
            }

            & $TestFirewallLifecycle $false
            "Strict M3 MSIX pack + firewall lifecycle + app.manifest & embedded RT_MANIFEST longPathAware=true verified"
        }
        Invoke-E2ETest "T4-10" { & $TestFirewallLifecycle $false; "Full M3 install -> scoped Private UDP firewall -> clean uninstall verified" }
    }

    if ($RunM4) {
        $IsArm64Host = ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64)
        $Arm64Unpack = Join-Path $WorkTemp "unpacked-arm64"

        # T1-F23-04 & T2-F23-05: PowerShell AST & WACK report-checker verification (headless, never launches appcert.exe GUI)
        Invoke-E2ETest "T1-F23-04" {
            $wackScript = Join-Path $RepoRoot "tools\run-wack.ps1"
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($wackScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -ne 0) { throw "run-wack.ps1 AST errors: $($parseErrors -join '; ')" }
            $passXml = Join-Path $WorkTemp "wack-pass.xml"
            Set-Content -LiteralPath $passXml -Encoding utf8NoBOM -Value @'
<?xml version="1.0" encoding="utf-8"?>
<REPORT OVERALL_RESULT="PASS">
  <REQUIREMENTS>
    <REQUIREMENT>
      <TEST NAME="Supported APIs"><RESULT><![CDATA[PASS]]></RESULT></TEST>
      <TEST NAME="Package Sanity"><RESULT><![CDATA[PASS]]></RESULT></TEST>
    </REQUIREMENT>
  </REQUIREMENTS>
</REPORT>
'@
            & pwsh -NoProfile -File $wackScript -CheckReportOnly -ReportPath $passXml
            if ($LASTEXITCODE -ne 0) { throw "run-wack.ps1 -CheckReportOnly failed on valid PASS XML" }
            "run-wack.ps1 AST 0 errors and -CheckReportOnly accepted valid PASS XML report"
        }

        Invoke-E2ETest "T2-F23-05" {
            $wackScript = Join-Path $RepoRoot "tools\run-wack.ps1"
            $fail1 = Join-Path $WorkTemp "wack-fail-overall.xml"
            Set-Content -LiteralPath $fail1 -Encoding utf8NoBOM -Value '<?xml version="1.0"?><REPORT OVERALL_RESULT="FAIL"><TEST NAME="Supported APIs"><RESULT><![CDATA[FAIL]]></RESULT></TEST></REPORT>'
            $res1 = Invoke-NativeCapture -FilePath "pwsh" -Arguments @(
                "-NoProfile", "-File", $wackScript, "-CheckReportOnly", "-ReportPath", $fail1
            )
            if ($res1.ExitCode -eq 0 -or $res1.Output -notmatch 'OVERALL_RESULT.*FAIL|WACK report FAILED') {
                throw "run-wack.ps1 did not reject OVERALL_RESULT=FAIL with expected diagnostic (rc=$($res1.ExitCode)): $($res1.Output)"
            }

            $fail2 = Join-Path $WorkTemp "wack-fail-test.xml"
            Set-Content -LiteralPath $fail2 -Encoding utf8NoBOM -Value '<?xml version="1.0"?><REPORT OVERALL_RESULT="PASS"><TEST NAME="Supported APIs"><RESULT><![CDATA[FAIL]]></RESULT></TEST></REPORT>'
            $res2 = Invoke-NativeCapture -FilePath "pwsh" -Arguments @(
                "-NoProfile", "-File", $wackScript, "-CheckReportOnly", "-ReportPath", $fail2
            )
            if ($res2.ExitCode -eq 0 -or $res2.Output -notmatch "Supported APIs") {
                throw "run-wack.ps1 did not reject PASS report with failing 'Supported APIs' test (rc=$($res2.ExitCode)): $($res2.Output)"
            }
            "run-wack.ps1 rejected OVERALL_RESULT=FAIL and PASS-with-failing-Supported-APIs report"
        }

        # ARM64 slice & dual-arch bundle/upload tests (require ARM64 host or staged -Arm64MsixPath / -BundlePath / -MsixUploadPath)
        Invoke-E2ETest "T1-F22-01" {
            if ([string]::IsNullOrWhiteSpace($Arm64MsixPath)) {
                if (-not $SkipBuild) {
                    if (-not $IsArm64Host) { throw "T1-F22-01 requires windows-11-arm host or explicit -Arm64MsixPath" }
                    & (Join-Path $RepoRoot "target-arm64\build-arm64.ps1") -SelfSignEphemeral
                    if ($LASTEXITCODE -ne 0) { throw "build-arm64.ps1 failed" }
                }
                $armName = (& $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --root $RepoRoot --arch arm64 --resolve-recipe).Trim()
                if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($armName)) {
                    throw "Failed to resolve ARM64 artifact_name from subplatforms/msix/arm64/RECIPE.toml"
                }
                $Arm64MsixPath = Join-Path $RepoRoot ("dist\" + $armName)
            }
            if (-not (Test-Path -LiteralPath $Arm64MsixPath -PathType Leaf)) {
                throw "ARM64 MSIX not found at '$Arm64MsixPath'"
            }
            $makeAppxExe = Get-MakeAppxExe
            & $makeAppxExe unpack /o /p $Arm64MsixPath /d $Arm64Unpack
            if ($LASTEXITCODE -ne 0) { throw "makeappx unpack failed on ARM64 MSIX" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") --unpacked $Arm64Unpack --arch arm64 --milestone M4
            if ($LASTEXITCODE -ne 0) { throw "verify_pe_hardening.py failed on ARM64 MSIX" }
            "ARM64 MSIX unpacked & PE32+ 0xAA64 hardening + 31 FFI / 3 COM exports verified"
        }

        Invoke-E2ETest "T2-F22-03" {
            if (-not (Test-Path -LiteralPath $Arm64Unpack -PathType Container)) {
                throw "ARM64 unpacked directory unavailable (run T1-F22-01 or pass -Arm64MsixPath)"
            }
            $resolvedX64ExtDll = ""
            if (-not [string]::IsNullOrWhiteSpace($X64ExtDll)) {
                $resolvedX64ExtDll = Resolve-ExistingAbsolutePath -Path $X64ExtDll -Label "-X64ExtDll"
            }
            elseif (Test-Path -LiteralPath $ExtDll -PathType Leaf) {
                $resolvedX64ExtDll = (Resolve-Path -LiteralPath $ExtDll).Path
            }
            elseif (-not [string]::IsNullOrWhiteSpace($MsixPath) -and (Test-Path -LiteralPath $MsixPath -PathType Leaf)) {
                $x64Meta = Read-MsixManifestMetadata -MsixFile $MsixPath
                if ($x64Meta.Architecture -ne "x64") {
                    throw "-MsixPath '$MsixPath' has architecture '$($x64Meta.Architecture)', expected 'x64' to extract totaldrop_explorer_ext.dll"
                }
                $dllBytes = Read-EntryBytesFromZip -ZipPath $MsixPath -EntryName "totaldrop_explorer_ext.dll"
                if ($null -eq $dllBytes -or $dllBytes.Length -eq 0) {
                    throw "x64 MSIX '$MsixPath' does not contain totaldrop_explorer_ext.dll"
                }
                $extractDir = Join-Path $WorkTemp "extracted-x64-ext"
                New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
                $resolvedX64ExtDll = Join-Path $extractDir "totaldrop_explorer_ext.dll"
                [System.IO.File]::WriteAllBytes($resolvedX64ExtDll, $dllBytes)
            }
            elseif (-not [string]::IsNullOrWhiteSpace($BundlePath) -and (Test-Path -LiteralPath $BundlePath -PathType Leaf)) {
                Add-Type -AssemblyName System.IO.Compression
                $bundleFull = (Resolve-Path -LiteralPath $BundlePath).Path
                $innerX64Bytes = $null
                $bfs = [System.IO.File]::OpenRead($bundleFull)
                try {
                    $bzip = [System.IO.Compression.ZipArchive]::new($bfs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
                    try {
                        foreach ($entry in $bzip.Entries) {
                            if ($entry.FullName -match '(?i)x64.*\.msix$') {
                                $es = $entry.Open()
                                try {
                                    $ms = [System.IO.MemoryStream]::new()
                                    try {
                                        $es.CopyTo($ms)
                                        $innerX64Bytes = $ms.ToArray()
                                    }
                                    finally { $ms.Dispose() }
                                }
                                finally { $es.Dispose() }
                                break
                            }
                        }
                    }
                    finally { $bzip.Dispose() }
                }
                finally { $bfs.Dispose() }
                if ($null -eq $innerX64Bytes -or $innerX64Bytes.Length -eq 0) {
                    throw "Bundle '$BundlePath' did not contain an inner x64 .msix slice for T2-F22-03"
                }
                $extractDir = Join-Path $WorkTemp "extracted-x64-ext"
                New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
                $tmpInnerMsix = Join-Path $extractDir "inner-x64.msix"
                [System.IO.File]::WriteAllBytes($tmpInnerMsix, $innerX64Bytes)
                $dllBytes = Read-EntryBytesFromZip -ZipPath $tmpInnerMsix -EntryName "totaldrop_explorer_ext.dll"
                if ($null -eq $dllBytes -or $dllBytes.Length -eq 0) {
                    throw "Inner x64 MSIX inside '$BundlePath' did not contain totaldrop_explorer_ext.dll"
                }
                $resolvedX64ExtDll = Join-Path $extractDir "totaldrop_explorer_ext.dll"
                [System.IO.File]::WriteAllBytes($resolvedX64ExtDll, $dllBytes)
            }
            else {
                throw "x64 totaldrop_explorer_ext.dll unavailable for cross-arch contamination test; pass -X64ExtDll, an x64 -MsixPath, a dual-arch -BundlePath, or build $ExtDll"
            }

            $poisonDir = Join-Path $WorkTemp "arm64-cross-arch-poison"
            Copy-Item -LiteralPath $Arm64Unpack -Destination $poisonDir -Recurse -Force
            Copy-Item -LiteralPath $resolvedX64ExtDll -Destination (Join-Path $poisonDir "totaldrop_explorer_ext.dll") -Force
            $resPoison = Invoke-NativeCapture -FilePath $PythonExe -Arguments @(
                "-B", (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py"),
                "--unpacked", $poisonDir, "--arch", "arm64", "--milestone", "M4"
            )
            if ($resPoison.ExitCode -eq 0 -or $resPoison.Output -notmatch "0xAA64" -or $resPoison.Output -notmatch "0x8664") {
                throw "Cross-architecture x64-in-ARM64 contamination was not caught (rc=$($resPoison.ExitCode)): $($resPoison.Output)"
            }
            "Cross-architecture x64 totaldrop_explorer_ext.dll in ARM64 tree rejected (expected 0xAA64, got 0x8664)"
        }

        Invoke-E2ETest "T2-F22-06" {
            if (-not (Test-Path -LiteralPath $Arm64Unpack -PathType Container)) { throw "ARM64 unpacked directory unavailable" }
            & $PythonExe -B (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") --unpacked $Arm64Unpack --arch arm64 --milestone M4 --self-test-mutations
            if ($LASTEXITCODE -ne 0) { throw "ARM64 PE hardening mutation self-test failed" }
            "All ARM64 PE/CRT/0x800/NX+HEVA mutations caught"
        }

        foreach ($bundleTest in @("T1-F22-02", "T1-F22-06", "T3-23", "T4-11")) {
            Invoke-E2ETest $bundleTest {
                if ([string]::IsNullOrWhiteSpace($BundlePath) -or -not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) {
                    throw "$bundleTest requires staged dual-arch -BundlePath from windows-release.yml / build-msixbundle.ps1"
                }
                $hasUpload = -not [string]::IsNullOrWhiteSpace($MsixUploadPath)
                if ($hasUpload -and -not (Test-Path -LiteralPath $MsixUploadPath -PathType Leaf)) {
                    throw "-MsixUploadPath was provided for $bundleTest, but file does not exist: '$MsixUploadPath'"
                }
                if (($bundleTest -in @("T1-F22-06", "T3-23", "T4-11")) -and -not $hasUpload) {
                    throw "$bundleTest requires staged -MsixUploadPath alongside -BundlePath (refusing to silently skip .msixupload verification)"
                }

                $verArgs = @("-B", (Join-Path $RepoRoot "tools\verify-msix-artifact.py"), "--bundle", $BundlePath, "--expected-version", $BundleVersion, "--store-mode", "--allow-test-identity")
                if ($hasUpload) {
                    $verArgs += @("--msixupload", $MsixUploadPath)
                }
                & $PythonExe @verArgs
                if ($LASTEXITCODE -ne 0) { throw "verify-msix-artifact.py failed for $bundleTest" }

                $opcArgs = @("-B", (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py"), "--bundle", $BundlePath, "--expected-version", $BundleVersion, "--store-mode")
                if ($hasUpload) {
                    $opcArgs += @("--msixupload", $MsixUploadPath)
                }
                & $PythonExe @opcArgs
                if ($LASTEXITCODE -ne 0) { throw "verify_msix_opc.py failed for $bundleTest" }

                if ($hasUpload) {
                    "Dual-arch .msixbundle + .msixupload ($BundleVersion) verified by both verify-msix-artifact.py and verify_msix_opc.py ($bundleTest)"
                }
                else {
                    "Dual-arch .msixbundle ($BundleVersion) verified by both verify-msix-artifact.py and verify_msix_opc.py ($bundleTest)"
                }
            }
        }
    }
}
finally {
    if ($null -ne $SavedFfiDllPath) {
        $env:TOTALDROP_FFI_DLL_PATH = $SavedFfiDllPath
    }
    else {
        Remove-Item Env:TOTALDROP_FFI_DLL_PATH -ErrorAction SilentlyContinue
    }
    if ($null -ne $SavedExtDllPath) {
        $env:TOTALDROP_EXPLORER_EXT_DLL = $SavedExtDllPath
    }
    else {
        Remove-Item Env:TOTALDROP_EXPLORER_EXT_DLL -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $WorkTemp) {
        Remove-Item -LiteralPath $WorkTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not [string]::IsNullOrWhiteSpace($ResultsJson)) {
    $Results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultsJson -Encoding utf8NoBOM
}

$failedCount = @($Results.Values | Where-Object { $_.status -ne "PASS" }).Count
Write-Host ("==> Invoke-WindowsE2E summary: {0}/{1} PASS, {2} FAIL" -f ($Results.Count - $failedCount), $Results.Count, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
