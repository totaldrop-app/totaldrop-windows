#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Builds the isolated Windows 11 ARM64 slice of TotalDrop (Rust C ABI FFI
    cdylib + WinUI 3 .NET 10 Native AOT executable + MakePri resources.pri +
    strict makeappx.exe arm64 MSIX package) on GitHub's `windows-11-arm` runner,
    and optionally bundles `x64` + `arm64` into a single `.msixbundle` for
    Microsoft Store Partner Center submission (ADR 0016, #86).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version = "0.1.1.0",

    [Parameter()]
    [string]$OutputDir = "",

    [Parameter()]
    [switch]$CreateStoreBundle,

    [Parameter()]
    [Alias("SignEphemeralTestCert")]
    [switch]$SelfSignEphemeral
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter()]
        [string]$PreferredArch = "arm64"
    )

    $archOrder = if ($PreferredArch -eq "arm64") { @("arm64", "x64") } else { @("x64", "arm64") }

    $kitsBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitsBin) {
        $versionDirs = Get-ChildItem -LiteralPath $kitsBin -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($vDir in $versionDirs) {
            foreach ($arch in $archOrder) {
                $candidate = Join-Path $vDir.FullName "$arch\$ToolName"
                if (Test-Path -LiteralPath $candidate) {
                    return $candidate
                }
            }
        }
    }

    $nugetRoot = if (-not [string]::IsNullOrWhiteSpace($env:NUGET_PACKAGES)) {
        $env:NUGET_PACKAGES
    } else {
        Join-Path $env:USERPROFILE ".nuget\packages"
    }
    $btRoot = Join-Path $nugetRoot "microsoft.windows.sdk.buildtools"
    if (Test-Path -LiteralPath $btRoot) {
        $pkgDirs = Get-ChildItem -LiteralPath $btRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
        foreach ($pkgDir in $pkgDirs) {
            $binRoot = Join-Path $pkgDir.FullName "bin"
            if (-not (Test-Path -LiteralPath $binRoot)) { continue }
            $sdkDirs = Get-ChildItem -LiteralPath $binRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                Sort-Object { [version]$_.Name } -Descending
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

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Required Windows SDK tool '$ToolName' not found in Windows Kits 10, NuGet BuildTools, or PATH."
}

$ScriptDir = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$ResolvedOutDir = if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    Join-Path $RepoRoot "dist"
} else {
    $OutputDir
}
New-Item -ItemType Directory -Force -Path $ResolvedOutDir | Out-Null
$ResolvedOutDir = (Resolve-Path -LiteralPath $ResolvedOutDir).Path

$WorkRoot = Join-Path $RepoRoot "dist\work-arm64"
$PublishDir = Join-Path $WorkRoot "publish-win-arm64"
$StagingDir = Join-Path $WorkRoot "staging-arm64"
$PriWorkDir = Join-Path $WorkRoot "pri-work-arm64"
$BundleInputDir = Join-Path $WorkRoot "bundle-input"
$OutMsixName = "TotalDrop_${Version}_arm64.msix"
$OutMsix = Join-Path $ResolvedOutDir $OutMsixName
$X64Msix = Join-Path $ResolvedOutDir "TotalDrop_${Version}_x64.msix"
$OutBundleName = "TotalDrop_${Version}_x64_arm64.msixbundle"
$OutBundle = Join-Path $ResolvedOutDir $OutBundleName
$FfiDll = Join-Path $RepoRoot "target\aarch64-pc-windows-msvc\release\totaldrop_windows_ffi.dll"

Write-Host "==> [arm64 1/5] Building Rust totaldrop-windows-ffi cdylib (aarch64-pc-windows-msvc)..."
$SavedRustFlags = $env:RUSTFLAGS
$SavedEncodedRustFlags = $env:CARGO_ENCODED_RUSTFLAGS
Push-Location $RepoRoot
try {
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
    cargo build `
        --config (Join-Path $ScriptDir "cargo-config.toml") `
        --target aarch64-pc-windows-msvc `
        -p totaldrop-windows-ffi `
        --release `
        --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build (totaldrop-windows-ffi, aarch64-pc-windows-msvc) failed with exit code $LASTEXITCODE"
    }
}
finally {
    if ($null -ne $SavedRustFlags) {
        $env:RUSTFLAGS = $SavedRustFlags
    }
    if ($null -ne $SavedEncodedRustFlags) {
        $env:CARGO_ENCODED_RUSTFLAGS = $SavedEncodedRustFlags
    }
    Pop-Location
}

if (-not (Test-Path -LiteralPath $FfiDll)) {
    throw "Expected native FFI DLL missing at $FfiDll"
}

Write-Host "==> [arm64 2/5] Publishing WinUI 3 shell with .NET 10 LTS Native AOT (win-arm64)..."
if (Test-Path -LiteralPath $PublishDir) {
    Remove-Item -LiteralPath $PublishDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $PublishDir | Out-Null

Push-Location (Join-Path $RepoRoot "ui-winui3-fluent2")
try {
    $DotnetVersion = ((& dotnet --version) -join "").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet --version failed with exit code $LASTEXITCODE"
    }
    Write-Host "    Active dotnet SDK: $DotnetVersion"
    if ($DotnetVersion -notlike "10.0.*") {
        throw "Expected .NET 10.0.x LTS SDK (pinned by ui-winui3-fluent2/global.json), got '$DotnetVersion'"
    }

    dotnet publish TotalDrop.WinUI.csproj `
        -r win-arm64 `
        -c Release `
        -p:Platform=ARM64 `
        -p:PublishAot=true `
        -p:WindowsAppSDKSelfContained=false `
        -o $PublishDir
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish (win-arm64 Native AOT) failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

$MakePriExe = Resolve-WindowsKitTool -ToolName "MakePri.exe" -PreferredArch "arm64"
$MakeAppxExe = Resolve-WindowsKitTool -ToolName "makeappx.exe" -PreferredArch "arm64"

Write-Host "==> [arm64 3/5] Staging arm64 MSIX layout & compiling unified resources.pri..."
if (Test-Path -LiteralPath $StagingDir) {
    Remove-Item -LiteralPath $StagingDir -Recurse -Force
}
if (Test-Path -LiteralPath $PriWorkDir) {
    Remove-Item -LiteralPath $PriWorkDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StagingDir, $PriWorkDir | Out-Null

Copy-Item -Path (Join-Path $PublishDir "*") -Destination $StagingDir -Recurse -Force
Get-ChildItem -LiteralPath $StagingDir -Include "*.pdb", "*.pri" -Recurse -File -ErrorAction SilentlyContinue |
    Remove-Item -Force

foreach ($requiredRel in @(
    "totaldrop-winui.exe",
    "totaldrop_windows_ffi.dll",
    "App.xbf",
    "MainWindow.xbf",
    "Views\SendPage.xbf",
    "Views\ReceivePage.xbf",
    "Views\SettingsPage.xbf",
    "Assets\StoreLogo.scale-100.png",
    "Assets\TotalDrop.ico"
)) {
    $reqPath = Join-Path $StagingDir $requiredRel
    if (-not (Test-Path -LiteralPath $reqPath)) {
        throw "Required staged payload missing: $reqPath"
    }
}

if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    throw "Invalid MSIX -Version '$Version'. Expected four-part numeric version (Major.Minor.Build.Revision)."
}
$StagedManifest = Join-Path $StagingDir "AppxManifest.xml"
Copy-Item `
    -LiteralPath (Join-Path $ScriptDir "Package.arm64.appxmanifest") `
    -Destination $StagedManifest `
    -Force
$manifestDoc = [System.Xml.XmlDocument]::new()
$manifestDoc.PreserveWhitespace = $true
$manifestDoc.XmlResolver = $null
$manifestDoc.Load($StagedManifest)
$nsMgr = [System.Xml.XmlNamespaceManager]::new($manifestDoc.NameTable)
$nsMgr.AddNamespace("appx", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
$identityNode = $manifestDoc.SelectSingleNode("/appx:Package/appx:Identity", $nsMgr)
if ($null -eq $identityNode) {
    throw "Staged AppxManifest.xml is missing /Package/Identity."
}
if ($identityNode.GetAttribute("Version") -ne $Version) {
    Write-Host "    Patching staged AppxManifest.xml Identity/@Version: $($identityNode.GetAttribute('Version')) -> $Version"
    $identityNode.SetAttribute("Version", $Version)
    $manifestDoc.Save($StagedManifest)
}

$StringsSrc = Join-Path $RepoRoot "ui-winui3-fluent2\Strings"
$StringsStage = Join-Path $StagingDir "Strings"
$ReswFiles = @(Get-ChildItem -LiteralPath $StringsSrc -Filter "Resources.resw" -Recurse -File)
if ($ReswFiles.Count -ne 35) {
    throw "Expected 35 Resources.resw locale catalogs under $StringsSrc, found $($ReswFiles.Count)"
}
foreach ($resw in $ReswFiles) {
    $localeTag = $resw.Directory.Name
    $destDir = Join-Path $StringsStage $localeTag
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    Copy-Item -LiteralPath $resw.FullName -Destination (Join-Path $destDir "Resources.resw") -Force
}

$PriConfigPath = Join-Path $PriWorkDir "priconfig-arm64.xml"
$ResourcesPri = Join-Path $StagingDir "resources.pri"
$PriDumpPath = Join-Path $PriWorkDir "resources-arm64.pri.xml"

& $MakePriExe createconfig /cf $PriConfigPath /dq lang-en /o /pv 10.0.0
if ($LASTEXITCODE -ne 0) {
    throw "MakePri.exe createconfig failed with exit code $LASTEXITCODE"
}

[xml]$priXml = Get-Content -LiteralPath $PriConfigPath -Raw
$pkgNode = $priXml.SelectSingleNode("/resources/packaging")
if ($null -ne $pkgNode) {
    [void]$priXml.resources.RemoveChild($pkgNode)
}
$priXml.Save($PriConfigPath)

& $MakePriExe new `
    /pr $StagingDir `
    /cf $PriConfigPath `
    /mn (Join-Path $StagingDir "AppxManifest.xml") `
    /of $ResourcesPri `
    /o
if ($LASTEXITCODE -ne 0) {
    throw "MakePri.exe new failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $ResourcesPri) -or (Get-Item -LiteralPath $ResourcesPri).Length -le 0) {
    throw "MakePri.exe did not generate a non-empty resources.pri at $ResourcesPri"
}

$splitPris = @(Get-ChildItem -LiteralPath $StagingDir -Filter "resources.*.pri" -File -ErrorAction SilentlyContinue)
if ($splitPris.Count -gt 0) {
    throw "Unexpected split PRI files generated in staging directory: $($splitPris.Name -join ', ')"
}

& $MakePriExe dump /if $ResourcesPri /of $PriDumpPath /dt detailed /o
if ($LASTEXITCODE -ne 0) {
    throw "MakePri.exe dump failed with exit code $LASTEXITCODE"
}

Remove-Item -LiteralPath $StringsStage -Recurse -Force

Write-Host "==> [arm64 4/5] Packing $OutMsixName with strict makeappx.exe (no /nv)..."
& $MakeAppxExe pack /o /h SHA256 /d $StagingDir /p $OutMsix
if ($LASTEXITCODE -ne 0) {
    throw "makeappx.exe pack (arm64) failed with exit code $LASTEXITCODE"
}

if ($CreateStoreBundle) {
    Write-Host "==> [arm64 5/5] Bundling x64 + arm64 MSIX slices into $OutBundleName..."
    if (-not (Test-Path -LiteralPath $X64Msix)) {
        throw "x64 MSIX slice not found at $X64Msix. Run target-x86_64/build-x64.ps1 first."
    }
    if (Test-Path -LiteralPath $BundleInputDir) {
        Remove-Item -LiteralPath $BundleInputDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $BundleInputDir | Out-Null
    Copy-Item -LiteralPath $X64Msix -Destination $BundleInputDir -Force
    Copy-Item -LiteralPath $OutMsix -Destination $BundleInputDir -Force

    & $MakeAppxExe bundle /o /bv $Version /d $BundleInputDir /p $OutBundle
    if ($LASTEXITCODE -ne 0) {
        throw "makeappx.exe bundle failed with exit code $LASTEXITCODE"
    }
    Write-Host "==> Built multi-arch Store bundle: $OutBundle"
}

$TargetArtifact = if ($CreateStoreBundle) { $OutBundle } else { $OutMsix }
$TargetName = Split-Path -Leaf $TargetArtifact

if ($SelfSignEphemeral) {
    $SignToolExe = Resolve-WindowsKitTool -ToolName "signtool.exe" -PreferredArch "arm64"
    Write-Host "==> Signing CI test artifact with ephemeral zero-PFX self-signed cert (ADR 0016)..."
    $Cert = $null
    try {
        $Cert = New-SelfSignedCertificate `
            -Type Custom `
            -Subject "CN=TotalDrop" `
            -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddDays(1) `
            -FriendlyName "TotalDrop Ephemeral CI Test Cert" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
        & $SignToolExe sign /fd SHA256 /sha1 $Cert.Thumbprint $TargetArtifact
        if ($LASTEXITCODE -ne 0) {
            throw "signtool.exe sign failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        if ($null -ne $Cert -and (Test-Path -LiteralPath "Cert:\CurrentUser\My\$($Cert.Thumbprint)")) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($Cert.Thumbprint)" -Force
        }
    }
}

$HashHex = (Get-FileHash -Algorithm SHA256 -LiteralPath $TargetArtifact).Hash.ToLowerInvariant()
$ChecksumsPath = Join-Path $ResolvedOutDir "SHA256SUMS"
[System.IO.File]::WriteAllText(
    $ChecksumsPath,
    "$HashHex  $TargetName`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "==> Built arm64 artifact: $TargetArtifact (SHA-256: $HashHex)"
