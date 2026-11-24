#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Runs Windows App Certification Kit (WACK / appcert.exe) against a TotalDrop
    .msix or .msixbundle package on an interactive Windows 11 desktop, or
    validates an existing WACK XML report with -CheckReportOnly (ADR 0016).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PackagePath = "",

    [Parameter()]
    [string]$ReportPath = "",

    [Parameter()]
    [string]$AppCertPath = "",

    [Parameter()]
    [switch]$CheckReportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-AppCertExe {
    param(
        [Parameter()]
        [string]$ExplicitPath = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "Explicit -AppCertPath does not exist: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    foreach ($regPath in @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots",
        "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
    )) {
        if (Test-Path -LiteralPath $regPath) {
            $props = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
            if ($null -ne $props -and $null -ne $props.PSObject.Properties["KitsRoot10"]) {
                $kitsRoot = [string]$props.KitsRoot10
                if (-not [string]::IsNullOrWhiteSpace($kitsRoot)) {
                    $candidate = Join-Path $kitsRoot "App Certification Kit\appcert.exe"
                    if (Test-Path -LiteralPath $candidate) {
                        return $candidate
                    }
                }
            }
        }
    }

    foreach ($pfVar in @("ProgramFiles(x86)", "ProgramFiles")) {
        $pfRoot = [System.Environment]::GetEnvironmentVariable($pfVar)
        if (-not [string]::IsNullOrWhiteSpace($pfRoot)) {
            $candidate = Join-Path $pfRoot "Windows Kits\10\App Certification Kit\appcert.exe"
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    $cmd = Get-Command appcert.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Windows App Certification Kit (appcert.exe) not found. Install the Windows 11 SDK with Windows App Certification Kit enabled."
}

function Get-PrimaryDisplayResolution {
    if (-not ([System.Management.Automation.PSTypeName]"TotalDropWackDisplayNative").Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class TotalDropWackDisplayNative
{
    private const int ENUM_CURRENT_SETTINGS = -1;
    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DEVMODEW
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmDeviceName;
        public ushort dmSpecVersion;
        public ushort dmDriverVersion;
        public ushort dmSize;
        public ushort dmDriverExtra;
        public uint dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public uint dmDisplayOrientation;
        public uint dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmFormName;
        public ushort dmLogPixels;
        public uint dmBitsPerPel;
        public uint dmPelsWidth;
        public uint dmPelsHeight;
        public uint dmDisplayFlags;
        public uint dmDisplayFrequency;
        public uint dmICMMethod;
        public uint dmICMIntent;
        public uint dmMediaType;
        public uint dmDitherType;
        public uint dmReserved1;
        public uint dmReserved2;
        public uint dmPanningWidth;
        public uint dmPanningHeight;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumDisplaySettingsW(string lpszDeviceName, int iModeNum, ref DEVMODEW lpDevMode);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    public static int[] GetPhysicalResolution()
    {
        DEVMODEW dm = new DEVMODEW();
        dm.dmSize = (ushort)Marshal.SizeOf<DEVMODEW>();
        if (EnumDisplaySettingsW(null, ENUM_CURRENT_SETTINGS, ref dm) && dm.dmPelsWidth > 0 && dm.dmPelsHeight > 0)
        {
            return new int[] { (int)dm.dmPelsWidth, (int)dm.dmPelsHeight };
        }
        return new int[] { GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
    }
}
"@ -ErrorAction Stop
    }
    return [TotalDropWackDisplayNative]::GetPhysicalResolution()
}

function Assert-WackInteractivePreconditions {
    if (-not $IsWindows) {
        throw "WACK (appcert.exe) requires an interactive Windows 11 desktop session."
    }

    $sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($sessionId -eq 0) {
        throw "WACK cannot run in Session 0 (headless service or non-interactive CI runner). Run from an interactive Windows 11 desktop session."
    }

    $uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path -LiteralPath $uacRegPath)) {
        throw "Unable to inspect Windows UAC policy at $uacRegPath."
    }
    $uacProps = Get-ItemProperty -LiteralPath $uacRegPath -ErrorAction Stop
    if ($null -eq $uacProps.PSObject.Properties["EnableLUA"] -or [int]$uacProps.EnableLUA -ne 1) {
        throw "Windows User Account Control (EnableLUA == 1) must be enabled before running WACK."
    }

    $res = Get-PrimaryDisplayResolution
    $width = [int]$res[0]
    $height = [int]$res[1]
    $landscapeOk = ($width -ge 1024) -and ($height -ge 768)
    $portraitOk = ($width -ge 768) -and ($height -ge 1024)
    if (-not ($landscapeOk -or $portraitOk)) {
        throw "WACK requires a physical display resolution >= 1024x768 (or >= 768x1024 portrait); detected ${width}x${height}."
    }
    Write-Host "    WACK preconditions OK: SessionId=$sessionId, EnableLUA=1, Display=${width}x${height}"
}

function Get-XmlAttributeValues {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [Parameter(Mandatory = $true)]
        [string]$AttributeName
    )

    $values = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Node.Attributes) {
        return ,$values
    }
    foreach ($attr in $Node.Attributes) {
        if ($attr.NamespaceURI -eq "http://www.w3.org/2000/xmlns/") {
            continue
        }
        if ($attr.LocalName.Equals($AttributeName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $values.Add([string]$attr.Value)
        }
    }
    return ,$values
}

function Format-SanitizedWackText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $sb = [System.Text.StringBuilder]::new($Value.Length)
    foreach ($ch in $Value.ToCharArray()) {
        $cp = [int][char]$ch
        if (
            $cp -lt 0x20 -or $cp -eq 0x7F -or ($cp -ge 0x80 -and $cp -le 0x9F) -or
            ($cp -ge 0x202A -and $cp -le 0x202E) -or ($cp -ge 0x2066 -and $cp -le 0x2069) -or
            $cp -eq 0x061C
        ) {
            [void]$sb.Append(('<U+{0:X4}>' -f $cp))
        }
        else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function Test-WackReportXml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFile
    )

    if (-not (Test-Path -LiteralPath $ReportFile -PathType Leaf)) {
        $safeReportPath = Format-SanitizedWackText -Value $ReportFile
        [Console]::Error.WriteLine("WACK error: report file not found: $safeReportPath")
        return $false
    }
    $resolvedFile = (Resolve-Path -LiteralPath $ReportFile).Path
    $safeResolvedFile = Format-SanitizedWackText -Value $resolvedFile

    $doc = [System.Xml.XmlDocument]::new()
    $doc.XmlResolver = $null
    $readerSettings = [System.Xml.XmlReaderSettings]::new()
    $readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $readerSettings.XmlResolver = $null

    try {
        $fs = [System.IO.File]::OpenRead($resolvedFile)
        try {
            $reader = [System.Xml.XmlReader]::Create($fs, $readerSettings)
            try {
                $doc.Load($reader)
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $fs.Dispose()
        }
    }
    catch [System.Xml.XmlException], [System.Text.DecoderFallbackException], [System.IO.IOException], [System.UnauthorizedAccessException] {
        $safeErr = Format-SanitizedWackText -Value $_.Exception.Message
        [Console]::Error.WriteLine("WACK error: malformed, unreadable, or unsafe XML report '$safeResolvedFile': $safeErr")
        return $false
    }

    $reportNode = $doc.DocumentElement
    if ($null -eq $reportNode -or -not $reportNode.LocalName.Equals("REPORT", [System.StringComparison]::OrdinalIgnoreCase)) {
        [Console]::Error.WriteLine("WACK error: XML report is missing root <REPORT> element: $safeResolvedFile")
        return $false
    }

    $overallValues = Get-XmlAttributeValues -Node $reportNode -AttributeName "OVERALL_RESULT"
    $overallError = $null
    $overallRaw = ""
    $overall = ""
    if ($overallValues.Count -eq 0) {
        $overallRaw = "<missing>"
        $overallError = "WACK error: <REPORT> is missing OVERALL_RESULT attribute"
    }
    elseif ($overallValues.Count -gt 1) {
        $overallParts = [System.Collections.Generic.List[string]]::new()
        foreach ($ov in $overallValues) {
            $ovPart = if ([string]::IsNullOrWhiteSpace($ov)) { "<empty>" } else { $ov.Trim() }
            $overallParts.Add($ovPart)
        }
        $overallJoined = $overallParts -join ", "
        $overallRaw = "<duplicate: $overallJoined>"
        $overallError = "WACK error: <REPORT> contains duplicate case-variant OVERALL_RESULT attributes ($overallJoined)"
    }
    else {
        $overallRaw = $overallValues[0]
        $overall = $overallRaw.Trim().ToUpperInvariant()
    }

    $allElements = $doc.SelectNodes("//*")
    $testNodes = [System.Collections.Generic.List[System.Xml.XmlNode]]::new()
    if ($null -ne $allElements) {
        foreach ($el in $allElements) {
            if ($el.LocalName.Equals("TEST", [System.StringComparison]::OrdinalIgnoreCase)) {
                $testNodes.Add($el)
            }
        }
    }

    $allowedTestResults = @("PASS", "NOT APPLICABLE", "SKIPPED")
    $failedTests = [System.Collections.Generic.List[string]]::new()
    $passCount = 0
    foreach ($testNode in $testNodes) {
        $resultValues = Get-XmlAttributeValues -Node $testNode -AttributeName "RESULT"
        foreach ($child in $testNode.ChildNodes) {
            if (
                $child.NodeType -eq [System.Xml.XmlNodeType]::Element -and
                $child.LocalName.Equals("RESULT", [System.StringComparison]::OrdinalIgnoreCase)
            ) {
                $resultValues.Add([string]$child.InnerText)
            }
        }

        $testFailed = $false
        $displayResult = ""
        if ($resultValues.Count -eq 0) {
            $testFailed = $true
            $displayResult = "<missing>"
        }
        elseif ($resultValues.Count -gt 1) {
            $testFailed = $true
            $dupParts = [System.Collections.Generic.List[string]]::new()
            foreach ($rv in $resultValues) {
                $rvPart = if ([string]::IsNullOrWhiteSpace($rv)) { "<empty>" } else { $rv.Trim() }
                $dupParts.Add($rvPart)
            }
            $displayResult = "<duplicate: $($dupParts -join ', ')>"
        }
        else {
            $resultRaw = $resultValues[0]
            $resultNorm = $resultRaw.Trim().ToUpperInvariant()
            if ($resultNorm -eq "PASS") {
                $passCount++
            }
            if ($allowedTestResults -notcontains $resultNorm) {
                $testFailed = $true
                $displayResult = if ([string]::IsNullOrWhiteSpace($resultRaw)) { "<missing>" } else { $resultRaw.Trim() }
            }
        }

        if ($testFailed) {
            $testName = ""
            foreach ($nv in (Get-XmlAttributeValues -Node $testNode -AttributeName "NAME")) {
                if (-not [string]::IsNullOrWhiteSpace($nv)) {
                    $testName = $nv.Trim()
                    break
                }
            }
            if ([string]::IsNullOrWhiteSpace($testName)) {
                foreach ($iv in (Get-XmlAttributeValues -Node $testNode -AttributeName "INDEX")) {
                    if (-not [string]::IsNullOrWhiteSpace($iv)) {
                        $testName = "TEST#" + $iv.Trim()
                        break
                    }
                }
            }
            if ([string]::IsNullOrWhiteSpace($testName)) {
                $testName = "<unnamed test>"
            }
            $safeTestName = Format-SanitizedWackText -Value $testName
            $safeDisplayResult = Format-SanitizedWackText -Value $displayResult
            $failedTests.Add("$safeTestName (RESULT='$safeDisplayResult')")
        }
    }

    $passed = ($null -eq $overallError) -and ($overall -eq "PASS") -and ($testNodes.Count -ge 1) -and ($passCount -ge 1) -and ($failedTests.Count -eq 0)
    if (-not $passed) {
        $safeOverallRaw = Format-SanitizedWackText -Value $overallRaw
        [Console]::Error.WriteLine("WACK report FAILED: $safeResolvedFile (OVERALL_RESULT='$safeOverallRaw', tests=$($testNodes.Count), passed=$passCount, failed=$($failedTests.Count))")
        if ($null -ne $overallError) {
            [Console]::Error.WriteLine((Format-SanitizedWackText -Value $overallError))
        }
        if ($testNodes.Count -lt 1) {
            [Console]::Error.WriteLine("WACK error: report contains zero <TEST> elements")
        }
        elseif ($passCount -lt 1) {
            [Console]::Error.WriteLine("WACK error: report contains zero PASS <TEST> elements (all tests skipped, not applicable, or failed)")
        }
        foreach ($failedEntry in $failedTests) {
            [Console]::Error.WriteLine("WACK FAILED test: $failedEntry")
        }
        return $false
    }

    Write-Host "WACK report PASS: $safeResolvedFile (tests=$($testNodes.Count), passed=$passCount, failed=0)"
    return $true
}

if ($CheckReportOnly) {
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        throw "-ReportPath is required when -CheckReportOnly is specified."
    }
    $ok = Test-WackReportXml -ReportFile $ReportPath
    if (-not $ok) {
        exit 1
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($PackagePath)) {
    throw "-PackagePath (.msix or .msixbundle) is required unless -CheckReportOnly is specified."
}
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    throw "Package not found: $PackagePath"
}
$resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
$pkgExt = [System.IO.Path]::GetExtension($resolvedPackage).ToLowerInvariant()
if ($pkgExt -ne ".msix" -and $pkgExt -ne ".msixbundle") {
    throw "Unsupported package extension '$pkgExt'. Expected .msix or .msixbundle."
}

$resolvedReport = if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    Join-Path (Split-Path -Parent $resolvedPackage) "wack-report.xml"
} else {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
}
$reportParent = Split-Path -Parent $resolvedReport
if (-not [string]::IsNullOrWhiteSpace($reportParent)) {
    New-Item -ItemType Directory -Force -Path $reportParent | Out-Null
}

Assert-WackInteractivePreconditions
$appCert = Resolve-AppCertExe -ExplicitPath $AppCertPath
Write-Host "==> Running Windows App Certification Kit (WACK)..."
Write-Host "    appcert: $appCert"
Write-Host "    package: $resolvedPackage"
Write-Host "    report:  $resolvedReport"

if (Test-Path -LiteralPath $resolvedReport) {
    Remove-Item -LiteralPath $resolvedReport -Force
}

& $appCert reset
if ($LASTEXITCODE -ne 0) {
    throw "appcert.exe reset failed with exit code $LASTEXITCODE"
}

$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $appCert test -appxpackagepath $resolvedPackage -reportoutputpath $resolvedReport
    $testExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $prevEap
}

$reportValid = $false
if (Test-Path -LiteralPath $resolvedReport -PathType Leaf) {
    $reportValid = Test-WackReportXml -ReportFile $resolvedReport
} else {
    $safeExpectedReport = Format-SanitizedWackText -Value $resolvedReport
    [Console]::Error.WriteLine("WACK error: appcert.exe did not generate expected XML report at $safeExpectedReport")
}

if ($testExitCode -ne 0 -or -not $reportValid) {
    [Console]::Error.WriteLine("WACK certification check failed (appcert exit=$testExitCode, report_pass=$reportValid).")
    exit 1
}

exit 0
