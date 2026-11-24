#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Builds the isolated Windows 11 x86_64 slice of TotalDrop (Rust C ABI FFI +
    Explorer COM cdylibs + WinUI 3 .NET 10 Native AOT executable + MakePri
    resources.pri + strict makeappx.exe x64 MSIX package, optional Store
    identity projection and deterministic .appxsym symbols) on GitHub's
    `windows-latest` runner (ADR 0016).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version = "0.1.1.0",

    [Parameter()]
    [string]$OutputDir = "",

    [Parameter()]
    [Alias("SignEphemeralTestCert")]
    [switch]$SelfSignEphemeral,

    [Parameter()]
    [string]$StoreIdentityName = "",

    [Parameter()]
    [string]$StorePublisher = "",

    [Parameter()]
    [string]$StorePublisherDisplayName = "",

    [Parameter()]
    [switch]$EmitSymbols,

    [Parameter()]
    [switch]$StoreMode,

    [Parameter()]
    [switch]$AllowTestIdentity
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$UnsignedPackageOid = "2.25.311729368913984317654407730594956997722"

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
        throw "Invalid MSIX -Version '$Value'. Expected four-part numeric version (Major.Minor.Build.Revision)."
    }
    $parts = $Value.Split('.')
    $nums = @()
    foreach ($part in $parts) {
        if ($part.Length -gt 1 -and $part.StartsWith('0')) {
            throw "Invalid MSIX -Version '$Value': leading zeros are not permitted in version component '$part'."
        }
        [int]$num = 0
        if (-not [int]::TryParse($part, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$num) -or $num -lt 0 -or $num -gt 65535) {
            throw "Invalid MSIX -Version '$Value': each component must be in 0..65535 (got '$part')."
        }
        $nums += $num
    }
    if ($RequireStoreRules) {
        if ($nums[0] -lt 1) {
            throw "Invalid Store MSIX -Version '$Value': Microsoft Store requires Major >= 1 (1..65535)."
        }
        if ($nums[3] -ne 0) {
            throw "Invalid Store MSIX -Version '$Value': Microsoft Store requires Revision == 0 (4th component is reserved)."
        }
    }
}

function Assert-NoControlOrBidiChars {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    foreach ($ch in $Value.ToCharArray()) {
        $cp = [int][char]$ch
        if ($cp -lt 0x20 -or $cp -eq 0x7F -or ($cp -ge 0x80 -and $cp -le 0x9F) -or ($cp -ge 0x202A -and $cp -le 0x202E) -or ($cp -ge 0x2066 -and $cp -le 0x2069) -or $cp -eq 0x061C) {
            throw "Invalid ${Label}: contains forbidden control or Bidi override character U+$($cp.ToString('X4'))."
        }
    }
}

function Read-XmlDocumentStrict {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [switch]$PreserveWhitespace
    )

    $doc = [System.Xml.XmlDocument]::new()
    $doc.PreserveWhitespace = [bool]$PreserveWhitespace
    $doc.XmlResolver = $null
    $readerSettings = [System.Xml.XmlReaderSettings]::new()
    $readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $readerSettings.XmlResolver = $null
    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $fs = [System.IO.File]::OpenRead($resolvedPath)
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
    return $doc
}

function Remove-PathWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [int]$MaxAttempts = 5,

        [Parameter()]
        [int]$DelayMs = 250
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            }
            if (-not (Test-Path -LiteralPath $Path)) {
                return
            }
        }
        catch {
            if ($attempt -ge $MaxAttempts) {
                throw
            }
        }
        Start-Sleep -Milliseconds $DelayMs
    }
}

function Remove-UnescapedX500Whitespace {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $len = $Value.Length
    $start = 0
    while ($start -lt $len -and [char]::IsWhiteSpace($Value[$start])) {
        $start++
    }
    $lastSigEnd = $start
    $escaped = $false
    for ($i = $start; $i -lt $len; $i++) {
        $ch = $Value[$i]
        if ($escaped) {
            $escaped = $false
            $lastSigEnd = $i + 1
            continue
        }
        if ($ch -eq '\') {
            $escaped = $true
            $lastSigEnd = $i + 1
            continue
        }
        if (-not [char]::IsWhiteSpace($ch)) {
            $lastSigEnd = $i + 1
        }
    }
    return $Value.Substring($start, $lastSigEnd - $start)
}

function Test-AsciiHexChar {
    param(
        [Parameter(Mandatory = $true)]
        [char]$Ch
    )

    $code = [int]$Ch
    return (($code -ge 0x30 -and $code -le 0x39) -or ($code -ge 0x41 -and $code -le 0x46) -or ($code -ge 0x61 -and $code -le 0x66))
}

function ConvertFrom-Rfc2253RdnValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RawText,

        [Parameter()]
        [switch]$Quoted,

        [Parameter(Mandatory = $true)]
        [string]$Publisher,

        [Parameter(Mandatory = $true)]
        [string]$Rdn
    )

    # RFC 2253 / RFC 4514 section 2.4 single-character escapable set: , + " \ < > ; # = <space>
    $escapableChars = @(
        [char]0x2C, [char]0x2B, [char]0x22, [char]0x5C, [char]0x3C,
        [char]0x3E, [char]0x3B, [char]0x23, [char]0x3D, [char]0x20
    )
    # Forbidden unescaped chars in unquoted RDN values: ", ;, <, >, +, `, $, |, &
    $forbiddenUnquoted = @(
        [char]0x22, [char]0x3B, [char]0x3C, [char]0x3E, [char]0x2B,
        [char]0x60, [char]0x24, [char]0x7C, [char]0x26
    )
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $sb = [System.Text.StringBuilder]::new()
    $len = $RawText.Length
    $i = 0
    while ($i -lt $len) {
        $c = $RawText[$i]
        if ($c -eq '\') {
            if (($i + 1) -ge $len) {
                throw "Invalid X.500 Publisher '$Publisher': trailing escape in RDN '$Rdn'."
            }
            $nxt = $RawText[$i + 1]
            if ($escapableChars -ccontains $nxt) {
                [void]$sb.Append($nxt)
                $i += 2
            }
            elseif ((($i + 2) -lt $len) -and (Test-AsciiHexChar -Ch $nxt) -and (Test-AsciiHexChar -Ch $RawText[$i + 2])) {
                $byteList = [System.Collections.Generic.List[byte]]::new()
                while ((($i + 2) -lt $len) -and ($RawText[$i] -eq '\') -and (Test-AsciiHexChar -Ch $RawText[$i + 1]) -and (Test-AsciiHexChar -Ch $RawText[$i + 2])) {
                    $hexPair = $RawText.Substring($i + 1, 2)
                    $byteList.Add([System.Convert]::ToByte($hexPair, 16))
                    $i += 3
                }
                try {
                    [void]$sb.Append($strictUtf8.GetString($byteList.ToArray()))
                }
                catch [System.Text.DecoderFallbackException] {
                    throw "Invalid X.500 Publisher '$Publisher': invalid UTF-8 byte sequence in RFC 2253 hex escape in RDN '$Rdn'."
                }
            }
            else {
                throw "Invalid X.500 Publisher '$Publisher': invalid RFC 2253 escape sequence '\$nxt' in RDN '$Rdn'."
            }
        }
        else {
            if (-not $Quoted -and ($forbiddenUnquoted -ccontains $c)) {
                throw "Invalid X.500 Publisher '$Publisher': forbidden unescaped character '$c' in unquoted RDN '$Rdn'."
            }
            [void]$sb.Append($c)
            $i++
        }
    }
    return $sb.ToString()
}

function ConvertFrom-X500Publisher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Publisher
    )

    if ([string]::IsNullOrEmpty((Remove-UnescapedX500Whitespace -Value $Publisher)) -or $Publisher.Length -gt 8192) {
        throw "Invalid Publisher: must be a non-empty X.500 distinguished name (<= 8192 chars)."
    }
    Assert-NoControlOrBidiChars -Value $Publisher -Label "Publisher"
    if ($Publisher.IndexOf($UnsignedPackageOid, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Forbidden unsigned-package OID '$UnsignedPackageOid' detected in Publisher '$Publisher'."
    }

    # Split RFC 2253 comma-separated RDNs while respecting double quotes and backslash escapes.
    $rdns = [System.Collections.Generic.List[string]]::new()
    $current = [System.Text.StringBuilder]::new()
    $inQuotes = $false
    $escaped = $false
    foreach ($ch in $Publisher.ToCharArray()) {
        if ($escaped) {
            [void]$current.Append($ch)
            $escaped = $false
            continue
        }
        if ($ch -eq '\') {
            [void]$current.Append($ch)
            $escaped = $true
            continue
        }
        if ($ch -eq '"') {
            $inQuotes = -not $inQuotes
            [void]$current.Append($ch)
            continue
        }
        if ($ch -eq ',' -and -not $inQuotes) {
            $rdns.Add((Remove-UnescapedX500Whitespace -Value $current.ToString()))
            [void]$current.Clear()
            continue
        }
        [void]$current.Append($ch)
    }
    if ($inQuotes -or $escaped) {
        throw "Invalid X.500 Publisher '$Publisher': unterminated quote or escape sequence."
    }
    $rdns.Add((Remove-UnescapedX500Whitespace -Value $current.ToString()))

    $parsed = [System.Collections.Generic.List[object]]::new()
    $hasCn = $false
    foreach ($rdn in $rdns) {
        if ([string]::IsNullOrWhiteSpace($rdn)) {
            throw "Invalid X.500 Publisher '$Publisher': empty RDN segment."
        }
        $eqIdx = $rdn.IndexOf('=')
        if ($eqIdx -lt 1) {
            throw "Invalid X.500 Publisher '$Publisher': malformed RDN '$rdn' (expected e.g. 'CN=...')."
        }
        $key = $rdn.Substring(0, $eqIdx).Trim()
        $val = Remove-UnescapedX500Whitespace -Value $rdn.Substring($eqIdx + 1)
        if ($key -notmatch '\A(?:[A-Za-z][A-Za-z0-9-]*|(?:OID\.)?[0-9]+(?:\.[0-9]+)+)\z' -or [string]::IsNullOrEmpty($val)) {
            throw "Invalid X.500 Publisher '$Publisher': malformed RDN '$rdn' (expected e.g. 'CN=...')."
        }

        if ($val.StartsWith('#')) {
            throw "Invalid X.500 Publisher '$Publisher': ASN.1 BER #hex RDN values are not permitted in MSIX Identity/@Publisher ('$rdn')."
        }

        $decodedVal = ""
        if ($val.StartsWith('"')) {
            if ($val.Length -lt 2) {
                throw "Invalid X.500 Publisher '$Publisher': malformed quoted RDN '$rdn'."
            }
            $qEscaped = $false
            $closed = $false
            for ($i = 1; $i -lt $val.Length; $i++) {
                $c = $val[$i]
                if ($qEscaped) {
                    $qEscaped = $false
                    continue
                }
                if ($c -eq '\') {
                    $qEscaped = $true
                    continue
                }
                if ($c -eq '"') {
                    if ($i -ne ($val.Length - 1)) {
                        throw "Invalid X.500 Publisher '$Publisher': unexpected trailing characters after closing quote in RDN '$rdn'."
                    }
                    $closed = $true
                    break
                }
            }
            if (-not $closed -or $qEscaped) {
                throw "Invalid X.500 Publisher '$Publisher': unterminated quoted RDN '$rdn'."
            }
            $decodedVal = ConvertFrom-Rfc2253RdnValue -RawText $val.Substring(1, $val.Length - 2) -Quoted -Publisher $Publisher -Rdn $rdn
        }
        else {
            $decodedVal = ConvertFrom-Rfc2253RdnValue -RawText $val -Publisher $Publisher -Rdn $rdn
        }

        Assert-NoControlOrBidiChars -Value $decodedVal -Label "decoded Publisher RDN '$rdn'"
        if ($decodedVal.IndexOf($UnsignedPackageOid, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Forbidden unsigned-package OID '$UnsignedPackageOid' detected in decoded Publisher RDN '$rdn'."
        }
        if ([string]::IsNullOrWhiteSpace($decodedVal)) {
            throw "Invalid X.500 Publisher '$Publisher': empty RDN value in '$rdn'."
        }

        $keyUpper = $key.ToUpperInvariant()
        if ($keyUpper -eq "CN" -and -not [string]::IsNullOrWhiteSpace($decodedVal)) {
            $hasCn = $true
        }
        $parsed.Add([PSCustomObject]@{ Key = $keyUpper; Value = $decodedVal })
    }
    if (-not $hasCn) {
        throw "Invalid X.500 Publisher '$Publisher': must include a non-empty 'CN=' attribute."
    }
    return $parsed.ToArray()
}

function Assert-X500Publisher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Publisher
    )

    [void](ConvertFrom-X500Publisher -Publisher $Publisher)
}

function Test-PlaceholderTestIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IdentityName,

        [Parameter(Mandatory = $true)]
        [string]$Publisher
    )

    if ($IdentityName.Trim().Equals("TotalDrop.TotalDrop", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $placeholderCns = @("totaldrop", "00000000-0000-0000-0000-000000000000")
    $rdns = @(ConvertFrom-X500Publisher -Publisher $Publisher)
    foreach ($rdn in $rdns) {
        if ($rdn.Key -eq "CN" -and ($placeholderCns -contains $rdn.Value.Trim().ToLowerInvariant())) {
            return $true
        }
    }
    return $false
}

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter()]
        [string]$PreferredArch = "x64"
    )

    $archOrder = if ($PreferredArch -eq "arm64") { @("arm64", "x64") } else { @("x64", "arm64") }

    # Self-contained strict ASCII 4-part numeric version sorter (zero external helpers for isolated AST extraction).
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

    # 3. Ambient PATH fallback
    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Required Windows SDK tool '$ToolName' not found in Windows Kits 10, NuGet BuildTools, or PATH."
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
$SourceManifestPath = Join-Path $ScriptDir "Package.x64.appxmanifest"

# Pre-flight manifest & Store identity validation before compiling Rust / .NET.
Assert-NoControlOrBidiChars -Value $StoreIdentityName -Label "StoreIdentityName"
Assert-NoControlOrBidiChars -Value $StorePublisher -Label "StorePublisher"
Assert-NoControlOrBidiChars -Value $StorePublisherDisplayName -Label "StorePublisherDisplayName"

$preManifestDoc = Read-XmlDocumentStrict -Path $SourceManifestPath
$preNsMgr = [System.Xml.XmlNamespaceManager]::new($preManifestDoc.NameTable)
$preNsMgr.AddNamespace("appx", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
$preIdent = $preManifestDoc.SelectSingleNode("/appx:Package/appx:Identity", $preNsMgr)
$prePubDisp = $preManifestDoc.SelectSingleNode("/appx:Package/appx:Properties/appx:PublisherDisplayName", $preNsMgr)
if ($null -eq $preIdent -or $null -eq $prePubDisp) {
    throw "Source manifest $SourceManifestPath is missing /Package/Identity or /Package/Properties/PublisherDisplayName."
}

$EffectiveIdentityName = if (-not [string]::IsNullOrWhiteSpace($StoreIdentityName)) {
    $StoreIdentityName.Trim()
} else {
    $preIdent.GetAttribute("Name")
}
$EffectivePublisher = if (-not [string]::IsNullOrWhiteSpace($StorePublisher)) {
    Remove-UnescapedX500Whitespace -Value $StorePublisher
} else {
    $preIdent.GetAttribute("Publisher")
}
$EffectivePublisherDisplayName = if (-not [string]::IsNullOrWhiteSpace($StorePublisherDisplayName)) {
    $StorePublisherDisplayName.Trim()
} else {
    $prePubDisp.InnerText.Trim()
}

Assert-NoControlOrBidiChars -Value $EffectiveIdentityName -Label "IdentityName"
if ($EffectiveIdentityName -notmatch '^[A-Za-z0-9.-]{3,50}$') {
    throw "Invalid Identity Name '$EffectiveIdentityName'. Expected 3..50 ASCII alphanumeric, dot, or hyphen characters."
}
Assert-X500Publisher -Publisher $EffectivePublisher
if ([string]::IsNullOrWhiteSpace($EffectivePublisherDisplayName) -or $EffectivePublisherDisplayName.Length -gt 256) {
    throw "Invalid PublisherDisplayName '$EffectivePublisherDisplayName'. Must be 1..256 characters."
}
Assert-NoControlOrBidiChars -Value $EffectivePublisherDisplayName -Label "PublisherDisplayName"

if ($StoreMode) {
    $isPlaceholderIdentity = Test-PlaceholderTestIdentity -IdentityName $EffectiveIdentityName -Publisher $EffectivePublisher
    if ($isPlaceholderIdentity -and -not $AllowTestIdentity) {
        throw "Refusing placeholder test identity (Name='$EffectiveIdentityName', Publisher='$EffectivePublisher') in -StoreMode. Supply Partner Center -StoreIdentityName / -StorePublisher or pass -AllowTestIdentity for dry-runs."
    }
}

$ResolvedOutDir = if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    Join-Path $RepoRoot "dist"
} else {
    $OutputDir
}
New-Item -ItemType Directory -Force -Path $ResolvedOutDir | Out-Null
$ResolvedOutDir = (Resolve-Path -LiteralPath $ResolvedOutDir).Path

$WorkRoot = Join-Path $RepoRoot "dist\work-x64"
$PublishDir = Join-Path $WorkRoot "publish-win-x64"
$StagingDir = Join-Path $WorkRoot "staging-x64"
$PriWorkDir = Join-Path $WorkRoot "pri-work-x64"
$OutMsixName = "TotalDrop_${Version}_x64.msix"
$OutMsix = Join-Path $ResolvedOutDir $OutMsixName
$OutAppxSymName = "TotalDrop_${Version}_x64.appxsym"
$OutAppxSym = Join-Path $ResolvedOutDir $OutAppxSymName
$TargetReleaseDir = Join-Path $RepoRoot "target\x86_64-pc-windows-msvc\release"
$FfiDll = Join-Path $TargetReleaseDir "totaldrop_windows_ffi.dll"
$ExplorerExtDll = Join-Path $TargetReleaseDir "totaldrop_explorer_ext.dll"

Write-Host "==> [x64 1/5] Building Rust totaldrop-windows-ffi & totaldrop-explorer-ext cdylibs (x86_64-pc-windows-msvc)..."
$SavedRustFlags = [System.Environment]::GetEnvironmentVariable("RUSTFLAGS")
$SavedEncodedRustFlags = [System.Environment]::GetEnvironmentVariable("CARGO_ENCODED_RUSTFLAGS")
Push-Location $RepoRoot
try {
    # Clear ambient RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS so target-x86_64/cargo-config.toml
    # (+crt-static, SIMD, /DEPENDENTLOADFLAG:0x800, /CETCOMPAT, ASLR, NX) applies in full.
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
    $cargoArgs = @(
        "build",
        "--config", (Join-Path $ScriptDir "cargo-config.toml"),
        "--target", "x86_64-pc-windows-msvc",
        "-p", "totaldrop-windows-ffi",
        "-p", "totaldrop-explorer-ext",
        "--release",
        "--locked"
    )
    if ($EmitSymbols) {
        # Override workspace [profile.release] strip=true so MSVC emits standalone PDBs with matching RSDS GUIDs.
        $cargoArgs += @("--config", "profile.release.debug=true", "--config", "profile.release.strip=false")
    }
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build (totaldrop-windows-ffi / totaldrop-explorer-ext, x86_64-pc-windows-msvc) failed with exit code $LASTEXITCODE"
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
if (-not (Test-Path -LiteralPath $ExplorerExtDll)) {
    throw "Expected native Explorer COM DLL missing at $ExplorerExtDll"
}

Write-Host "==> [x64 2/5] Publishing WinUI 3 shell with .NET 10 LTS Native AOT (win-x64)..."
Remove-PathWithRetry -Path $PublishDir
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

    $publishArgs = @(
        "publish",
        "TotalDrop.WinUI.csproj",
        "-r", "win-x64",
        "-c", "Release",
        "-p:Platform=x64",
        "-p:PublishAot=true",
        "-p:WindowsAppSDKSelfContained=false",
        "-p:AssemblyVersion=$Version",
        "-p:FileVersion=$Version",
        "-o", $PublishDir
    )
    if ($EmitSymbols) {
        $publishArgs += @(
            "-p:DebugSymbols=true",
            "-p:DebugType=portable",
            "-p:NativeDebugSymbols=true",
            "-p:StripSymbols=false",
            "-p:CopyOutputSymbolsToPublishDirectory=true"
        )
    }
    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish (win-x64 Native AOT) failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

$MakePriExe = Resolve-WindowsKitTool -ToolName "MakePri.exe" -PreferredArch "x64"
$MakeAppxExe = Resolve-WindowsKitTool -ToolName "makeappx.exe" -PreferredArch "x64"
Write-Host "    MakePri:  $MakePriExe"
Write-Host "    MakeAppx: $MakeAppxExe"

Write-Host "==> [x64 3/5] Staging x64 MSIX layout & compiling unified resources.pri..."
Remove-PathWithRetry -Path $StagingDir
Remove-PathWithRetry -Path $PriWorkDir
New-Item -ItemType Directory -Force -Path $StagingDir, $PriWorkDir | Out-Null

Get-ChildItem -LiteralPath $PublishDir | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $StagingDir -Recurse -Force
}
Copy-Item -LiteralPath $ExplorerExtDll -Destination (Join-Path $StagingDir "totaldrop_explorer_ext.dll") -Force

# Strip debug symbols and any stale PRI files prior to MakePri indexing.
foreach ($staleItem in @(Get-ChildItem -LiteralPath $StagingDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension.ToLowerInvariant() -in @(".pdb", ".pri") })) {
    Remove-PathWithRetry -Path $staleItem.FullName
}

foreach ($requiredRel in @(
    "totaldrop-winui.exe",
    "totaldrop_windows_ffi.dll",
    "totaldrop_explorer_ext.dll",
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

$StagedManifest = Join-Path $StagingDir "AppxManifest.xml"
Copy-Item `
    -LiteralPath $SourceManifestPath `
    -Destination $StagedManifest `
    -Force
$manifestDoc = Read-XmlDocumentStrict -Path $StagedManifest -PreserveWhitespace
$nsMgr = [System.Xml.XmlNamespaceManager]::new($manifestDoc.NameTable)
$nsMgr.AddNamespace("appx", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
$identityNode = $manifestDoc.SelectSingleNode("/appx:Package/appx:Identity", $nsMgr)
$pubDisplayNode = $manifestDoc.SelectSingleNode("/appx:Package/appx:Properties/appx:PublisherDisplayName", $nsMgr)
if ($null -eq $identityNode -or $null -eq $pubDisplayNode) {
    throw "Staged AppxManifest.xml is missing /Package/Identity or /Package/Properties/PublisherDisplayName."
}
$manifestChanged = $false
if ($identityNode.GetAttribute("Version") -cne $Version) {
    Write-Host "    Patching staged AppxManifest.xml Identity/@Version: $($identityNode.GetAttribute('Version')) -> $Version"
    $identityNode.SetAttribute("Version", $Version)
    $manifestChanged = $true
}
if ($identityNode.GetAttribute("Name") -cne $EffectiveIdentityName) {
    Write-Host "    Patching staged AppxManifest.xml Identity/@Name: $($identityNode.GetAttribute('Name')) -> $EffectiveIdentityName"
    $identityNode.SetAttribute("Name", $EffectiveIdentityName)
    $manifestChanged = $true
}
if ($identityNode.GetAttribute("Publisher") -cne $EffectivePublisher) {
    Write-Host "    Patching staged AppxManifest.xml Identity/@Publisher: $($identityNode.GetAttribute('Publisher')) -> $EffectivePublisher"
    $identityNode.SetAttribute("Publisher", $EffectivePublisher)
    $manifestChanged = $true
}
if ($pubDisplayNode.InnerText -cne $EffectivePublisherDisplayName) {
    Write-Host "    Patching staged AppxManifest.xml Properties/PublisherDisplayName -> $EffectivePublisherDisplayName"
    $pubDisplayNode.InnerText = $EffectivePublisherDisplayName
    $manifestChanged = $true
}
if ($manifestChanged) {
    $manifestDoc.Save($StagedManifest)
}

# Stage 35-locale .resw catalogs temporarily for MakePri indexing (exclude locales.json).
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

$PriConfigPath = Join-Path $PriWorkDir "priconfig-x64.xml"
$ResourcesPri = Join-Path $StagingDir "resources.pri"
$PriDumpPath = Join-Path $PriWorkDir "resources-x64.pri.xml"

& $MakePriExe createconfig /cf $PriConfigPath /dq lang-en /o /pv 10.0.0
if ($LASTEXITCODE -ne 0) {
    throw "MakePri.exe createconfig failed with exit code $LASTEXITCODE"
}

# Remove <packaging> autoResourcePackage splits so MakePri emits one unified resources.pri.
$priXml = Read-XmlDocumentStrict -Path $PriConfigPath -PreserveWhitespace
$pkgNode = $priXml.SelectSingleNode("/resources/packaging")
if ($null -ne $pkgNode -and $null -ne $pkgNode.ParentNode) {
    [void]$pkgNode.ParentNode.RemoveChild($pkgNode)
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

# Remove raw .resw files after MakePri compiled them into resources.pri.
Remove-PathWithRetry -Path $StringsStage

# Normalize staged file timestamps to SOURCE_DATE_EPOCH prior to makeappx pack.
foreach ($stagedFile in @(Get-ChildItem -LiteralPath $StagingDir -Recurse -File)) {
    [System.IO.File]::SetLastWriteTimeUtc($stagedFile.FullName, $EpochUtc)
}

Write-Host "==> [x64 4/5] Packing $OutMsixName with strict makeappx.exe (no /nv)..."
& $MakeAppxExe pack /o /h SHA256 /d $StagingDir /p $OutMsix
if ($LASTEXITCODE -ne 0) {
    throw "makeappx.exe pack (x64) failed with exit code $LASTEXITCODE"
}
[System.IO.File]::SetLastWriteTimeUtc($OutMsix, $EpochUtc)

if ($EmitSymbols) {
    Write-Host "==> Packing deterministic x64 debug symbols archive: $OutAppxSymName..."
    $pdbEntries = @{
        "totaldrop-winui.pdb"        = (Join-Path $PublishDir "totaldrop-winui.pdb")
        "totaldrop_windows_ffi.pdb"  = (Join-Path $TargetReleaseDir "totaldrop_windows_ffi.pdb")
        "totaldrop_explorer_ext.pdb" = (Join-Path $TargetReleaseDir "totaldrop_explorer_ext.pdb")
    }
    foreach ($pdbKey in ($pdbEntries.Keys | Sort-Object)) {
        $pdbPath = [string]$pdbEntries[$pdbKey]
        if (-not (Test-Path -LiteralPath $pdbPath) -or (Get-Item -LiteralPath $pdbPath).Length -le 0) {
            throw "Expected non-empty PDB symbol file missing for -EmitSymbols: $pdbPath"
        }
    }
    New-DeterministicZipArchive -DestinationPath $OutAppxSym -EntryMap $pdbEntries -EpochSeconds $SourceDateEpoch
}

if ($SelfSignEphemeral) {
    $SignToolExe = Resolve-WindowsKitTool -ToolName "signtool.exe" -PreferredArch "x64"
    Write-Host "==> [x64 5/5] Signing CI test MSIX with ephemeral zero-PFX self-signed cert (Subject: $EffectivePublisher)..."
    Write-Host "    SignTool: $SignToolExe"
    $Cert = $null
    try {
        $Cert = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $EffectivePublisher `
            -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddDays(1) `
            -FriendlyName "TotalDrop Ephemeral CI Test Cert" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
        & $SignToolExe sign /fd SHA256 /sha1 $Cert.Thumbprint $OutMsix
        if ($LASTEXITCODE -ne 0) {
            throw "signtool.exe sign failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        if ($null -ne $Cert -and (Test-Path -LiteralPath "Cert:\CurrentUser\My\$($Cert.Thumbprint)")) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($Cert.Thumbprint)" -Force
        }
    }
} else {
    Write-Host "==> [x64 5/5] Skipping ephemeral signing (unsigned Store-ready MSIX)."
}

$ArtifactsToHash = [System.Collections.Generic.List[string]]::new()
$ArtifactsToHash.Add($OutMsixName)
if ($EmitSymbols) {
    $ArtifactsToHash.Add($OutAppxSymName)
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

$MsixHashHex = (Get-FileHash -Algorithm SHA256 -LiteralPath $OutMsix).Hash.ToLowerInvariant()
Write-Host "==> Built x64 MSIX: $OutMsix (SHA-256: $MsixHashHex)"
if ($EmitSymbols) {
    $SymHashHex = (Get-FileHash -Algorithm SHA256 -LiteralPath $OutAppxSym).Hash.ToLowerInvariant()
    Write-Host "==> Built x64 Symbols: $OutAppxSym (SHA-256: $SymHashHex)"
}
