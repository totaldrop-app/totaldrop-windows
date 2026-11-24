// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TotalDrop.WinUI.Interop;

/// <summary>
/// Source-generated <see cref="JsonSerializerContext"/> for Native AOT IPC and
/// C ABI payloads exchanged with <c>totaldrop_windows_ffi.dll</c>.
/// Zero runtime reflection is used anywhere in the WinUI 3 shell (ADR 0016).
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(VersionInfoDto))]
[JsonSerializable(typeof(BridgeErrorEnvelopeDto))]
[JsonSerializable(typeof(BridgeUiBundleDto))]
[JsonSerializable(typeof(ValidatedCodeDto))]
[JsonSerializable(typeof(RegionalPercentDto))]
[JsonSerializable(typeof(ActivationEnvelopeDto))]
public sealed partial class TotalDropJsonContext : JsonSerializerContext;

/// <summary>
/// Version metadata returned by <c>totaldrop_win_version_json</c>.
/// </summary>
public sealed record VersionInfoDto(
    string AppVersion,
    string CoreVersion,
    string MsixVersion);

/// <summary>
/// Structured FFI error details inside <see cref="BridgeErrorEnvelopeDto"/>.
/// </summary>
public sealed record BridgeErrorDto(
    string Kind,
    string? L10nKey,
    string? Cause,
    string Message);

/// <summary>
/// Error envelope returned by <c>totaldrop_windows_ffi.dll</c> on validation
/// failure or internal panic containment.
/// </summary>
public sealed record BridgeErrorEnvelopeDto(
    bool? Ok,
    BridgeErrorDto? Error);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::l10n::WindowsUiBundle</c>.
/// </summary>
public sealed record BridgeUiBundleDto(
    string LanguageTag,
    string RegionTag,
    string FlowDirection,
    bool HasDraftTranslations,
    string ExplorerSendWith,
    string AppTagline,
    string SendTitle,
    string SendAddFiles,
    string SendDropHere,
    string SendDropHint,
    string SendStrongCode,
    string SendStrongCodeHint,
    string SendCreateCode,
    string SendYourCode,
    string SendCopy,
    string SendShare,
    string ReceiveTitle,
    string ReceiveCodeLabel,
    string ReceiveCodeHint,
    string ReceivePaste,
    string ReceiveConnect,
    string ReceiveAccept,
    string ReceiveDecline,
    string VerificationTitle,
    string VerificationHint,
    string SettingsTitle,
    string Cancel,
    string KeepAwakeReason,
    string VersionLabel);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::uri::ValidatedCode</c>.
/// </summary>
public sealed record ValidatedCodeDto(
    uint Nameplate,
    byte WordCount,
    string DisplayEnglish,
    string Canonical,
    string LtrIsolated,
    string ProtocolUri,
    string WebUri);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::l10n::RegionalPercent</c> (#483).
/// </summary>
public sealed record RegionalPercentDto(
    byte Whole,
    string Formatted);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::activation::ActivationEnvelope</c>.
/// </summary>
public sealed record ActivationEnvelopeDto(
    uint Version,
    uint? InitiatorPid,
    ActivationPayloadDto Payload);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::activation::ActivationPayload</c>.
/// </summary>
public sealed record ActivationPayloadDto(
    string Kind,
    string[]? Paths,
    ValidatedCodeDto? Code,
    string? Text,
    string? Screen);

/// <summary>
/// Source-generated <see cref="LibraryImportAttribute"/> C ABI boundary into
/// <c>totaldrop_windows_ffi.dll</c> and Win32 power-management APIs.
/// All cryptography, protocol framing, URI validation, and regional formatting
/// run in Rust; C# only drives WinUI 3 controls (ADR 0016).
/// </summary>
public static partial class NativeBridge
{
    private const string BridgeDll = "totaldrop_windows_ffi";

    [Flags]
    public enum ExecutionState : uint
    {
        SystemRequired = 0x0000_0001,
        Continuous = 0x8000_0000,
    }

    /// <summary>
    /// Prevents Windows from entering sleep while an active transfer is running
    /// (ADR 0016, #340), releasing the request immediately when finished.
    /// </summary>
    [LibraryImport("kernel32.dll", SetLastError = false)]
    public static partial ExecutionState SetThreadExecutionState(ExecutionState esFlags);

    /// <summary>
    /// Retrieves the Windows Terminal Services session ID of the current process
    /// to scope <c>\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.&lt;SessionId&gt;</c>.
    /// </summary>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    /// <summary>
    /// Returns app, core, and MSIX version metadata as JSON.
    /// </summary>
    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_version_json")]
    public static partial nint GetVersionJson();

    /// <summary>
    /// Validates a <c>totaldrop://r/…</c> or <c>https://totaldrop.app/r#…</c>
    /// activation URI via <c>totaldrop_proto::TransferCode::from_link</c>.
    /// </summary>
    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_validate_uri_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ValidateUriJson(string rawUri);

    /// <summary>
    /// Validates interactive Receive-box code input via
    /// <c>totaldrop_proto::TransferCode::parse</c>.
    /// </summary>
    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_validate_input_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ValidateUserInputJson(string rawInput);

    /// <summary>
    /// Formats floor-rounded regional transfer progress (#483) in Rust.
    /// </summary>
    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_format_percent_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint FormatRegionalPercentJson(ulong doneBytes, ulong totalBytes, string regionTag);

    /// <summary>
    /// Resolves the 35-language UI bundle for the user's preferred Windows
    /// display languages and regional format.
    /// </summary>
    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_ui_bundle_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ResolveUiBundleJson(string commaSeparatedBcp47Tags, string regionTag, string appVersion);

    /// <summary>
    /// Frees a UTF-8 buffer allocated by <c>totaldrop_windows_ffi.dll</c>.
    /// </summary>
    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_string_free")]
    public static partial void FreeBridgeString(nint ptr);

    private static string? TakeJsonString(nint ptr)
    {
        if (ptr == 0)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            FreeBridgeString(ptr);
        }
    }

    private static bool TryExtractError(string json, out BridgeErrorDto? error)
    {
        try
        {
            BridgeErrorEnvelopeDto? envelope = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.BridgeErrorEnvelopeDto);
            if (envelope is { Ok: false, Error: not null })
            {
                error = envelope.Error;
                return true;
            }
        }
        catch (JsonException)
        {
            // Fall through so the caller returns a non-throwing failure.
        }

        error = null;
        return false;
    }

    /// <summary>
    /// Reads and validates version metadata from <c>totaldrop_windows_ffi.dll</c>.
    /// </summary>
    public static VersionInfoDto? TryGetVersionInfo()
    {
        string? json = TakeJsonString(GetVersionJson());
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return null;
        }

        try
        {
            VersionInfoDto? info = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.VersionInfoDto);
            return info is { AppVersion.Length: > 0, CoreVersion.Length: > 0, MsixVersion.Length: > 0 }
                ? info
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Validates a protocol or web activation URI, explicitly separating
    /// structured Rust error envelopes from valid <see cref="ValidatedCodeDto"/> payloads.
    /// </summary>
    public static bool TryValidateUri(
        string rawUri,
        out ValidatedCodeDto? code,
        out BridgeErrorDto? error)
    {
        code = null;
        error = null;

        if (rawUri is not null && rawUri.Contains('\0'))
        {
            error = new BridgeErrorDto(
                Kind: "invalid_activation_link",
                L10nKey: "errorInvalidCode",
                Cause: null,
                Message: "input is not a valid TotalDrop activation link or transfer code");
            return false;
        }

        string? json = TakeJsonString(ValidateUriJson(rawUri!));
        if (string.IsNullOrEmpty(json))
        {
            return false;
        }

        if (TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            ValidatedCodeDto? validated = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.ValidatedCodeDto);
            if (validated is { Nameplate: > 0, DisplayEnglish.Length: > 0, Canonical.Length: > 0 })
            {
                code = validated;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// Validates interactive Receive-box code input, explicitly rejecting
    /// structured Rust error envelopes.
    /// </summary>
    public static bool TryValidateUserInput(
        string rawInput,
        out ValidatedCodeDto? code,
        out BridgeErrorDto? error)
    {
        code = null;
        error = null;

        if (rawInput is not null && rawInput.Contains('\0'))
        {
            error = new BridgeErrorDto(
                Kind: "invalid_activation_link",
                L10nKey: "receiveCodeInvalid",
                Cause: null,
                Message: "input is not a valid TotalDrop activation link or transfer code");
            return false;
        }

        string? json = TakeJsonString(ValidateUserInputJson(rawInput!));
        if (string.IsNullOrEmpty(json))
        {
            return false;
        }

        if (TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            ValidatedCodeDto? validated = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.ValidatedCodeDto);
            if (validated is { Nameplate: > 0, DisplayEnglish.Length: > 0, Canonical.Length: > 0 })
            {
                code = validated;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// Resolves the localized 35-language UI bundle, rejecting error envelopes.
    /// </summary>
    public static BridgeUiBundleDto? TryResolveUiBundle(
        string commaSeparatedBcp47Tags,
        string regionTag,
        string appVersion)
    {
        string? json = TakeJsonString(ResolveUiBundleJson(commaSeparatedBcp47Tags, regionTag, appVersion));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return null;
        }

        try
        {
            BridgeUiBundleDto? bundle = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.BridgeUiBundleDto);
            return bundle is { LanguageTag.Length: > 0, SendTitle.Length: > 0, ReceiveTitle.Length: > 0 }
                ? bundle
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Formats floor-rounded regional progress percentage (#483), rejecting error envelopes.
    /// </summary>
    public static RegionalPercentDto? TryFormatRegionalPercent(
        ulong doneBytes,
        ulong totalBytes,
        string regionTag)
    {
        string? json = TakeJsonString(FormatRegionalPercentJson(doneBytes, totalBytes, regionTag));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return null;
        }

        try
        {
            RegionalPercentDto? percent = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.RegionalPercentDto);
            return percent is { Formatted.Length: > 0 } ? percent : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Pure-managed fallback helper mirroring <c>whole_percent</c> (#483) when
    /// running design-time XAML previews without the native bridge loaded:
    /// always floors <c>done * 100 / total</c> so 100% never appears early.
    /// </summary>
    public static int ComputeWholePercentFloor(ulong done, ulong total)
    {
        if (total == 0)
        {
            return 0;
        }

        if (done >= total)
        {
            return 100;
        }

        ulong pct = (ulong)(((UInt128)done * 100) / total);
        return (int)Math.Min(pct, 99UL);
    }
}
