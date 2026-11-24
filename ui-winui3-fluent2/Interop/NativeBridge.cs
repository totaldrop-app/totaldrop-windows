// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
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
[JsonSerializable(typeof(StatusOkDto))]
[JsonSerializable(typeof(BridgeErrorEnvelopeDto))]
[JsonSerializable(typeof(BridgeUiBundleDto))]
[JsonSerializable(typeof(ValidatedCodeDto))]
[JsonSerializable(typeof(RegionalPercentDto))]
[JsonSerializable(typeof(FormattedBytesDto))]
[JsonSerializable(typeof(FormattedMessageDto))]
[JsonSerializable(typeof(SanitizedFilenameDto))]
[JsonSerializable(typeof(SanitizedPeerTextDto))]
[JsonSerializable(typeof(ValidatedPathDto))]
[JsonSerializable(typeof(ValidatedPathDto[]))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(BridgeNetworkConfigDto))]
[JsonSerializable(typeof(AppSettingsFileDto))]
[JsonSerializable(typeof(SessionEventDto))]
[JsonSerializable(typeof(RouterDecisionDto))]
[JsonSerializable(typeof(RouterDecisionDto[]))]
[JsonSerializable(typeof(MarkAnimationStateDto))]
[JsonSerializable(typeof(UiBundleReadyMessageDto))]
[JsonSerializable(typeof(MarkAnimationMessageDto))]
[JsonSerializable(typeof(WindowsActivityStateDto))]
public sealed partial class TotalDropJsonContext : JsonSerializerContext;

/// <summary>
/// Version metadata returned by <c>totaldrop_win_version_json</c>.
/// </summary>
public sealed record VersionInfoDto(
    string AppVersion,
    string CoreVersion,
    string MsixVersion);

/// <summary>
/// Pure boolean status returned by <c>totaldrop_win_validate_server_url_json</c>.
/// </summary>
public sealed record StatusOkDto(bool Ok);

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
/// DTO mirror of <c>totaldrop_windows_bridge::l10n::WindowsUiBundle</c>
/// (29 Phase 1 fields preserved verbatim + 80 Phase 2 fields = 109 total).
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
    string VersionLabel,
    string DesktopGenericName,
    string HomeSendTitle,
    string HomeSendBody,
    string HomeReceiveTitle,
    string HomeReceiveBody,
    string HomeFooter,
    string SameNetworkNote,
    string Done,
    string TryAgain,
    string Back,
    string Stop,
    string KeepGoing,
    string MoreInfo,
    string OpenFolder,
    string CancelTransferTitle,
    string CancelTransferBody,
    string TechnicalDetail,
    string SendEmpty,
    string SendEmptyHint,
    string SendCounting,
    string SendRemove,
    string SendPreparing,
    string SendAddFailed,
    string SendCodeHint,
    string SendWaiting,
    string SendWaitingAccept,
    string SendCopied,
    string SendSending,
    string SendDone,
    string PickTitle,
    string SendText,
    string SendTextHint,
    string SendTextDone,
    string SendTextShortened,
    string SendTextHidden,
    string SendClipboard,
    string SendClipboardEmpty,
    string SendClipboardKept,
    string ReceiveCodeHelp,
    string ReceiveCodeInvalid,
    string ReceiveConnecting,
    string ReceiveOffer,
    string ReceiveOfferText,
    string ReceiveOfferTextNote,
    string ReceiveDeclined,
    string ReceiveTextDeclined,
    string ReceiveReceiving,
    string ReceiveDone,
    string ReceiveTextDone,
    string ReceiveTextShortened,
    string ReceiveTextHidden,
    string CopyText,
    string TextCopied,
    string CodeSuggestions,
    string SettingsServer,
    string SettingsServerHelp,
    string SettingsServerReset,
    string SettingsServerInvalid,
    string SettingsSave,
    string SettingsAbout,
    string SettingsAboutBody,
    string SettingsPrivacy,
    string SettingsPrivacyBody,
    string PrivacyMode,
    string PrivacyModeHint,
    string PrivacyModeConfirmTitle,
    string PrivacyModeConfirmBody,
    string PrivacyModeTurnOn,
    string DraftTranslation,
    string SettingsWordsEnglish,
    string ErrorInvalidCode,
    string ErrorWrongCode,
    string ErrorInvalidOffer,
    string ErrorTextDamaged,
    string ErrorBadServer,
    string ErrorCodeExpired,
    string ErrorCodeNotInUse,
    string ErrorOther,
    string ShareBusy,
    string LinkBusy);

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
/// DTO returned by <c>totaldrop_win_format_bytes_json</c>.
/// </summary>
public sealed record FormattedBytesDto(
    ulong Bytes,
    string Formatted);

/// <summary>
/// DTO returned by <c>totaldrop_win_format_message_json</c>.
/// </summary>
public sealed record FormattedMessageDto(
    string Key,
    string LanguageTag,
    string Formatted);

/// <summary>
/// DTO returned by <c>totaldrop_win_sanitize_filename_json</c>.
/// </summary>
public sealed record SanitizedFilenameDto(
    string Sanitized,
    bool HasHiddenControls);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::l10n::SanitizedPeerText</c>.
/// </summary>
public sealed record SanitizedPeerTextDto(
    string DisplayText,
    bool Shortened,
    bool HasHiddenControls);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::activation::NormalizedWindowsPath</c>.
/// </summary>
public sealed record ValidatedPathDto(
    string ExtendedPath,
    string UnprefixedPath,
    string SafeDisplayPath,
    string RootKind,
    ulong Utf16Len,
    bool ExceedsLegacyMaxPath);

/// <summary>
/// DTO mirror of <c>totaldrop_windows_bridge::session::BridgeNetworkConfig</c>.
/// </summary>
public sealed record BridgeNetworkConfigDto(
    string RendezvousServer,
    string RelayServer,
    string StunServer,
    bool PrivacyRelayOnly,
    bool StrongerThreeWordCode);

/// <summary>
/// On-disk local settings file schema distinguishing omitted (<see langword="null"/>)
/// properties from explicit empty strings (<c>""</c>).
/// </summary>
public sealed record AppSettingsFileDto(
    string? RendezvousServer,
    string? RelayServer,
    string? StunServer,
    bool? PrivacyRelayOnly,
    bool? StrongerThreeWordCode);

/// <summary>
/// Flat Native AOT DTO matching every NDJSON line emitted by
/// <c>totaldrop_win_session_poll_events_ndjson</c> (tagged by <c>event</c>).
/// </summary>
public sealed record SessionEventDto(
    string Event,
    ValidatedCodeDto? Code = null,
    string? ShareText = null,
    ulong? Files = null,
    ulong? Dirs = null,
    ulong? TotalBytes = null,
    ulong? DoneBytes = null,
    string? FormattedDone = null,
    string? FormattedTotal = null,
    string? FormattedBytes = null,
    ulong? Skipped = null,
    bool? IsText = null,
    string? Caption = null,
    string[]? VerificationWords = null,
    string? JoinedWordsLtr = null,
    string[]? TopLevel = null,
    string[]? TopLevelSanitized = null,
    ulong? MoreCount = null,
    RegionalPercentDto? Percent = null,
    ulong? FilesOk = null,
    ulong? FilesFailed = null,
    ulong? Bytes = null,
    string? SavedTo = null,
    string[]? Placed = null,
    string? ReceivedText = null,
    SanitizedPeerTextDto? SanitizedText = null,
    string? Summary = null,
    string? Kind = null,
    string? L10nKey = null,
    string? Cause = null,
    string? CauseDetail = null,
    string? TechnicalEnglish = null);

/// <summary>
/// Flat Native AOT DTO for <c>totaldrop_windows_bridge::ipc_router::RouterDecision</c>
/// (<c>#[serde(tag = "decision", rename_all = "snake_case")]</c>).
/// </summary>
public sealed record RouterDecisionDto(
    string Decision,
    string[]? Paths = null,
    string? RawText = null,
    SanitizedPeerTextDto? SanitizedPreview = null,
    ValidatedCodeDto? Code = null,
    string? Screen = null,
    string? LocalizedBanner = null,
    uint? InitiatorPid = null);

/// <summary>
/// DTO for Kose mark animation state emitted by <c>WinUiBridgeMessage::MarkAnimationState</c>.
/// </summary>
public sealed record MarkAnimationStateDto(
    bool Animate,
    string HexLight,
    string HexDark,
    uint CycleMs);

/// <summary>
/// Adjacently-tagged <c>WinUiBridgeMessage::UiBundleReady</c> envelope.
/// </summary>
public sealed record UiBundleReadyMessageDto(
    string Kind,
    BridgeUiBundleDto? Data);

/// <summary>
/// Adjacently-tagged <c>WinUiBridgeMessage::MarkAnimationState</c> envelope.
/// </summary>
public sealed record MarkAnimationMessageDto(
    string Kind,
    MarkAnimationStateDto? Data);

/// <summary>
/// Mirrors <c>totaldrop_windows_bridge::ipc_router::WindowsActivityState</c>
/// (<c>#[serde(tag = "state", rename_all = "snake_case")]</c>).
/// </summary>
public sealed record WindowsActivityStateDto(
    string State,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Code = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ulong? DoneBytes = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ulong? TotalBytes = null)
{
    public static WindowsActivityStateDto Idle { get; } = new("idle");

    public static WindowsActivityStateDto PreparingSend { get; } = new("preparing_send");

    public static WindowsActivityStateDto WaitingForPeer(string code) =>
        new("waiting_for_peer", Code: code ?? string.Empty);

    public static WindowsActivityStateDto ConnectingReceive(string code) =>
        new("connecting_receive", Code: code ?? string.Empty);

    public static WindowsActivityStateDto OfferPromptPending { get; } = new("offer_prompt_pending");

    public static WindowsActivityStateDto Transferring(ulong doneBytes, ulong totalBytes) =>
        new("transferring", DoneBytes: doneBytes, TotalBytes: totalBytes);

    public static WindowsActivityStateDto ShowingTextNote { get; } = new("showing_text_note");
}

/// <summary>
/// Reflection-free placeholder argument for <see cref="NativeBridge.TryFormatMessage"/>.
/// </summary>
public readonly record struct MessageArg
{
    public string Name { get; }
    public bool IsCount { get; }
    public ulong CountValue { get; }
    public string? TextValue { get; }

    private MessageArg(string name, ulong countValue)
    {
        Name = name;
        IsCount = true;
        CountValue = countValue;
        TextValue = null;
    }

    private MessageArg(string name, string textValue)
    {
        Name = name;
        IsCount = false;
        CountValue = 0;
        TextValue = textValue;
    }

    public static MessageArg FromCount(string name, ulong value) => new(name, value);

    public static MessageArg FromText(string name, string value) => new(name, value);
}

/// <summary>
/// Source-generated <see cref="LibraryImportAttribute"/> C ABI boundary into
/// <c>totaldrop_windows_ffi.dll</c> and Win32 power/shell APIs.
/// All cryptography, protocol framing, URI/path/URL validation, and 35-language
/// regional formatting run in Rust; C# only drives WinUI 3 controls (ADR 0016).
/// </summary>
public static partial class NativeBridge
{
    private const string BridgeDll = "totaldrop_windows_ffi";

    public const int FfiOk = 0;
    public const int FfiErrNullPointer = -1;
    public const int FfiErrInvalidUtf8 = -2;
    public const int FfiErrInvalidHandle = -3;
    public const int FfiErrInvalidState = -4;
    public const int FfiErrInvalidArg = -5;
    public const int FfiErrInternal = -99;

    public const ulong MaxTextBytes = 1_048_576;
    public const int MaxShownTextChars = 16_384;

    private static readonly Guid FolderIdDownloads = new("374DE290-123F-4565-9164-39C4925E467B");

    // -----------------------------------------------------------------------
    // Win32 System P/Invokes

    /// <summary>
    /// Retrieves the Windows Terminal Services session ID of the current process
    /// to scope <c>\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.&lt;SessionId&gt;</c>.
    /// </summary>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [LibraryImport("shell32.dll")]
    private static partial int SHGetKnownFolderPath(
        in Guid rfid,
        uint dwFlags,
        nint hToken,
        out nint ppszPath);

    [LibraryImport("ole32.dll")]
    private static partial void CoTaskMemFree(nint pv);

    /// <summary>
    /// Resolves the canonical default receive folder (<c>Downloads\TotalDrop</c>),
    /// using <c>SHGetKnownFolderPath(FOLDERID_Downloads)</c> on Windows and
    /// falling back safely to <c>UserProfile/Downloads/TotalDrop</c>.
    /// </summary>
    public static string ResolveDefaultDownloadsFolder()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                int hr = SHGetKnownFolderPath(in FolderIdDownloads, 0, 0, out nint pathPtr);
                if (hr == 0 && pathPtr != 0)
                {
                    try
                    {
                        string? downloads = Marshal.PtrToStringUni(pathPtr);
                        if (!string.IsNullOrWhiteSpace(downloads))
                        {
                            return Path.Combine(downloads, "TotalDrop");
                        }
                    }
                    finally
                    {
                        CoTaskMemFree(pathPtr);
                    }
                }
            }
            catch (DllNotFoundException)
            {
                // Fall back to UserProfile\Downloads below.
            }
            catch (EntryPointNotFoundException)
            {
                // Fall back to UserProfile\Downloads below.
            }
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads",
            "TotalDrop");
    }

    // -----------------------------------------------------------------------
    // Phase 1 C ABI Exports (6 symbols)

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_string_free")]
    public static partial void FreeBridgeString(nint ptr);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_version_json")]
    public static partial nint GetVersionJson();

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_validate_uri_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ValidateUriJson(string rawUri);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_validate_input_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ValidateUserInputJson(string rawInput);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_format_percent_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint FormatRegionalPercentJson(ulong doneBytes, ulong totalBytes, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_ui_bundle_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ResolveUiBundleJson(string commaSeparatedBcp47Tags, string regionTag, string appVersion);

    // -----------------------------------------------------------------------
    // Phase 2 Group A C ABI Exports (8 symbols)

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_extract_clipboard_code_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ExtractClipboardCodeJson(string rawText);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_code_completions_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint CodeCompletionsJson(string prefix, uint limit);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_format_bytes_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint FormatBytesJson(ulong bytes, string langTags, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_format_message_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint FormatMessageJson(string key, string argsJson, string langTags, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_sanitize_filename_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint SanitizeFilenameJson(string raw);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_sanitize_text_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint SanitizeTextJson(string raw);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_validate_server_url_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ValidateServerUrlJson(string url);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_validate_paths_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ValidatePathsJson(string pathsJson);

    // -----------------------------------------------------------------------
    // Phase 2 Group B C ABI Exports (10 symbols)

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_send_files_start", StringMarshalling = StringMarshalling.Utf8)]
    public static partial ulong SendFilesStart(string cfgJson, string pathsJson, string langTags, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_send_text_start", StringMarshalling = StringMarshalling.Utf8)]
    public static partial ulong SendTextStart(string cfgJson, string text, string langTags, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_receive_connect_start", StringMarshalling = StringMarshalling.Utf8)]
    public static partial ulong ReceiveConnectStart(string cfgJson, string codeOrUri, string langTags, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_receive_accept_files", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int ReceiveAcceptFiles(ulong sessionId, string destDir);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_receive_accept_text")]
    public static partial int ReceiveAcceptText(ulong sessionId);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_receive_decline")]
    public static partial int ReceiveDecline(ulong sessionId);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_session_poll_events_ndjson")]
    public static partial nint SessionPollEventsNdjson(ulong sessionId);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_session_cancel")]
    public static partial int SessionCancel(ulong sessionId);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_session_destroy")]
    public static partial int SessionDestroy(ulong sessionId);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_shutdown")]
    public static partial int Shutdown(uint timeoutMs);

    // -----------------------------------------------------------------------
    // Phase 3 C ABI Exports (7 single-window IPC router symbols -> 31 cumulative)

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_create", StringMarshalling = StringMarshalling.Utf8)]
    public static partial ulong RouterCreate(
        uint sessionId,
        string langTags,
        string regionTag,
        string appVersion,
        [MarshalAs(UnmanagedType.U1)] bool animationsEnabled);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_ingest_ipc_bytes_json")]
    public static unsafe partial nint RouterIngestIpcBytesJson(ulong routerId, byte* ptr, nuint len);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_update_locale_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint RouterUpdateLocaleJson(ulong routerId, string langTags, string regionTag);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_set_animations_json")]
    public static partial nint RouterSetAnimationsJson(
        ulong routerId,
        [MarshalAs(UnmanagedType.U1)] bool enabled);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_set_activity_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint RouterSetActivityJson(ulong routerId, string activityJson);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_drain_ndjson")]
    public static partial nint RouterDrainNdjson(ulong routerId);

    [LibraryImport(BridgeDll, EntryPoint = "totaldrop_win_router_destroy")]
    public static partial int RouterDestroy(ulong routerId);

    // -----------------------------------------------------------------------
    // Managed Wrappers (Zero Reflection, NUL-Guarded)

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

    private static bool ContainsNul(string? value) =>
        value is not null && value.Contains('\0');

    private static string StripNul(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : value.Replace("\0", string.Empty, StringComparison.Ordinal);

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

    private static string SerializeMessageArgs(ReadOnlySpan<MessageArg> args)
    {
        if (args.IsEmpty)
        {
            return "{}";
        }

        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            foreach (MessageArg arg in args)
            {
                if (arg.IsCount)
                {
                    writer.WriteNumber(arg.Name, arg.CountValue);
                }
                else
                {
                    writer.WriteString(arg.Name, arg.TextValue ?? string.Empty);
                }
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

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

    public static bool TryValidateUri(
        string rawUri,
        out ValidatedCodeDto? code,
        out BridgeErrorDto? error)
    {
        code = null;
        error = null;

        if (ContainsNul(rawUri))
        {
            error = new BridgeErrorDto(
                Kind: "invalid_activation_link",
                L10nKey: "errorInvalidCode",
                Cause: null,
                Message: "input is not a valid TotalDrop activation link or transfer code");
            return false;
        }

        string? json = TakeJsonString(ValidateUriJson(rawUri ?? string.Empty));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
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

    public static bool TryValidateUserInput(
        string rawInput,
        out ValidatedCodeDto? code,
        out BridgeErrorDto? error)
    {
        code = null;
        error = null;

        if (ContainsNul(rawInput))
        {
            error = new BridgeErrorDto(
                Kind: "invalid_activation_link",
                L10nKey: "receiveCodeInvalid",
                Cause: null,
                Message: "input is not a valid TotalDrop activation link or transfer code");
            return false;
        }

        string? json = TakeJsonString(ValidateUserInputJson(rawInput ?? string.Empty));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
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

    public static bool TryExtractClipboardCode(
        string rawText,
        out ValidatedCodeDto? code,
        out BridgeErrorDto? error)
    {
        code = null;
        error = null;

        if (ContainsNul(rawText))
        {
            error = new BridgeErrorDto(
                Kind: "no_code_found_in_text",
                L10nKey: "errorInvalidCode",
                Cause: null,
                Message: "no TotalDrop transfer code found in text");
            return false;
        }

        string? json = TakeJsonString(ExtractClipboardCodeJson(rawText ?? string.Empty));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
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

    public static string[] TryGetCodeCompletions(string prefix, uint limit = 4)
    {
        if (string.IsNullOrEmpty(prefix) || limit == 0 || ContainsNul(prefix))
        {
            return [];
        }

        string? json = TakeJsonString(CodeCompletionsJson(prefix, limit));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize(json, TotalDropJsonContext.Default.StringArray) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    public static BridgeUiBundleDto? TryResolveUiBundle(
        string commaSeparatedBcp47Tags,
        string regionTag,
        string appVersion)
    {
        string? json = TakeJsonString(ResolveUiBundleJson(
            StripNul(commaSeparatedBcp47Tags),
            StripNul(regionTag),
            StripNul(appVersion)));
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

    public static RegionalPercentDto? TryFormatRegionalPercent(
        ulong doneBytes,
        ulong totalBytes,
        string regionTag)
    {
        string? json = TakeJsonString(FormatRegionalPercentJson(doneBytes, totalBytes, StripNul(regionTag)));
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

    public static FormattedBytesDto? TryFormatBytes(
        ulong bytes,
        string langTags,
        string regionTag)
    {
        string? json = TakeJsonString(FormatBytesJson(bytes, StripNul(langTags), StripNul(regionTag)));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return null;
        }

        try
        {
            FormattedBytesDto? dto = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.FormattedBytesDto);
            return dto is { Formatted.Length: > 0 } ? dto : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool TryFormatMessage(
        string key,
        ReadOnlySpan<MessageArg> args,
        string langTags,
        string regionTag,
        out string formatted,
        out BridgeErrorDto? error)
    {
        formatted = string.Empty;
        error = null;

        if (string.IsNullOrEmpty(key) || ContainsNul(key))
        {
            error = new BridgeErrorDto("empty_key", "errorOther", null, "localization message key must not be empty");
            return false;
        }

        foreach (MessageArg arg in args)
        {
            if (ContainsNul(arg.Name) || (arg.TextValue is not null && ContainsNul(arg.TextValue)))
            {
                error = new BridgeErrorDto("invalid_arg", "errorOther", null, "message arguments must not contain NUL bytes");
                return false;
            }
        }

        string argsJson = SerializeMessageArgs(args);

        string? json = TakeJsonString(FormatMessageJson(key, argsJson, StripNul(langTags), StripNul(regionTag)));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            FormattedMessageDto? dto = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.FormattedMessageDto);
            if (dto is not null)
            {
                formatted = dto.Formatted;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    public static SanitizedFilenameDto? TrySanitizeFilename(string raw)
    {
        if (ContainsNul(raw))
        {
            return null;
        }

        string? json = TakeJsonString(SanitizeFilenameJson(raw ?? string.Empty));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(json, TotalDropJsonContext.Default.SanitizedFilenameDto);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static SanitizedPeerTextDto? TrySanitizeText(string raw)
    {
        if (ContainsNul(raw))
        {
            return null;
        }

        string? json = TakeJsonString(SanitizeTextJson(raw ?? string.Empty));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out _))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(json, TotalDropJsonContext.Default.SanitizedPeerTextDto);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool TryValidateServerUrl(string url, out BridgeErrorDto? error)
    {
        error = null;
        if (ContainsNul(url))
        {
            error = new BridgeErrorDto("bad_server", "errorBadServer", null, "server URL must not contain NUL");
            return false;
        }

        string? json = TakeJsonString(ValidateServerUrlJson(url ?? string.Empty));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            StatusOkDto? status = JsonSerializer.Deserialize(json, TotalDropJsonContext.Default.StatusOkDto);
            return status is { Ok: true };
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static bool TryValidatePaths(
        IEnumerable<string> rawPaths,
        out ValidatedPathDto[] normalized,
        out BridgeErrorDto? error)
    {
        normalized = [];
        error = null;

        string[] pathArray = rawPaths is string[] arr ? arr : [.. rawPaths];
        foreach (string item in pathArray)
        {
            if (ContainsNul(item))
            {
                error = new BridgeErrorDto(
                    "control_character",
                    "errorStorage",
                    null,
                    "Windows path contains a NUL control character");
                return false;
            }
        }

        string pathsJson = JsonSerializer.Serialize(pathArray, TotalDropJsonContext.Default.StringArray);
        string? json = TakeJsonString(ValidatePathsJson(pathsJson));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            ValidatedPathDto[]? parsed = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.ValidatedPathDtoArray);
            if (parsed is not null)
            {
                normalized = parsed;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    public static ulong StartSendFiles(
        BridgeNetworkConfigDto config,
        string[] paths,
        string langTags,
        string regionTag)
    {
        foreach (string path in paths)
        {
            if (ContainsNul(path))
            {
                return 0;
            }
        }

        string cfgJson = JsonSerializer.Serialize(config, TotalDropJsonContext.Default.BridgeNetworkConfigDto);
        string pathsJson = JsonSerializer.Serialize(paths, TotalDropJsonContext.Default.StringArray);
        if (ContainsNul(cfgJson) || ContainsNul(pathsJson))
        {
            return 0;
        }

        return SendFilesStart(cfgJson, pathsJson, StripNul(langTags), StripNul(regionTag));
    }

    public static ulong StartSendText(
        BridgeNetworkConfigDto config,
        string text,
        string langTags,
        string regionTag)
    {
        if (ContainsNul(text))
        {
            return 0;
        }

        string cfgJson = JsonSerializer.Serialize(config, TotalDropJsonContext.Default.BridgeNetworkConfigDto);
        if (ContainsNul(cfgJson))
        {
            return 0;
        }

        return SendTextStart(cfgJson, text ?? string.Empty, StripNul(langTags), StripNul(regionTag));
    }

    public static ulong StartReceiveConnect(
        BridgeNetworkConfigDto config,
        string codeOrUri,
        string langTags,
        string regionTag)
    {
        if (ContainsNul(codeOrUri))
        {
            return 0;
        }

        string cfgJson = JsonSerializer.Serialize(config, TotalDropJsonContext.Default.BridgeNetworkConfigDto);
        if (ContainsNul(cfgJson))
        {
            return 0;
        }

        return ReceiveConnectStart(cfgJson, codeOrUri ?? string.Empty, StripNul(langTags), StripNul(regionTag));
    }

    public static int TryAcceptReceiveFiles(ulong sessionId, string destDir)
    {
        if (string.IsNullOrWhiteSpace(destDir) || ContainsNul(destDir))
        {
            return FfiErrInvalidArg;
        }

        return ReceiveAcceptFiles(sessionId, destDir);
    }

    public static bool TryPollSessionEvents(
        ulong sessionId,
        out List<SessionEventDto> events,
        out BridgeErrorDto? error)
    {
        events = [];
        error = null;

        string? ndjson = TakeJsonString(SessionPollEventsNdjson(sessionId));
        if (ndjson is null)
        {
            return false;
        }

        if (ndjson.Length == 0)
        {
            return true;
        }

        if (TryExtractError(ndjson, out error))
        {
            return false;
        }

        foreach (ReadOnlySpan<char> rawLine in ndjson.AsSpan().EnumerateLines())
        {
            ReadOnlySpan<char> line = rawLine.Trim();
            if (line.IsEmpty)
            {
                continue;
            }

            try
            {
                SessionEventDto? ev = JsonSerializer.Deserialize(
                    line,
                    TotalDropJsonContext.Default.SessionEventDto);
                if (ev is not null)
                {
                    events.Add(ev);
                }
            }
            catch (JsonException)
            {
                // Skip malformed line defensively without crashing the UI loop.
            }
        }

        return true;
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

    // -----------------------------------------------------------------------
    // Phase 3 Managed Router Wrappers & Reflection-Free Outgoing Frame Builders

    public static ulong TryCreateRouter(
        uint sessionId,
        string langTags,
        string regionTag,
        string appVersion,
        bool animationsEnabled) =>
        RouterCreate(
            sessionId,
            StripNul(langTags),
            StripNul(regionTag),
            StripNul(appVersion),
            animationsEnabled);

    /// <summary>
    /// Feeds raw Named Pipe bytes directly into Rust <c>IpcFrameDecoder</c> and
    /// <c>WinUiWindowRouter</c>. Passing <see cref="ReadOnlySpan{T}.Empty"/>
    /// signals stream EOF / frame-boundary validation (<c>len == 0</c>).
    /// </summary>
    public static unsafe bool TryIngestRouterIpcBytes(
        ulong routerId,
        ReadOnlySpan<byte> chunk,
        out RouterDecisionDto[] decisions,
        out BridgeErrorDto? error)
    {
        decisions = [];
        error = null;

        nint rawPtr;
        fixed (byte* p = chunk)
        {
            rawPtr = RouterIngestIpcBytesJson(routerId, p, (nuint)chunk.Length);
        }

        string? json = TakeJsonString(rawPtr);
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            RouterDecisionDto[]? parsed = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.RouterDecisionDtoArray);
            if (parsed is not null)
            {
                decisions = parsed;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    public static bool TryUpdateRouterLocale(
        ulong routerId,
        string langTags,
        string regionTag,
        out BridgeUiBundleDto? bundle,
        out BridgeErrorDto? error)
    {
        bundle = null;
        error = null;

        string? json = TakeJsonString(RouterUpdateLocaleJson(routerId, StripNul(langTags), StripNul(regionTag)));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        try
        {
            UiBundleReadyMessageDto? msg = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.UiBundleReadyMessageDto);
            if (msg is { Kind: "ui_bundle_ready", Data: not null })
            {
                bundle = msg.Data;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    public static bool TrySetRouterAnimations(
        ulong routerId,
        bool enabled,
        out MarkAnimationStateDto? mark,
        out BridgeErrorDto? error)
    {
        mark = null;
        error = null;

        string? json = TakeJsonString(RouterSetAnimationsJson(routerId, enabled));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        return TryParseMarkAnimationMessage(json, out mark);
    }

    public static bool TrySetRouterActivity(
        ulong routerId,
        WindowsActivityStateDto activity,
        out MarkAnimationStateDto? mark,
        out BridgeErrorDto? error)
    {
        mark = null;
        error = null;

        string activityJson = JsonSerializer.Serialize(
            activity,
            TotalDropJsonContext.Default.WindowsActivityStateDto);
        string? json = TakeJsonString(RouterSetActivityJson(routerId, StripNul(activityJson)));
        if (string.IsNullOrEmpty(json) || TryExtractError(json, out error))
        {
            return false;
        }

        return TryParseMarkAnimationMessage(json, out mark);
    }

    public static bool TryDrainRouterNdjson(
        ulong routerId,
        out string ndjson,
        out BridgeErrorDto? error)
    {
        ndjson = string.Empty;
        error = null;

        string? raw = TakeJsonString(RouterDrainNdjson(routerId));
        if (raw is null)
        {
            return false;
        }

        if (raw.Length == 0)
        {
            return true;
        }

        if (TryExtractError(raw, out error))
        {
            return false;
        }

        ndjson = raw;
        return true;
    }

    public static int TryDestroyRouter(ulong routerId) =>
        routerId == 0 ? FfiErrInvalidHandle : RouterDestroy(routerId);

    /// <summary>
    /// Encodes a schema-v1 <c>explorer_send</c> envelope with 4-byte LE length
    /// prefix using reflection-free <see cref="Utf8JsonWriter"/>.
    /// </summary>
    public static byte[] BuildFramedExplorerSendEnvelope(
        IReadOnlyList<string> rawPaths,
        uint? initiatorPid = null) =>
        EncodeFramedEnvelope(initiatorPid, writer =>
        {
            writer.WriteString("kind", "explorer_send");
            writer.WriteStartArray("paths");
            foreach (string path in rawPaths)
            {
                writer.WriteStringValue(path ?? string.Empty);
            }

            writer.WriteEndArray();
        });

    /// <summary>
    /// Encodes a schema-v1 <c>share_target</c> envelope with 4-byte LE length
    /// prefix using reflection-free <see cref="Utf8JsonWriter"/>.
    /// </summary>
    public static byte[] BuildFramedShareTargetEnvelope(
        IReadOnlyList<string>? rawPaths,
        string? text,
        uint? initiatorPid = null) =>
        EncodeFramedEnvelope(initiatorPid, writer =>
        {
            writer.WriteString("kind", "share_target");
            writer.WriteStartArray("paths");
            if (rawPaths is not null)
            {
                foreach (string path in rawPaths)
                {
                    writer.WriteStringValue(path ?? string.Empty);
                }
            }

            writer.WriteEndArray();
            if (text is null)
            {
                writer.WriteNull("text");
            }
            else
            {
                writer.WriteString("text", text);
            }
        });

    /// <summary>
    /// Encodes a schema-v1 <c>protocol_uri</c> envelope with 4-byte LE length
    /// prefix using reflection-free <see cref="Utf8JsonWriter"/>.
    /// </summary>
    public static byte[] BuildFramedProtocolUriEnvelope(
        ValidatedCodeDto code,
        uint? initiatorPid = null) =>
        EncodeFramedEnvelope(initiatorPid, writer =>
        {
            writer.WriteString("kind", "protocol_uri");
            writer.WriteStartObject("code");
            writer.WriteNumber("nameplate", code.Nameplate);
            writer.WriteNumber("word_count", code.WordCount);
            writer.WriteString("display_english", code.DisplayEnglish);
            writer.WriteString("canonical", code.Canonical);
            writer.WriteString("ltr_isolated", code.LtrIsolated);
            writer.WriteString("protocol_uri", code.ProtocolUri);
            writer.WriteString("web_uri", code.WebUri);
            writer.WriteEndObject();
        });

    /// <summary>
    /// Encodes a schema-v1 <c>open_screen</c> envelope with 4-byte LE length
    /// prefix using reflection-free <see cref="Utf8JsonWriter"/>.
    /// </summary>
    public static byte[] BuildFramedOpenScreenEnvelope(
        string screen,
        uint? initiatorPid = null) =>
        EncodeFramedEnvelope(initiatorPid, writer =>
        {
            writer.WriteString("kind", "open_screen");
            writer.WriteString("screen", screen);
        });

    private static bool TryParseMarkAnimationMessage(string json, out MarkAnimationStateDto? mark)
    {
        mark = null;
        try
        {
            MarkAnimationMessageDto? msg = JsonSerializer.Deserialize(
                json,
                TotalDropJsonContext.Default.MarkAnimationMessageDto);
            if (msg is { Kind: "mark_animation_state", Data: not null })
            {
                mark = msg.Data;
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    private static byte[] EncodeFramedEnvelope(uint? initiatorPid, Action<Utf8JsonWriter> writePayload)
    {
        ArrayBufferWriter<byte> payloadBuffer = new(256);
        using (Utf8JsonWriter writer = new(payloadBuffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", 1);
            if (initiatorPid.HasValue)
            {
                writer.WriteNumber("initiator_pid", initiatorPid.Value);
            }
            else
            {
                writer.WriteNull("initiator_pid");
            }

            writer.WriteStartObject("payload");
            writePayload(writer);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        ReadOnlySpan<byte> payloadSpan = payloadBuffer.WrittenSpan;
        byte[] framed = new byte[4 + payloadSpan.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(framed.AsSpan(0, 4), (uint)payloadSpan.Length);
        payloadSpan.CopyTo(framed.AsSpan(4));
        return framed;
    }
}
