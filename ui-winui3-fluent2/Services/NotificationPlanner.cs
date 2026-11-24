// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Globalization;
using System.Security;
using System.Text;
using TotalDrop.WinUI.Interop;

namespace TotalDrop.WinUI.Services;

/// <summary>
/// Direction of a TotalDrop transfer session.
/// </summary>
public enum TransferRole
{
    Send,
    Receive,
}

/// <summary>
/// Canonical 10-stage transfer lifecycle matching Linux <c>stage.rs</c> (#340):
/// 6 awake stages (<see cref="Preparing"/>, <see cref="Waiting"/>,
/// <see cref="Connected"/>, <see cref="Transferring"/>, <see cref="Connecting"/>,
/// <see cref="Offer"/>) and 4 sleep-allowed stages (<see cref="Idle"/>,
/// <see cref="Done"/>, <see cref="Failed"/>, <see cref="Declined"/>).
/// </summary>
public enum TransferLifecycleStage
{
    Idle,
    Preparing,
    Waiting,
    Connected,
    Transferring,
    Connecting,
    Offer,
    Done,
    Failed,
    Declined,
}

/// <summary>
/// Localization and Rust sanitization surface required by
/// <see cref="NotificationPlanner"/> without coupling to WinUI 3 XAML types.
/// </summary>
public interface INotificationLocalizer
{
    string SendDone { get; }

    string SendTextDone { get; }

    string ReceiveOffer { get; }

    string ReceiveOfferText { get; }

    string ReceiveDone { get; }

    string ReceiveTextDone { get; }

    string ReceiveDeclined { get; }

    string ReceiveTextDeclined { get; }

    string ErrorTextDamaged { get; }

    string ErrorOther { get; }

    string FormatMessage(string key, params MessageArg[] args);

    string FormatBytes(ulong bytes);

    string SanitizeFilename(string rawFilename);
}

/// <summary>
/// Notification event descriptor structurally incapable of carrying raw sent or
/// received plain-text content or raw <c>technical_english</c> diagnostics
/// (Feature #19 privacy invariant, Linux <c>Main.qml:202-222</c> parity).
/// </summary>
public sealed record NotificationEventInput(
    TransferRole Role,
    TransferLifecycleStage Stage,
    bool WindowActive,
    bool IsText = false,
    ulong FilesOk = 0,
    ulong FilesFailed = 0,
    ulong OfferFiles = 0,
    ulong ByteCount = 0,
    string? FormattedBytes = null,
    string? SavedToFolder = null,
    string? ErrorL10nKey = null,
    string? LocalizedErrorSummary = null);

/// <summary>
/// Planned background Windows App Notification ready for WinAppSDK 1.8
/// <c>AppNotificationManager.Default.Show</c>.
/// </summary>
public sealed record PlannedToastNotification(
    string Title,
    string Body,
    string XmlPayload);

/// <summary>
/// Pure <c>net10.0</c> background Toast planner matching Linux
/// <c>Main.qml:202-222</c> parity: zero foreground toasts, zero progress spam,
/// zero plain-text body or <c>technical_english</c> leakage, Rust Bidi
/// sanitization, and strict XML escaping of <c>&amp;</c>, <c>&lt;</c>,
/// <c>&gt;</c>, <c>&quot;</c>, and <c>&apos;</c>.
/// </summary>
public static class NotificationPlanner
{
    private const string AppTitle = "TotalDrop";

    public static PlannedToastNotification? TryPlan(
        NotificationEventInput input,
        INotificationLocalizer localizer)
    {
        // Rule 1: Never show a toast when the single window is already active.
        if (input.WindowActive)
        {
            return null;
        }

        // Rule 2: Zero progress / transient state spam.
        if (input.Stage is TransferLifecycleStage.Idle
            or TransferLifecycleStage.Preparing
            or TransferLifecycleStage.Waiting
            or TransferLifecycleStage.Connected
            or TransferLifecycleStage.Transferring
            or TransferLifecycleStage.Connecting)
        {
            return null;
        }

        string title;
        string body;

        switch (input.Stage)
        {
            case TransferLifecycleStage.Offer:
                if (input.Role != TransferRole.Receive)
                {
                    return null;
                }

                if (input.IsText)
                {
                    title = NonEmptyOr(localizer.ReceiveOfferText, AppTitle);
                    body = ResolveSize(input, localizer);
                }
                else
                {
                    title = NonEmptyOr(localizer.ReceiveOffer, AppTitle);
                    body = localizer.FormatMessage(
                        "receiveOfferSummary",
                        MessageArg.FromCount("files", input.OfferFiles),
                        MessageArg.FromText("size", ResolveSize(input, localizer)));
                }

                break;

            case TransferLifecycleStage.Done:
                if (input.IsText && input.Role == TransferRole.Send && input.FilesFailed > 0)
                {
                    // Exact Linux Main.qml:206 parity: text verification failure on send.
                    title = AppTitle;
                    body = NonEmptyOr(localizer.ErrorTextDamaged, localizer.ErrorOther);
                }
                else if (input.IsText && input.Role == TransferRole.Send)
                {
                    title = NonEmptyOr(localizer.SendDone, AppTitle);
                    body = NonEmptyOr(localizer.SendTextDone, localizer.SendDone);
                }
                else if (input.IsText && input.Role == TransferRole.Receive)
                {
                    title = NonEmptyOr(localizer.ReceiveTextDone, AppTitle);
                    body = ResolveSize(input, localizer);
                }
                else if (!input.IsText && input.Role == TransferRole.Send)
                {
                    title = NonEmptyOr(localizer.SendDone, AppTitle);
                    body = localizer.FormatMessage(
                        "sendDoneBody",
                        MessageArg.FromCount("count", Math.Max(1UL, input.FilesOk)));
                }
                else
                {
                    title = NonEmptyOr(localizer.ReceiveDone, AppTitle);
                    string sanitizedFolder = localizer.SanitizeFilename(input.SavedToFolder ?? string.Empty);
                    body = localizer.FormatMessage(
                        "receiveSaveTo",
                        MessageArg.FromText("folder", sanitizedFolder));
                }

                break;

            case TransferLifecycleStage.Declined:
                title = AppTitle;
                body = ResolveDeclinedBody(input, localizer);
                break;

            case TransferLifecycleStage.Failed:
                title = AppTitle;
                body = ResolveFailureBody(input, localizer);
                break;

            default:
                return null;
        }

        string fallbackError = NonEmptyOr(localizer.ErrorOther, AppTitle);
        string safeTitle = NonEmptyOr(title, AppTitle);
        string safeBody = NonEmptyOr(body, fallbackError);
        string xml = BuildToastXml(safeTitle, safeBody);
        return new PlannedToastNotification(safeTitle, safeBody, xml);
    }

    public static string BuildToastXml(string title, string body)
    {
        string cleanTitle = NonEmptyOr(title, AppTitle);
        string cleanBody = NonEmptyOr(body, AppTitle);
        string escapedTitle = SecurityElement.Escape(cleanTitle) ?? AppTitle;
        string escapedBody = SecurityElement.Escape(cleanBody) ?? AppTitle;
        return $"<toast launch=\"activate\"><visual><binding template=\"ToastGeneric\"><text>{escapedTitle}</text><text>{escapedBody}</text></binding></visual></toast>";
    }

    private static string ResolveSize(NotificationEventInput input, INotificationLocalizer localizer)
    {
        string cleanedInput = StripIllegalXmlControlChars(input.FormattedBytes, stripBidiIsolates: true);
        if (!string.IsNullOrWhiteSpace(cleanedInput))
        {
            return cleanedInput;
        }

        string formatted = StripIllegalXmlControlChars(localizer.FormatBytes(input.ByteCount));
        return string.IsNullOrWhiteSpace(formatted) ? $"{input.ByteCount} B" : formatted;
    }

    private static string ResolveFailureBody(NotificationEventInput input, INotificationLocalizer localizer)
    {
        if (!string.IsNullOrWhiteSpace(input.ErrorL10nKey))
        {
            string rawFormatted = string.Equals(input.ErrorL10nKey, "sendTextTooLong", StringComparison.Ordinal)
                ? localizer.FormatMessage(
                    "sendTextTooLong",
                    MessageArg.FromText("size", localizer.FormatBytes(NativeBridge.MaxTextBytes)))
                : localizer.FormatMessage(input.ErrorL10nKey);
            string keyFormatted = StripIllegalXmlControlChars(rawFormatted);
            if (!string.IsNullOrWhiteSpace(keyFormatted) && !ContainsUnexpandedPlaceholder(keyFormatted))
            {
                return keyFormatted;
            }
        }

        string summary = StripIllegalXmlControlChars(input.LocalizedErrorSummary, stripBidiIsolates: true);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            return summary;
        }

        return localizer.ErrorOther;
    }

    private static string ResolveDeclinedBody(NotificationEventInput input, INotificationLocalizer localizer)
    {
        if (!string.IsNullOrWhiteSpace(input.ErrorL10nKey))
        {
            string keyFormatted = StripIllegalXmlControlChars(localizer.FormatMessage(input.ErrorL10nKey));
            if (!string.IsNullOrWhiteSpace(keyFormatted) && !ContainsUnexpandedPlaceholder(keyFormatted))
            {
                return keyFormatted;
            }
        }

        string summary = StripIllegalXmlControlChars(input.LocalizedErrorSummary, stripBidiIsolates: true);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            return summary;
        }

        if (input.Role == TransferRole.Send)
        {
            string declined = StripIllegalXmlControlChars(localizer.FormatMessage("errorDeclined"));
            return string.IsNullOrWhiteSpace(declined) ? localizer.ErrorOther : declined;
        }

        return input.IsText ? localizer.ReceiveTextDeclined : localizer.ReceiveDeclined;
    }

    private static bool ContainsUnexpandedPlaceholder(string text)
    {
        int i = 0;
        while (i < text.Length)
        {
            int open = text.IndexOf('{', i);
            if (open < 0)
            {
                return false;
            }

            int close = text.IndexOf('}', open + 1);
            if (close < 0)
            {
                return false;
            }

            if (close > open + 1)
            {
                bool allIdent = true;
                for (int k = open + 1; k < close; k++)
                {
                    char ch = text[k];
                    if (ch is not ((>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_'))
                    {
                        allIdent = false;
                        break;
                    }
                }

                if (allIdent)
                {
                    return true;
                }
            }

            i = open + 1;
        }

        return false;
    }

    private static string NonEmptyOr(string? primary, string fallback)
    {
        string cleaned = StripIllegalXmlControlChars(primary);
        return string.IsNullOrWhiteSpace(cleaned) ? fallback : cleaned;
    }

    private static bool IsDisallowedToastScalar(int cp, bool stripBidiIsolates)
    {
        if (cp is '\t' or '\n' or '\r' or 0x200C or 0x200D)
        {
            return false;
        }

        if (!stripBidiIsolates && cp is 0x2068 or 0x2069)
        {
            // Preserve legitimate Rust FSI/PDI bidi isolates emitted by totaldrop-l10n.
            return false;
        }

        if ((cp >= 0xFDD0 && cp <= 0xFDEF)
            || (cp & 0xFFFE) == 0xFFFE
            || (cp >= 0xE0000 && cp <= 0xE007F))
        {
            return true;
        }

        UnicodeCategory cat = Rune.GetUnicodeCategory(new Rune(cp));
        return cat is UnicodeCategory.Control
            or UnicodeCategory.Format
            or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator;
    }

    private static string StripIllegalXmlControlChars(string? raw, bool stripBidiIsolates = false)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        StringBuilder? sb = null;
        for (int i = 0; i < raw.Length; i++)
        {
            char c = raw[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < raw.Length && char.IsLowSurrogate(raw[i + 1]))
                {
                    char low = raw[i + 1];
                    int cp = char.ConvertToUtf32(c, low);
                    if (IsDisallowedToastScalar(cp, stripBidiIsolates))
                    {
                        sb ??= new StringBuilder(raw.Length).Append(raw, 0, i);
                    }
                    else if (sb is not null)
                    {
                        sb.Append(c);
                        sb.Append(low);
                    }

                    i++;
                    continue;
                }

                // Drop lone/unpaired high surrogate (illegal in XML 1.0).
                sb ??= new StringBuilder(raw.Length).Append(raw, 0, i);
                continue;
            }

            bool illegal = char.IsLowSurrogate(c) || IsDisallowedToastScalar(c, stripBidiIsolates);
            if (illegal)
            {
                sb ??= new StringBuilder(raw.Length).Append(raw, 0, i);
            }
            else if (sb is not null)
            {
                sb.Append(c);
            }
        }

        return sb is null ? raw : sb.ToString();
    }
}
