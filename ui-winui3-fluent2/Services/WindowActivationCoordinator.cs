// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Globalization;
using System.Text;

namespace TotalDrop.WinUI.Services;

/// <summary>
/// Classified command-line activation intent matching Rust
/// <c>totaldrop_windows_bridge::activation::parse_launch_args</c>.
/// </summary>
public enum LaunchActionKind
{
    None,
    ForegroundOnly,
    ProtocolUri,
    ExplorerSend,
    OpenScreen,
}

/// <summary>
/// Parsed command-line activation action produced by
/// <see cref="WindowActivationCoordinator.ClassifyLaunchArguments"/>.
/// </summary>
public sealed record LaunchAction(
    LaunchActionKind Kind,
    string? Target = null,
    IReadOnlyList<string>? Paths = null);

/// <summary>
/// Pure <c>net10.0</c> single-window activation coordinator shared between
/// <c>MainWindow</c> and headless xUnit tests (zero WinAppSDK dependencies).
///
/// Enforces two invariants:
/// 1. Incoming activations arriving after a transfer reached a terminal card
///    (<see cref="TransferLifecycleStage.Done"/>,
///    <see cref="TransferLifecycleStage.Declined"/>, or
///    <see cref="TransferLifecycleStage.Failed"/>) reset the target screen back
///    to <see cref="TransferLifecycleStage.Idle"/> first (preserving visible
///    in-memory received text notes).
/// 2. Launch arguments stop scanning switches at <c>--</c> and recognize
///    <c>totaldrop:</c>, <c>https://</c>, and <c>http://</c> links case-insensitively
///    even when wrapped in invisible Unicode format characters, matching Rust
///    <c>parse_launch_args</c>.
/// </summary>
public static class WindowActivationCoordinator
{
    /// <summary>
    /// Returns <see langword="true"/> when <c>SendViewModel</c> must reset from a
    /// terminal stage back to <see cref="TransferLifecycleStage.Idle"/> before
    /// applying an incoming file or text activation.
    /// </summary>
    public static bool TryPlanSendResetForIncomingActivation(
        TransferLifecycleStage currentStage,
        out bool clearSelection)
    {
        switch (currentStage)
        {
            case TransferLifecycleStage.Done:
                clearSelection = true;
                return true;

            case TransferLifecycleStage.Failed:
                clearSelection = false;
                return true;

            default:
                clearSelection = false;
                return false;
        }
    }

    /// <summary>
    /// Returns <see langword="true"/> when <c>ReceiveViewModel</c> must reset from
    /// a terminal stage back to <see cref="TransferLifecycleStage.Idle"/> before
    /// applying an incoming protocol URI activation. Never resets while a
    /// verified in-memory received text note is displayed.
    /// </summary>
    public static bool ShouldResetReceiveForIncomingActivation(
        TransferLifecycleStage currentStage,
        bool isReceivedTextVisible)
    {
        if (isReceivedTextVisible)
        {
            return false;
        }

        return currentStage is TransferLifecycleStage.Done
            or TransferLifecycleStage.Declined
            or TransferLifecycleStage.Failed;
    }

    /// <summary>
    /// Applies the terminal-phase reset policy before invoking the incoming Send
    /// activation action, returning whether a reset occurred.
    /// </summary>
    public static bool PrepareSendForIncomingActivation(
        TransferLifecycleStage currentStage,
        Action<bool> resetSendToIdle)
    {
        if (TryPlanSendResetForIncomingActivation(currentStage, out bool clearSelection))
        {
            resetSendToIdle(clearSelection);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Applies the terminal-phase reset policy before invoking an incoming
    /// Receive code activation, returning whether a reset occurred.
    /// </summary>
    public static bool PrepareReceiveForIncomingActivation(
        TransferLifecycleStage currentStage,
        bool isReceivedTextVisible,
        Action resetReceiveToIdle)
    {
        if (ShouldResetReceiveForIncomingActivation(currentStage, isReceivedTextVisible))
        {
            resetReceiveToIdle();
            return true;
        }

        return false;
    }

    /// <summary>
    /// Classifies command-line launch arguments (excluding <c>argv[0]</c>) in
    /// parity with Rust <c>parse_launch_args</c>: stops option scanning at
    /// <c>--</c>, handles <c>----AppNotificationActivated:</c> and
    /// <c>--ipc-await</c>, and accepts <c>totaldrop:</c>,
    /// <c>https://</c>, and <c>http://</c> activation URIs case-insensitively.
    /// </summary>
    public static LaunchAction ClassifyLaunchArguments(string[] args)
    {
        if (args.Length == 0)
        {
            return new LaunchAction(LaunchActionKind.None);
        }

        foreach (string arg in args)
        {
            if (arg.StartsWith("----AppNotificationActivated:", StringComparison.OrdinalIgnoreCase))
            {
                return new LaunchAction(LaunchActionKind.ForegroundOnly);
            }
        }

        if (args.Length == 1 && string.Equals(args[0], "--ipc-await", StringComparison.Ordinal))
        {
            return new LaunchAction(LaunchActionKind.None);
        }

        bool explorerMode = false;
        bool optionsActive = true;
        string? screen = null;
        List<string> rawItems = [];

        foreach (string arg in args)
        {
            if (optionsActive)
            {
                if (string.Equals(arg, "--", StringComparison.Ordinal))
                {
                    optionsActive = false;
                    continue;
                }

                if (string.Equals(arg, "--explorer-send", StringComparison.Ordinal))
                {
                    explorerMode = true;
                    continue;
                }

                if (arg.StartsWith("--screen=", StringComparison.Ordinal))
                {
                    string target = arg["--screen=".Length..];
                    if (target is "send" or "clipboard" or "receive" or "settings")
                    {
                        screen = target;
                    }

                    continue;
                }

                if (arg.StartsWith('-') && arg.Length > 1)
                {
                    // Ignore Windows App SDK / system switches prior to `--`.
                    continue;
                }
            }

            rawItems.Add(arg);
        }

        if (explorerMode)
        {
            return rawItems.Count > 0
                ? new LaunchAction(LaunchActionKind.ExplorerSend, Paths: rawItems)
                : new LaunchAction(LaunchActionKind.None);
        }

        if (rawItems.Count == 1 && LooksLikeActivationUri(rawItems[0]))
        {
            return new LaunchAction(LaunchActionKind.ProtocolUri, Target: rawItems[0]);
        }

        if (rawItems.Count > 0)
        {
            return new LaunchAction(LaunchActionKind.ExplorerSend, Paths: rawItems);
        }

        if (screen is not null)
        {
            return new LaunchAction(LaunchActionKind.OpenScreen, Target: screen);
        }

        return new LaunchAction(LaunchActionKind.None);
    }

    internal static bool LooksLikeActivationUri(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }

        string cleaned = StripInvisibleFormatAndTrim(raw);
        return cleaned.StartsWith("totaldrop:", StringComparison.OrdinalIgnoreCase)
            || cleaned.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || cleaned.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
    }

    private static string StripInvisibleFormatAndTrim(string raw)
    {
        StringBuilder? sb = null;
        int index = 0;
        foreach (Rune rune in raw.EnumerateRunes())
        {
            UnicodeCategory category = Rune.GetUnicodeCategory(rune);
            if (category == UnicodeCategory.Format)
            {
                sb ??= new StringBuilder(raw.Length).Append(raw, 0, index);
            }
            else if (sb is not null)
            {
                sb.Append(rune.ToString());
            }

            index += rune.Utf16SequenceLength;
        }

        string stripped = sb is null ? raw : sb.ToString();
        return stripped.Trim();
    }
}
