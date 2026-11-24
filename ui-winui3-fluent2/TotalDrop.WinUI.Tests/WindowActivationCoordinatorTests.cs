// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

public sealed class WindowActivationCoordinatorTests
{
    [Fact]
    public void Tier5_SendActivationReset_ResetsTerminalPhasesAndClearsOnlyOnDone()
    {
        // Done -> must reset to Idle and clear already-sent selection so stale files do not merge.
        bool doneClear = false;
        bool doneReset = WindowActivationCoordinator.PrepareSendForIncomingActivation(
            TransferLifecycleStage.Done,
            clear => doneClear = clear);
        Assert.True(doneReset);
        Assert.True(doneClear);

        // Failed -> must reset to Idle while preserving selection (clearSelection: false).
        bool failedClear = true;
        bool failedReset = WindowActivationCoordinator.PrepareSendForIncomingActivation(
            TransferLifecycleStage.Failed,
            clear => failedClear = clear);
        Assert.True(failedReset);
        Assert.False(failedClear);

        // Idle & active transfer stages -> must NOT trigger a terminal reset.
        TransferLifecycleStage[] nonTerminal =
        [
            TransferLifecycleStage.Idle,
            TransferLifecycleStage.Preparing,
            TransferLifecycleStage.Waiting,
            TransferLifecycleStage.Connected,
            TransferLifecycleStage.Transferring,
        ];
        foreach (TransferLifecycleStage stage in nonTerminal)
        {
            bool called = false;
            bool reset = WindowActivationCoordinator.PrepareSendForIncomingActivation(
                stage,
                _ => called = true);
            Assert.False(reset, $"Send stage {stage} must not trigger terminal reset");
            Assert.False(called);
        }
    }

    [Fact]
    public void Tier5_ReceiveActivationReset_ResetsTerminalCardsWhilePreservingReceivedTextNote()
    {
        // Terminal file-receive cards (Done [files], Declined, Failed) -> reset to Idle.
        TransferLifecycleStage[] terminalResettable =
        [
            TransferLifecycleStage.Done,
            TransferLifecycleStage.Declined,
            TransferLifecycleStage.Failed,
        ];
        foreach (TransferLifecycleStage stage in terminalResettable)
        {
            bool called = false;
            bool reset = WindowActivationCoordinator.PrepareReceiveForIncomingActivation(
                stage,
                isReceivedTextVisible: false,
                () => called = true);
            Assert.True(reset, $"Receive stage {stage} without visible text note must reset to Idle");
            Assert.True(called);
        }

        // Verified in-memory received text note MUST NEVER be clobbered.
        bool textNoteResetCalled = false;
        bool textNoteReset = WindowActivationCoordinator.PrepareReceiveForIncomingActivation(
            TransferLifecycleStage.Done,
            isReceivedTextVisible: true,
            () => textNoteResetCalled = true);
        Assert.False(textNoteReset);
        Assert.False(textNoteResetCalled);

        // Idle & active receive stages -> must NOT trigger a terminal reset.
        TransferLifecycleStage[] nonTerminal =
        [
            TransferLifecycleStage.Idle,
            TransferLifecycleStage.Connecting,
            TransferLifecycleStage.Offer,
            TransferLifecycleStage.Transferring,
        ];
        foreach (TransferLifecycleStage stage in nonTerminal)
        {
            bool called = false;
            bool reset = WindowActivationCoordinator.PrepareReceiveForIncomingActivation(
                stage,
                isReceivedTextVisible: false,
                () => called = true);
            Assert.False(reset, $"Receive stage {stage} must not trigger terminal reset");
            Assert.False(called);
        }
    }

    [Fact]
    public void Tier5_ClassifyLaunchArguments_HonorsOptionTerminatorAndHttpUppercaseBidiUris()
    {
        // Option scanning MUST stop at `--` so filenames after `--` are never misparsed as flags/URIs.
        LaunchAction expWithFlagLikeArg = WindowActivationCoordinator.ClassifyLaunchArguments(
            ["--explorer-send", "--", @"C:\Users\Alice\a.txt", "--screen=settings"]);
        Assert.Equal(LaunchActionKind.ExplorerSend, expWithFlagLikeArg.Kind);
        Assert.Equal(
            [@"C:\Users\Alice\a.txt", "--screen=settings"],
            expWithFlagLikeArg.Paths);

        LaunchAction bareAfterTerminator = WindowActivationCoordinator.ClassifyLaunchArguments(
            ["--", "--screen=settings"]);
        Assert.Equal(LaunchActionKind.ExplorerSend, bareAfterTerminator.Kind);
        Assert.Equal(["--screen=settings"], bareAfterTerminator.Paths);

        LaunchAction expWithUriArg = WindowActivationCoordinator.ClassifyLaunchArguments(
            ["--explorer-send", "--", "totaldrop://r/7-harbor-rocket"]);
        Assert.Equal(LaunchActionKind.ExplorerSend, expWithUriArg.Kind);
        Assert.Equal(["totaldrop://r/7-harbor-rocket"], expWithUriArg.Paths);

        // Protocol URIs accept http://, https://, totaldrop:, uppercase casing, and Bidi isolates.
        string[] uris =
        [
            "totaldrop://r/7-harbor-rocket",
            "TOTALDROP://r/7-harbor-rocket",
            "https://totaldrop.app/r#7-harbor-rocket",
            "http://totaldrop.app/r#7-harbor-rocket",
            "HTTP://TOTALDROP.APP/r#7-harbor-rocket",
            "\u2068totaldrop://r/7-harbor-rocket\u2069",
        ];
        foreach (string uri in uris)
        {
            LaunchAction act = WindowActivationCoordinator.ClassifyLaunchArguments([uri]);
            Assert.Equal(LaunchActionKind.ProtocolUri, act.Kind);
            Assert.Equal(uri, act.Target);
        }

        // Standard switches and sentinels.
        Assert.Equal(
            LaunchActionKind.ForegroundOnly,
            WindowActivationCoordinator.ClassifyLaunchArguments(["----AppNotificationActivated:activate"]).Kind);
        Assert.Equal(
            LaunchActionKind.None,
            WindowActivationCoordinator.ClassifyLaunchArguments(["--ipc-await"]).Kind);
        LaunchAction screenAct = WindowActivationCoordinator.ClassifyLaunchArguments(["--screen=settings"]);
        Assert.Equal(LaunchActionKind.OpenScreen, screenAct.Kind);
        Assert.Equal("settings", screenAct.Target);
        Assert.Equal(
            LaunchActionKind.None,
            WindowActivationCoordinator.ClassifyLaunchArguments([]).Kind);
    }
}
