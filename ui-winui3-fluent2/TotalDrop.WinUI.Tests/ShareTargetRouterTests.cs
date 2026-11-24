// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

/// <summary>
/// Headless <c>net10.0</c> tests for <see cref="ShareTargetRouter"/> exercising
/// live Rust <c>totaldrop_win_router_ingest_ipc_bytes_json</c> across plain text,
/// TotalDrop links, UNC paths, guaranteed <c>ReportCompleted()</c> lifecycle
/// completion, and <c>SemaphoreSlim</c> stream-gate serialization (T3-10 parity).
/// </summary>
public sealed class ShareTargetRouterTests
{
    private sealed class RecordingShareLifecycle : IShareOperationLifecycle
    {
        public int StartedCount { get; private set; }

        public int DataRetrievedCount { get; private set; }

        public int CompletedCount { get; private set; }

        public void ReportStarted() => StartedCount++;

        public void ReportDataRetrieved() => DataRetrievedCount++;

        public void ReportCompleted() => CompletedCount++;
    }

    [Fact]
    public async Task ShareTargetRouter_PlainTextTotalDropLinkUncAndErrorPaths_GuaranteesReportCompleted()
    {
        ulong routerId = NativeBridge.TryCreateRouter(310, "en-US", "en-US", "0.1.0-beta.1", animationsEnabled: true);
        Assert.NotEqual(0UL, routerId);
        using SemaphoreSlim gate = new(1, 1);
        try
        {
            // 1. Plain text -> navigate_send_text (never Receive code input)
            RecordingShareLifecycle lcText = new();
            ShareTargetRouteResult rText = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(Text: "Ship report at 14:00")),
                lcText,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(rText.Succeeded, rText.Error?.Message);
            RouterDecisionDto decText = Assert.Single(rText.Decisions);
            Assert.Equal("navigate_send_text", decText.Decision);
            Assert.Equal("Ship report at 14:00", decText.RawText);
            Assert.Equal(1, lcText.StartedCount);
            Assert.Equal(1, lcText.DataRetrievedCount);
            Assert.Equal(1, lcText.CompletedCount);

            // 2. TotalDrop WebLink -> navigate_receive_code (display_english == "7-harbor-rocket", zero auto-dial)
            RecordingShareLifecycle lcLink = new();
            ShareTargetRouteResult rLink = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(WebLink: "https://totaldrop.app/r#7-harbor-rocket")),
                lcLink,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(rLink.Succeeded, rLink.Error?.Message);
            RouterDecisionDto decLink = Assert.Single(rLink.Decisions);
            Assert.Equal("navigate_receive_code", decLink.Decision);
            Assert.Equal("7-harbor-rocket", decLink.Code?.DisplayEnglish);
            Assert.Equal(1, lcLink.StartedCount);
            Assert.Equal(1, lcLink.DataRetrievedCount);
            Assert.Equal(1, lcLink.CompletedCount);

            // 3. UNC StorageItem -> navigate_send_files with \\?\UNC\...
            RecordingShareLifecycle lcUnc = new();
            ShareTargetRouteResult rUnc = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(StorageItemPaths: [@"\\nas01\share\doc.pdf"])),
                lcUnc,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(rUnc.Succeeded, rUnc.Error?.Message);
            RouterDecisionDto decUnc = Assert.Single(rUnc.Decisions);
            Assert.Equal("navigate_send_files", decUnc.Decision);
            Assert.NotNull(decUnc.Paths);
            Assert.Equal([@"\\?\UNC\nas01\share\doc.pdf"], decUnc.Paths);
            Assert.Equal(1, lcUnc.StartedCount);
            Assert.Equal(1, lcUnc.DataRetrievedCount);
            Assert.Equal(1, lcUnc.CompletedCount);

            // 4. Throwing WinRT extraction -> Succeeded == false AND ReportCompleted() still called
            RecordingShareLifecycle lcErr = new();
            ShareTargetRouteResult rErr = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromException<ShareTargetInput>(new InvalidOperationException("simulated extraction error")),
                lcErr,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.False(rErr.Succeeded);
            Assert.Equal(1, lcErr.StartedCount);
            Assert.Equal(1, lcErr.CompletedCount);

            // 5. Concurrent serialized submissions through SemaphoreSlim gate
            Task<ShareTargetRouteResult>[] burst = Enumerable.Range(0, 8)
                .Select(i => ShareTargetRouter.RouteAsync(
                    routerId,
                    () => Task.FromResult(new ShareTargetInput(Text: $"Burst note #{i}")),
                    new RecordingShareLifecycle(),
                    initiatorPid: null,
                    routerLock: null,
                    routerStreamGate: gate))
                .ToArray();
            ShareTargetRouteResult[] results = await Task.WhenAll(burst);
            Assert.All(results, static r =>
            {
                Assert.True(r.Succeeded, r.Error?.Message);
                Assert.Equal("navigate_send_text", Assert.Single(r.Decisions).Decision);
            });
        }
        finally
        {
            _ = NativeBridge.TryDestroyRouter(routerId);
        }
    }
}
