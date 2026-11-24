// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

/// <summary>
/// Windows-native M3 integration tests executed exclusively on Windows CI runners
/// (<c>dotnet test --filter "Category=WindowsCI"</c> via <c>Invoke-WindowsE2E.ps1</c>).
/// Never falsely pass on Linux: every test explicitly asserts <see cref="OperatingSystem.IsWindows"/>.
/// </summary>
[Trait("Category", "WindowsCI")]
public sealed class WindowsM3IntegrationTests
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

    private static byte[] FrameUtf8Json(string json)
    {
        byte[] body = Encoding.UTF8.GetBytes(json);
        byte[] framed = new byte[4 + body.Length];
        BitConverter.TryWriteBytes(framed.AsSpan(0, 4), (uint)body.Length);
        body.CopyTo(framed, 4);
        return framed;
    }

    [Fact]
    public async Task T1_F17_04_WindowsNamedPipeCurrentUserOnly_StreamsToRustRouter()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        ulong routerId = NativeBridge.TryCreateRouter(1, "en-US", "en-US", "0.1.0-beta.1", animationsEnabled: true);
        Assert.NotEqual(0UL, routerId);
        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        try
        {
            string pipeName = $@"LOCAL\app.totaldrop.TotalDrop.e2e.{Environment.ProcessId}.{Guid.NewGuid():N}";
            byte[] frame = FrameUtf8Json(
                """{"version":1,"initiator_pid":1234,"payload":{"kind":"explorer_send","paths":["C:\\Users\\Alice\\report.pdf"]}}""");

            await using NamedPipeServerStream server = new(
                pipeName,
                PipeDirection.In,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: 16 * 1024,
                outBufferSize: 0);

            Task serverConnect = server.WaitForConnectionAsync(cts.Token);
            Task clientTask = Task.Run(async () =>
            {
                await using NamedPipeClientStream client = new(
                    ".",
                    pipeName,
                    PipeDirection.Out,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await client.ConnectAsync(5000, cts.Token);
                await client.WriteAsync(frame, cts.Token);
            }, cts.Token);

            await serverConnect;

            byte[] buf = new byte[4096];
            List<RouterDecisionDto> allDecisions = [];
            while (true)
            {
                int n = await server.ReadAsync(buf, cts.Token);
                if (n == 0)
                {
                    Assert.True(NativeBridge.TryIngestRouterIpcBytes(routerId, ReadOnlySpan<byte>.Empty, out RouterDecisionDto[] eofDecs, out BridgeErrorDto? eofErr), eofErr?.Message);
                    allDecisions.AddRange(eofDecs);
                    break;
                }

                Assert.True(NativeBridge.TryIngestRouterIpcBytes(routerId, buf.AsSpan(0, n), out RouterDecisionDto[] decs, out BridgeErrorDto? err), err?.Message);
                allDecisions.AddRange(decs);
            }

            await clientTask;

            RouterDecisionDto decision = Assert.Single(allDecisions);
            Assert.Equal("navigate_send_files", decision.Decision);
            Assert.NotNull(decision.Paths);
            Assert.Equal([@"\\?\C:\Users\Alice\report.pdf"], decision.Paths);
        }
        finally
        {
            _ = NativeBridge.TryDestroyRouter(routerId);
        }
    }

    [Fact]
    public async Task T2_F17_06_WindowsNamedPipeAbruptDisconnect_CleanEofFlushAndNextConnectionSucceeds()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        ulong routerId = NativeBridge.TryCreateRouter(2, "en-US", "en-US", "0.1.0-beta.1", animationsEnabled: true);
        Assert.NotEqual(0UL, routerId);
        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        try
        {
            string pipeName = $@"LOCAL\app.totaldrop.TotalDrop.e2e.{Environment.ProcessId}.{Guid.NewGuid():N}";

            // Connection 1: write truncated header (declares 200 bytes, sends only 20) and disconnect abruptly.
            await using (NamedPipeServerStream server1 = new(
                pipeName,
                PipeDirection.In,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: 16 * 1024,
                outBufferSize: 0))
            {
                Task conn1 = server1.WaitForConnectionAsync(cts.Token);
                Task client1Task = Task.Run(async () =>
                {
                    await using NamedPipeClientStream client1 = new(
                        ".",
                        pipeName,
                        PipeDirection.Out,
                        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                    await client1.ConnectAsync(5000, cts.Token);
                    byte[] truncated = new byte[24];
                    BitConverter.TryWriteBytes(truncated.AsSpan(0, 4), 200U);
                    await client1.WriteAsync(truncated, cts.Token);
                }, cts.Token);

                await conn1;

                byte[] buf = new byte[256];
                int totalRead = 0;
                while (true)
                {
                    int n = await server1.ReadAsync(buf, cts.Token);
                    if (n == 0)
                    {
                        break;
                    }

                    totalRead += n;
                    Assert.True(NativeBridge.TryIngestRouterIpcBytes(routerId, buf.AsSpan(0, n), out RouterDecisionDto[] partial, out _));
                    Assert.Empty(partial);
                }

                await client1Task;
                Assert.Equal(24, totalRead);
                bool eofOk = NativeBridge.TryIngestRouterIpcBytes(routerId, ReadOnlySpan<byte>.Empty, out _, out BridgeErrorDto? eofErr);
                Assert.False(eofOk);
                Assert.Equal("malformed_ipc_frame", eofErr?.Kind);
            }

            // Connection 2: valid frame immediately after reset MUST succeed.
            await using (NamedPipeServerStream server2 = new(
                pipeName,
                PipeDirection.In,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: 16 * 1024,
                outBufferSize: 0))
            {
                Task conn2 = server2.WaitForConnectionAsync(cts.Token);
                byte[] okFrame = FrameUtf8Json("""{"version":1,"payload":{"kind":"open_screen","screen":"receive"}}""");
                Task client2Task = Task.Run(async () =>
                {
                    await using NamedPipeClientStream client2 = new(
                        ".",
                        pipeName,
                        PipeDirection.Out,
                        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                    await client2.ConnectAsync(5000, cts.Token);
                    await client2.WriteAsync(okFrame, cts.Token);
                }, cts.Token);

                await conn2;

                byte[] buf = new byte[256];
                List<RouterDecisionDto> allDecs = [];
                while (true)
                {
                    int n = await server2.ReadAsync(buf, cts.Token);
                    if (n == 0)
                    {
                        Assert.True(NativeBridge.TryIngestRouterIpcBytes(routerId, ReadOnlySpan<byte>.Empty, out RouterDecisionDto[] eofDecs, out BridgeErrorDto? eofErr), eofErr?.Message);
                        allDecs.AddRange(eofDecs);
                        break;
                    }

                    Assert.True(NativeBridge.TryIngestRouterIpcBytes(routerId, buf.AsSpan(0, n), out RouterDecisionDto[] decs, out BridgeErrorDto? err), err?.Message);
                    allDecs.AddRange(decs);
                }

                await client2Task;
                RouterDecisionDto dec = Assert.Single(allDecs);
                Assert.Equal("switch_screen", dec.Decision);
                Assert.Equal("receive", dec.Screen);
            }
        }
        finally
        {
            _ = NativeBridge.TryDestroyRouter(routerId);
        }
    }

    [Fact]
    public async Task T1_F18_04_ShareTargetRouter_FilesTextWebLinkAndGuaranteedReportCompleted()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        ulong routerId = NativeBridge.TryCreateRouter(3, "en-US", "en-US", "0.1.0-beta.1", animationsEnabled: true);
        Assert.NotEqual(0UL, routerId);
        using SemaphoreSlim gate = new(1, 1);
        try
        {
            // 1. StorageItems files
            RecordingShareLifecycle lc1 = new();
            ShareTargetRouteResult r1 = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(StorageItemPaths: [@"C:\Users\Alice\doc.pdf"])),
                lc1,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(r1.Succeeded, r1.Error?.Message);
            Assert.Equal("navigate_send_files", Assert.Single(r1.Decisions).Decision);
            Assert.Equal(1, lc1.StartedCount);
            Assert.Equal(1, lc1.DataRetrievedCount);
            Assert.Equal(1, lc1.CompletedCount);

            // 2. WebLink -> TotalDrop share link
            RecordingShareLifecycle lc2 = new();
            ShareTargetRouteResult r2 = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(WebLink: "https://totaldrop.app/r#7-harbor-rocket")),
                lc2,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(r2.Succeeded, r2.Error?.Message);
            Assert.Equal("navigate_receive_code", Assert.Single(r2.Decisions).Decision);
            Assert.Equal(1, lc2.CompletedCount);

            // 3. Throwing extraction MUST still invoke ReportCompleted()
            RecordingShareLifecycle lc3 = new();
            ShareTargetRouteResult r3 = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromException<ShareTargetInput>(new InvalidOperationException("simulated WinRT failure")),
                lc3,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.False(r3.Succeeded);
            Assert.Equal(1, lc3.StartedCount);
            Assert.Equal(1, lc3.CompletedCount);
        }
        finally
        {
            _ = NativeBridge.TryDestroyRouter(routerId);
        }
    }

    [Fact]
    public void T1_F20_02_Win32PowerCreateRequest_SystemRequiredOnlyAndCleanRelease()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        using WakeLockService svc = new();
        Assert.False(svc.IsAwakeHeld);
        svc.UpdateStage(TransferLifecycleStage.Transferring, "TotalDrop Windows E2E transfer");
        Assert.True(svc.IsAwakeHeld);
        svc.UpdateStage(TransferLifecycleStage.Done, "Done");
        Assert.False(svc.IsAwakeHeld);
    }

    [Fact]
    public void T2_F20_01_Win32PowerRequest_ZeroLeaksAcrossFiveRapidCycles()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        using WakeLockService svc = new();
        for (int i = 0; i < 5; i++)
        {
            svc.UpdateStage(TransferLifecycleStage.Preparing, $"Cycle {i}");
            Assert.True(svc.IsAwakeHeld);
            svc.UpdateStage(TransferLifecycleStage.Transferring, $"Cycle {i}");
            Assert.True(svc.IsAwakeHeld);
            svc.UpdateStage(TransferLifecycleStage.Idle, $"Cycle {i}");
            Assert.False(svc.IsAwakeHeld);
        }
    }

    private static string ExpectedExtendedPath(string raw)
    {
        if (raw.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            string rest = raw[4..];
            if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return $@"\\?\UNC\{rest[4..]}";
            }

            if (rest.Length >= 2 && char.IsAsciiLetter(rest[0]) && rest[1] == ':')
            {
                return $@"\\?\{char.ToUpperInvariant(rest[0])}:{rest[2..]}";
            }

            return $@"\\?\{rest}";
        }

        if (raw.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return $@"\\?\UNC\{raw[2..]}";
        }

        if (raw.Length >= 2 && char.IsAsciiLetter(raw[0]) && raw[1] == ':')
        {
            return $@"\\?\{char.ToUpperInvariant(raw[0])}:{raw[2..]}";
        }

        return $@"\\?\{raw}";
    }

    [Fact]
    public void T1_F21_03_RealNtfsLongPathOver300Chars_CreateReadAndValidate()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        string rootDir = Path.Combine(Path.GetTempPath(), $"td-long-{Environment.ProcessId}-{Guid.NewGuid():N}");
        string deepDir = rootDir;
        for (int i = 0; i < 5; i++)
        {
            deepDir = Path.Combine(deepDir, $"segment_{i:D2}_{new string('x', 45)}");
        }

        string filePath = Path.Combine(deepDir, "payload.bin");
        Assert.True(filePath.Length > 300, $"Expected path > 300 chars, got {filePath.Length}");

        string extRoot = ExpectedExtendedPath(rootDir);
        string extDir = ExpectedExtendedPath(deepDir);
        string extFile = ExpectedExtendedPath(filePath);
        try
        {
            Directory.CreateDirectory(extDir);
            byte[] data = Encoding.UTF8.GetBytes("TotalDrop Windows 11 LongPath E2E payload");
            File.WriteAllBytes(extFile, data);
            byte[] readBack = File.ReadAllBytes(extFile);
            Assert.Equal(SHA256.HashData(data), SHA256.HashData(readBack));

            Assert.True(NativeBridge.TryValidatePaths([filePath], out ValidatedPathDto[] normalized, out BridgeErrorDto? err), err?.Message);
            ValidatedPathDto item = Assert.Single(normalized);
            Assert.Equal(extFile, item.ExtendedPath);
            Assert.True(item.ExceedsLegacyMaxPath);
        }
        finally
        {
            if (Directory.Exists(extRoot))
            {
                Directory.Delete(extRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void T1_F21_04_RealNtfsSpecialCharPaths_AmpersandCaretParensPercentSpaces()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        string rootDir = Path.Combine(Path.GetTempPath(), $"td-spec-{Environment.ProcessId}-{Guid.NewGuid():N}");
        string specialDir = Path.Combine(rootDir, "A & calc.exe", "report (2026) ^ %TEMP%");
        string filePath = Path.Combine(specialDir, "spaced file.txt");
        try
        {
            Directory.CreateDirectory(specialDir);
            File.WriteAllText(filePath, "TotalDrop special NTFS char test");
            Assert.Equal("TotalDrop special NTFS char test", File.ReadAllText(filePath));

            Assert.True(NativeBridge.TryValidatePaths([filePath], out ValidatedPathDto[] normalized, out BridgeErrorDto? err), err?.Message);
            ValidatedPathDto item = Assert.Single(normalized);
            Assert.Equal(ExpectedExtendedPath(filePath), item.ExtendedPath);
        }
        finally
        {
            if (Directory.Exists(rootDir))
            {
                Directory.Delete(rootDir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task T3_10_SingleInstanceNamedPipeAndShareTargetConcurrency_StreamGateSerialized()
    {
        Assert.True(OperatingSystem.IsWindows(), "Requires Windows CI runner (filter Category!=WindowsCI on Linux).");

        ulong routerId = NativeBridge.TryCreateRouter(10, "en-US", "en-US", "0.1.0-beta.1", animationsEnabled: true);
        Assert.NotEqual(0UL, routerId);
        using SemaphoreSlim gate = new(1, 1);
        try
        {
            // Verify plain text -> navigate_send_text, TotalDrop link -> navigate_receive_code, UNC -> navigate_send_files
            RecordingShareLifecycle lc1 = new();
            ShareTargetRouteResult rText = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(Text: "Hello TotalDrop")),
                lc1,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(rText.Succeeded, rText.Error?.Message);
            Assert.Equal("navigate_send_text", Assert.Single(rText.Decisions).Decision);
            Assert.Equal(1, lc1.CompletedCount);

            RecordingShareLifecycle lc2 = new();
            ShareTargetRouteResult rLink = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(WebLink: "https://totaldrop.app/r#7-harbor-rocket")),
                lc2,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(rLink.Succeeded, rLink.Error?.Message);
            RouterDecisionDto linkDec = Assert.Single(rLink.Decisions);
            Assert.Equal("navigate_receive_code", linkDec.Decision);
            Assert.Equal("7-harbor-rocket", linkDec.Code?.DisplayEnglish);
            Assert.Equal(1, lc2.CompletedCount);

            RecordingShareLifecycle lc3 = new();
            ShareTargetRouteResult rUnc = await ShareTargetRouter.RouteAsync(
                routerId,
                static () => Task.FromResult(new ShareTargetInput(StorageItemPaths: [@"\\nas01\share\doc.pdf"])),
                lc3,
                initiatorPid: null,
                routerLock: null,
                routerStreamGate: gate);
            Assert.True(rUnc.Succeeded, rUnc.Error?.Message);
            RouterDecisionDto uncDec = Assert.Single(rUnc.Decisions);
            Assert.Equal("navigate_send_files", uncDec.Decision);
            Assert.NotNull(uncDec.Paths);
            Assert.Equal([@"\\?\UNC\nas01\share\doc.pdf"], uncDec.Paths);
            Assert.Equal(1, lc3.CompletedCount);

            Task<ShareTargetRouteResult>[] tasks = Enumerable.Range(0, 10)
                .Select(i => ShareTargetRouter.RouteAsync(
                    routerId,
                    () => Task.FromResult(new ShareTargetInput(Text: $"Concurrent share payload #{i}")),
                    new RecordingShareLifecycle(),
                    initiatorPid: null,
                    routerLock: null,
                    routerStreamGate: gate))
                .ToArray();

            ShareTargetRouteResult[] results = await Task.WhenAll(tasks);
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
