// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Diagnostics;
using System.Text;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

/// <summary>
/// Architecture A loopback transfer tests (T3-04) executing against external
/// <c>totaldrop-rendezvous</c> and <c>totaldrop-relay</c> binaries bound strictly to
/// <c>127.0.0.1:0</c>. Supply absolute executable paths via
/// <c>TOTALDROP_TEST_RENDEZVOUS_BIN</c> and <c>TOTALDROP_TEST_RELAY_BIN</c>, or build the
/// sibling <c>totaldrop-servers</c> repository. Excluded from single-repo PR CI via
/// <c>--filter "FullyQualifiedName!~LoopbackRelayTransferTests"</c>.
/// </summary>
public sealed class LoopbackRelayTransferTests
{
    private sealed class LoopbackServerProcess : IDisposable
    {
        private readonly Process _process;
        public string Url { get; }

        private LoopbackServerProcess(Process process, string url)
        {
            _process = process;
            Url = url;
        }

        public static LoopbackServerProcess StartRendezvous()
        {
            string bin = ResolveBinary("TOTALDROP_TEST_RENDEZVOUS_BIN", "totaldrop-rendezvous");
            return StartAndAwaitAddress(bin, "127.0.0.1:0", "127.0.0.1:", static addr => $"ws://{addr}");
        }

        public static LoopbackServerProcess StartRelay()
        {
            string bin = ResolveBinary("TOTALDROP_TEST_RELAY_BIN", "totaldrop-relay");
            return StartAndAwaitAddress(
                bin,
                "127.0.0.1:0 127.0.0.1:0",
                "WebSocket on 127.0.0.1:",
                static addr => $"ws://{addr}/v0/relay");
        }

        private static string ResolveBinary(string envVar, string baseName)
        {
            string? configured = Environment.GetEnvironmentVariable(envVar);
            if (!string.IsNullOrWhiteSpace(configured))
            {
                string trimmed = configured.Trim();
                string resolved = Path.GetFullPath(trimmed);
                if (!File.Exists(resolved))
                {
                    string hint = Path.IsPathFullyQualified(trimmed)
                        ? string.Empty
                        : $" ({envVar} was relative; testhost CWD is '{Environment.CurrentDirectory}'. Pass an absolute path.)";
                    throw new FileNotFoundException(
                        $"{envVar} points to missing binary '{trimmed}' (resolved to '{resolved}').{hint}");
                }

                return resolved;
            }

            string ext = OperatingSystem.IsWindows() ? ".exe" : string.Empty;
            string repoRoot = FfiResolver.FindRepoRoot(AppContext.BaseDirectory);
            string[] candidates =
            [
                Path.Combine(repoRoot, "..", "totaldrop-servers", "target", "release", baseName + ext),
                Path.Combine(repoRoot, "..", "totaldrop-servers", "target", "debug", baseName + ext),
                Path.Combine(repoRoot, "..", "totaldrop-servers", "rust-shared", "target", "release", baseName + ext),
                Path.Combine(repoRoot, "..", "totaldrop-servers", "rust-shared", "target", "debug", baseName + ext),
                Path.Combine(repoRoot, "..", "..", "totaldrop-app", "totaldrop-servers", "target", "release", baseName + ext),
                Path.Combine(repoRoot, "..", "..", "totaldrop-app", "totaldrop-servers", "target", "debug", baseName + ext),
                Path.Combine(repoRoot, "..", "..", "totaldrop-app", "totaldrop-servers", "rust-shared", "target", "release", baseName + ext),
                Path.Combine(repoRoot, "..", "..", "totaldrop-app", "totaldrop-servers", "rust-shared", "target", "debug", baseName + ext),
            ];
            foreach (string candidate in candidates)
            {
                string full = Path.GetFullPath(candidate);
                if (File.Exists(full))
                {
                    return full;
                }
            }

            throw new FileNotFoundException(
                $"Required Architecture A loopback binary '{baseName}' not found; set {envVar} to an absolute executable path.");
        }

        private static LoopbackServerProcess StartAndAwaitAddress(
            string binaryPath,
            string arguments,
            string marker,
            Func<string, string> urlFactory)
        {
            ProcessStartInfo psi = new()
            {
                FileName = binaryPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };

            Process proc = Process.Start(psi)
                ?? throw new InvalidOperationException($"Failed to start {binaryPath}");

            TaskCompletionSource<string> urlTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
            proc.ErrorDataReceived += (_, args) =>
            {
                string? line = args.Data;
                if (string.IsNullOrEmpty(line))
                {
                    return;
                }

                int idx = line.IndexOf(marker, StringComparison.Ordinal);
                if (idx >= 0)
                {
                    int addrStart = marker.StartsWith("WebSocket on ", StringComparison.Ordinal)
                        ? idx + "WebSocket on ".Length
                        : idx;
                    string tail = line[addrStart..];
                    int end = tail.IndexOfAny([' ', ',', '\t', '\r', '\n']);
                    string addr = end >= 0 ? tail[..end] : tail;
                    if (!string.IsNullOrWhiteSpace(addr))
                    {
                        urlTcs.TrySetResult(urlFactory(addr));
                    }
                }
            };
            proc.BeginErrorReadLine();
            proc.BeginOutputReadLine();

            if (!urlTcs.Task.Wait(TimeSpan.FromSeconds(10)))
            {
                try
                {
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(3000);
                }
                catch (InvalidOperationException)
                {
                    // Process already exited.
                }

                proc.Dispose();
                throw new TimeoutException($"Timed out waiting for '{binaryPath}' listening address.");
            }

            return new LoopbackServerProcess(proc, urlTcs.Task.Result);
        }

        public void Dispose()
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(3000);
                }
            }
            catch (InvalidOperationException)
            {
                // Ignore if already exited.
            }
            finally
            {
                _process.Dispose();
            }
        }
    }

    private static SessionEventDto WaitForEvent(
        ulong sessionId,
        List<SessionEventDto> collected,
        string targetEvent,
        TimeSpan timeout)
    {
        Stopwatch sw = Stopwatch.StartNew();
        while (true)
        {
            SessionEventDto? existing = collected.FirstOrDefault(e => e.Event == targetEvent);
            if (existing is not null)
            {
                return existing;
            }

            if (targetEvent != "failed")
            {
                SessionEventDto? failed = collected.FirstOrDefault(e => e.Event == "failed");
                if (failed is not null)
                {
                    throw new InvalidOperationException(
                        $"Unexpected failed event while waiting for '{targetEvent}': {failed.L10nKey} / {failed.TechnicalEnglish}");
                }
            }

            Assert.True(
                NativeBridge.TryPollSessionEvents(sessionId, out List<SessionEventDto> batch, out BridgeErrorDto? pollErr),
                $"TryPollSessionEvents failed: {pollErr?.Message}");
            collected.AddRange(batch);

            existing = collected.FirstOrDefault(e => e.Event == targetEvent);
            if (existing is not null)
            {
                return existing;
            }

            if (sw.Elapsed >= timeout)
            {
                string seen = string.Join(", ", collected.Select(e => e.Event));
                throw new TimeoutException($"Timed out waiting for '{targetEvent}'; saw: [{seen}]");
            }

            Thread.Sleep(15);
        }
    }

    [Fact]
    public void T3_04_CustomLoopbackPrivacyRelaySettings_And1024ByteUtf8TextTransfer()
    {
        using LoopbackServerProcess rendezvous = LoopbackServerProcess.StartRendezvous();
        using LoopbackServerProcess relay = LoopbackServerProcess.StartRelay();

        string tempDir = Path.Combine(
            Path.GetTempPath(),
            $"totaldrop-winui-t304-{Environment.ProcessId}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        ulong sendId = 0;
        ulong recvId = 0;
        try
        {
            SettingsStore store = new(tempDir);

            // Reject non-loopback ws:// and userinfo spoofing URLs via Rust FFI.
            Assert.False(store.TrySaveServerUrl("ws://192.168.1.5:4000", out string? err1));
            Assert.Equal("settingsServerInvalid", err1);
            Assert.False(store.TrySaveServerUrl("wss://user@host", out string? err2));
            Assert.Equal("settingsServerInvalid", err2);

            // Validate & save custom loopback rendezvous + relay with empty STUN and Privacy Mode ON.
            Assert.True(NativeBridge.TryValidateServerUrl(rendezvous.Url, out _));
            BridgeNetworkConfigDto config = new(
                RendezvousServer: rendezvous.Url,
                RelayServer: relay.Url,
                StunServer: string.Empty,
                PrivacyRelayOnly: true,
                StrongerThreeWordCode: false);
            Assert.True(store.TrySaveAtomic(config));

            // Reload via fresh SettingsStore and verify empty STUN is preserved (zero Cloudflare STUN).
            SettingsStore reloaded = new(tempDir);
            Assert.Equal(rendezvous.Url, reloaded.Current.RendezvousServer);
            Assert.Equal(relay.Url, reloaded.Current.RelayServer);
            Assert.Equal(string.Empty, reloaded.Current.StunServer);
            Assert.True(reloaded.Current.PrivacyRelayOnly);

            // Construct exact 1024-byte UTF-8 text payload.
            StringBuilder sb = new(1024);
            sb.Append("TotalDrop-T3-04-K\u00F6\u015Fe-");
            while (Encoding.UTF8.GetByteCount(sb.ToString()) < 1024)
            {
                sb.Append('X');
            }

            string payload = sb.ToString();
            Assert.Equal(1024, Encoding.UTF8.GetByteCount(payload));

            sendId = NativeBridge.StartSendText(reloaded.Current, payload, "en-US", "en-US");
            Assert.NotEqual(0UL, sendId);

            List<SessionEventDto> sendEvents = [];
            SessionEventDto codeReady = WaitForEvent(sendId, sendEvents, "code_ready", TimeSpan.FromSeconds(15));
            Assert.True(codeReady.IsText);
            string code = codeReady.Code?.DisplayEnglish
                ?? throw new InvalidOperationException("code_ready missing DisplayEnglish");

            recvId = NativeBridge.StartReceiveConnect(reloaded.Current, code, "en-US", "en-US");
            Assert.NotEqual(0UL, recvId);

            List<SessionEventDto> recvEvents = [];
            SessionEventDto offer = WaitForEvent(recvId, recvEvents, "offer_ready", TimeSpan.FromSeconds(20));
            Assert.True(offer.IsText);

            Assert.Equal(NativeBridge.FfiOk, NativeBridge.ReceiveAcceptText(recvId));
            SessionEventDto recvDone = WaitForEvent(recvId, recvEvents, "done", TimeSpan.FromSeconds(20));
            _ = WaitForEvent(sendId, sendEvents, "done", TimeSpan.FromSeconds(20));

            Assert.Equal(payload, recvDone.ReceivedText);
        }
        finally
        {
            if (recvId != 0)
            {
                _ = NativeBridge.SessionDestroy(recvId);
            }

            if (sendId != 0)
            {
                _ = NativeBridge.SessionDestroy(sendId);
            }

            _ = NativeBridge.Shutdown(1500);
            if (Directory.Exists(tempDir))
            {
                try
                {
                    Directory.Delete(tempDir, recursive: true);
                }
                catch (IOException)
                {
                    // Ignore cleanup lock errors.
                }
            }
        }
    }
}
