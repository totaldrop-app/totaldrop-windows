// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Text.Json;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

public sealed class SettingsStoreTests
{
    private sealed class TempSettingsDir : IDisposable
    {
        public string Path { get; }

        public TempSettingsDir(string tag)
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"totaldrop-winui-tests-{tag}-{Environment.ProcessId}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch (IOException)
            {
                // Ignore transient cleanup lock errors.
            }
        }
    }

    [Fact]
    public void T1_F12_01_SaveCustomLoopbackAndPrivacyMode_AtomicRoundTrip()
    {
        using TempSettingsDir tmp = new("t1-f12-01");
        SettingsStore store = new(tmp.Path);

        bool savedUrl = store.TrySaveServerUrl("ws://127.0.0.1:4400", out string? errKey);
        Assert.True(savedUrl, $"TrySaveServerUrl failed with {errKey}");
        Assert.Null(errKey);
        Assert.True(store.TrySetPrivacyMode(true));

        Assert.True(File.Exists(store.SettingsPath));
        string[] tempFiles = Directory.GetFiles(tmp.Path, "*.tmp");
        Assert.Empty(tempFiles);

        string rawJson = File.ReadAllText(store.SettingsPath);
        using JsonDocument doc = JsonDocument.Parse(rawJson);
        Assert.Equal("ws://127.0.0.1:4400", doc.RootElement.GetProperty("rendezvous_server").GetString());
        Assert.True(doc.RootElement.GetProperty("privacy_relay_only").GetBoolean());

        SettingsStore reloaded = new(tmp.Path);
        Assert.Equal("ws://127.0.0.1:4400", reloaded.Current.RendezvousServer);
        Assert.True(reloaded.Current.PrivacyRelayOnly);
    }

    [Fact]
    public void T1_F12_02_ResetServerUrl_RestoresDefaultAndDisablesCanReset()
    {
        using TempSettingsDir tmp = new("t1-f12-02");
        SettingsStore store = new(tmp.Path);

        Assert.True(store.TrySaveServerUrl("ws://127.0.0.1:4400", out string? errKey));
        Assert.Null(errKey);
        Assert.True(store.CanResetServer);

        Assert.True(store.TryResetServerUrl());
        // Offline string/metadata check only — zero network connection.
        Assert.Equal(SettingsStore.DefaultRendezvousServer, store.Current.RendezvousServer);
        Assert.Equal("wss://rendezvous.totaldrop.app", store.Current.RendezvousServer);
        Assert.False(store.CanResetServer);

        SettingsStore reloaded = new(tmp.Path);
        Assert.Equal("wss://rendezvous.totaldrop.app", reloaded.Current.RendezvousServer);
        Assert.False(reloaded.CanResetServer);
    }

    [Fact]
    public void T2_F12_01_MissingEmptyAndCorruptSettings_FallbackToDefaults()
    {
        // (a) Nonexistent settings.json
        using (TempSettingsDir tmpMissing = new("t2-f12-01-missing"))
        {
            SettingsStore s = new(tmpMissing.Path);
            Assert.Equal("wss://rendezvous.totaldrop.app", s.Current.RendezvousServer);
            Assert.False(s.Current.PrivacyRelayOnly);
        }

        // (b) 0-byte empty file
        using (TempSettingsDir tmpEmpty = new("t2-f12-01-empty"))
        {
            File.WriteAllBytes(Path.Combine(tmpEmpty.Path, "settings.json"), []);
            SettingsStore s = new(tmpEmpty.Path);
            Assert.Equal("wss://rendezvous.totaldrop.app", s.Current.RendezvousServer);
            Assert.False(s.Current.PrivacyRelayOnly);
        }

        // (c) Truncated corrupt JSON
        using (TempSettingsDir tmpCorrupt = new("t2-f12-01-corrupt"))
        {
            File.WriteAllText(Path.Combine(tmpCorrupt.Path, "settings.json"), "{\"rendezvous_server\":");
            SettingsStore s = new(tmpCorrupt.Path);
            Assert.Equal("wss://rendezvous.totaldrop.app", s.Current.RendezvousServer);
            Assert.False(s.Current.PrivacyRelayOnly);
        }
    }

    [Fact]
    public void T2_F12_02_InvalidServerUrls_RejectedAndPreserveFileBytes()
    {
        using TempSettingsDir tmp = new("t2-f12-02");
        SettingsStore store = new(tmp.Path);

        Assert.True(store.TrySaveServerUrl("ws://127.0.0.1:4400", out _));
        byte[] beforeBytes = File.ReadAllBytes(store.SettingsPath);

        string[] invalidUrls =
        [
            "wss://",
            "wss://user@host",
            "ws://192.168.1.5:4000",
            "ftp://example.test",
        ];

        foreach (string badUrl in invalidUrls)
        {
            bool ok = store.TrySaveServerUrl(badUrl, out string? errorL10nKey);
            Assert.False(ok, $"Invalid URL '{badUrl}' must be rejected");
            Assert.Equal("settingsServerInvalid", errorL10nKey);

            bool formattedOk = NativeBridge.TryFormatMessage(
                "settingsServerInvalid",
                [],
                "en-US",
                "en-US",
                out string localized,
                out BridgeErrorDto? fmtErr);
            Assert.True(formattedOk, $"TryFormatMessage failed: {fmtErr?.Message}");
            Assert.False(string.IsNullOrWhiteSpace(localized));
        }

        byte[] afterBytes = File.ReadAllBytes(store.SettingsPath);
        Assert.Equal(beforeBytes, afterBytes);
    }

    [Fact]
    public void Tier5_TrySaveServerUrl_RejectsBidiAndNonAsciiAndPreservesSettingsBytes()
    {
        using TempSettingsDir tmp = new("tier5-bidi-urls");
        SettingsStore store = new(tmp.Path);

        Assert.True(store.TrySaveServerUrl("ws://127.0.0.1:4400", out _));
        byte[] beforeBytes = File.ReadAllBytes(store.SettingsPath);

        string[] hostileUrls =
        [
            "wss://example.test/\u202Eevil",
            "wss://example.test/\u2066spoof",
            "wss://example.test/\u2069spoof",
            "wss://example.test/\u2028line",
            "wss://example.test/\uFDD0nonchar",
            "wss://example.test/\uFFFFnonchar",
            "wss://example.test/\U000E0041tag",
            "wss://example.test\u00A0",
            "wss://example.test/a\u00A0b",
            "wss://example.test/caf\u00E9",
        ];

        foreach (string badUrl in hostileUrls)
        {
            bool saved = store.TrySaveServerUrl(badUrl, out string? errorL10nKey);
            Assert.False(saved, $"Hostile Bidi/non-ASCII URL '{badUrl}' must be rejected");
            Assert.Equal("settingsServerInvalid", errorL10nKey);
        }

        Assert.Equal(beforeBytes, File.ReadAllBytes(store.SettingsPath));
        Assert.Equal("ws://127.0.0.1:4400", new SettingsStore(tmp.Path).Current.RendezvousServer);
    }

    [Fact]
    public async Task Tier5_SettingsStore_SymlinkOversizeHostileJsonEmptyOverridesFallbackAndConcurrency()
    {
        // 1. Symlink settings.json -> ignored and replaced with defaults.
        using (TempSettingsDir tmpSym = new("tier5-symlink"))
        {
            string targetFile = Path.Combine(tmpSym.Path, "outside.json");
            File.WriteAllText(
                targetFile,
                "{\"rendezvous_server\":\"ws://127.0.0.1:4400\",\"privacy_relay_only\":true}");
            File.CreateSymbolicLink(Path.Combine(tmpSym.Path, "settings.json"), targetFile);

            SettingsStore store = new(tmpSym.Path);
            Assert.Equal(SettingsStore.DefaultRendezvousServer, store.Current.RendezvousServer);
            Assert.False(store.Current.PrivacyRelayOnly);
        }

        // 2. Oversized (> 65_536 bytes) settings.json -> falls back to defaults.
        using (TempSettingsDir tmpBig = new("tier5-oversize"))
        {
            string padding = new(' ', SettingsStore.MaxSettingsFileBytes + 64);
            string hugeJson = $"{{\"rendezvous_server\":\"ws://127.0.0.1:4400\"{padding}}}";
            File.WriteAllText(Path.Combine(tmpBig.Path, "settings.json"), hugeJson);

            SettingsStore store = new(tmpBig.Path);
            Assert.Equal(SettingsStore.DefaultRendezvousServer, store.Current.RendezvousServer);
        }

        // 3. Valid JSON with hostile/invalid fields falls back per-field while keeping valid flags.
        using (TempSettingsDir tmpHostile = new("tier5-hostile-fields"))
        {
            string hostileJson = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["rendezvous_server"] = "wss://example.test/\u202Eevil",
                ["relay_server"] = "ws://evil.example:4000/relay",
                ["stun_server"] = "stun.example.test:3478\u202E",
                ["privacy_relay_only"] = true,
                ["stronger_three_word_code"] = true,
            });
            File.WriteAllText(Path.Combine(tmpHostile.Path, "settings.json"), hostileJson);

            SettingsStore store = new(tmpHostile.Path);
            Assert.Equal(SettingsStore.DefaultRendezvousServer, store.Current.RendezvousServer);
            Assert.Equal(SettingsStore.DefaultRelayServer, store.Current.RelayServer);
            Assert.Equal(SettingsStore.DefaultStunServer, store.Current.StunServer);
            Assert.True(store.Current.PrivacyRelayOnly);
            Assert.True(store.Current.StrongerThreeWordCode);
        }

        // 4. Explicit empty relay_server = "" and stun_server = "" are preserved (distinct from omitted/null).
        using (TempSettingsDir tmpEmptyOverrides = new("tier5-empty-overrides"))
        {
            File.WriteAllText(
                Path.Combine(tmpEmptyOverrides.Path, "settings.json"),
                "{\"rendezvous_server\":\"ws://127.0.0.1:4400\",\"relay_server\":\"\",\"stun_server\":\"\"}");

            SettingsStore store = new(tmpEmptyOverrides.Path);
            Assert.Equal("ws://127.0.0.1:4400", store.Current.RendezvousServer);
            Assert.Equal(string.Empty, store.Current.RelayServer);
            Assert.Equal(string.Empty, store.Current.StunServer);
        }

        // 5. Tightened HasBasicWebSocketScheme design-time fallback enforces ws:// loopback-only & valid authority/port.
        string[] fallbackReject =
        [
            "ws://evil.example:4000",
            "ws://192.168.1.5:4000",
            "ws://[2001:db8::1]:4000",
            "wss://:443",
            "wss://example.test:",
            "wss://example.test:0",
            "wss://example.test:70000",
            "wss://user@example.test:443",
            "wss://example.test/#frag",
            "wss://example.test/\u202Eevil",
            "wss://example.test/a b",
            "http://127.0.0.1:4400",
        ];
        foreach (string bad in fallbackReject)
        {
            Assert.False(
                SettingsStore.HasBasicWebSocketScheme(bad),
                $"HasBasicWebSocketScheme must reject '{bad}'");
        }

        string[] fallbackAccept =
        [
            "wss://example.test",
            "wss://example.test:443/v0/relay",
            "wss://[2001:db8::1]:443/v0",
            "ws://localhost:4400",
            "ws://127.0.0.1:4400/ws",
            "ws://[::1]:4400",
        ];
        foreach (string good in fallbackAccept)
        {
            Assert.True(
                SettingsStore.HasBasicWebSocketScheme(good),
                $"HasBasicWebSocketScheme must accept '{good}'");
        }

        // 6. Concurrent Load() + TrySaveAtomic() stress test.
        using (TempSettingsDir tmpConc = new("tier5-concurrent"))
        {
            SettingsStore store = new(tmpConc.Path);
            BridgeNetworkConfigDto cfgA = SettingsStore.CreateDefaultConfig() with
            {
                RendezvousServer = "ws://127.0.0.1:4401",
                PrivacyRelayOnly = true,
            };
            BridgeNetworkConfigDto cfgB = SettingsStore.CreateDefaultConfig() with
            {
                RendezvousServer = "ws://127.0.0.1:4402",
                PrivacyRelayOnly = false,
            };
            Assert.True(store.TrySaveAtomic(cfgA));

            Task writer = Task.Run(() =>
            {
                for (int i = 0; i < 60; i++)
                {
                    Assert.True(store.TrySaveAtomic((i & 1) == 0 ? cfgA : cfgB));
                }
            });
            Task reader = Task.Run(() =>
            {
                for (int i = 0; i < 120; i++)
                {
                    BridgeNetworkConfigDto loaded = store.Load();
                    Assert.True(
                        loaded.RendezvousServer is "ws://127.0.0.1:4401" or "ws://127.0.0.1:4402",
                        $"Unexpected concurrent loaded URL: {loaded.RendezvousServer}");
                }
            });
            await Task.WhenAll(writer, reader);
            Assert.Empty(Directory.GetFiles(tmpConc.Path, "*.tmp"));
        }
    }
}
