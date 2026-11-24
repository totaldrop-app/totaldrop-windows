// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Text;
using System.Text.Json;
using TotalDrop.WinUI.Interop;

namespace TotalDrop.WinUI.Services;

/// <summary>
/// Persists user settings locally to <c>%LOCALAPPDATA%\TotalDrop\settings.json</c>
/// using atomic temp-file flush + replace (never cloud-synced via Windows
/// roaming storage, ADR 0016).
/// </summary>
public sealed class SettingsStore
{
    public const string DefaultRendezvousServer = "wss://rendezvous.totaldrop.app";
    public const string DefaultRelayServer = "wss://relay.totaldrop.app/v0/relay";
    public const string DefaultStunServer = "stun.cloudflare.com:3478";

    public const int MaxSettingsFileBytes = 65_536;

    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly object _sync = new();
    private readonly string _directoryPath;
    private BridgeNetworkConfigDto _current;

    public string SettingsPath { get; }

    public BridgeNetworkConfigDto Current
    {
        get
        {
            lock (_sync)
            {
                return _current;
            }
        }
    }

    public bool CanResetServer =>
        !string.Equals(Current.RendezvousServer, DefaultRendezvousServer, StringComparison.Ordinal);

    public SettingsStore(string? directoryOverride = null)
    {
        _directoryPath = string.IsNullOrWhiteSpace(directoryOverride)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "TotalDrop")
            : directoryOverride;
        SettingsPath = Path.Combine(_directoryPath, "settings.json");
        _current = Load();
    }

    public static BridgeNetworkConfigDto CreateDefaultConfig() =>
        new(
            RendezvousServer: DefaultRendezvousServer,
            RelayServer: DefaultRelayServer,
            StunServer: DefaultStunServer,
            PrivacyRelayOnly: false,
            StrongerThreeWordCode: false);

    /// <summary>
    /// Reads <see cref="SettingsPath"/> safely, falling back to
    /// <see cref="CreateDefaultConfig"/> on missing, symlinked, oversized
    /// (&gt; 64 KiB), empty, or corrupt JSON without throwing. Preserves explicit
    /// empty strings (<c>""</c>) for relay/STUN overrides while defaulting
    /// omitted (<see langword="null"/>) or invalid fields.
    /// </summary>
    public BridgeNetworkConfigDto Load()
    {
        BridgeNetworkConfigDto defaults = CreateDefaultConfig();
        if (!File.Exists(SettingsPath))
        {
            return defaults;
        }

        try
        {
            if (IsSymlinkOrReparsePoint(SettingsPath))
            {
                return defaults;
            }

            byte[]? bytes = ReadBoundedSettingsBytes(SettingsPath);
            if (bytes is null || bytes.Length == 0)
            {
                return defaults;
            }

            AppSettingsFileDto? parsed = JsonSerializer.Deserialize(
                bytes,
                TotalDropJsonContext.Default.AppSettingsFileDto);
            if (parsed is null)
            {
                return defaults;
            }

            string rendezvousCandidate = string.IsNullOrWhiteSpace(parsed.RendezvousServer)
                ? defaults.RendezvousServer
                : parsed.RendezvousServer.Trim();
            string rendezvous = IsValidLoadedServerUrl(rendezvousCandidate)
                ? rendezvousCandidate
                : defaults.RendezvousServer;

            string relay;
            if (parsed.RelayServer is null)
            {
                relay = defaults.RelayServer;
            }
            else
            {
                string relayTrimmed = parsed.RelayServer.Trim();
                relay = relayTrimmed.Length == 0 || IsValidLoadedServerUrl(relayTrimmed)
                    ? relayTrimmed
                    : defaults.RelayServer;
            }

            string stun;
            if (parsed.StunServer is null)
            {
                stun = defaults.StunServer;
            }
            else
            {
                string stunTrimmed = parsed.StunServer.Trim();
                stun = !ContainsDisallowedControlOrBidi(stunTrimmed)
                    ? stunTrimmed
                    : defaults.StunServer;
            }

            return new BridgeNetworkConfigDto(
                RendezvousServer: rendezvous,
                RelayServer: relay,
                StunServer: stun,
                PrivacyRelayOnly: parsed.PrivacyRelayOnly ?? defaults.PrivacyRelayOnly,
                StrongerThreeWordCode: parsed.StrongerThreeWordCode ?? defaults.StrongerThreeWordCode);
        }
        catch (IOException)
        {
            return defaults;
        }
        catch (UnauthorizedAccessException)
        {
            return defaults;
        }
        catch (JsonException)
        {
            return defaults;
        }
        catch (NotSupportedException)
        {
            return defaults;
        }
        catch (ArgumentException)
        {
            return defaults;
        }
    }

    /// <summary>
    /// Atomically writes <paramref name="config"/> to <see cref="SettingsPath"/>
    /// via a sibling temp file, disk flush, and overwrite move. On failure,
    /// cleans up the temp file and leaves any existing <c>settings.json</c>
    /// untouched.
    /// </summary>
    public bool TrySaveAtomic(BridgeNetworkConfigDto config)
    {
        lock (_sync)
        {
            return TrySaveAtomicLocked(config);
        }
    }

    /// <summary>
    /// Validates <paramref name="rawUrl"/> strictly via Rust
    /// <c>totaldrop_win_validate_server_url_json</c> before atomically saving.
    /// Invalid URLs are rejected with <c>"settingsServerInvalid"</c> without
    /// touching <c>settings.json</c>.
    /// </summary>
    public bool TrySaveServerUrl(string rawUrl, out string? errorL10nKey)
    {
        errorL10nKey = null;
        string trimmed = (rawUrl ?? string.Empty).Trim();
        if (!NativeBridge.TryValidateServerUrl(trimmed, out _))
        {
            errorL10nKey = "settingsServerInvalid";
            return false;
        }

        lock (_sync)
        {
            BridgeNetworkConfigDto updated = _current with { RendezvousServer = trimmed };
            if (!TrySaveAtomicLocked(updated))
            {
                errorL10nKey = "errorStorage";
                return false;
            }
        }

        return true;
    }

    public bool TryResetServerUrl()
    {
        lock (_sync)
        {
            BridgeNetworkConfigDto updated = _current with { RendezvousServer = DefaultRendezvousServer };
            return TrySaveAtomicLocked(updated);
        }
    }

    public bool TrySetPrivacyMode(bool enabled)
    {
        lock (_sync)
        {
            BridgeNetworkConfigDto updated = _current with { PrivacyRelayOnly = enabled };
            return TrySaveAtomicLocked(updated);
        }
    }

    public bool TrySetStrongerThreeWordCode(bool enabled)
    {
        lock (_sync)
        {
            BridgeNetworkConfigDto updated = _current with { StrongerThreeWordCode = enabled };
            return TrySaveAtomicLocked(updated);
        }
    }

    private bool TrySaveAtomicLocked(BridgeNetworkConfigDto config)
    {
        string tempPath = Path.Combine(_directoryPath, $"settings.{Guid.NewGuid():N}.tmp");
        try
        {
            Directory.CreateDirectory(_directoryPath);
            string json = JsonSerializer.Serialize(
                config,
                TotalDropJsonContext.Default.BridgeNetworkConfigDto);

            using (FileStream fs = new(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.None))
            {
                byte[] utf8 = Utf8NoBom.GetBytes(json);
                fs.Write(utf8, 0, utf8.Length);
                fs.Flush(flushToDisk: true);
            }

            File.Move(tempPath, SettingsPath, overwrite: true);
            _current = config;
            return true;
        }
        catch (IOException)
        {
            TryDeleteSilently(tempPath);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            TryDeleteSilently(tempPath);
            return false;
        }
        catch (NotSupportedException)
        {
            TryDeleteSilently(tempPath);
            return false;
        }
        catch (ArgumentException)
        {
            TryDeleteSilently(tempPath);
            return false;
        }
    }

    private static bool IsSymlinkOrReparsePoint(string path)
    {
        FileAttributes attrs = File.GetAttributes(path);
        if ((attrs & FileAttributes.ReparsePoint) != 0)
        {
            return true;
        }

        return new FileInfo(path).LinkTarget is not null;
    }

    private static byte[]? ReadBoundedSettingsBytes(string path)
    {
        using FileStream fs = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);

        if (fs.CanSeek && fs.Length > MaxSettingsFileBytes)
        {
            return null;
        }

        using MemoryStream ms = new();
        byte[] buffer = new byte[4096];
        int totalRead = 0;
        while (true)
        {
            int read = fs.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
            if (totalRead > MaxSettingsFileBytes)
            {
                return null;
            }

            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }

    private static bool IsValidLoadedServerUrl(string candidate)
    {
        if (string.IsNullOrEmpty(candidate) || ContainsDisallowedControlOrBidi(candidate))
        {
            return false;
        }

        try
        {
            return NativeBridge.TryValidateServerUrl(candidate, out _);
        }
        catch (DllNotFoundException)
        {
            // Design-time fallback when totaldrop_windows_ffi.dll is unavailable.
            return HasBasicWebSocketScheme(candidate);
        }
    }

    private static bool HasBasicWebSocketScheme(string candidate)
    {
        string rest;
        if (candidate.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
        {
            rest = candidate[6..];
        }
        else if (candidate.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            rest = candidate[5..];
        }
        else
        {
            return false;
        }

        if (rest.Length == 0 || rest.Contains('#'))
        {
            return false;
        }

        int slashIdx = rest.IndexOfAny(['/', '?']);
        string authority = slashIdx >= 0 ? rest[..slashIdx] : rest;
        if (authority.Length == 0 || authority.Contains('@'))
        {
            return false;
        }

        foreach (char c in authority)
        {
            if (char.IsWhiteSpace(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ContainsDisallowedControlOrBidi(string value)
    {
        foreach (Rune rune in value.EnumerateRunes())
        {
            int cp = rune.Value;
            if (Rune.IsControl(rune)
                || cp == 0x00AD
                || (cp >= 0x0600 && cp <= 0x0605)
                || cp == 0x061C
                || cp == 0x06DD
                || cp == 0x070F
                || (cp >= 0x0890 && cp <= 0x0891)
                || cp == 0x08E2
                || cp == 0x180E
                || (cp >= 0x200B && cp <= 0x200F)
                || (cp >= 0x2028 && cp <= 0x202E)
                || (cp >= 0x2060 && cp <= 0x206F)
                || (cp >= 0xFDD0 && cp <= 0xFDEF)
                || cp == 0xFEFF
                || (cp >= 0xFFF9 && cp <= 0xFFFB)
                || cp == 0x110BD
                || cp == 0x110CD
                || (cp >= 0x13430 && cp <= 0x1343F)
                || (cp >= 0x1BCA0 && cp <= 0x1BCA3)
                || (cp >= 0x1D173 && cp <= 0x1D17A)
                || (cp >= 0xE0000 && cp <= 0xE007F)
                || (cp & 0xFFFE) == 0xFFFE)
            {
                return true;
            }
        }

        return false;
    }

    private static void TryDeleteSilently(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Ignore cleanup errors on failing storage.
        }
        catch (UnauthorizedAccessException)
        {
            // Ignore cleanup errors on failing storage.
        }
        catch (NotSupportedException)
        {
            // Ignore cleanup errors on failing storage.
        }
        catch (ArgumentException)
        {
            // Ignore cleanup errors on failing storage.
        }
    }
}
