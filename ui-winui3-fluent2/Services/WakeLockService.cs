// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace TotalDrop.WinUI.Services;

internal enum PowerRequestType : int
{
    DisplayRequired = 0,
    SystemRequired = 1,
    AwayModeRequired = 2,
    ExecutionRequired = 3,
}

/// <summary>
/// Exact 32-byte WinNT <c>REASON_CONTEXT</c> layout on 64-bit Windows (<c>x64</c>
/// and <c>ARM64</c>): <c>ULONG Version (4) + DWORD Flags (4) + union Reason (24)</c>
/// == 32 bytes. 100% blittable for <c>[assembly: DisableRuntimeMarshalling]</c>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct PowerRequestContext
{
    public uint Version;             // 0 = POWER_REQUEST_CONTEXT_VERSION
    public uint Flags;               // 1 = POWER_REQUEST_CONTEXT_SIMPLE_STRING
    public char* SimpleReasonString; // LPWSTR (pinned UTF-16 string)
    public uint Reserved1;           // Detailed.LocalizedReasonId tail
    public uint Reserved2;           // Detailed.ReasonStringCount tail
    public nint Reserved3;           // Detailed.ReasonStrings tail
}

internal static partial class PowerRequestNative
{
    public const uint ContextVersion = 0;
    public const uint ContextSimpleString = 0x0000_0001;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static unsafe partial nint PowerCreateRequest(in PowerRequestContext context);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PowerSetRequest(nint powerRequest, PowerRequestType requestType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PowerClearRequest(nint powerRequest, PowerRequestType requestType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint hObject);
}

/// <summary>
/// Injectable Win32 <c>PowerCreateRequest</c> backend enabling deterministic
/// headless unit testing on both Linux and Windows.
/// </summary>
public interface IPowerRequestBackend
{
    bool TryAcquire(string reason, out nint handle);

    void Release(nint handle);
}

internal sealed class Win32PowerRequestBackend : IPowerRequestBackend
{
    public unsafe bool TryAcquire(string reason, out nint handle)
    {
        handle = 0;
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            fixed (char* reasonPtr = reason)
            {
                PowerRequestContext ctx = new()
                {
                    Version = PowerRequestNative.ContextVersion,
                    Flags = PowerRequestNative.ContextSimpleString,
                    SimpleReasonString = reasonPtr,
                };

                nint created = PowerRequestNative.PowerCreateRequest(in ctx);
                if (created == 0 || created == -1)
                {
                    return false;
                }

                if (!PowerRequestNative.PowerSetRequest(created, PowerRequestType.SystemRequired))
                {
                    _ = PowerRequestNative.CloseHandle(created);
                    return false;
                }

                handle = created;
                return true;
            }
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    public void Release(nint handle)
    {
        if (handle == 0 || handle == -1 || !OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            _ = PowerRequestNative.PowerClearRequest(handle, PowerRequestType.SystemRequired);
            _ = PowerRequestNative.CloseHandle(handle);
        }
        catch (DllNotFoundException)
        {
            // Non-Windows or design-time preview.
        }
        catch (EntryPointNotFoundException)
        {
            // Non-Windows or design-time preview.
        }
    }
}

/// <summary>
/// Serialized, idempotent Windows keep-awake power request service
/// (<c>PowerCreateRequest</c> + <c>PowerRequestSystemRequired</c>,
/// <c>totaldrop-app/totaldrop#340</c>, Feature #20).
/// <para>
/// Holds at most one active <c>SYSTEM</c> power request per process during the
/// 6 awake stages (<c>Preparing</c>, <c>Waiting</c>, <c>Connected</c>,
/// <c>Transferring</c>, <c>Connecting</c>, <c>Offer</c>) while allowing the
/// display to dim or lock, and releases immediately on the 4 sleep stages
/// (<c>Idle</c>, <c>Done</c>, <c>Failed</c>, <c>Declined</c>) and on dispose.
/// </para>
/// <para>
/// <b>Modern Standby (S0ix) DC Battery Caveat:</b> On Modern Standby Windows 11
/// laptops running on battery power, Windows may cap unprivileged desktop
/// <c>PowerRequestSystemRequired</c> requests after ~5 minutes of idle screen-off
/// time; this is an OS power-policy boundary rather than a handle leak.
/// </para>
/// </summary>
public sealed partial class WakeLockService : IDisposable
{
    private readonly IPowerRequestBackend _backend;
    private readonly object _gate = new();
    private nint _activeHandle;
    private bool _disposed;

    public WakeLockService(IPowerRequestBackend? backend = null)
    {
        _backend = backend ?? new Win32PowerRequestBackend();
    }

    public bool IsAwakeHeld
    {
        get
        {
            lock (_gate)
            {
                return _activeHandle != 0;
            }
        }
    }

    /// <summary>
    /// Exact 6-awake / 4-sleep truth table matching Linux <c>stage.rs:85-96</c>.
    /// </summary>
    public static bool StageKeepsAwake(TransferLifecycleStage stage) =>
        stage is TransferLifecycleStage.Preparing
            or TransferLifecycleStage.Waiting
            or TransferLifecycleStage.Connected
            or TransferLifecycleStage.Transferring
            or TransferLifecycleStage.Connecting
            or TransferLifecycleStage.Offer;

    public static bool ShouldStayAwake(TransferLifecycleStage sendStage, TransferLifecycleStage receiveStage) =>
        StageKeepsAwake(sendStage) || StageKeepsAwake(receiveStage);

    public void UpdateStage(TransferLifecycleStage stage, string reason) =>
        SetAwake(StageKeepsAwake(stage), reason);

    public void UpdateStages(
        TransferLifecycleStage sendStage,
        TransferLifecycleStage receiveStage,
        string reason) =>
        SetAwake(ShouldStayAwake(sendStage, receiveStage), reason);

    public void SetAwake(bool shouldStayAwake, string reason)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (shouldStayAwake)
            {
                if (_activeHandle != 0)
                {
                    return;
                }

                string safeReason = SanitizeReason(reason);
                if (_backend.TryAcquire(safeReason, out nint acquired) && acquired != 0 && acquired != -1)
                {
                    _activeHandle = acquired;
                }
            }
            else if (_activeHandle != 0)
            {
                nint toRelease = _activeHandle;
                _activeHandle = 0;
                _backend.Release(toRelease);
            }
        }
    }

    public void Dispose()
    {
        nint toRelease;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            toRelease = _activeHandle;
            _activeHandle = 0;
        }

        if (toRelease != 0)
        {
            _backend.Release(toRelease);
        }
    }

    internal static int NativeContextSizeBytes()
    {
        unsafe
        {
            return sizeof(PowerRequestContext);
        }
    }

    private const int MaxReasonLength = 256;

    private static bool IsDisallowedReasonScalar(int cp)
    {
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

    internal static string SanitizeReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            return "TotalDrop";
        }

        ReadOnlySpan<char> trimmed = reason.AsSpan().Trim();
        Span<char> buffer = stackalloc char[MaxReasonLength];
        int written = 0;
        for (int i = 0; i < trimmed.Length; i++)
        {
            char c = trimmed[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < trimmed.Length && char.IsLowSurrogate(trimmed[i + 1]))
                {
                    char low = trimmed[i + 1];
                    int cp = char.ConvertToUtf32(c, low);
                    i++;
                    if (IsDisallowedReasonScalar(cp))
                    {
                        continue;
                    }

                    if (written + 2 > MaxReasonLength)
                    {
                        break;
                    }

                    buffer[written++] = c;
                    buffer[written++] = low;
                }

                // Skip lone/unpaired high surrogates.
                continue;
            }

            if (char.IsLowSurrogate(c) || IsDisallowedReasonScalar(c))
            {
                continue;
            }

            if (written >= MaxReasonLength)
            {
                break;
            }

            buffer[written++] = c;
        }

        string cleaned = new string(buffer[..written]).Trim();
        return string.IsNullOrEmpty(cleaned) ? "TotalDrop" : cleaned;
    }
}
