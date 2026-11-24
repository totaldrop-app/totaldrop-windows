// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

public sealed class WakeLockServiceTests
{
    private sealed class FakePowerRequestBackend : IPowerRequestBackend
    {
        private nint _nextHandle = 100;

        public bool FailAcquires { get; set; }

        public List<string> AcquiredReasons { get; } = [];

        public List<nint> AcquiredHandles { get; } = [];

        public List<nint> ReleasedHandles { get; } = [];

        public bool TryAcquire(string reason, out nint handle)
        {
            if (FailAcquires)
            {
                handle = 0;
                return false;
            }

            handle = ++_nextHandle;
            AcquiredReasons.Add(reason);
            AcquiredHandles.Add(handle);
            return true;
        }

        public void Release(nint handle)
        {
            ReleasedHandles.Add(handle);
        }
    }

    [Fact]
    public void T1_F20_01_ExactSixAwakeFourSleepStageMatrix_IdempotentAndDisposed()
    {
        // Exact 32-byte WinNT REASON_CONTEXT layout on 64-bit x64/ARM64
        Assert.Equal(32, WakeLockService.NativeContextSizeBytes());

        TransferLifecycleStage[] awakeStages =
        [
            TransferLifecycleStage.Preparing,
            TransferLifecycleStage.Waiting,
            TransferLifecycleStage.Connected,
            TransferLifecycleStage.Transferring,
            TransferLifecycleStage.Connecting,
            TransferLifecycleStage.Offer,
        ];
        TransferLifecycleStage[] sleepStages =
        [
            TransferLifecycleStage.Idle,
            TransferLifecycleStage.Done,
            TransferLifecycleStage.Failed,
            TransferLifecycleStage.Declined,
        ];

        Assert.Equal(6, awakeStages.Length);
        Assert.Equal(4, sleepStages.Length);
        Assert.Equal(10, Enum.GetValues<TransferLifecycleStage>().Length);

        foreach (TransferLifecycleStage s in awakeStages)
        {
            Assert.True(WakeLockService.StageKeepsAwake(s), $"Expected awake stage: {s}");
        }

        foreach (TransferLifecycleStage s in sleepStages)
        {
            Assert.False(WakeLockService.StageKeepsAwake(s), $"Expected sleep stage: {s}");
        }

        FakePowerRequestBackend backend = new();
        using WakeLockService svc = new(backend);
        Assert.False(svc.IsAwakeHeld);

        // Transition across all 6 awake stages sequentially: MUST acquire exactly ONCE (idempotent).
        foreach (TransferLifecycleStage s in awakeStages)
        {
            svc.UpdateStage(s, "TotalDrop transfer in progress");
            Assert.True(svc.IsAwakeHeld);
        }

        Assert.Single(backend.AcquiredHandles);
        Assert.Empty(backend.ReleasedHandles);

        // Each of the 4 sleep stages releases cleanly and stays released.
        foreach (TransferLifecycleStage s in sleepStages)
        {
            svc.UpdateStage(TransferLifecycleStage.Transferring, "Transferring");
            Assert.True(svc.IsAwakeHeld);
            svc.UpdateStage(s, "Done");
            Assert.False(svc.IsAwakeHeld);
        }

        Assert.Equal(backend.AcquiredHandles.Count, backend.ReleasedHandles.Count);

        // Combined dual-role UpdateStages keeps awake if EITHER send or receive is active.
        svc.UpdateStages(TransferLifecycleStage.Done, TransferLifecycleStage.Offer, "Incoming offer");
        Assert.True(svc.IsAwakeHeld);
        svc.UpdateStages(TransferLifecycleStage.Idle, TransferLifecycleStage.Declined, "Declined");
        Assert.False(svc.IsAwakeHeld);

        // Dispose releases any active handle and prevents subsequent acquisition.
        svc.UpdateStage(TransferLifecycleStage.Waiting, "Waiting for peer");
        Assert.True(svc.IsAwakeHeld);
        svc.Dispose();
        Assert.False(svc.IsAwakeHeld);
        Assert.Equal(backend.AcquiredHandles.Count, backend.ReleasedHandles.Count);

        int countAfterDispose = backend.AcquiredHandles.Count;
        svc.UpdateStage(TransferLifecycleStage.Transferring, "After dispose");
        Assert.False(svc.IsAwakeHeld);
        Assert.Equal(countAfterDispose, backend.AcquiredHandles.Count);
    }

    [Fact]
    public void T2_F20_05_DisposeFailureAndReasonSanitization_ZeroHandleLeakOrCrash()
    {
        // (a) Backend acquisition failure never throws or corrupts state
        FakePowerRequestBackend failingBackend = new() { FailAcquires = true };
        using (WakeLockService svc = new(failingBackend))
        {
            svc.UpdateStage(TransferLifecycleStage.Transferring, "Active transfer");
            Assert.False(svc.IsAwakeHeld);
            svc.UpdateStage(TransferLifecycleStage.Idle, "Idle");
            Assert.Empty(failingBackend.ReleasedHandles);
        }

        // (b) Double Dispose releases held handle at most once
        FakePowerRequestBackend doubleDisposeBackend = new();
        WakeLockService svc2 = new(doubleDisposeBackend);
        svc2.UpdateStage(TransferLifecycleStage.Preparing, "Preparing");
        Assert.True(svc2.IsAwakeHeld);
        svc2.Dispose();
        svc2.Dispose();
        Assert.Single(doubleDisposeBackend.AcquiredHandles);
        Assert.Single(doubleDisposeBackend.ReleasedHandles);

        // (c) Reason sanitization: control chars, lone surrogates, >256 UTF-16 truncation, empty fallback
        Assert.Equal("TotalDrop", WakeLockService.SanitizeReason(null));
        Assert.Equal("TotalDrop", WakeLockService.SanitizeReason("   \r\n\t  "));
        Assert.Equal("TotalDrop", WakeLockService.SanitizeReason("\0\u0007\u001B\uD800"));

        string cleaned = WakeLockService.SanitizeReason("  Transfer\0\r\n\u001B active \uD800 OK  ");
        Assert.Equal("Transfer active  OK", cleaned);

        // 255 'a' + 2-unit emoji '🚀' (= 257 UTF-16) must truncate cleanly to 255 without splitting surrogate pair
        string boundary = new string('a', 255) + "\U0001F680";
        string truncated = WakeLockService.SanitizeReason(boundary);
        Assert.Equal(255, truncated.Length);
        Assert.DoesNotContain(truncated, static c => char.IsSurrogate(c));
    }
}
