// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using TotalDrop.WinUI.Interop;

namespace TotalDrop.WinUI.Services;

/// <summary>
/// Pure-managed representation of an incoming Windows Share Target payload so
/// routing logic can be tested headlessly on <c>net10.0</c> without WinRT UI.
/// </summary>
public sealed record ShareTargetInput(
    IReadOnlyList<string>? StorageItemPaths = null,
    string? WebLink = null,
    string? Text = null);

/// <summary>
/// Lifecycle contract mirroring <c>Windows.ApplicationModel.DataTransfer.ShareTarget.ShareOperation</c>.
/// </summary>
public interface IShareOperationLifecycle
{
    void ReportStarted();

    void ReportDataRetrieved();

    void ReportCompleted();
}

/// <summary>
/// Three-state outcome of routing an in-process activation frame through Rust
/// <c>WinUiWindowRouter</c>, distinguishing live Rust validation rejection from
/// design-time / shutdown unavailability.
/// </summary>
public enum LocalRouteOutcome
{
    /// <summary>Live Rust router accepted the frame and returned decisions.</summary>
    Routed,

    /// <summary>Live Rust router explicitly rejected an invalid or hostile frame.</summary>
    Rejected,

    /// <summary>Router handle or native DLL was unavailable or gate wait timed out.</summary>
    Unavailable,
}

/// <summary>
/// Outcome of routing an incoming Share Target payload through Rust
/// <c>WinUiWindowRouter</c>.
/// </summary>
public sealed record ShareTargetRouteResult(
    bool Succeeded,
    RouterDecisionDto[] Decisions,
    BridgeErrorDto? Error);

/// <summary>
/// Routes Windows Share Target payloads strictly through Rust
/// <c>totaldrop_win_router_ingest_ipc_bytes_json</c> with guaranteed
/// <c>ReportStarted -&gt; ReportDataRetrieved -&gt; ReportCompleted</c> lifecycle
/// completion across all exit paths (Features #17 &amp; #18, ADR 0016).
/// </summary>
public static class ShareTargetRouter
{
    private static readonly TimeSpan DefaultGateTimeout = TimeSpan.FromSeconds(2);

    public static ShareTargetRouteResult Route(
        ulong routerId,
        Func<ShareTargetInput> extractPayload,
        IShareOperationLifecycle lifecycle,
        uint? initiatorPid = null,
        object? routerLock = null)
    {
        bool dataRetrieved = false;
        try
        {
            lifecycle.ReportStarted();
            ShareTargetInput input = extractPayload();
            lifecycle.ReportDataRetrieved();
            dataRetrieved = true;
            return RouteExtractedInput(routerId, input, initiatorPid, routerLock);
        }
        catch (Exception ex)
        {
            return new ShareTargetRouteResult(
                Succeeded: false,
                Decisions: [],
                Error: new BridgeErrorDto("share_extract_failed", "errorOther", null, ex.Message));
        }
        finally
        {
            FinishLifecycle(lifecycle, dataRetrieved);
        }
    }

    public static Task<ShareTargetRouteResult> RouteAsync(
        ulong routerId,
        Func<Task<ShareTargetInput>> extractPayloadAsync,
        IShareOperationLifecycle lifecycle,
        uint? initiatorPid = null,
        object? routerLock = null) =>
        RouteAsync(
            routerId,
            extractPayloadAsync,
            lifecycle,
            initiatorPid,
            routerLock,
            routerStreamGate: null,
            gateTimeout: null);

    public static Task<ShareTargetRouteResult> RouteAsync(
        ulong routerId,
        Func<Task<ShareTargetInput>> extractPayloadAsync,
        IShareOperationLifecycle lifecycle,
        uint? initiatorPid,
        object? routerLock,
        SemaphoreSlim? routerStreamGate,
        TimeSpan? gateTimeout = null)
    {
        TimeSpan timeout = gateTimeout ?? DefaultGateTimeout;
        return RouteAsync(
            extractPayloadAsync,
            lifecycle,
            ingestFrameAsync: async frame =>
            {
                if (routerStreamGate is null)
                {
                    return IngestFramedBytes(routerId, frame, routerLock);
                }

                bool acquired = false;
                try
                {
                    if (!await routerStreamGate.WaitAsync(timeout).ConfigureAwait(false))
                    {
                        return new ShareTargetRouteResult(
                            Succeeded: false,
                            Decisions: [],
                            Error: new BridgeErrorDto("router_gate_timeout", "errorOther", null, "router stream gate timed out"));
                    }

                    acquired = true;
                    return IngestFramedBytes(routerId, frame, routerLock);
                }
                catch (ObjectDisposedException)
                {
                    return new ShareTargetRouteResult(
                        Succeeded: false,
                        Decisions: [],
                        Error: new BridgeErrorDto("router_disposed", "errorOther", null, "router stream gate disposed"));
                }
                finally
                {
                    if (acquired)
                    {
                        try
                        {
                            routerStreamGate.Release();
                        }
                        catch (ObjectDisposedException)
                        {
                            // Window teardown disposed the gate concurrently.
                        }
                    }
                }
            },
            initiatorPid: initiatorPid);
    }

    /// <summary>
    /// Runs WinRT payload extraction and <c>ReportDataRetrieved</c> strictly
    /// BEFORE invoking <paramref name="ingestFrameAsync"/> so callers never hold
    /// <c>_routerStreamGate</c> across async WinRT extraction calls.
    /// </summary>
    public static async Task<ShareTargetRouteResult> RouteAsync(
        Func<Task<ShareTargetInput>> extractPayloadAsync,
        IShareOperationLifecycle lifecycle,
        Func<byte[], Task<ShareTargetRouteResult>> ingestFrameAsync,
        uint? initiatorPid = null)
    {
        bool dataRetrieved = false;
        try
        {
            lifecycle.ReportStarted();
            ShareTargetInput input = await extractPayloadAsync().ConfigureAwait(false);
            lifecycle.ReportDataRetrieved();
            dataRetrieved = true;
            byte[] frame = BuildEnvelopeFrame(input, initiatorPid);
            return await ingestFrameAsync(frame).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new ShareTargetRouteResult(
                Succeeded: false,
                Decisions: [],
                Error: new BridgeErrorDto("share_extract_failed", "errorOther", null, ex.Message));
        }
        finally
        {
            FinishLifecycle(lifecycle, dataRetrieved);
        }
    }

    private static void FinishLifecycle(IShareOperationLifecycle lifecycle, bool dataRetrieved)
    {
        if (!dataRetrieved)
        {
            try
            {
                lifecycle.ReportDataRetrieved();
            }
            catch (Exception)
            {
                // Best-effort completion when ShareOperation fails during extraction.
            }
        }

        try
        {
            lifecycle.ReportCompleted();
        }
        catch (Exception)
        {
            // Never propagate WinRT share-broker teardown errors.
        }
    }

    private static ShareTargetRouteResult RouteExtractedInput(
        ulong routerId,
        ShareTargetInput input,
        uint? initiatorPid,
        object? routerLock)
    {
        if (routerId == 0)
        {
            return new ShareTargetRouteResult(
                Succeeded: false,
                Decisions: [],
                Error: new BridgeErrorDto("invalid_handle", "errorOther", null, "router handle is not initialized"));
        }

        byte[] frame = BuildEnvelopeFrame(input, initiatorPid);
        return IngestFramedBytes(routerId, frame, routerLock);
    }

    private static ShareTargetRouteResult IngestFramedBytes(
        ulong routerId,
        byte[] frame,
        object? routerLock)
    {
        if (routerId == 0)
        {
            return new ShareTargetRouteResult(
                Succeeded: false,
                Decisions: [],
                Error: new BridgeErrorDto("invalid_handle", "errorOther", null, "router handle is not initialized"));
        }

        if (routerLock is not null)
        {
            lock (routerLock)
            {
                return IngestFrameAndFlushLocked(routerId, frame);
            }
        }

        return IngestFrameAndFlushLocked(routerId, frame);
    }

    private static byte[] BuildEnvelopeFrame(ShareTargetInput input, uint? initiatorPid)
    {
        if (input.StorageItemPaths is { Count: > 0 } paths)
        {
            return NativeBridge.BuildFramedShareTargetEnvelope(paths, text: null, initiatorPid);
        }

        string? candidate = !string.IsNullOrWhiteSpace(input.WebLink)
            ? input.WebLink
            : !string.IsNullOrEmpty(input.Text)
                ? input.Text
                : null;

        if (!string.IsNullOrEmpty(candidate))
        {
            string trimmed = candidate.Trim();
            if (NativeBridge.TryValidateUri(trimmed, out ValidatedCodeDto? validated, out _)
                && validated is not null)
            {
                // Valid TotalDrop link routes to Receive without auto-dialing.
                return NativeBridge.BuildFramedProtocolUriEnvelope(validated, initiatorPid);
            }

            // Plain text and non-TotalDrop URLs route to SendPage text mode (#313).
            return NativeBridge.BuildFramedShareTargetEnvelope(rawPaths: null, text: candidate, initiatorPid);
        }

        // Empty ShareTarget payload falls back to Send screen via Rust router.
        return NativeBridge.BuildFramedShareTargetEnvelope(rawPaths: null, text: null, initiatorPid);
    }

    internal static ShareTargetRouteResult IngestFrameAndFlushLocked(ulong routerId, byte[] frame)
    {
        try
        {
            if (!NativeBridge.TryIngestRouterIpcBytes(
                    routerId,
                    frame,
                    out RouterDecisionDto[] decisions,
                    out BridgeErrorDto? ingestError))
            {
                return new ShareTargetRouteResult(Succeeded: false, Decisions: [], Error: ingestError);
            }

            if (!NativeBridge.TryIngestRouterIpcBytes(
                    routerId,
                    ReadOnlySpan<byte>.Empty,
                    out _,
                    out BridgeErrorDto? eofError))
            {
                return new ShareTargetRouteResult(Succeeded: false, Decisions: [], Error: eofError);
            }

            return new ShareTargetRouteResult(Succeeded: true, Decisions: decisions, Error: null);
        }
        finally
        {
            // Immediately drain Rust's WinUiWindowRouter outbox so Share Target
            // plaintext and path lists are never retained in Rust heap memory.
            _ = NativeBridge.TryDrainRouterNdjson(routerId, out _, out _);
        }
    }
}
