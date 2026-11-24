// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Runtime.InteropServices;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace TotalDrop.WinUI.Interop;

/// <summary>
/// Native AOT-safe outgoing Windows Share Sheet (<see cref="DataTransferManager"/>)
/// helper using CsWinRT <see cref="ActivationFactory"/> and explicit COM vtable
/// function pointers (<c>IDataTransferManagerInterop : IUnknown</c>).
/// Zero legacy COM-import or runtime P/Invoke attributes, zero reflection, and
/// zero extra Win32 DLL dependencies (ADR 0016).
/// </summary>
internal static unsafe class WindowsShareSheet
{
    // ShObjIdl_core.h: IDataTransferManagerInterop inherits directly from IUnknown
    // (slot 0: QueryInterface, 1: AddRef, 2: Release, 3: GetForWindow, 4: ShowShareUIForWindow).
    private static readonly Guid IidDataTransferManagerInterop =
        new("3A3DCD6C-3EAB-43DC-BCDE-45671CE800C8");

    private static readonly Guid IidDataTransferManager =
        new("A5CAEE9B-8708-49D1-8D36-67D25A8DA00C");

    private sealed record SharePayload(string Title, string Text, Uri? WebLink);

    private static readonly object Gate = new();
    private static DataTransferManager? _attachedDtm;
    private static nint _attachedHwnd;
    private static SharePayload? _pendingPayload;

    /// <summary>
    /// Opens the Windows 11 Share Sheet for <paramref name="hwnd"/> populated with
    /// the transfer code/message and optional <c>https://totaldrop.app/r#</c> web link.
    /// Returns <see langword="false"/> if the Share Broker is unavailable so callers
    /// can fall back cleanly to the clipboard.
    /// </summary>
    public static bool TryShowShareSheet(nint hwnd, string title, string text, string? webUri)
    {
        if (hwnd == 0 || string.IsNullOrEmpty(text))
        {
            return false;
        }

        Uri? parsedUri = !string.IsNullOrEmpty(webUri)
            && Uri.TryCreate(webUri, UriKind.Absolute, out Uri? uri)
            && (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            ? uri
            : null;
        string safeTitle = string.IsNullOrWhiteSpace(title) ? "TotalDrop" : title;

        nint interopPtr = 0;
        nint dtmPtr = 0;
        try
        {
            using IObjectReference factory = ActivationFactory.Get(
                "Windows.ApplicationModel.DataTransfer.DataTransferManager");
            nint factoryPtr = factory.ThisPtr;
            if (factoryPtr == 0)
            {
                return false;
            }

            // Slot 0: IUnknown::QueryInterface for IID_IDataTransferManagerInterop.
            void** factoryVtbl = *(void***)factoryPtr;
            delegate* unmanaged[Stdcall]<nint, Guid*, nint*, int> qi =
                (delegate* unmanaged[Stdcall]<nint, Guid*, nint*, int>)factoryVtbl[0];
            Guid interopIid = IidDataTransferManagerInterop;
            int hr = qi(factoryPtr, &interopIid, &interopPtr);
            if (hr < 0 || interopPtr == 0)
            {
                return false;
            }

            // Slot 3: IDataTransferManagerInterop::GetForWindow(hwnd, IID_IDataTransferManager, &dtmPtr).
            void** interopVtbl = *(void***)interopPtr;
            delegate* unmanaged[Stdcall]<nint, nint, Guid*, nint*, int> getForWindow =
                (delegate* unmanaged[Stdcall]<nint, nint, Guid*, nint*, int>)interopVtbl[3];
            Guid dtmIid = IidDataTransferManager;
            hr = getForWindow(interopPtr, hwnd, &dtmIid, &dtmPtr);
            if (hr < 0 || dtmPtr == 0)
            {
                return false;
            }

            // Project ABI pointer to managed DataTransferManager (FromAbi AddRefs; finally releases dtmPtr).
            DataTransferManager dtm = DataTransferManager.FromAbi(dtmPtr);
            lock (Gate)
            {
                _pendingPayload = new SharePayload(safeTitle, text, parsedUri);
                if (!ReferenceEquals(_attachedDtm, dtm) || _attachedHwnd != hwnd)
                {
                    if (_attachedDtm is not null)
                    {
                        _attachedDtm.DataRequested -= OnDataRequested;
                    }

                    dtm.DataRequested += OnDataRequested;
                    _attachedDtm = dtm;
                    _attachedHwnd = hwnd;
                }
            }

            // Slot 4: IDataTransferManagerInterop::ShowShareUIForWindow(hwnd).
            delegate* unmanaged[Stdcall]<nint, nint, int> showShareUi =
                (delegate* unmanaged[Stdcall]<nint, nint, int>)interopVtbl[4];
            hr = showShareUi(interopPtr, hwnd);
            return hr >= 0;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (dtmPtr != 0)
            {
                Marshal.Release(dtmPtr);
            }

            if (interopPtr != 0)
            {
                Marshal.Release(interopPtr);
            }
        }
    }

    /// <summary>
    /// Detaches any cached <see cref="DataTransferManager"/> event handler during
    /// window teardown so no stale callback outlives the window.
    /// </summary>
    public static void Detach()
    {
        lock (Gate)
        {
            if (_attachedDtm is not null)
            {
                try
                {
                    _attachedDtm.DataRequested -= OnDataRequested;
                }
                catch (Exception)
                {
                    // Ignore COM teardown errors during window shutdown.
                }

                _attachedDtm = null;
            }

            _attachedHwnd = 0;
            _pendingPayload = null;
        }
    }

    private static void OnDataRequested(DataTransferManager sender, DataRequestedEventArgs args)
    {
        SharePayload? payload;
        lock (Gate)
        {
            payload = _pendingPayload;
        }

        if (payload is null)
        {
            return;
        }

        try
        {
            args.Request.Data.Properties.Title = payload.Title;
            args.Request.Data.SetText(payload.Text);
            if (payload.WebLink is not null)
            {
                args.Request.Data.SetWebLink(payload.WebLink);
            }
        }
        catch (Exception)
        {
            // Ignore transient WinRT Share Broker / COM errors during DataRequested.
        }
    }
}
