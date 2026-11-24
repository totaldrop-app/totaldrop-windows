// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.ViewModels;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using Windows.UI.ViewManagement;
using WinRT.Interop;

namespace TotalDrop.WinUI.Views;

/// <summary>
/// Fluent 2 Send screen code-behind handling Files/Folders pickers, Explorer
/// drag-and-drop (all routed through Rust <c>totaldrop_win_validate_paths_json</c>),
/// plain-text sending (<c>MAX_TEXT = 1 MiB</c>), live async FFI polling,
/// reduced-motion Kose animation gating, and cancel confirmation dialogs.
/// </summary>
public sealed partial class SendPage : Page
{
    private readonly UISettings _uiSettings = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _pollTimer;
    private bool _koseAnimating;
    private ContentDialog? _activeCancelDialog;

    public SendViewModel ViewModel { get; private set; } = new();

    public SendPage()
    {
        InitializeComponent();
        Unloaded += OnPageUnloaded;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is SendViewModel vm)
        {
            ViewModel = vm;
            Bindings.Update();
            RefreshKoseAnimation();
            if (ViewModel.ActiveSessionId != 0 && ViewModel.IsTransferRunning)
            {
                StartPolling();
                PollSessionOnce();
            }
        }
    }

    public void ShutdownSession()
    {
        StopPolling();
        DismissActiveDialog();
        ulong sid = ViewModel.ActiveSessionId;
        if (sid != 0)
        {
            try
            {
                _ = NativeBridge.SessionCancel(sid);
                _ = NativeBridge.SessionDestroy(sid);
            }
            catch (DllNotFoundException)
            {
                // Design-time preview fallback.
            }

            ViewModel.ActiveSessionId = 0;
        }

        RefreshKoseAnimation();
    }

    private void OnPageUnloaded(object sender, RoutedEventArgs e)
    {
        StopPolling();
        DismissActiveDialog();
    }

    private void OnPagePreviewKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Escape && ViewModel.HasUnsentInput)
        {
            // Keep unsent files/text intact on Escape (Linux SendPage.qml parity).
            e.Handled = true;
        }
    }

    private void OnSwitchToFilesModeClick(object sender, RoutedEventArgs e)
    {
        ViewModel.Mode = SendInputMode.Files;
    }

    private void OnSwitchToTextModeClick(object sender, RoutedEventArgs e)
    {
        ViewModel.Mode = SendInputMode.Text;
    }

    private void OnCardDragOver(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            e.AcceptedOperation = DataPackageOperation.Copy;
        }
    }

    private async void OnCardDrop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            return;
        }

        IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();
        List<string> rawPaths = new(items.Count);
        foreach (IStorageItem item in items)
        {
            if (!string.IsNullOrWhiteSpace(item.Path))
            {
                rawPaths.Add(item.Path);
            }
        }

        if (rawPaths.Count > 0 && ViewModel.TryAddRawPaths(rawPaths))
        {
            _ = MeasurePendingDirectoriesAsync();
        }
    }

    private async void OnAddFilesClick(object sender, RoutedEventArgs e)
    {
        FileOpenPicker picker = new();
        picker.FileTypeFilter.Add("*");
        InitializePickerWindow(picker);

        IReadOnlyList<StorageFile> picked = await picker.PickMultipleFilesAsync();
        if (picked is { Count: > 0 })
        {
            List<string> rawPaths = new(picked.Count);
            foreach (StorageFile file in picked)
            {
                if (!string.IsNullOrWhiteSpace(file.Path))
                {
                    rawPaths.Add(file.Path);
                }
            }

            if (rawPaths.Count > 0 && ViewModel.TryAddRawPaths(rawPaths))
            {
                _ = MeasurePendingDirectoriesAsync();
            }
        }
    }

    private async void OnAddFolderClick(object sender, RoutedEventArgs e)
    {
        FolderPicker picker = new();
        picker.FileTypeFilter.Add("*");
        InitializePickerWindow(picker);

        StorageFolder? folder = await picker.PickSingleFolderAsync();
        if (folder is not null && !string.IsNullOrWhiteSpace(folder.Path))
        {
            if (ViewModel.TryAddRawPaths(new[] { folder.Path }))
            {
                _ = MeasurePendingDirectoriesAsync();
            }
        }
    }

    private void OnRemoveItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: TransferItemModel item })
        {
            ViewModel.RemoveItem(item);
        }
    }

    private async void OnPasteSendTextClick(object sender, RoutedEventArgs e)
    {
        try
        {
            DataPackageView content = Clipboard.GetContent();
            if (content.Contains(StandardDataFormats.Text))
            {
                string pasted = await content.GetTextAsync();
                ViewModel.ApplyPastedText(pasted, fromClipboardShortcut: false);
            }
            else
            {
                ViewModel.TextClipboardNotice = ViewModel.Strings.SendClipboardEmpty;
            }
        }
        catch (COMException)
        {
            // Ignore transient Win32 clipboard lock (CLIPBRD_E_CANT_OPEN).
            ViewModel.TextClipboardNotice = ViewModel.Strings.SendClipboardEmpty;
        }
    }

    private void OnClearTextClick(object sender, RoutedEventArgs e)
    {
        ViewModel.ClearTextInput();
    }

    private void OnCreateCodeClick(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.CanCreateCode)
        {
            return;
        }

        DestroyCurrentSession();
        ViewModel.BeginPreparing();

        BridgeNetworkConfigDto config = ViewModel.Settings.Current with
        {
            StrongerThreeWordCode = ViewModel.UseStrongerThreeWordCode,
        };

        try
        {
            ulong sid;
            if (ViewModel.Mode == SendInputMode.Text)
            {
                sid = NativeBridge.StartSendText(
                    config,
                    ViewModel.OutgoingText,
                    ViewModel.Strings.PreferredLanguageTags,
                    ViewModel.Strings.RegionTag);
            }
            else
            {
                string[] paths = new string[ViewModel.SelectedItems.Count];
                for (int i = 0; i < ViewModel.SelectedItems.Count; i++)
                {
                    paths[i] = ViewModel.SelectedItems[i].ExtendedPath;
                }

                sid = NativeBridge.StartSendFiles(
                    config,
                    paths,
                    ViewModel.Strings.PreferredLanguageTags,
                    ViewModel.Strings.RegionTag);
            }

            if (sid == 0)
            {
                ViewModel.ApplySessionEvent(new SessionEventDto(
                    Event: "failed",
                    Summary: ViewModel.Strings.ErrorOther,
                    TechnicalEnglish: "failed to start transfer session"));
                RefreshKoseAnimation();
                return;
            }

            ViewModel.ActiveSessionId = sid;
            StartPolling();
            RefreshKoseAnimation();
        }
        catch (DllNotFoundException)
        {
            ViewModel.ApplySessionEvent(new SessionEventDto(
                Event: "failed",
                Summary: ViewModel.Strings.ErrorOther,
                TechnicalEnglish: "totaldrop_windows_ffi.dll not available"));
            RefreshKoseAnimation();
        }
    }

    private void OnCopyCodeClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(ViewModel.TransferCode))
        {
            return;
        }

        try
        {
            DataPackage pkg = new();
            pkg.SetText(ViewModel.TransferCode);
            Clipboard.SetContent(pkg);
            ViewModel.CopiedFeedbackVisible = true;
        }
        catch (COMException)
        {
            // Ignore transient Win32 clipboard lock (CLIPBRD_E_CANT_OPEN).
        }
    }

    private void OnShareCodeClick(object sender, RoutedEventArgs e)
    {
        string sharePayload = !string.IsNullOrEmpty(ViewModel.TransferWebUri)
            ? ViewModel.TransferWebUri
            : ViewModel.TransferCode;
        if (string.IsNullOrEmpty(sharePayload))
        {
            return;
        }

        try
        {
            DataPackage pkg = new();
            pkg.SetText(sharePayload);
            Clipboard.SetContent(pkg);
            ViewModel.CopiedFeedbackVisible = true;
        }
        catch (COMException)
        {
            // Ignore transient Win32 clipboard lock (CLIPBRD_E_CANT_OPEN).
        }
    }

    private async void OnCancelSendClick(object sender, RoutedEventArgs e)
    {
        if (_activeCancelDialog is not null || !ViewModel.IsTransferRunning || ViewModel.ActiveSessionId == 0)
        {
            return;
        }

        if (XamlRoot is null)
        {
            CancelActiveSession();
            return;
        }

        ContentDialog dialog = new()
        {
            XamlRoot = XamlRoot,
            Title = ViewModel.Strings.CancelTransferTitle,
            Content = ViewModel.Strings.CancelTransferBody,
            PrimaryButtonText = ViewModel.Strings.Stop,
            CloseButtonText = ViewModel.Strings.KeepGoing,
            DefaultButton = ContentDialogButton.Close,
        };
        _activeCancelDialog = dialog;
        try
        {
            ContentDialogResult result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary && ViewModel.IsTransferRunning)
            {
                CancelActiveSession();
            }
        }
        finally
        {
            if (ReferenceEquals(_activeCancelDialog, dialog))
            {
                _activeCancelDialog = null;
            }
        }
    }

    private void OnToggleErrorDetailsClick(object sender, RoutedEventArgs e)
    {
        ViewModel.ShowErrorDetails = !ViewModel.ShowErrorDetails;
    }

    private void OnTryAgainClick(object sender, RoutedEventArgs e)
    {
        DestroyCurrentSession();
        ViewModel.ResetToIdle(clearSelection: false);
        RefreshKoseAnimation();
    }

    private void OnDoneResetClick(object sender, RoutedEventArgs e)
    {
        DestroyCurrentSession();
        ViewModel.ResetToIdle(clearSelection: true);
        RefreshKoseAnimation();
    }

    private void CancelActiveSession()
    {
        ulong sid = ViewModel.ActiveSessionId;
        if (sid != 0)
        {
            try
            {
                _ = NativeBridge.SessionCancel(sid);
            }
            catch (DllNotFoundException)
            {
                // Design-time preview fallback.
            }
        }
    }

    private void StartPolling()
    {
        if (_pollTimer is null)
        {
            _pollTimer = DispatcherQueue.CreateTimer();
            _pollTimer.Interval = TimeSpan.FromMilliseconds(80);
            _pollTimer.Tick += OnPollTimerTick;
        }

        _pollTimer.Start();
    }

    private void StopPolling()
    {
        _pollTimer?.Stop();
    }

    private void OnPollTimerTick(Microsoft.UI.Dispatching.DispatcherQueueTimer sender, object args)
    {
        PollSessionOnce();
    }

    private void PollSessionOnce()
    {
        RefreshKoseAnimation();
        ulong sid = ViewModel.ActiveSessionId;
        if (sid == 0)
        {
            StopPolling();
            return;
        }

        try
        {
            if (!NativeBridge.TryPollSessionEvents(sid, out List<SessionEventDto> events, out _))
            {
                StopPolling();
                return;
            }

            foreach (SessionEventDto ev in events)
            {
                ViewModel.ApplySessionEvent(ev);
                if (ev.Event is "done" or "failed")
                {
                    DismissActiveDialog();
                    DestroyCurrentSession();
                    RefreshKoseAnimation();
                    break;
                }
            }
        }
        catch (DllNotFoundException)
        {
            StopPolling();
        }
    }

    private void DestroyCurrentSession()
    {
        StopPolling();
        ulong sid = ViewModel.ActiveSessionId;
        if (sid != 0)
        {
            try
            {
                _ = NativeBridge.SessionDestroy(sid);
            }
            catch (DllNotFoundException)
            {
                // Design-time preview fallback.
            }

            ViewModel.ActiveSessionId = 0;
        }
    }

    private void DismissActiveDialog()
    {
        _activeCancelDialog?.Hide();
        _activeCancelDialog = null;
    }

    private void RefreshKoseAnimation()
    {
        bool shouldAnimate = ViewModel.IsTransferRunning && _uiSettings.AnimationsEnabled;
        if (shouldAnimate && !_koseAnimating)
        {
            SendKoseStoryboard.Begin();
            _koseAnimating = true;
        }
        else if (!shouldAnimate)
        {
            if (_koseAnimating)
            {
                SendKoseStoryboard.Stop();
                _koseAnimating = false;
            }

            SendKoseRotate.Angle = 0;
        }
    }

    private void InitializePickerWindow(object picker)
    {
        if (XamlRoot?.ContentIslandEnvironment is not null)
        {
            nint hwnd = Win32Interop.GetWindowFromWindowId(XamlRoot.ContentIslandEnvironment.AppWindowId);
            InitializeWithWindow.Initialize(picker, hwnd);
        }
    }

    private async Task MeasurePendingDirectoriesAsync()
    {
        List<TransferItemModel> dirs = [];
        foreach (TransferItemModel item in ViewModel.SelectedItems)
        {
            if (item.IsDirectory)
            {
                dirs.Add(item);
            }
        }

        if (dirs.Count == 0)
        {
            return;
        }

        foreach (TransferItemModel dirItem in dirs)
        {
            ulong bytes = await Task.Run(() => ComputeDirectoryBytes(dirItem.ExtendedPath));
            dirItem.ByteSize = bytes;
            dirItem.FormattedSize = ViewModel.Strings.FormatBytes(bytes);
        }

        ViewModel.UpdateSelectionSummaryFromItems();
    }

    private static ulong ComputeDirectoryBytes(string rootPath)
    {
        ulong total = 0;
        try
        {
            EnumerationOptions opts = new()
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = System.IO.FileAttributes.ReparsePoint,
            };
            foreach (FileInfo file in new DirectoryInfo(rootPath).EnumerateFiles("*", opts))
            {
                total += (ulong)Math.Max(0, file.Length);
            }
        }
        catch (IOException)
        {
            // Ignore unreadable entries during preview size scan.
        }
        catch (UnauthorizedAccessException)
        {
            // Ignore unreadable entries during preview size scan.
        }

        return total;
    }
}
