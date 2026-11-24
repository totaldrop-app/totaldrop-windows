// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
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
/// Fluent 2 Receive screen code-behind delegating code parsing, BIP-39
/// autocomplete, clipboard code extraction, rendezvous pairing, offer
/// acceptance/decline, and verified in-memory text reception to
/// <c>totaldrop_windows_ffi.dll</c>.
/// </summary>
public sealed partial class ReceivePage : Page
{
    private readonly UISettings _uiSettings = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _pollTimer;
    private bool _koseAnimating;
    private ContentDialog? _activeCancelDialog;

    public ReceiveViewModel ViewModel { get; private set; } = new();

    public ReceivePage()
    {
        InitializeComponent();
        Unloaded += OnPageUnloaded;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is ReceiveViewModel vm)
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
        // Escape MUST be suppressed while verified in-memory received text is visible
        // so the user cannot accidentally lose unsaved text (Linux ReceivePage.qml parity).
        if (e.Key == VirtualKey.Escape && ViewModel.IsReceivedTextVisible)
        {
            e.Handled = true;
        }
    }

    private void OnCodeInputBoxLoaded(object sender, RoutedEventArgs e)
    {
        // AutoSuggestBox does not expose IsSpellCheckEnabled/IsTextPredictionEnabled
        // directly in WinUI 3 XAML; disable them on the inner TextBox once loaded.
        TextBox? inner = FindDescendantTextBox(CodeInputBox);
        if (inner is not null)
        {
            inner.IsSpellCheckEnabled = false;
            inner.IsTextPredictionEnabled = false;
        }
    }

    private static TextBox? FindDescendantTextBox(DependencyObject root)
    {
        int count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(root, i);
            if (child is TextBox tb)
            {
                return tb;
            }

            TextBox? nested = FindDescendantTextBox(child);
            if (nested is not null)
            {
                return nested;
            }
        }

        return null;
    }

    private void OnCodeInputTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput)
        {
            return;
        }

        string text = sender.Text ?? string.Empty;
        ViewModel.CodeInput = text;
        ViewModel.ValidationMessage = string.Empty;

        int sepIdx = text.LastIndexOfAny(['-', ' ']);
        if (sepIdx < 0)
        {
            sender.ItemsSource = Array.Empty<string>();
            return;
        }

        string prefixHead = text[..(sepIdx + 1)];
        string token = text[(sepIdx + 1)..];
        if (token.Length < 2)
        {
            sender.ItemsSource = Array.Empty<string>();
            return;
        }

        foreach (char c in token)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= 'A' and <= 'Z')))
            {
                sender.ItemsSource = Array.Empty<string>();
                return;
            }
        }

        try
        {
            string[] matches = NativeBridge.TryGetCodeCompletions(token, 4);
            if (matches.Length == 0 || (matches.Length == 1 && string.Equals(matches[0], token, StringComparison.OrdinalIgnoreCase)))
            {
                sender.ItemsSource = Array.Empty<string>();
                return;
            }

            string[] fullSuggestions = new string[matches.Length];
            for (int i = 0; i < matches.Length; i++)
            {
                fullSuggestions[i] = prefixHead + matches[i];
            }

            sender.ItemsSource = fullSuggestions;
        }
        catch (DllNotFoundException)
        {
            sender.ItemsSource = Array.Empty<string>();
        }
    }

    private void OnCodeSuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
    {
        if (args.SelectedItem is string chosen)
        {
            ViewModel.CodeInput = chosen;
            sender.Text = chosen;
        }
    }

    private void OnCodeQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
    {
        if (args.ChosenSuggestion is string chosen)
        {
            ViewModel.CodeInput = chosen;
            return;
        }

        BeginConnect();
    }

    private async void OnPasteClick(object sender, RoutedEventArgs e)
    {
        string pasted;
        try
        {
            DataPackageView content = Clipboard.GetContent();
            if (!content.Contains(StandardDataFormats.Text))
            {
                return;
            }

            pasted = await content.GetTextAsync();
        }
        catch (COMException)
        {
            // Ignore transient Win32 clipboard lock (CLIPBRD_E_CANT_OPEN).
            return;
        }

        try
        {
            if (NativeBridge.TryExtractClipboardCode(pasted, out ValidatedCodeDto? extracted, out _)
                && extracted is not null)
            {
                ViewModel.CodeInput = extracted.DisplayEnglish;
                ViewModel.ValidationMessage = string.Empty;
                return;
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback.
        }

        ViewModel.CodeInput = pasted.Trim();
        ViewModel.ValidationMessage = string.Empty;
    }

    private void OnConnectClick(object sender, RoutedEventArgs e)
    {
        BeginConnect();
    }

    private void BeginConnect()
    {
        string typed = ViewModel.CodeInput;
        if (string.IsNullOrWhiteSpace(typed))
        {
            ViewModel.ValidationMessage = ViewModel.Strings.ReceiveCodeInvalid;
            return;
        }

        ValidatedCodeDto? validated;
        BridgeErrorDto? error;
        try
        {
            if (!NativeBridge.TryValidateUserInput(typed, out validated, out error) || validated is null)
            {
                string errKey = string.IsNullOrEmpty(error?.L10nKey) ? "receiveCodeInvalid" : error.L10nKey;
                string localized = ViewModel.Strings.FormatMessage(errKey);
                ViewModel.ValidationMessage = string.IsNullOrEmpty(localized)
                    ? ViewModel.Strings.ReceiveCodeInvalid
                    : localized;
                return;
            }
        }
        catch (DllNotFoundException)
        {
            ViewModel.ValidationMessage = ViewModel.Strings.ReceiveCodeInvalid;
            return;
        }

        DestroyCurrentSession();
        ViewModel.CodeInput = validated.DisplayEnglish;
        ViewModel.BeginConnecting(validated.DisplayEnglish);

        try
        {
            ulong sid = NativeBridge.StartReceiveConnect(
                ViewModel.Settings.Current,
                validated.DisplayEnglish,
                ViewModel.Strings.PreferredLanguageTags,
                ViewModel.Strings.RegionTag);
            if (sid == 0)
            {
                ViewModel.ApplySessionEvent(new SessionEventDto(
                    Event: "failed",
                    Summary: ViewModel.Strings.ErrorOther,
                    TechnicalEnglish: "failed to start receive connection"));
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

    private async void OnChooseDestinationClick(object sender, RoutedEventArgs e)
    {
        FolderPicker picker = new();
        picker.FileTypeFilter.Add("*");
        if (XamlRoot?.ContentIslandEnvironment is not null)
        {
            nint hwnd = Win32Interop.GetWindowFromWindowId(XamlRoot.ContentIslandEnvironment.AppWindowId);
            InitializeWithWindow.Initialize(picker, hwnd);
        }

        StorageFolder? folder = await picker.PickSingleFolderAsync();
        if (folder is not null && !string.IsNullOrWhiteSpace(folder.Path))
        {
            ViewModel.DestinationFolder = folder.Path;
        }
    }

    private void OnAcceptClick(object sender, RoutedEventArgs e)
    {
        ulong sid = ViewModel.ActiveSessionId;
        if (sid == 0 || ViewModel.Phase != ReceivePhase.Offer)
        {
            return;
        }

        try
        {
            int status = ViewModel.IsTextOffer
                ? NativeBridge.ReceiveAcceptText(sid)
                : NativeBridge.TryAcceptReceiveFiles(sid, ViewModel.DestinationFolder);
            if (status == NativeBridge.FfiOk)
            {
                ViewModel.BeginTransferring();
                StartPolling();
                RefreshKoseAnimation();
            }
            else
            {
                ViewModel.ApplySessionEvent(new SessionEventDto(
                    Event: "failed",
                    Summary: ViewModel.Strings.ErrorOther,
                    TechnicalEnglish: $"receive accept returned status {status}"));
                DestroyCurrentSession();
                RefreshKoseAnimation();
            }
        }
        catch (DllNotFoundException)
        {
            ViewModel.ApplySessionEvent(new SessionEventDto(
                Event: "failed",
                Summary: ViewModel.Strings.ErrorOther,
                TechnicalEnglish: "totaldrop_windows_ffi.dll not available"));
        }
    }

    private void OnDeclineClick(object sender, RoutedEventArgs e)
    {
        ulong sid = ViewModel.ActiveSessionId;
        if (sid == 0 || ViewModel.Phase != ReceivePhase.Offer)
        {
            return;
        }

        try
        {
            _ = NativeBridge.ReceiveDecline(sid);
            StartPolling();
        }
        catch (DllNotFoundException)
        {
            ViewModel.ResetToIdle(clearCode: false);
        }
    }

    private async void OnCancelReceiveClick(object sender, RoutedEventArgs e)
    {
        if (_activeCancelDialog is not null || ViewModel.ActiveSessionId == 0 || !ViewModel.IsTransferRunning)
        {
            return;
        }

        if (ViewModel.Phase == ReceivePhase.Connecting || XamlRoot is null)
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

    private async void OnOpenFolderClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ViewModel.SavedToFolder))
        {
            return;
        }

        try
        {
            _ = await Launcher.LaunchFolderPathAsync(ViewModel.SavedToFolder);
        }
        catch (Exception)
        {
            // Ignore shell launch errors if folder was moved after transfer.
        }
    }

    private void OnCopyReceivedTextClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(ViewModel.RawReceivedText))
        {
            return;
        }

        try
        {
            DataPackage pkg = new();
            pkg.SetText(ViewModel.RawReceivedText);
            Clipboard.SetContent(pkg);
            ViewModel.TextCopiedFeedbackVisible = true;
        }
        catch (COMException)
        {
            // Ignore transient Win32 clipboard lock (CLIPBRD_E_CANT_OPEN).
        }
    }

    private void OnToggleErrorDetailsClick(object sender, RoutedEventArgs e)
    {
        ViewModel.ShowErrorDetails = !ViewModel.ShowErrorDetails;
    }

    private void OnDoneResetClick(object sender, RoutedEventArgs e)
    {
        DestroyCurrentSession();
        ViewModel.ResetToIdle(clearCode: true);
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
                if (ev.Event is "done" or "declined" or "failed")
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
        bool shouldAnimate = ViewModel.Phase == ReceivePhase.Connecting && _uiSettings.AnimationsEnabled;
        if (shouldAnimate && !_koseAnimating)
        {
            ReceiveKoseStoryboard.Begin();
            _koseAnimating = true;
        }
        else if (!shouldAnimate)
        {
            if (_koseAnimating)
            {
                ReceiveKoseStoryboard.Stop();
                _koseAnimating = false;
            }

            ReceiveKoseRotate.Angle = 0;
        }
    }
}
