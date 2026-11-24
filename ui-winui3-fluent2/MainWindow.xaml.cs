// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using TotalDrop.WinUI.ViewModels;
using TotalDrop.WinUI.Views;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;
using Windows.System.UserProfile;
using Windows.UI;
using Windows.UI.ViewManagement;
using WinRT.Interop;

namespace TotalDrop.WinUI;

/// <summary>
/// Primary Windows 11 Fluent 2 window.
/// Configures <see cref="MicaBackdrop"/> with <see cref="DesktopAcrylicBackdrop"/>
/// fallback, custom <c>TitleBar</c>, live Windows System Accent Color and High
/// Contrast adaptation, and reduced-motion gating (<c>UISettings.AnimationsEnabled</c>)
/// per ADR 0016 and <c>docs/tasarim.md</c>.
/// </summary>
public sealed partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly UISettings _uiSettings = new();
    private readonly AccessibilitySettings _accessibilitySettings = new();
    private readonly SettingsStore _settingsStore = new();
    private string _lastPrimaryTag = "send";
    private bool _brandMarkRunning;
    private bool _brandMarkDone;
    private bool _brandMarkAnimating;
    private readonly object _routerLock = new();
    private readonly SemaphoreSlim _routerStreamGate = new(1, 1);
    private readonly WakeLockService _wakeLockService = new();
    private readonly NotificationService _notificationService;
    private AppWindow? _appWindow;
    private ContentDialog? _activeCloseDialog;
    private ulong _routerId;
    private uint _sessionId;
    private bool _isWindowActive = true;
    private bool _closingConfirmed;
    private bool _isBusyNoticeOpen;
    private string _busyNoticeMessage = string.Empty;

    public UiStringsViewModel Strings { get; } = new();

    public SendViewModel SendVm { get; }

    public ReceiveViewModel ReceiveVm { get; }

    public SettingsViewModel SettingsVm { get; }

    public string SendTabTitle => Strings.SendTitle;

    public string ReceiveTabTitle => Strings.ReceiveTitle;

    public bool AnimationsAllowed => _uiSettings.AnimationsEnabled;

    public uint SessionId => _sessionId;

    public bool HasActiveTransfer => SendVm.IsTransferRunning || ReceiveVm.IsTransferRunning;

    public bool IsBusyNoticeOpen
    {
        get => _isBusyNoticeOpen;
        set
        {
            if (_isBusyNoticeOpen != value)
            {
                _isBusyNoticeOpen = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsBusyNoticeOpen)));
            }
        }
    }

    public string BusyNoticeMessage
    {
        get => _busyNoticeMessage;
        private set
        {
            if (_busyNoticeMessage != value)
            {
                _busyNoticeMessage = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(BusyNoticeMessage)));
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        _notificationService = new NotificationService(() => DispatcherQueue.TryEnqueue(BringToForeground));

        SendVm = new SendViewModel(Strings, _settingsStore);
        ReceiveVm = new ReceiveViewModel(Strings, _settingsStore);
        SettingsVm = new SettingsViewModel(Strings, _settingsStore);

        SendVm.BrandMarkStateChanged = UpdateBrandMarkState;
        ReceiveVm.BrandMarkStateChanged = UpdateBrandMarkState;
        SendVm.TransferLifecycleChanged = OnTransferLifecycleChanged;
        ReceiveVm.TransferLifecycleChanged = OnTransferLifecycleChanged;
        SendVm.BackgroundNotificationReady = OnBackgroundNotificationReady;
        ReceiveVm.BackgroundNotificationReady = OnBackgroundNotificationReady;
        SettingsVm.RequestNavigateBack = NavigateBackFromSettings;

        InitializeComponent();

        ConfigureCustomTitleBar();
        ConfigureFluentBackdrop();
        InitializeSessionAndRouter();
        ApplyLocalizationAndFlowDirection();
        UpdateTitleBarCaptionColors();
        _notificationService.Register();

        // Live theme, Accent Color, High Contrast, and OS motion/effects listeners without restart (ADR 0016).
        _uiSettings.ColorValuesChanged += OnSystemColorsChanged;
        _uiSettings.AdvancedEffectsEnabledChanged += OnSystemEffectsChanged;
        _accessibilitySettings.HighContrastChanged += OnHighContrastChanged;
        Activated += OnWindowActivated;
        RootShellGrid.ActualThemeChanged += (_, _) => UpdateTitleBarCaptionColors();
        ShellNavigation.Loaded += OnShellNavigationLoaded;

        NavigateToSend();
    }

    private void ConfigureCustomTitleBar()
    {
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        nint hwnd = WindowNative.GetWindowHandle(this);
        Microsoft.UI.WindowId windowId = Win32Interop.GetWindowIdFromWindow(hwnd);
        AppWindow appWindow = AppWindow.GetFromWindowId(windowId);
        _appWindow = appWindow;
        appWindow.Closing += OnAppWindowClosing;
        appWindow.Resize(new SizeInt32(720, 640));

        if (AppWindowTitleBar.IsCustomizationSupported())
        {
            appWindow.TitleBar.ExtendsContentIntoTitleBar = true;
            appWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        }
    }

    private void InitializeSessionAndRouter()
    {
        uint pid = (uint)Environment.ProcessId;
        uint sessionId = 0;
        if (OperatingSystem.IsWindows() && !NativeBridge.ProcessIdToSessionId(pid, out sessionId))
        {
            sessionId = 0;
        }

        _sessionId = sessionId;

        IReadOnlyList<string> preferredLanguages = GlobalizationPreferences.Languages;
        string joinedTags = string.Join(',', preferredLanguages);
        string regionTag = System.Globalization.CultureInfo.CurrentCulture.Name;

        try
        {
            string appVersion = NativeBridge.TryGetVersionInfo()?.AppVersion ?? FallbackAppVersion;
            lock (_routerLock)
            {
                _routerId = NativeBridge.TryCreateRouter(
                    _sessionId,
                    joinedTags,
                    regionTag,
                    appVersion,
                    _uiSettings.AnimationsEnabled);
                DrainRouterOutboxLocked();
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time XAML preview fallback before Rust DLL is staged.
        }
    }

    /// <summary>
    /// Selects <see cref="MicaBackdrop"/> on Windows 11, falls back to
    /// <see cref="DesktopAcrylicBackdrop"/> when Mica is unavailable, and clears
    /// translucent backdrops in High Contrast mode so solid system contrast
    /// surfaces take precedence.
    /// </summary>
    private void ConfigureFluentBackdrop()
    {
        if (_accessibilitySettings.HighContrast)
        {
            SystemBackdrop = null;
            return;
        }

        if (MicaController.IsSupported())
        {
            SystemBackdrop = new MicaBackdrop { Kind = MicaKind.Base };
        }
        else if (DesktopAcrylicController.IsSupported())
        {
            SystemBackdrop = new DesktopAcrylicBackdrop();
        }
        else
        {
            SystemBackdrop = null;
        }
    }

    private const string FallbackAppVersion = "0.1.0-beta.1";

    private void ApplyLocalizationAndFlowDirection()
    {
        IReadOnlyList<string> preferredLanguages = GlobalizationPreferences.Languages;
        string joinedTags = string.Join(',', preferredLanguages);
        string regionTag = System.Globalization.CultureInfo.CurrentCulture.Name;

        try
        {
            string appVersion = NativeBridge.TryGetVersionInfo()?.AppVersion ?? FallbackAppVersion;
            BridgeUiBundleDto? bundle = null;
            lock (_routerLock)
            {
                if (_routerId != 0
                    && NativeBridge.TryUpdateRouterLocale(_routerId, joinedTags, regionTag, out BridgeUiBundleDto? routerBundle, out _))
                {
                    bundle = routerBundle;
                }

                DrainRouterOutboxLocked();
            }

            bundle ??= NativeBridge.TryResolveUiBundle(joinedTags, regionTag, appVersion);
            if (bundle is not null)
            {
                Strings.ApplyBundle(bundle, joinedTags);
                RootShellGrid.FlowDirection = bundle.FlowDirection == "RightToLeft"
                    ? FlowDirection.RightToLeft
                    : FlowDirection.LeftToRight;

                ApplySettingsItemLocalization();

                SendVm.RefreshLocalizedDefaults();
                ReceiveVm.RefreshLocalizedDefaults();
                SettingsVm.RefreshDraftBanner();

                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SendTabTitle)));
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ReceiveTabTitle)));
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time XAML preview fallback before Rust DLL is staged.
        }
    }

    private void OnShellNavigationLoaded(object sender, RoutedEventArgs e)
    {
        ApplySettingsItemLocalization();
        if (ContentFrame.CurrentSourcePageType == typeof(SettingsPage)
            && ShellNavigation.SettingsItem is not null)
        {
            ShellNavigation.SelectedItem = ShellNavigation.SettingsItem;
        }
    }

    private void ApplySettingsItemLocalization()
    {
        if (ShellNavigation.SettingsItem is NavigationViewItem settingsItem
            && !string.IsNullOrEmpty(Strings.SettingsTitle))
        {
            settingsItem.Content = Strings.SettingsTitle;
            AutomationProperties.SetName(settingsItem, Strings.SettingsTitle);
        }
    }

    public void UpdateBrandMarkState(bool isRunning, bool isDone)
    {
        _brandMarkRunning = isRunning;
        _brandMarkDone = isDone;
        RefreshBrandMarkVisual();
    }

    public void RefreshBrandMarkVisual()
    {
        bool shouldAnimate = _brandMarkRunning && _uiSettings.AnimationsEnabled;
        if (shouldAnimate && !_brandMarkAnimating)
        {
            BrandMarkDoneCheckPath.Visibility = Visibility.Collapsed;
            KoseRotationStoryboard.Begin();
            _brandMarkAnimating = true;
        }
        else if (!shouldAnimate)
        {
            if (_brandMarkAnimating)
            {
                KoseRotationStoryboard.Stop();
                _brandMarkAnimating = false;
            }

            BrandMarkRotate.Angle = 0;
            BrandMarkDoneCheckPath.Visibility =
                _brandMarkDone && !_brandMarkRunning ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    public void ShutdownActiveSessions()
    {
        DismissActiveCloseDialog();

        if (ContentFrame.Content is SendPage sendPage)
        {
            sendPage.ShutdownSession();
        }
        else if (ContentFrame.Content is ReceivePage receivePage)
        {
            receivePage.ShutdownSession();
        }

        ShutdownSessionHandle(SendVm.ActiveSessionId);
        SendVm.ActiveSessionId = 0;

        ShutdownSessionHandle(ReceiveVm.ActiveSessionId);
        ReceiveVm.ActiveSessionId = 0;

        UpdateBrandMarkState(isRunning: false, isDone: false);
    }

    public void DisposeSystemIntegrations()
    {
        if (_appWindow is not null)
        {
            _appWindow.Closing -= OnAppWindowClosing;
            _appWindow = null;
        }

        DismissActiveCloseDialog();
        _wakeLockService.Dispose();
        WindowsShareSheet.Detach();
        DestroyRouterHandle();
        _notificationService.Dispose();
        _routerStreamGate.Dispose();
    }

    private void DestroyRouterHandle()
    {
        ulong idToDestroy;
        lock (_routerLock)
        {
            idToDestroy = _routerId;
            _routerId = 0;
        }

        if (idToDestroy != 0)
        {
            try
            {
                _ = NativeBridge.TryDestroyRouter(idToDestroy);
            }
            catch (DllNotFoundException)
            {
                // Design-time preview fallback.
            }
        }
    }

    private static void ShutdownSessionHandle(ulong sessionId)
    {
        if (sessionId == 0)
        {
            return;
        }

        try
        {
            _ = NativeBridge.SessionCancel(sessionId);
            _ = NativeBridge.SessionDestroy(sessionId);
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback.
        }
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_closingConfirmed || !HasActiveTransfer)
        {
            return;
        }

        args.Cancel = true;
        _ = ShowCloseConfirmationDialogAsync();
    }

    private async Task ShowCloseConfirmationDialogAsync()
    {
        if (_activeCloseDialog is not null)
        {
            return;
        }

        if (ContentFrame.Content is SendPage sendPage)
        {
            sendPage.DismissCancelDialog();
        }
        else if (ContentFrame.Content is ReceivePage receivePage)
        {
            receivePage.DismissCancelDialog();
        }

        if (RootShellGrid.XamlRoot is null)
        {
            _closingConfirmed = true;
            Close();
            return;
        }

        ContentDialog dialog = new()
        {
            XamlRoot = RootShellGrid.XamlRoot,
            Title = Strings.CancelTransferTitle,
            Content = Strings.CancelTransferBody,
            PrimaryButtonText = Strings.Stop,
            CloseButtonText = Strings.KeepGoing,
            DefaultButton = ContentDialogButton.Close,
        };
        _activeCloseDialog = dialog;
        try
        {
            ContentDialogResult result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary && HasActiveTransfer)
            {
                _closingConfirmed = true;
                Close();
            }
        }
        catch (COMException)
        {
            // Ignore dialog cancellation when another system modal or close raced.
        }
        finally
        {
            if (ReferenceEquals(_activeCloseDialog, dialog))
            {
                _activeCloseDialog = null;
            }
        }
    }

    private void DismissActiveCloseDialog()
    {
        _activeCloseDialog?.Hide();
        _activeCloseDialog = null;
    }

    private void OnTransferLifecycleChanged()
    {
        _wakeLockService.UpdateStages(
            SendVm.ToLifecycleStage(),
            ReceiveVm.ToLifecycleStage(),
            Strings.KeepAwakeReason);

        SyncRouterActivityState();

        // Linux Main.qml:201 parity: auto-dismiss close dialog if transfer reached terminal state.
        if (!HasActiveTransfer && _activeCloseDialog is not null)
        {
            DismissActiveCloseDialog();
        }
    }

    private void OnBackgroundNotificationReady(NotificationEventInput input)
    {
        _notificationService.Notify(input with { WindowActive = _isWindowActive }, Strings);
    }

    private WindowsActivityStateDto ComputeWindowActivityState()
    {
        if (SendVm.Phase == SendPhase.Transferring)
        {
            return WindowsActivityStateDto.Transferring(SendVm.DoneBytes, SendVm.TotalBytes);
        }

        if (ReceiveVm.Phase == ReceivePhase.Transferring)
        {
            return WindowsActivityStateDto.Transferring(ReceiveVm.DoneBytes, ReceiveVm.TotalBytes);
        }

        if (ReceiveVm.Phase == ReceivePhase.Offer)
        {
            return WindowsActivityStateDto.OfferPromptPending;
        }

        if (ReceiveVm.Phase == ReceivePhase.Connecting)
        {
            return WindowsActivityStateDto.ConnectingReceive(ReceiveVm.ConnectingCode);
        }

        if (SendVm.Phase == SendPhase.Preparing)
        {
            return WindowsActivityStateDto.PreparingSend;
        }

        if (SendVm.Phase is SendPhase.Waiting or SendPhase.Connected)
        {
            return WindowsActivityStateDto.WaitingForPeer(SendVm.TransferCode);
        }

        if (ReceiveVm.IsReceivedTextVisible)
        {
            return WindowsActivityStateDto.ShowingTextNote;
        }

        return WindowsActivityStateDto.Idle;
    }

    private void SyncRouterActivityState()
    {
        WindowsActivityStateDto state = ComputeWindowActivityState();
        try
        {
            lock (_routerLock)
            {
                if (_routerId != 0)
                {
                    _ = NativeBridge.TrySetRouterActivity(_routerId, state, out _, out _);
                    DrainRouterOutboxLocked();
                }
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback.
        }
    }

    private void SyncRouterAnimationsEnabled()
    {
        bool enabled = _uiSettings.AnimationsEnabled;
        try
        {
            lock (_routerLock)
            {
                if (_routerId != 0)
                {
                    _ = NativeBridge.TrySetRouterAnimations(_routerId, enabled, out _, out _);
                    DrainRouterOutboxLocked();
                }
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback.
        }
    }

    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
        _isWindowActive = args.WindowActivationState != WindowActivationState.Deactivated;
        SyncRouterAnimationsEnabled();
        RefreshBrandMarkVisual();
    }

    private void OnSystemColorsChanged(UISettings sender, object args)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ConfigureFluentBackdrop();
            UpdateTitleBarCaptionColors();
            RefreshBrandMarkVisual();
        });
    }

    private void OnSystemEffectsChanged(UISettings sender, object args)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            SyncRouterAnimationsEnabled();
            RefreshBrandMarkVisual();
        });
    }

    private void OnHighContrastChanged(AccessibilitySettings sender, object args)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ConfigureFluentBackdrop();
            UpdateTitleBarCaptionColors();
        });
    }

    /// <summary>
    /// Synchronizes WinUI 3 caption buttons (Minimize / Maximize / Close) with
    /// the live Windows Light, Dark, or High Contrast palette and system Accent
    /// Color (ADR 0016).
    /// </summary>
    private void UpdateTitleBarCaptionColors()
    {
        if (!AppWindowTitleBar.IsCustomizationSupported())
        {
            return;
        }

        nint hwnd = WindowNative.GetWindowHandle(this);
        AppWindow appWindow = AppWindow.GetFromWindowId(Win32Interop.GetWindowIdFromWindow(hwnd));
        AppWindowTitleBar titleBar = appWindow.TitleBar;

        titleBar.ButtonBackgroundColor = Colors.Transparent;
        titleBar.ButtonInactiveBackgroundColor = Colors.Transparent;

        if (_accessibilitySettings.HighContrast)
        {
            Color windowText = _uiSettings.GetColorValue(UIColorType.Foreground);
            Color highlight = _uiSettings.GetColorValue(UIColorType.Accent);
            titleBar.ButtonForegroundColor = windowText;
            titleBar.ButtonHoverForegroundColor = Colors.Black;
            titleBar.ButtonHoverBackgroundColor = highlight;
            return;
        }

        bool isDark = RootShellGrid.ActualTheme == ElementTheme.Dark;
        titleBar.ButtonForegroundColor = isDark ? Colors.White : Colors.Black;
        titleBar.ButtonHoverForegroundColor = isDark ? Colors.White : Colors.Black;
        titleBar.ButtonHoverBackgroundColor = isDark
            ? Color.FromArgb(0x24, 0xFF, 0xFF, 0xFF)
            : Color.FromArgb(0x18, 0x00, 0x00, 0x00);
        titleBar.ButtonPressedBackgroundColor = _uiSettings.GetColorValue(UIColorType.Accent);
    }

    private void NavigateContentFrame(Type pageType, object parameter)
    {
        if (ContentFrame.CurrentSourcePageType != pageType)
        {
            ContentFrame.Navigate(pageType, parameter);
        }
    }

    private void NavigateToSend()
    {
        _lastPrimaryTag = "send";
        ShellNavigation.SelectedItem = NavSendItem;
        NavigateContentFrame(typeof(SendPage), SendVm);
    }

    private void NavigateToReceive()
    {
        _lastPrimaryTag = "receive";
        ShellNavigation.SelectedItem = NavReceiveItem;
        NavigateContentFrame(typeof(ReceivePage), ReceiveVm);
    }

    private void NavigateToSettings()
    {
        if (ShellNavigation.SettingsItem is not null)
        {
            ShellNavigation.SelectedItem = ShellNavigation.SettingsItem;
        }

        NavigateContentFrame(typeof(SettingsPage), SettingsVm);
    }

    private void OnNavigationSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            NavigateContentFrame(typeof(SettingsPage), SettingsVm);
            return;
        }

        if (args.SelectedItem is NavigationViewItem { Tag: string tag })
        {
            _lastPrimaryTag = tag;
            switch (tag)
            {
                case "send":
                    NavigateContentFrame(typeof(SendPage), SendVm);
                    break;
                case "receive":
                    NavigateContentFrame(typeof(ReceivePage), ReceiveVm);
                    break;
            }
        }
    }

    private void NavigateBackFromSettings()
    {
        if (_lastPrimaryTag == "receive")
        {
            NavigateToReceive();
        }
        else
        {
            NavigateToSend();
        }
    }

    public void BringToForeground()
    {
        if (_appWindow?.Presenter is OverlappedPresenter presenter
            && presenter.State == OverlappedPresenterState.Minimized)
        {
            presenter.Restore();
        }

        Activate();
    }

    public Task AcquireRouterStreamGateAsync(CancellationToken cancellationToken) =>
        _routerStreamGate.WaitAsync(cancellationToken);

    public void ReleaseRouterStreamGate()
    {
        try
        {
            _routerStreamGate.Release();
        }
        catch (ObjectDisposedException)
        {
            // Shutdown disposed the gate while background IPC loop exited.
        }
    }

    private static readonly TimeSpan LocalRouterGateTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Feeds raw Named Pipe bytes (or <see cref="ReadOnlySpan{T}.Empty"/> for
    /// 0-byte EOF flush) directly into Rust <c>WinUiWindowRouter</c>.
    /// </summary>
    public bool TryIngestNamedPipeChunk(ReadOnlySpan<byte> chunk, out RouterDecisionDto[] decisions)
    {
        decisions = [];
        try
        {
            lock (_routerLock)
            {
                if (_routerId == 0)
                {
                    return false;
                }

                try
                {
                    return NativeBridge.TryIngestRouterIpcBytes(_routerId, chunk, out decisions, out _);
                }
                finally
                {
                    DrainRouterOutboxLocked();
                }
            }
        }
        catch (DllNotFoundException)
        {
            return false;
        }
    }

    public async Task RouteShareTargetAsync(
        Func<Task<ShareTargetInput>> extractPayloadAsync,
        IShareOperationLifecycle lifecycle)
    {
        ShareTargetRouteResult result = await ShareTargetRouter.RouteAsync(
            extractPayloadAsync,
            lifecycle,
            ingestFrameAsync: IngestShareTargetFrameAsync,
            initiatorPid: (uint)Environment.ProcessId);

        if (result.Succeeded && result.Decisions.Length > 0)
        {
            ApplyRouterDecisions(result.Decisions);
        }
    }

    private async Task<ShareTargetRouteResult> IngestShareTargetFrameAsync(byte[] frame)
    {
        bool acquired = false;
        try
        {
            if (!await _routerStreamGate.WaitAsync(LocalRouterGateTimeout).ConfigureAwait(false))
            {
                return new ShareTargetRouteResult(
                    Succeeded: false,
                    Decisions: [],
                    Error: new BridgeErrorDto("router_gate_timeout", "errorOther", null, "router stream gate timed out"));
            }

            acquired = true;
            lock (_routerLock)
            {
                if (_routerId == 0)
                {
                    return new ShareTargetRouteResult(
                        Succeeded: false,
                        Decisions: [],
                        Error: new BridgeErrorDto("invalid_handle", "errorOther", null, "router handle is not initialized"));
                }

                return ShareTargetRouter.IngestFrameAndFlushLocked(_routerId, frame);
            }
        }
        catch (DllNotFoundException)
        {
            return new ShareTargetRouteResult(
                Succeeded: false,
                Decisions: [],
                Error: new BridgeErrorDto("bridge_unavailable", "errorOther", null, "native bridge DLL unavailable"));
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
                ReleaseRouterStreamGate();
            }
        }
    }

    public async Task RouteProtocolUriAsync(string rawUri)
    {
        try
        {
            if (NativeBridge.TryValidateUri(rawUri, out ValidatedCodeDto? validated, out BridgeErrorDto? error)
                && validated is not null)
            {
                byte[] frame = NativeBridge.BuildFramedProtocolUriEnvelope(
                    validated,
                    initiatorPid: (uint)Environment.ProcessId);
                (LocalRouteOutcome outcome, RouterDecisionDto[] decisions) = await TryRouteLocalFrameAsync(frame);
                if (outcome == LocalRouteOutcome.Routed)
                {
                    ApplyRouterDecisions(decisions);
                    return;
                }

                if (outcome == LocalRouteOutcome.Rejected)
                {
                    return;
                }

                if (!IsWindowBusy())
                {
                    NavigateToReceive();
                    ReceiveVm.ApplyActivatedCode(validated.DisplayEnglish);
                }

                return;
            }

            // Invalid URI MUST NOT disturb an active transfer or received text note.
            if (IsWindowBusy())
            {
                return;
            }

            NavigateToReceive();
            string errKey = string.IsNullOrEmpty(error?.L10nKey) ? "errorInvalidCode" : error.L10nKey;
            string formatted = Strings.FormatMessage(errKey);
            ReceiveVm.ValidationMessage = string.IsNullOrEmpty(formatted) ? Strings.ErrorInvalidCode : formatted;
        }
        catch (DllNotFoundException)
        {
            if (!IsWindowBusy())
            {
                NavigateToReceive();
                ReceiveVm.ValidationMessage = Strings.ErrorInvalidCode;
            }
        }
    }

    public async Task RouteExplorerSendAsync(IReadOnlyList<string> rawPaths)
    {
        if (rawPaths.Count == 0)
        {
            return;
        }

        byte[] frame = NativeBridge.BuildFramedExplorerSendEnvelope(
            rawPaths,
            initiatorPid: (uint)Environment.ProcessId);
        (LocalRouteOutcome outcome, RouterDecisionDto[] decisions) = await TryRouteLocalFrameAsync(frame);
        if (outcome == LocalRouteOutcome.Routed)
        {
            ApplyRouterDecisions(decisions);
            return;
        }

        if (outcome == LocalRouteOutcome.Rejected)
        {
            // Live Rust router rejected invalid/hostile paths or >10,000 items;
            // never mutate SendVm or navigate away from the current screen.
            return;
        }

        if (!IsWindowBusy() && SendVm.TryAddRawPaths(rawPaths))
        {
            NavigateToSend();
            TriggerSendPageDirectoryMeasurement();
        }
    }

    public async Task RouteOpenScreenAsync(string screen)
    {
        byte[] frame = NativeBridge.BuildFramedOpenScreenEnvelope(
            screen,
            initiatorPid: (uint)Environment.ProcessId);
        (LocalRouteOutcome outcome, RouterDecisionDto[] decisions) = await TryRouteLocalFrameAsync(frame);
        if (outcome == LocalRouteOutcome.Routed)
        {
            ApplyRouterDecisions(decisions);
            return;
        }

        if (outcome == LocalRouteOutcome.Rejected)
        {
            return;
        }

        if (!IsWindowBusy())
        {
            ApplyScreenSwitch(screen);
        }
    }

    public async Task HandleLaunchArgumentsAsync(string[] args)
    {
        if (args.Length == 0)
        {
            return;
        }

        foreach (string arg in args)
        {
            if (arg.StartsWith("----AppNotificationActivated:", StringComparison.OrdinalIgnoreCase))
            {
                // Toast notification click activation: foreground-only, never pass to file validation.
                return;
            }
        }

        if (args.Length == 1 && args[0] == "--ipc-await")
        {
            return;
        }

        foreach (string arg in args)
        {
            if (arg.StartsWith("totaldrop:", StringComparison.OrdinalIgnoreCase)
                || arg.StartsWith("https://totaldrop.app/r#", StringComparison.OrdinalIgnoreCase))
            {
                await RouteProtocolUriAsync(arg);
                return;
            }

            if (arg.StartsWith("--screen=", StringComparison.Ordinal))
            {
                string target = arg["--screen=".Length..];
                if (target is "send" or "clipboard" or "receive" or "settings")
                {
                    await RouteOpenScreenAsync(target);
                    return;
                }
            }
        }

        List<string> filePaths = [];
        bool optionsActive = true;
        foreach (string arg in args)
        {
            if (optionsActive)
            {
                if (arg == "--")
                {
                    optionsActive = false;
                    continue;
                }

                if (arg == "--explorer-send" || (arg.StartsWith('-') && arg.Length > 1))
                {
                    continue;
                }
            }

            filePaths.Add(arg);
        }

        if (filePaths.Count > 0)
        {
            await RouteExplorerSendAsync(filePaths);
        }
    }

    public void ApplyRouterDecisions(IEnumerable<RouterDecisionDto> decisions)
    {
        foreach (RouterDecisionDto decision in decisions)
        {
            ApplyRouterDecision(decision);
        }
    }

    public void ApplyRouterDecision(RouterDecisionDto decision)
    {
        switch (decision.Decision)
        {
            case "navigate_send_files" when decision.Paths is { Length: > 0 } paths:
                IsBusyNoticeOpen = false;
                _ = SendVm.TryAddRawPaths(paths);
                NavigateToSend();
                TriggerSendPageDirectoryMeasurement();
                break;

            case "navigate_send_text" when !string.IsNullOrEmpty(decision.RawText):
                IsBusyNoticeOpen = false;
                SendVm.ApplyPastedText(decision.RawText, fromClipboardShortcut: false);
                NavigateToSend();
                break;

            case "navigate_receive_code" when decision.Code is not null:
                IsBusyNoticeOpen = false;
                NavigateToReceive();
                ReceiveVm.ApplyActivatedCode(decision.Code.DisplayEnglish);
                break;

            case "switch_screen" when !string.IsNullOrEmpty(decision.Screen):
                IsBusyNoticeOpen = false;
                ApplyScreenSwitch(decision.Screen);
                break;

            case "reject_busy":
                // Non-destructive localized banner: never navigate or clobber active transfer state.
                BusyNoticeMessage = string.IsNullOrEmpty(decision.LocalizedBanner)
                    ? Strings.ShareBusy
                    : decision.LocalizedBanner;
                IsBusyNoticeOpen = true;
                break;
        }
    }

    private void TriggerSendPageDirectoryMeasurement()
    {
        if (ContentFrame.Content is SendPage sendPage)
        {
            sendPage.TriggerPendingDirectoryMeasurement();
        }
    }

    private void ApplyScreenSwitch(string screen)
    {
        switch (screen)
        {
            case "send":
                NavigateToSend();
                break;
            case "clipboard":
                NavigateToSend();
                _ = PasteClipboardForShortcutAsync();
                break;
            case "receive":
                NavigateToReceive();
                break;
            case "settings":
                NavigateToSettings();
                break;
        }
    }

    private async Task PasteClipboardForShortcutAsync()
    {
        try
        {
            DataPackageView content = Clipboard.GetContent();
            if (content.Contains(StandardDataFormats.Text))
            {
                string pasted = await content.GetTextAsync();
                SendVm.ApplyPastedText(pasted, fromClipboardShortcut: true);
                return;
            }
        }
        catch (COMException)
        {
            // Ignore transient Win32 clipboard lock (CLIPBRD_E_CANT_OPEN).
        }

        SendVm.ApplyPastedText(string.Empty, fromClipboardShortcut: true);
    }

    private bool IsWindowBusy() => HasActiveTransfer || ReceiveVm.IsReceivedTextVisible;

    private void DrainRouterOutboxLocked()
    {
        if (_routerId != 0)
        {
            _ = NativeBridge.TryDrainRouterNdjson(_routerId, out _, out _);
        }
    }

    private async Task<(LocalRouteOutcome Outcome, RouterDecisionDto[] Decisions)> TryRouteLocalFrameAsync(byte[] frame)
    {
        bool acquired = false;
        try
        {
            if (!await _routerStreamGate.WaitAsync(LocalRouterGateTimeout).ConfigureAwait(false))
            {
                return (LocalRouteOutcome.Unavailable, []);
            }

            acquired = true;
            lock (_routerLock)
            {
                if (_routerId == 0)
                {
                    return (LocalRouteOutcome.Unavailable, []);
                }

                try
                {
                    if (!NativeBridge.TryIngestRouterIpcBytes(
                            _routerId,
                            frame,
                            out RouterDecisionDto[] decisions,
                            out BridgeErrorDto? ingestError))
                    {
                        return (
                            string.Equals(ingestError?.Kind, "invalid_handle", StringComparison.Ordinal)
                                ? LocalRouteOutcome.Unavailable
                                : LocalRouteOutcome.Rejected,
                            []);
                    }

                    if (!NativeBridge.TryIngestRouterIpcBytes(
                            _routerId,
                            ReadOnlySpan<byte>.Empty,
                            out _,
                            out BridgeErrorDto? eofError))
                    {
                        return (
                            string.Equals(eofError?.Kind, "invalid_handle", StringComparison.Ordinal)
                                ? LocalRouteOutcome.Unavailable
                                : LocalRouteOutcome.Rejected,
                            []);
                    }

                    return (LocalRouteOutcome.Routed, decisions);
                }
                finally
                {
                    DrainRouterOutboxLocked();
                }
            }
        }
        catch (DllNotFoundException)
        {
            return (LocalRouteOutcome.Unavailable, []);
        }
        catch (ObjectDisposedException)
        {
            return (LocalRouteOutcome.Unavailable, []);
        }
        finally
        {
            if (acquired)
            {
                ReleaseRouterStreamGate();
            }
        }
    }
}
