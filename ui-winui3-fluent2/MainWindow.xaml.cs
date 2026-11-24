// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.ComponentModel;
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

    public UiStringsViewModel Strings { get; } = new();

    public SendViewModel SendVm { get; }

    public ReceiveViewModel ReceiveVm { get; }

    public SettingsViewModel SettingsVm { get; }

    public string SendTabTitle => Strings.SendTitle;

    public string ReceiveTabTitle => Strings.ReceiveTitle;

    public bool AnimationsAllowed => _uiSettings.AnimationsEnabled;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        SendVm = new SendViewModel(Strings, _settingsStore);
        ReceiveVm = new ReceiveViewModel(Strings, _settingsStore);
        SettingsVm = new SettingsViewModel(Strings, _settingsStore);

        SendVm.BrandMarkStateChanged = UpdateBrandMarkState;
        ReceiveVm.BrandMarkStateChanged = UpdateBrandMarkState;
        SettingsVm.RequestNavigateBack = NavigateBackFromSettings;

        InitializeComponent();

        ConfigureCustomTitleBar();
        ConfigureFluentBackdrop();
        ApplyLocalizationAndFlowDirection();
        UpdateTitleBarCaptionColors();

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
        appWindow.Resize(new SizeInt32(720, 640));

        if (AppWindowTitleBar.IsCustomizationSupported())
        {
            appWindow.TitleBar.ExtendsContentIntoTitleBar = true;
            appWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
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
            BridgeUiBundleDto? bundle = NativeBridge.TryResolveUiBundle(joinedTags, regionTag, appVersion);
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

    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
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
        DispatcherQueue.TryEnqueue(RefreshBrandMarkVisual);
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
        Activate();
    }

    public void EnqueueSendSelection(IEnumerable<string> rawPaths)
    {
        _ = SendVm.TryAddRawPaths(rawPaths);
        NavigateToSend();
    }

    public void NavigateToReceiveFromUri(string rawUri)
    {
        NavigateToReceive();

        try
        {
            if (NativeBridge.TryValidateUri(rawUri, out ValidatedCodeDto? validated, out BridgeErrorDto? error)
                && validated is not null)
            {
                ReceiveVm.ApplyActivatedCode(validated.DisplayEnglish);
                return;
            }

            string errKey = string.IsNullOrEmpty(error?.L10nKey) ? "errorInvalidCode" : error.L10nKey;
            string formatted = Strings.FormatMessage(errKey);
            ReceiveVm.ValidationMessage = string.IsNullOrEmpty(formatted) ? Strings.ErrorInvalidCode : formatted;
            return;
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback.
        }

        ReceiveVm.ValidationMessage = Strings.ErrorInvalidCode;
    }

    public void HandleSharedText(string sharedText)
    {
        try
        {
            if (NativeBridge.TryValidateUri(sharedText.Trim(), out ValidatedCodeDto? validated, out _)
                && validated is not null)
            {
                NavigateToReceive();
                ReceiveVm.ApplyActivatedCode(validated.DisplayEnglish);
                return;
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback.
        }

        SendVm.ApplyPastedText(sharedText, fromClipboardShortcut: false);
        NavigateToSend();
    }

    public void HandleLaunchArguments(string[] args)
    {
        if (args.Length == 1 && args[0] == "--ipc-await")
        {
            return;
        }

        foreach (string arg in args)
        {
            if (arg.StartsWith("totaldrop:", StringComparison.OrdinalIgnoreCase)
                || arg.StartsWith("https://totaldrop.app/r#", StringComparison.OrdinalIgnoreCase))
            {
                NavigateToReceiveFromUri(arg);
                return;
            }

            if (arg == "--screen=receive")
            {
                NavigateToReceive();
                return;
            }

            if (arg == "--screen=settings")
            {
                NavigateToSettings();
                return;
            }
        }

        List<string> filePaths = [];
        foreach (string arg in args)
        {
            if (arg is "--explorer-send" or "--" || arg.StartsWith('-'))
            {
                continue;
            }

            filePaths.Add(arg);
        }

        if (filePaths.Count > 0)
        {
            EnqueueSendSelection(filePaths);
        }
    }

    public void ApplyIpcEnvelope(ActivationEnvelopeDto envelope)
    {
        switch (envelope.Payload.Kind)
        {
            case "explorer_send" when envelope.Payload.Paths is { Length: > 0 } paths:
                EnqueueSendSelection(paths);
                break;

            case "protocol_uri" when envelope.Payload.Code is not null:
                NavigateToReceive();
                ReceiveVm.ApplyActivatedCode(envelope.Payload.Code.DisplayEnglish);
                break;

            case "share_target":
                if (envelope.Payload.Paths is { Length: > 0 } sharedPaths)
                {
                    EnqueueSendSelection(sharedPaths);
                }
                else if (!string.IsNullOrEmpty(envelope.Payload.Text))
                {
                    HandleSharedText(envelope.Payload.Text);
                }

                break;

            case "open_screen" when envelope.Payload.Screen == "receive":
                NavigateToReceive();
                break;

            case "open_screen" when envelope.Payload.Screen == "settings":
                NavigateToSettings();
                break;
        }
    }
}
