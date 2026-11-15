// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using TotalDrop.WinUI.Interop;
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
/// per ADR 0016 and <c>docs/design.md</c>.
/// </summary>
public sealed partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly UISettings _uiSettings = new();
    private readonly AccessibilitySettings _accessibilitySettings = new();

    public SendViewModel SendVm { get; } = new();

    public ReceiveViewModel ReceiveVm { get; } = new();

    public string SendTabTitle { get; private set; } = "Send files";

    public string ReceiveTabTitle { get; private set; } = "Receive files";

    public bool AnimationsAllowed => _uiSettings.AnimationsEnabled;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        InitializeComponent();

        ConfigureCustomTitleBar();
        ConfigureFluentBackdrop();
        ApplyLocalizationAndFlowDirection();
        UpdateTitleBarCaptionColors();

        // Live theme, Accent Color, and High Contrast listeners without restart (ADR 0016).
        _uiSettings.ColorValuesChanged += OnSystemColorsChanged;
        _accessibilitySettings.HighContrastChanged += OnHighContrastChanged;
        RootShellGrid.ActualThemeChanged += (_, _) => UpdateTitleBarCaptionColors();

        ShellNavigation.SelectedItem = NavSendItem;
        ContentFrame.Navigate(typeof(SendPage), SendVm);
    }

    private void ConfigureCustomTitleBar()
    {
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        nint hwnd = WindowNative.GetWindowHandle(this);
        WindowId windowId = Win32Interop.GetWindowIdFromWindow(hwnd);
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

    private void ApplyLocalizationAndFlowDirection()
    {
        IReadOnlyList<string> preferredLanguages = GlobalizationPreferences.Languages;
        string joinedTags = string.Join(',', preferredLanguages);
        string regionTag = System.Globalization.CultureInfo.CurrentCulture.Name;

        try
        {
            nint jsonPtr = NativeBridge.ResolveUiBundleJson(joinedTags, regionTag, "0.2.0-beta.5");
            if (jsonPtr != 0)
            {
                try
                {
                    string? json = Marshal.PtrToStringUTF8(jsonPtr);
                    if (!string.IsNullOrEmpty(json))
                    {
                        BridgeUiBundleDto? bundle = JsonSerializer.Deserialize(
                            json,
                            TotalDropJsonContext.Default.BridgeUiBundleDto);
                        if (bundle is not null)
                        {
                            SendTabTitle = bundle.SendTitle;
                            ReceiveTabTitle = bundle.ReceiveTitle;
                            RootShellGrid.FlowDirection = bundle.FlowDirection == "RightToLeft"
                                ? FlowDirection.RightToLeft
                                : FlowDirection.LeftToRight;
                            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SendTabTitle)));
                            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ReceiveTabTitle)));
                        }
                    }
                }
                finally
                {
                    NativeBridge.FreeBridgeString(jsonPtr);
                }
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time XAML preview fallback before Rust DLL is staged.
        }
    }

    private void OnSystemColorsChanged(UISettings sender, object args)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ConfigureFluentBackdrop();
            UpdateTitleBarCaptionColors();
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

    private void OnNavigationSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            return;
        }

        if (args.SelectedItem is NavigationViewItem { Tag: string tag })
        {
            switch (tag)
            {
                case "send":
                    ContentFrame.Navigate(typeof(SendPage), SendVm);
                    break;
                case "receive":
                    ContentFrame.Navigate(typeof(ReceivePage), ReceiveVm);
                    break;
            }
        }
    }

    public void BringToForeground()
    {
        Activate();
    }

    public void EnqueueSendSelection(IEnumerable<string> extendedPaths)
    {
        SendVm.AddValidatedPaths(extendedPaths);
        ShellNavigation.SelectedItem = NavSendItem;
        ContentFrame.Navigate(typeof(SendPage), SendVm);
    }

    public void NavigateToReceiveFromUri(string rawUri)
    {
        ShellNavigation.SelectedItem = NavReceiveItem;
        ContentFrame.Navigate(typeof(ReceivePage), ReceiveVm);

        try
        {
            nint ptr = NativeBridge.ValidateUriJson(rawUri);
            if (ptr != 0)
            {
                try
                {
                    string? json = Marshal.PtrToStringUTF8(ptr);
                    if (!string.IsNullOrEmpty(json))
                    {
                        ValidatedCodeDto? validated = JsonSerializer.Deserialize(
                            json,
                            TotalDropJsonContext.Default.ValidatedCodeDto);
                        if (validated is not null)
                        {
                            ReceiveVm.ApplyActivatedCode(validated.DisplayEnglish);
                            return;
                        }
                    }
                }
                finally
                {
                    NativeBridge.FreeBridgeString(ptr);
                }
            }
        }
        catch (DllNotFoundException)
        {
            // Fallback stripped scheme only when running design preview.
        }

        ReceiveVm.ValidationMessage = "That code is not valid.";
    }

    public void HandleSharedText(string sharedText)
    {
        ShellNavigation.SelectedItem = NavReceiveItem;
        ContentFrame.Navigate(typeof(ReceivePage), ReceiveVm);
        ReceiveVm.CodeInput = sharedText.Trim();
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
                ShellNavigation.SelectedItem = NavReceiveItem;
                ContentFrame.Navigate(typeof(ReceivePage), ReceiveVm);
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
                ShellNavigation.SelectedItem = NavReceiveItem;
                ContentFrame.Navigate(typeof(ReceivePage), ReceiveVm);
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
                ShellNavigation.SelectedItem = NavReceiveItem;
                ContentFrame.Navigate(typeof(ReceivePage), ReceiveVm);
                break;
        }
    }
}
