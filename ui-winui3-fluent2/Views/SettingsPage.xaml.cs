// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using TotalDrop.WinUI.ViewModels;
using Windows.System;

namespace TotalDrop.WinUI.Views;

/// <summary>
/// Fluent 2 Settings screen code-behind validating the rendezvous server URL
/// via Rust FFI, confirming Privacy Mode activation via modal
/// <see cref="ContentDialog"/>, and implementing 2-step Escape revert parity
/// with TotalDrop Linux (<c>SettingsPage.qml:26-37</c>).
/// </summary>
public sealed partial class SettingsPage : Page
{
    private bool _suppressPrivacyToggle;
    private ContentDialog? _activePrivacyDialog;

    public SettingsViewModel ViewModel { get; private set; } = new();

    public SettingsPage()
    {
        InitializeComponent();
        Unloaded += OnPageUnloaded;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is SettingsViewModel vm)
        {
            ViewModel = vm;
            Bindings.Update();
            SyncPrivacyToggleFromViewModel();
        }
    }

    public void DismissPrivacyDialog()
    {
        _activePrivacyDialog?.Hide();
        _activePrivacyDialog = null;
    }

    private void OnPageUnloaded(object sender, RoutedEventArgs e)
    {
        DismissPrivacyDialog();
    }

    private void SyncPrivacyToggleFromViewModel()
    {
        _suppressPrivacyToggle = true;
        try
        {
            PrivacyModeToggle.IsOn = ViewModel.PrivacyModeEnabled;
        }
        finally
        {
            _suppressPrivacyToggle = false;
        }
    }

    private void OnPagePreviewKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != VirtualKey.Escape)
        {
            return;
        }

        // First Escape reverts unsaved server URL edit without leaving Settings;
        // second Escape returns to the active primary page (Linux parity).
        if (ViewModel.HasUnsavedServerEdit)
        {
            ViewModel.RevertServerUrlEdit();
            e.Handled = true;
            return;
        }

        e.Handled = true;
        ViewModel.RequestNavigateBack?.Invoke();
    }

    private void OnServerUrlKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter && ViewModel.CanSaveServer)
        {
            _ = ViewModel.TrySaveServerUrl();
            e.Handled = true;
        }
    }

    private void OnSaveServerClick(object sender, RoutedEventArgs e)
    {
        _ = ViewModel.TrySaveServerUrl();
    }

    private void OnResetServerClick(object sender, RoutedEventArgs e)
    {
        _ = ViewModel.TryResetServerUrl();
    }

    private async void OnPrivacyModeToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressPrivacyToggle)
        {
            return;
        }

        if (_activePrivacyDialog is not null)
        {
            SyncPrivacyToggleFromViewModel();
            return;
        }

        bool requestedOn = PrivacyModeToggle.IsOn;
        if (!requestedOn)
        {
            // Turning OFF saves immediately with no confirmation dialog.
            if (!ViewModel.TrySetPrivacyMode(false))
            {
                SyncPrivacyToggleFromViewModel();
            }

            return;
        }

        if (XamlRoot is null)
        {
            if (!ViewModel.TrySetPrivacyMode(true))
            {
                SyncPrivacyToggleFromViewModel();
            }

            return;
        }

        // Turning ON requires explicit modal confirmation before persisting (Linux parity).
        ContentDialog dialog = new()
        {
            XamlRoot = XamlRoot,
            Title = ViewModel.Strings.PrivacyModeConfirmTitle,
            Content = ViewModel.Strings.PrivacyModeConfirmBody,
            PrimaryButtonText = ViewModel.Strings.PrivacyModeTurnOn,
            CloseButtonText = ViewModel.Strings.Cancel,
            DefaultButton = ContentDialogButton.Close,
        };
        _activePrivacyDialog = dialog;
        try
        {
            ContentDialogResult result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                if (!ViewModel.TrySetPrivacyMode(true))
                {
                    SyncPrivacyToggleFromViewModel();
                }
            }
            else
            {
                SyncPrivacyToggleFromViewModel();
            }
        }
        catch (COMException)
        {
            // Ignore dialog cancellation when another modal or window close raced.
            SyncPrivacyToggleFromViewModel();
        }
        finally
        {
            if (ReferenceEquals(_activePrivacyDialog, dialog))
            {
                _activePrivacyDialog = null;
            }
        }
    }
}
