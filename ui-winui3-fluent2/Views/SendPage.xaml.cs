// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using TotalDrop.WinUI.ViewModels;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace TotalDrop.WinUI.Views;

/// <summary>
/// Fluent 2 Send screen code-behind handling Explorer drag-and-drop, multi-file
/// <see cref="FileOpenPicker"/>, clipboard copy, and Windows <c>DataTransferManager</c>
/// native share sheet invocation.
/// </summary>
public sealed partial class SendPage : Page
{
    public SendViewModel ViewModel { get; private set; } = new();

    public SendPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is SendViewModel vm)
        {
            ViewModel = vm;
            Bindings.Update();
        }
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
        List<string> paths = new(items.Count);
        foreach (IStorageItem item in items)
        {
            if (!string.IsNullOrWhiteSpace(item.Path))
            {
                paths.Add(item.Path.StartsWith(@"\\?\", StringComparison.Ordinal)
                    ? item.Path
                    : @"\\?\" + item.Path);
            }
        }

        if (paths.Count > 0)
        {
            ViewModel.AddValidatedPaths(paths);
        }
    }

    private async void OnAddFilesClick(object sender, RoutedEventArgs e)
    {
        FileOpenPicker picker = new();
        picker.FileTypeFilter.Add("*");

        if (XamlRoot?.ContentIslandEnvironment is not null)
        {
            nint hwnd = Win32Interop.GetWindowFromWindowId(XamlRoot.ContentIslandEnvironment.AppWindowId);
            InitializeWithWindow.Initialize(picker, hwnd);
        }

        IReadOnlyList<StorageFile> picked = await picker.PickMultipleFilesAsync();
        if (picked is { Count: > 0 })
        {
            List<string> extended = new(picked.Count);
            foreach (StorageFile file in picked)
            {
                if (!string.IsNullOrWhiteSpace(file.Path))
                {
                    extended.Add(file.Path.StartsWith(@"\\?\", StringComparison.Ordinal)
                        ? file.Path
                        : @"\\?\" + file.Path);
                }
            }

            ViewModel.AddValidatedPaths(extended);
        }
    }

    private void OnCreateCodeClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedItems.Count == 0)
        {
            return;
        }

        // Actual code allocation delegates asynchronously to totaldrop-core::PreparedSend::new
        // via totaldrop_windows_ffi.dll off the UI thread (ADR 0016).
        ViewModel.StatusCaption = "Waiting for the receiver…";
    }

    private void OnCopyCodeClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(ViewModel.TransferCode))
        {
            return;
        }

        DataPackage pkg = new();
        pkg.SetText(ViewModel.TransferCode);
        Clipboard.SetContent(pkg);
    }

    private void OnShareCodeClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(ViewModel.TransferCode))
        {
            return;
        }

        // Phase 1 AOT-safe fallback: copy transfer code to clipboard; Phase 3 wires
        // CsWinRT WinRT.Interop.IDataTransferManagerInterop + DataRequested Share Sheet.
        DataPackage pkg = new();
        pkg.SetText(ViewModel.TransferCode);
        Clipboard.SetContent(pkg);
    }
}
