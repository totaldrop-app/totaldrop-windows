// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using TotalDrop.WinUI.Interop;
using Windows.ApplicationModel.Activation;
using Windows.ApplicationModel.DataTransfer;
using Windows.ApplicationModel.DataTransfer.ShareTarget;
using Windows.Storage;

namespace TotalDrop.WinUI;

/// <summary>
/// Single-window Windows 11 application entry point (ADR 0016).
/// Handles:
/// <list type="bullet">
///   <item><description><c>totaldrop://r/&lt;code&gt;</c> protocol activation</description></item>
///   <item><description>Windows Share Target (<see cref="ShareOperation"/>) activation</description></item>
///   <item><description>File Explorer <c>IExplorerCommand</c> multi-file envelopes over session-local Named Pipe IPC</description></item>
///   <item><description>Single-instance redirection via <see cref="AppInstance"/></description></item>
/// </list>
/// </summary>
public partial class App : Application
{
    private const string SingleInstanceKey = "app.totaldrop.TotalDrop.Main";
    private const int MaxEnvelopeBytes = 4 * 1024 * 1024;

    private MainWindow? _mainWindow;
    private CancellationTokenSource? _ipcCts;

    public App()
    {
        InitializeComponent();
    }

    protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        AppInstance current = AppInstance.GetCurrent();
        AppActivationArguments activated = current.GetActivatedEventArgs();

        AppInstance mainInstance = AppInstance.FindOrRegisterForKey(SingleInstanceKey);
        if (!mainInstance.IsCurrent)
        {
            // Single-window rule (ADR 0016): forward protocol/share/Explorer
            // activations to the already-open window and exit immediately.
            await mainInstance.RedirectActivationToAsync(activated);
            Environment.Exit(0);
            return;
        }

        mainInstance.Activated += OnRedirectedActivation;

        _mainWindow = new MainWindow();
        _mainWindow.Closed += OnMainWindowClosed;
        _mainWindow.Activate();

        StartExplorerNamedPipeListener();
        await DispatchActivationAsync(activated);
    }

    private void OnRedirectedActivation(object? sender, AppActivationArguments e)
    {
        if (_mainWindow is null)
        {
            return;
        }

        _mainWindow.DispatcherQueue.TryEnqueue(async () =>
        {
            _mainWindow.BringToForeground();
            await DispatchActivationAsync(e);
        });
    }

    private async Task DispatchActivationAsync(AppActivationArguments activation)
    {
        if (_mainWindow is null)
        {
            return;
        }

        switch (activation.Kind)
        {
            case ExtendedActivationKind.Protocol
                when activation.Data is IProtocolActivatedEventArgs protocolArgs:
            {
                string rawUri = protocolArgs.Uri.AbsoluteUri;
                _mainWindow.NavigateToReceiveFromUri(rawUri);
                break;
            }

            case ExtendedActivationKind.ShareTarget
                when activation.Data is IShareTargetActivatedEventArgs shareArgs:
            {
                await HandleShareTargetAsync(shareArgs.ShareOperation);
                break;
            }

            case ExtendedActivationKind.Launch:
            {
                string[] cliArgs = Environment.GetCommandLineArgs();
                if (cliArgs.Length > 1)
                {
                    _mainWindow.HandleLaunchArguments(cliArgs.AsSpan(1).ToArray());
                }

                break;
            }
        }
    }

    private async Task HandleShareTargetAsync(ShareOperation shareOperation)
    {
        if (_mainWindow is null)
        {
            return;
        }

        shareOperation.ReportStarted();
        try
        {
            DataPackageView data = shareOperation.Data;
            if (data.Contains(StandardDataFormats.StorageItems))
            {
                IReadOnlyList<IStorageItem> items = await data.GetStorageItemsAsync();
                List<string> paths = new(items.Count);
                foreach (IStorageItem item in items)
                {
                    if (!string.IsNullOrWhiteSpace(item.Path))
                    {
                        paths.Add(item.Path);
                    }
                }

                if (paths.Count > 0)
                {
                    _mainWindow.EnqueueSendSelection(paths);
                }
            }
            else if (data.Contains(StandardDataFormats.WebLink))
            {
                Uri webLink = await data.GetWebLinkAsync();
                _mainWindow.NavigateToReceiveFromUri(webLink.AbsoluteUri);
            }
            else if (data.Contains(StandardDataFormats.Text))
            {
                string sharedText = await data.GetTextAsync();
                _mainWindow.HandleSharedText(sharedText);
            }
        }
        finally
        {
            shareOperation.ReportDataRetrieved();
        }
    }

    /// <summary>
    /// Listens on <c>\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.&lt;SessionId&gt;</c>
    /// restricted to the current Windows user (<see cref="PipeOptions.CurrentUserOnly"/>)
    /// for length-prefixed <see cref="ActivationEnvelopeDto"/> frames sent by
    /// <c>totaldrop_explorer_ext.dll</c> (<c>IExplorerCommand::Invoke</c>).
    /// </summary>
    private void StartExplorerNamedPipeListener()
    {
        _ipcCts = new CancellationTokenSource();
        CancellationToken token = _ipcCts.Token;

        uint pid = (uint)Environment.ProcessId;
        if (!NativeBridge.ProcessIdToSessionId(pid, out uint sessionId))
        {
            sessionId = 0;
        }

        string pipeName = $@"LOCAL\app.totaldrop.TotalDrop.v1.{sessionId}";

        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await using NamedPipeServerStream server = new(
                        pipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

                    await server.WaitForConnectionAsync(token);

                    byte[] lengthHeader = new byte[4];
                    await server.ReadExactlyAsync(lengthHeader, token);
                    uint frameLen = BinaryPrimitives.ReadUInt32LittleEndian(lengthHeader);
                    if (frameLen == 0 || frameLen > MaxEnvelopeBytes)
                    {
                        continue;
                    }

                    byte[] payloadBytes = new byte[frameLen];
                    await server.ReadExactlyAsync(payloadBytes, token);

                    ActivationEnvelopeDto? envelope = JsonSerializer.Deserialize(
                        payloadBytes,
                        TotalDropJsonContext.Default.ActivationEnvelopeDto);

                    if (envelope is { Version: 1 } && _mainWindow is not null)
                    {
                        _mainWindow.DispatcherQueue.TryEnqueue(() =>
                        {
                            _mainWindow.BringToForeground();
                            _mainWindow.ApplyIpcEnvelope(envelope);
                        });
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Explorer IPC listener warning: {ex.Message}");
                }
            }
        }, token);
    }

    private void OnMainWindowClosed(object sender, WindowEventArgs args)
    {
        _ipcCts?.Cancel();
        _ipcCts?.Dispose();
        _ipcCts = null;
        _mainWindow?.ShutdownActiveSessions();
        try
        {
            _ = NativeBridge.Shutdown(1500);
        }
        catch (DllNotFoundException)
        {
            // Design-time preview without staged native DLL.
        }

        NativeBridge.SetThreadExecutionState(NativeBridge.ExecutionState.Continuous);
    }
}
