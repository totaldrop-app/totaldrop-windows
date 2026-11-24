// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
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
///   <item><description>Windows Share Target (<see cref="ShareOperation"/>) activation via Rust <c>WinUiWindowRouter</c></description></item>
///   <item><description>File Explorer <c>IExplorerCommand</c> raw byte streaming over <see cref="PipeOptions.CurrentUserOnly"/> Named Pipe IPC</description></item>
///   <item><description>Windows App Notification (<c>----AppNotificationActivated:</c>) foreground activation</description></item>
///   <item><description>Single-instance redirection via <see cref="AppInstance"/></description></item>
/// </list>
/// </summary>
public partial class App : Application
{
    private const string SingleInstanceKey = "app.totaldrop.TotalDrop.Main";
    private const int NamedPipeChunkBytes = 16 * 1024;
    private static readonly TimeSpan NamedPipeReadTimeout = TimeSpan.FromSeconds(5);

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
            // Single-window rule (ADR 0016): forward protocol/share/Explorer/toast
            // activations to the already-open window and exit immediately.
            try
            {
                await mainInstance.RedirectActivationToAsync(activated);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Single-instance redirection failed: {ex.Message}");
                if (activated.Kind == ExtendedActivationKind.ShareTarget
                    && activated.Data is IShareTargetActivatedEventArgs shareArgs)
                {
                    try
                    {
                        shareArgs.ShareOperation.ReportCompleted();
                    }
                    catch (Exception)
                    {
                        // Ignore WinRT share-broker teardown errors during exit.
                    }
                }
            }

            Environment.Exit(0);
            return;
        }

        mainInstance.Activated += OnRedirectedActivation;

        _mainWindow = new MainWindow();
        _mainWindow.Closed += OnMainWindowClosed;
        _mainWindow.Activate();

        StartExplorerNamedPipeListener(_mainWindow.SessionId);
        try
        {
            await DispatchActivationAsync(activated, isRedirected: false);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Initial activation dispatch failed: {ex.Message}");
        }
    }

    private void OnRedirectedActivation(object? sender, AppActivationArguments e)
    {
        if (_mainWindow is null)
        {
            return;
        }

        _mainWindow.DispatcherQueue.TryEnqueue(async () =>
        {
            try
            {
                _mainWindow.BringToForeground();
                await DispatchActivationAsync(e, isRedirected: true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Redirected activation dispatch failed: {ex.Message}");
            }
        });
    }

    private async Task DispatchActivationAsync(AppActivationArguments activation, bool isRedirected)
    {
        if (activation.Kind == ExtendedActivationKind.ShareTarget
            && activation.Data is IShareTargetActivatedEventArgs shareArgs)
        {
            await HandleShareTargetAsync(shareArgs.ShareOperation);
            return;
        }

        if (_mainWindow is null)
        {
            return;
        }

        switch (activation.Kind)
        {
            case ExtendedActivationKind.AppNotification:
            {
                _mainWindow.BringToForeground();
                break;
            }

            case ExtendedActivationKind.Protocol
                when activation.Data is IProtocolActivatedEventArgs protocolArgs
                    && protocolArgs.Uri is not null:
            {
                string rawUri = protocolArgs.Uri.AbsoluteUri;
                await _mainWindow.RouteProtocolUriAsync(rawUri);
                break;
            }

            case ExtendedActivationKind.Launch:
            {
                string[] rawArgs = ExtractLaunchArguments(activation, isRedirected);
                foreach (string arg in rawArgs)
                {
                    if (arg.StartsWith("----AppNotificationActivated:", StringComparison.OrdinalIgnoreCase))
                    {
                        _mainWindow.BringToForeground();
                        return;
                    }
                }

                if (rawArgs.Length > 0)
                {
                    await _mainWindow.HandleLaunchArgumentsAsync(rawArgs);
                }

                break;
            }
        }
    }

    private static string[] ExtractLaunchArguments(AppActivationArguments activation, bool isRedirected)
    {
        if (!isRedirected)
        {
            string[] cliArgs = Environment.GetCommandLineArgs();
            return cliArgs.Length > 1 ? cliArgs.AsSpan(1).ToArray() : [];
        }

        if (activation.Data is ILaunchActivatedEventArgs launchArgs
            && !string.IsNullOrWhiteSpace(launchArgs.Arguments))
        {
            return SplitWin32CommandLineArgs(launchArgs.Arguments);
        }

        return [];
    }

    /// <summary>
    /// Deterministic <c>CommandLineToArgvW</c>-compatible splitter for redirected
    /// <see cref="ILaunchActivatedEventArgs.Arguments"/> without calling
    /// <c>Environment.GetCommandLineArgs()</c> (which returns the primary process's
    /// original arguments instead of the secondary activation's arguments).
    /// </summary>
    internal static string[] SplitWin32CommandLineArgs(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return [];
        }

        List<string> tokens = [];
        int idx = 0;
        int len = commandLine.Length;

        while (idx < len)
        {
            while (idx < len && (commandLine[idx] == ' ' || commandLine[idx] == '\t'))
            {
                idx++;
            }

            if (idx >= len)
            {
                break;
            }

            StringBuilder current = new();
            bool inQuotes = false;
            int backslashes = 0;

            while (idx < len)
            {
                char ch = commandLine[idx++];
                if (ch == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (ch == '"')
                {
                    current.Append('\\', backslashes / 2);
                    if ((backslashes & 1) == 0)
                    {
                        if (inQuotes && idx < len && commandLine[idx] == '"')
                        {
                            idx++;
                            current.Append('"');
                        }
                        else
                        {
                            inQuotes = !inQuotes;
                        }
                    }
                    else
                    {
                        current.Append('"');
                    }

                    backslashes = 0;
                    continue;
                }

                if (backslashes > 0)
                {
                    current.Append('\\', backslashes);
                    backslashes = 0;
                }

                if (!inQuotes && (ch == ' ' || ch == '\t'))
                {
                    break;
                }

                current.Append(ch);
            }

            if (backslashes > 0)
            {
                current.Append('\\', backslashes);
            }

            tokens.Add(current.ToString());
        }

        if (tokens.Count > 0
            && GetWin32FileName(tokens[0]).Equals("totaldrop-winui.exe", StringComparison.OrdinalIgnoreCase))
        {
            tokens.RemoveAt(0);
        }

        return [.. tokens];
    }

    private static ReadOnlySpan<char> GetWin32FileName(string path)
    {
        int sep = path.AsSpan().LastIndexOfAny('\\', '/');
        return sep >= 0 ? path.AsSpan(sep + 1) : path.AsSpan();
    }

    private async Task HandleShareTargetAsync(ShareOperation shareOperation)
    {
        WinRtShareOperationAdapter lifecycle = new(shareOperation);
        if (_mainWindow is null)
        {
            // Complete ShareOperation cleanly even if window failed to initialize.
            _ = ShareTargetRouter.Route(
                routerId: 0,
                extractPayload: static () => new ShareTargetInput(),
                lifecycle: lifecycle);
            return;
        }

        await _mainWindow.RouteShareTargetAsync(
            extractPayloadAsync: () => ExtractShareTargetInputAsync(shareOperation.Data),
            lifecycle: lifecycle);
    }

    private static async Task<ShareTargetInput> ExtractShareTargetInputAsync(DataPackageView data)
    {
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
                return new ShareTargetInput(StorageItemPaths: paths);
            }
        }

        if (data.Contains(StandardDataFormats.WebLink))
        {
            Uri? webLink = await data.GetWebLinkAsync();
            if (webLink is not null)
            {
                return new ShareTargetInput(WebLink: webLink.AbsoluteUri);
            }
        }

        if (data.Contains(StandardDataFormats.Text))
        {
            string sharedText = await data.GetTextAsync();
            return new ShareTargetInput(Text: sharedText);
        }

        return new ShareTargetInput();
    }

    /// <summary>
    /// Listens on <c>\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.&lt;SessionId&gt;</c>
    /// restricted to the current Windows user (<see cref="PipeOptions.CurrentUserOnly"/>)
    /// and streams raw byte chunks + 0-byte EOF flush directly into Rust
    /// <c>totaldrop_win_router_ingest_ipc_bytes_json</c> (zero C# JSON/framing parsing).
    /// </summary>
    private void StartExplorerNamedPipeListener(uint sessionId)
    {
        _ipcCts = new CancellationTokenSource();
        CancellationToken token = _ipcCts.Token;

        string pipeName = $@"LOCAL\app.totaldrop.TotalDrop.v1.{sessionId}";

        _ = Task.Run(async () =>
        {
            byte[] buffer = new byte[NamedPipeChunkBytes];

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

                    await server.WaitForConnectionAsync(token).ConfigureAwait(false);

                    MainWindow? window = _mainWindow;
                    if (window is null)
                    {
                        continue;
                    }

                    await window.AcquireRouterStreamGateAsync(token).ConfigureAwait(false);
                    bool needsEofFlush = false;
                    try
                    {
                        using CancellationTokenSource connCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                        connCts.CancelAfter(NamedPipeReadTimeout);

                        while (!token.IsCancellationRequested)
                        {
                            int bytesRead = await server
                                .ReadAsync(buffer.AsMemory(0, buffer.Length), connCts.Token)
                                .ConfigureAwait(false);
                            if (bytesRead == 0)
                            {
                                // Clean EOF flush: validates no truncated header or partial frame remains.
                                needsEofFlush = false;
                                _ = DispatchNamedPipeChunk(window, ReadOnlySpan<byte>.Empty);
                                break;
                            }

                            needsEofFlush = true;
                            if (!DispatchNamedPipeChunk(window, buffer.AsSpan(0, bytesRead)))
                            {
                                // Rust rejected oversized (>4 MiB) or malformed frame and reset its decoder.
                                needsEofFlush = false;
                                break;
                            }
                        }
                    }
                    finally
                    {
                        try
                        {
                            if (needsEofFlush)
                            {
                                // Abrupt IOException, timeout, or cancellation mid-frame: flush 0-byte EOF
                                // before releasing the gate so Rust resets IpcFrameDecoder cleanly (F-01).
                                _ = window.TryIngestNamedPipeChunk(ReadOnlySpan<byte>.Empty, out _);
                            }
                        }
                        finally
                        {
                            window.ReleaseRouterStreamGate();
                        }
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    break;
                }
                catch (OperationCanceledException)
                {
                    Debug.WriteLine("Explorer IPC listener connection timed out.");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Explorer IPC listener warning: {ex.Message}");
                    try
                    {
                        await Task.Delay(250, token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }, token);
    }

    private static bool DispatchNamedPipeChunk(MainWindow window, ReadOnlySpan<byte> chunk)
    {
        if (!window.TryIngestNamedPipeChunk(chunk, out RouterDecisionDto[] decisions))
        {
            return false;
        }

        if (decisions.Length > 0)
        {
            window.DispatcherQueue.TryEnqueue(() =>
            {
                window.BringToForeground();
                window.ApplyRouterDecisions(decisions);
            });
        }

        return true;
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

        _mainWindow?.DisposeSystemIntegrations();
    }

    private sealed class WinRtShareOperationAdapter(ShareOperation shareOperation) : IShareOperationLifecycle
    {
        public void ReportStarted() => shareOperation.ReportStarted();

        public void ReportDataRetrieved() => shareOperation.ReportDataRetrieved();

        public void ReportCompleted() => shareOperation.ReportCompleted();
    }
}
