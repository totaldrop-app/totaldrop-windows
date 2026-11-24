// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using Microsoft.Windows.AppNotifications;

namespace TotalDrop.WinUI.Services;

/// <summary>
/// WinAppSDK 1.8 <see cref="AppNotificationManager"/> runtime service posting
/// background-only Windows App Notifications planned by
/// <see cref="NotificationPlanner"/> and activating the single window on click
/// (Feature #19, ADR 0016).
/// </summary>
public sealed partial class NotificationService : IDisposable
{
    private readonly Action _onActivateWindow;
    private bool _registered;
    private bool _disposed;

    public NotificationService(Action onActivateWindow)
    {
        _onActivateWindow = onActivateWindow;
    }

    /// <summary>
    /// Subscribes <see cref="AppNotificationManager.NotificationInvoked"/>
    /// BEFORE calling <see cref="AppNotificationManager.Register"/> as required
    /// by Windows App SDK 1.8. Safe no-op in unpackaged or headless environments.
    /// </summary>
    public void Register()
    {
        if (_disposed || _registered)
        {
            return;
        }

        try
        {
            AppNotificationManager manager = AppNotificationManager.Default;
            manager.NotificationInvoked += OnNotificationInvoked;
            manager.Register();
            _registered = true;
        }
        catch (Exception)
        {
            try
            {
                AppNotificationManager.Default.NotificationInvoked -= OnNotificationInvoked;
            }
            catch (Exception)
            {
                // Ignore teardown errors when WPN is unavailable.
            }

            _registered = false;
        }
    }

    public void Notify(NotificationEventInput input, INotificationLocalizer localizer)
    {
        if (_disposed || !_registered)
        {
            return;
        }

        PlannedToastNotification? planned = NotificationPlanner.TryPlan(input, localizer);
        if (planned is null)
        {
            return;
        }

        try
        {
            AppNotification notification = new(planned.XmlPayload);
            AppNotificationManager.Default.Show(notification);
        }
        catch (Exception)
        {
            // Ignore transient WPN delivery failures (e.g., quiet hours / headless CI).
        }
    }

    private void OnNotificationInvoked(AppNotificationManager sender, AppNotificationActivatedEventArgs args)
    {
        _onActivateWindow();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_registered)
        {
            _registered = false;
            try
            {
                AppNotificationManager manager = AppNotificationManager.Default;
                manager.NotificationInvoked -= OnNotificationInvoked;
                manager.Unregister();
            }
            catch (Exception)
            {
                // Ignore WPN cleanup errors during process exit.
            }
        }
    }
}
