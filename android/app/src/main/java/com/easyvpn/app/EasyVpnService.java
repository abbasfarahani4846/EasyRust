package com.easyvpn.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

public final class EasyVpnService extends VpnService {
    public static final String ACTION_START = "com.easyvpn.app.START";
    public static final String ACTION_STOP = "com.easyvpn.app.STOP";
    public static final String EXTRA_PORT = "socksPort";
    public static final String EXTRA_ALLOWED = "allowedApps";
    public static final String EXTRA_DISALLOWED = "disallowedApps";

    private static final String TAG = "EasyVpn";
    private static final String CHANNEL_ID = "vpn";
    private static final int NOTIFICATION_ID = 1;
    private static final int MTU = 1500;

    private ParcelFileDescriptor tun;
    private boolean nativeStarted;
    private boolean failed;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || ACTION_STOP.equals(intent.getAction())) {
            shutdown(true);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(intent.getAction())) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        failed = false;
        try {
            showForegroundNotification();
            shutdown(false);
            Native.onVpnState(1, "");

            int port = intent.getIntExtra(EXTRA_PORT, 0);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid SOCKS port");
            }

            Builder builder = new Builder()
                    .setSession("EasyVpn")
                    .setMtu(MTU)
                    .addAddress("172.19.0.1", 30)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1");

            Set<String> allowed = packages(intent.getStringExtra(EXTRA_ALLOWED));
            Set<String> disallowed = packages(intent.getStringExtra(EXTRA_DISALLOWED));

            if (!allowed.isEmpty()) {
                int added = 0;
                for (String name : allowed) {
                    // Our own package must NEVER enter the VPN, including allowlist mode.
                    if (getPackageName().equals(name)) {
                        continue;
                    }
                    try {
                        builder.addAllowedApplication(name);
                        added++;
                    } catch (PackageManager.NameNotFoundException error) {
                        Log.w(TAG, "Skipping unknown package " + name);
                    }
                }
                if (added == 0) {
                    throw new IllegalArgumentException("No installed apps in VPN allowlist");
                }
            } else {
                builder.addDisallowedApplication(getPackageName());
                for (String name : disallowed) {
                    if (getPackageName().equals(name)) {
                        continue;
                    }
                    try {
                        builder.addDisallowedApplication(name);
                    } catch (PackageManager.NameNotFoundException error) {
                        Log.w(TAG, "Skipping unknown package " + name);
                    }
                }
            }

            tun = builder.establish();
            if (tun == null) {
                throw new IllegalStateException("VPN permission revoked or establish failed");
            }
            // Java owns the descriptor. Rust uses close_fd_on_drop(false).
            nativeStarted = true;
            int result = Native.startTun(tun.getFd(), port, MTU);
            if (result != 0) {
                throw new IllegalStateException("TUN forwarding failed: " + result);
            }
            Native.onVpnState(2, "");
        } catch (Exception error) {
            Log.e(TAG, "VPN startup failed", error);
            failed = true;
            shutdown(false);
            stopForeground(STOP_FOREGROUND_REMOVE);
            Native.onVpnState(4, error.toString());
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    private static Set<String> packages(String csv) {
        Set<String> result = new LinkedHashSet<String>();
        if (csv != null) {
            for (String entry : csv.split(",")) {
                String name = entry.trim();
                if (!name.isEmpty()) {
                    result.add(name);
                }
            }
        }
        return result;
    }

    private void showForegroundNotification() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(
                CHANNEL_ID, getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW));

        PendingIntent open = PendingIntent.getActivity(
                this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Intent stopIntent = new Intent(this, EasyVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stop = PendingIntent.getService(
                this, 1, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_vpn)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.vpn_notification_text))
                .setContentIntent(open)
                .setOngoing(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .addAction(new Notification.Action.Builder(
                        android.graphics.drawable.Icon.createWithResource(
                                this, R.drawable.ic_stat_vpn),
                        getString(R.string.disconnect), stop).build())
                .build();

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void shutdown(boolean reportIdle) {
        if (nativeStarted) {
            nativeStarted = false;
            try {
                Native.stopTun();
            } catch (RuntimeException error) {
                Log.e(TAG, "Cannot stop TUN forwarding", error);
            }
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException error) {
                Log.w(TAG, "Cannot close TUN descriptor", error);
            } finally {
                tun = null;
            }
        }
        if (reportIdle) {
            failed = false;
            stopForeground(STOP_FOREGROUND_REMOVE);
            Native.onVpnState(0, "");
        }
    }

    @Override
    public void onRevoke() {
        shutdown(true);
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        shutdown(!failed);
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
