package com.easyvpn.app;

import android.Manifest;
import android.app.Activity;
import android.app.NativeActivity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public final class MainActivity extends NativeActivity {
    private static final String TAG = "EasyVpn";
    private static final int VPN_PERMISSION_REQUEST = 1;
    private static final int NOTIFICATION_PERMISSION_REQUEST = 2;
    private static volatile MainActivity instance;

    private boolean awaitingVpnPermission;
    private int pendingPort;
    private String pendingAllowed = "";
    private String pendingDisallowed = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // NativeActivity loads Rust during super.onCreate(), so prepare assets first.
        try {
            copyCoreAssets();
        } catch (IOException error) {
            Log.e(TAG, "Cannot prepare core assets", error);
            throw new IllegalStateException("Cannot prepare core assets", error);
        }

        instance = this;
        super.onCreate(savedInstanceState);

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[] { Manifest.permission.POST_NOTIFICATIONS },
                    NOTIFICATION_PERMISSION_REQUEST);
        }
    }

    private void copyCoreAssets() throws IOException {
        File directory = new File(getFilesDir(), "assets");
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("Cannot create " + directory);
        }
        copyAsset(directory, "geoip.dat");
        copyAsset(directory, "geosite.dat");
    }

    private void copyAsset(File directory, String name) throws IOException {
        File target = new File(directory, name);
        File temporary = new File(directory, name + ".tmp");
        long size = 0;
        try {
            try (InputStream input = getAssets().open(name);
                 FileOutputStream output = new FileOutputStream(temporary)) {
                byte[] buffer = new byte[65536];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    output.write(buffer, 0, count);
                    size += count;
                }
                output.getFD().sync();
            }
            if (target.isFile() && target.length() == size) {
                return;
            }
            if (!temporary.renameTo(target)) {
                try (FileInputStream input = new FileInputStream(temporary);
                     FileOutputStream output = new FileOutputStream(target)) {
                    byte[] buffer = new byte[65536];
                    int count;
                    while ((count = input.read(buffer)) != -1) {
                        output.write(buffer, 0, count);
                    }
                    output.getFD().sync();
                }
            }
        } finally {
            if (temporary.exists() && !temporary.delete()) {
                Log.w(TAG, "Cannot delete " + temporary);
            }
        }
    }

    public static void startScanner() {
        final MainActivity activity = instance;
        if (activity == null) {
            Native.onQrResult(2, "Activity is not available");
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (activity.isFinishing() || activity.isDestroyed()) {
                        Native.onQrResult(2, "Activity is not available");
                        return;
                    }
                    activity.startActivity(new Intent(activity, ScannerActivity.class));
                } catch (RuntimeException error) {
                    Log.e(TAG, "Cannot open QR scanner", error);
                    Native.onQrResult(2, "Cannot open camera scanner: " + error.toString());
                }
            }
        });
    }

    public static void startVpn(final int port, final String allowed,
                                final String disallowed) {
        final MainActivity activity = instance;
        if (activity == null) {
            Native.onVpnState(4, "Activity is not available");
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                activity.requestVpn(port, allowed, disallowed);
            }
        });
    }

    private void requestVpn(int port, String allowed, String disallowed) {
        if (port < 1 || port > 65535) {
            Native.onVpnState(4, "Invalid SOCKS port");
            return;
        }
        pendingPort = port;
        pendingAllowed = allowed == null ? "" : allowed;
        pendingDisallowed = disallowed == null ? "" : disallowed;
        Native.onVpnState(1, "");
        try {
            Intent permission = VpnService.prepare(this);
            if (permission != null) {
                if (!awaitingVpnPermission) {
                    awaitingVpnPermission = true;
                    startActivityForResult(permission, VPN_PERMISSION_REQUEST);
                }
            } else {
                awaitingVpnPermission = false;
                launchVpnService();
            }
        } catch (RuntimeException error) {
            awaitingVpnPermission = false;
            pendingPort = 0;
            Native.onVpnState(4, error.toString());
        }
    }

    private void launchVpnService() {
        if (pendingPort == 0) {
            return;
        }
        Intent intent = new Intent(this, EasyVpnService.class);
        intent.setAction(EasyVpnService.ACTION_START);
        intent.putExtra(EasyVpnService.EXTRA_PORT, pendingPort);
        intent.putExtra(EasyVpnService.EXTRA_ALLOWED, pendingAllowed);
        intent.putExtra(EasyVpnService.EXTRA_DISALLOWED, pendingDisallowed);
        pendingPort = 0;
        startForegroundService(intent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_PERMISSION_REQUEST) {
            return;
        }
        boolean requested = awaitingVpnPermission;
        awaitingVpnPermission = false;
        if (!requested || pendingPort == 0) {
            return;
        }
        if (resultCode == Activity.RESULT_OK) {
            try {
                launchVpnService();
            } catch (RuntimeException error) {
                Native.onVpnState(4, error.toString());
            }
        } else {
            pendingPort = 0;
            Native.onVpnState(3, "permission denied");
        }
    }

    public static void stopVpn() {
        final MainActivity activity = instance;
        if (activity == null) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                activity.pendingPort = 0;
                activity.awaitingVpnPermission = false;
                try {
                    Intent intent = new Intent(activity, EasyVpnService.class);
                    intent.setAction(EasyVpnService.ACTION_STOP);
                    activity.startService(intent);
                } catch (RuntimeException error) {
                    Log.e(TAG, "Cannot send VPN stop", error);
                    Native.onVpnState(4, error.toString());
                }
            }
        });
    }

    @Override
    protected void onDestroy() {
        if (instance == this) {
            instance = null;
        }
        super.onDestroy();
    }
}
