package com.easyvpn.app;

/** JNI bridge implemented by libeasyvpn.so. */
public final class Native {
    static {
        System.loadLibrary("easyvpn");
    }

    private Native() {
    }

    public static native int startTun(int fd, int socksPort, int mtu);

    public static native void stopTun();

    public static native void onVpnState(int state, String message);

    /** Returns the decoded text, or null when this frame contains no readable QR. */
    public static native String decodeQr(byte[] luma, int width, int height, int rowStride);

    /** The Back key was pressed; Rust decides whether to navigate or leave the app. */
    public static native void onBack();

    /** status: 0 = success, 1 = cancelled, 2 = failure. */
    public static native void onQrResult(int status, String text);
}
