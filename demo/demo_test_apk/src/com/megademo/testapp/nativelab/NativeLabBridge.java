package com.megademo.testapp.nativelab;

/**
 * Java-side native boundary fixture. A test .so may expose the lab protocol on
 * localhost:7777; missing native code is deliberately handled safely.
 */
public final class NativeLabBridge {
    private static boolean loaded;

    static {
        try {
            System.loadLibrary("demo_lab");
            loaded = true;
        } catch (UnsatisfiedLinkError ignored) {
            loaded = false;
        }
    }

    private NativeLabBridge() {}

    public static boolean isAvailable() {
        if (!loaded) {
            return false;
        }
        try {
            return nativePing();
        } catch (UnsatisfiedLinkError ignored) {
            return false;
        }
    }

    public static native boolean nativePing();

    public static native int nativeCoinsFromLab();
}
