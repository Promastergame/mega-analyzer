package com.megademo.testapp.auth;

import android.os.Debug;

/** Integrity/debug fixture for detection, explanation and strategy tests. */
public final class IntegrityGate {
    public boolean isTrustedDevice() {
        return !Debug.isDebuggerConnected();
    }
}
