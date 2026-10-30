package com.megademo.testapp.auth;

import android.content.Context;

/** Simple local session gate used as a non-monetization control fixture. */
public final class AuthGate {
    private final Context context;

    public AuthGate(Context context) {
        this.context = context;
    }

    public boolean isAuthenticated() {
        return context.getSharedPreferences("demo_session", Context.MODE_PRIVATE)
                .getString("token", "").length() > 0;
    }
}
