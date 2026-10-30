package com.megademo.testapp.auth;

import android.content.Context;
import android.content.SharedPreferences;

import com.megademo.testapp.server.SubscriptionClient;

/** Feature-flag fixture with a local flag and a premium fallback. */
public final class FeatureGate {
    private final SharedPreferences flags;

    public FeatureGate(Context context) {
        flags = context.getSharedPreferences("demo_flags", Context.MODE_PRIVATE);
    }

    public boolean isFeatureEnabled(String name) {
        if ("premium_store".equals(name)) {
            return new SubscriptionClient().hasPremium();
        }
        return flags.getBoolean(name, false);
    }
}
