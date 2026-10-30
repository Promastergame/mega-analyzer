package com.megademo.testapp.auth;

import android.content.Context;

import com.megademo.testapp.server.AgeVerificationClient;

/** Local app-owned gate that consumes the server age decision. */
public final class AgeGate {
    private final Context context;

    public AgeGate(Context context) {
        this.context = context;
    }

    public boolean canOpenMatureSection(String profileId) {
        boolean serverAdult = new AgeVerificationClient().isAdult(profileId);
        boolean rememberedAdult = context.getSharedPreferences("demo_age", Context.MODE_PRIVATE)
                .getBoolean("adult", false);
        return serverAdult && rememberedAdult;
    }
}
