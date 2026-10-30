package com.megademo.testapp.react;

import com.megademo.testapp.server.AgeVerificationClient;

/**
 * Java-мост к React Native бандлу (РЕАКТ БУНДЛ).
 *
 * Паритет с react_native/index.android.bundle: тот же endpoint
 * (AGE_VERIFY_URL == JS AGE_ENDPOINT), та же семантика гейта
 * (server && native). Демо для bundle-aware анализа: endpoint, JSON-парсер,
 * native bridge и boolean-gate находятся в одном JS-графе, а здесь — его
 * Java-зеркало. URL — демо для ConstReplaceStrategy (string-pool only).
 */
public final class ReactAgeBridge {
    private static final String AGE_VERIFY_URL = "http://127.0.0.1:5555/age/verify";

    private ReactAgeBridge() {
    }

    public static String getBundleEndpoint() {
        return AGE_VERIFY_URL;
    }

    /** Зеркало JS canOpenMatureSection(): server && native. */
    public static boolean isAgeApproved(String profileId) {
        boolean serverAdult = new AgeVerificationClient().isAdult(profileId);
        boolean nativeAdult = nativeIsAgeApproved(profileId);
        return serverAdult && nativeAdult;
    }

    private static boolean nativeIsAgeApproved(String profileId) {
        return profileId != null && profileId.length() > 0;
    }
}
