package com.megademo.testapp.ads;

/** Pseudo-ad SDK wrapper with a local ad decision point and reward callback. */
public final class PseudoAdController {
    private boolean adLoaded;

    public boolean shouldShowAd() {
        return !new WalletServiceHolder().isAdFree();
    }

    public void loadAd() {
        adLoaded = true;
    }

    public boolean showRewardedAd() {
        if (!adLoaded || !shouldShowAd()) {
            return false;
        }
        adLoaded = false;
        return true;
    }

    public PseudoAdView createAdView(android.content.Context context) {
        if (!shouldShowAd()) {
            return null;
        }
        loadAd();
        return new PseudoAdView(context);
    }

    private static final class WalletServiceHolder {
        boolean isAdFree() {
            return false;
        }
    }
}
