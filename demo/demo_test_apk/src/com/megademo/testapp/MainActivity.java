package com.megademo.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.megademo.testapp.ads.PseudoAdController;
import com.megademo.testapp.auth.AgeGate;
import com.megademo.testapp.auth.FeatureGate;
import com.megademo.testapp.coins.CooldownService;
import com.megademo.testapp.coins.WalletService;
import com.megademo.testapp.coins.WideWalletService;
import com.megademo.testapp.nativelab.NativeLabBridge;
import com.megademo.testapp.premium.SubscriptionGate;
import com.megademo.testapp.premium.TokenSessionService;
import com.megademo.testapp.react.ReactAgeBridge;
import com.megademo.testapp.server.SubscriptionClient;

/** Hub-активити лабы: дергает каждую специализацию (см. ARCHITECTURE.md). */
public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        WalletService wallet = new WalletService(this);
        WideWalletService wideWallet = new WideWalletService(this);
        CooldownService cooldown = new CooldownService(this);
        FeatureGate features = new FeatureGate(this);
        AgeGate ageGate = new AgeGate(this);
        SubscriptionGate premium = new SubscriptionGate(this);
        TokenSessionService tokens = new TokenSessionService(this);
        String text = "coins=" + wallet.getCoins()
                + " coinsLong=" + wideWallet.getCoinsLong()
                + " cooldown=" + cooldown.getCooldownRemaining("spin")
                + " premium=" + new SubscriptionClient().hasPremium()
                + " gate=" + premium.hasPremium()
                + " token=" + tokens.getAuthToken()
                + " ads=" + new PseudoAdController().shouldShowAd()
                + " age18=" + ageGate.canOpenMatureSection("demo-profile")
                + " ageBridge=" + ReactAgeBridge.isAgeApproved("demo-profile")
                + " lab=" + NativeLabBridge.isAvailable();
        if (features.isFeatureEnabled("premium_store")) {
            text += " store=enabled";
        }
        final String displayText = text;
        TextView view = new TextView(this);
        view.setText(displayText);
        setContentView(view);
    }
}
