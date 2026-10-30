package com.megademo.testapp.coins;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Wide-экономка (МОНЕТКИ, long).
 *
 * Баланс в long — типовой кейс мобильных игр (getCoins()J). Демо для
 * WideMaxInjectionStrategy: 32-битный const сюда не встанет (нужна пара
 * регистров + const-wide), whole-body стаб выкинул бы телеметрию.
 */
public final class WideWalletService {
    private static final String PREFS = "demo_wallet_wide";
    private static final String COINS = "coins_long";
    private static final String GEMS = "gems_long";
    private final SharedPreferences prefs;

    public WideWalletService(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public long getCoinsLong() {
        return prefs.getLong(COINS, 250L);
    }

    public long getGemsLong() {
        return prefs.getLong(GEMS, 10L);
    }

    public double getCoinsDouble() {
        return (double) getCoinsLong();
    }

    public boolean canAffordLong(long cost) {
        return getCoinsLong() >= cost;
    }

    public boolean spendCoinsLong(long cost) {
        if (!canAffordLong(cost)) {
            return false;
        }
        prefs.edit().putLong(COINS, getCoinsLong() - cost).apply();
        return true;
    }
}
