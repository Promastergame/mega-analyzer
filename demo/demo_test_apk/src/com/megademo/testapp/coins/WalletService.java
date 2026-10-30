package com.megademo.testapp.coins;

import android.content.Context;
import android.content.SharedPreferences;

/** Local economy fixture: value provider, price gate and state mutation. */
public final class WalletService {
    private static final String PREFS = "demo_wallet";
    private static final String COINS = "coins";
    private final SharedPreferences prefs;

    public WalletService(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public int getCoins() {
        return prefs.getInt(COINS, 250);
    }

    public int getGemCost() {
        return 50;
    }

    public boolean canAfford(int cost) {
        return getCoins() >= cost;
    }

    public boolean spendCoins(int cost) {
        if (!canAfford(cost)) {
            return false;
        }
        prefs.edit().putInt(COINS, getCoins() - cost).apply();
        return true;
    }
}
