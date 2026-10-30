package com.megademo.testapp.premium;

import android.content.Context;

import com.megademo.testapp.server.SubscriptionClient;

/**
 * Премиум-гейт (ПОДПИСКА).
 *
 * AND-funnel: сервер И локальный кэш должны сказать «да». Демо для
 * EntryGateStrategy / PartialBypassStrategy: инвертировать ВСЕ ветки здесь
 * нельзя (сломает AND-семантику) — трогаем только entry-gate. Боксированный
 * Boolean — демо для ObjectReturnInjectionStrategy (sget FALSE→TRUE in place).
 */
public final class SubscriptionGate {
    private final Context context;

    public SubscriptionGate(Context context) {
        this.context = context;
    }

    public boolean hasPremium() {
        boolean serverPremium = new SubscriptionClient().hasPremium();
        boolean cachedPremium = context.getSharedPreferences("demo_premium", Context.MODE_PRIVATE)
                .getBoolean("premium", false);
        return serverPremium && cachedPremium;
    }

    public Boolean isPremiumBoxed() {
        return hasPremium() ? Boolean.TRUE : Boolean.FALSE;
    }

    public boolean isTrialExpired() {
        long trialEnd = context.getSharedPreferences("demo_premium", Context.MODE_PRIVATE)
                .getLong("trial_end", 0L);
        return System.currentTimeMillis() > trialEnd;
    }
}
