package com.megademo.testapp.coins;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Кулдауны и таймеры (МОНЕТКИ/время).
 *
 * Геттеры остаточного времени: ноль означает «готово сейчас».
 * Демо для CooldownResetInjectionStrategy (хирургический const-0 перед
 * return, тело с телеметрией сохраняется).
 */
public final class CooldownService {
    private static final String PREFS = "demo_cooldown";
    private final SharedPreferences prefs;

    public CooldownService(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /** Остаток кулдауна в секундах. 0 = спин готов. */
    public int getCooldownRemaining(String action) {
        long readyAt = prefs.getLong("ready_" + action, 0L);
        long left = (readyAt - System.currentTimeMillis()) / 1000L;
        return left <= 0 ? 0 : (int) left;
    }

    /** Время до следующего бесплатного спина, мс. */
    public int getNextSpinMs() {
        return getCooldownRemaining("spin") * 1000;
    }

    /** Время до награды. */
    public int getTimeLeft() {
        return getCooldownRemaining("reward");
    }

    public boolean isCooldownReady(String action) {
        return getCooldownRemaining(action) == 0;
    }

    public void startCooldown(String action, int seconds) {
        prefs.edit().putLong("ready_" + action,
                System.currentTimeMillis() + seconds * 1000L).apply();
    }
}
