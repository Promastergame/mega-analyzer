package com.megademo.testapp.premium;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.List;

/**
 * Токены сессии (ПОДПИСКА/объекты).
 *
 * Объектные геттеры: String-токен, боксированный Boolean, список скоупов.
 * Демо для ObjectReturnInjectionStrategy (const-string → "", Boolean
 * FALSE→TRUE, коллекции → empty) и ConstReplaceStrategy (endpoint-строки).
 */
public final class TokenSessionService {
    private static final String PREFS = "demo_session";
    private static final String TOKEN_URL = "http://127.0.0.1:5555/subscription/status";
    private final SharedPreferences prefs;

    public TokenSessionService(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public String getAuthToken() {
        return prefs.getString("token", "");
    }

    public String getTokenEndpoint() {
        return TOKEN_URL;
    }

    public Boolean isTokenValidBoxed() {
        return getAuthToken().length() > 0 ? Boolean.TRUE : Boolean.FALSE;
    }

    public List<String> getTokenScopes() {
        String raw = prefs.getString("scopes", "");
        if (raw.length() == 0) {
            return Collections.emptyList();
        }
        return Collections.singletonList(raw);
    }
}
