package com.megademo.testapp.server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/** Localhost economy endpoint fixture. The endpoint is intentionally test-only. */
public final class EconomyClient {
    private static final String ECONOMY_URL = "http://127.0.0.1:5555/economy/coins";

    public int fetchCoins() {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(ECONOMY_URL).openConnection();
            connection.setConnectTimeout(250);
            connection.setReadTimeout(250);
            connection.setRequestMethod("GET");
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                return 0;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
            String response = reader.readLine();
            reader.close();
            return parseCoins(response);
        } catch (Exception ignored) {
            return 0;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private int parseCoins(String response) {
        if (response == null) {
            return 0;
        }
        int marker = response.indexOf("\"coins\"");
        if (marker < 0) {
            return 0;
        }
        int colon = response.indexOf(':', marker);
        if (colon < 0) {
            return 0;
        }
        String digits = response.substring(colon + 1).replaceAll("[^0-9]", "");
        return digits.length() == 0 ? 0 : Integer.parseInt(digits);
    }
}
