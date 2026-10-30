package com.megademo.testapp.server;

import java.net.HttpURLConnection;
import java.net.URL;

/** Server-backed subscription fixture. It never contacts a real service. */
public final class SubscriptionClient {
    private static final String STATUS_URL = "http://127.0.0.1:5555/subscription/status";

    public boolean hasPremium() {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(STATUS_URL).openConnection();
            connection.setConnectTimeout(250);
            connection.setReadTimeout(250);
            connection.setRequestMethod("GET");
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                return false;
            }
            byte[] data = new byte[256];
            int length = connection.getInputStream().read(data);
            String response = new String(data, 0, Math.max(0, length), "UTF-8");
            return response.contains("\"active\":true");
        } catch (Exception ignored) {
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
