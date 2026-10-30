package com.megademo.testapp.server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/** Java/Smali age-verification fixture. The endpoint is loopback-only. */
public final class AgeVerificationClient {
    private static final String AGE_URL = "http://127.0.0.1:5555/age/verify";

    public boolean isAdult(String profileId) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(AGE_URL + "?profile=" + profileId).openConnection();
            connection.setConnectTimeout(250);
            connection.setReadTimeout(250);
            connection.setRequestMethod("GET");
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                return false;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
            String response = reader.readLine();
            reader.close();
            return response != null && response.contains("\"adult\":true");
        } catch (Exception ignored) {
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
