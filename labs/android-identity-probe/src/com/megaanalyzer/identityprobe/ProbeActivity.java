package com.megaanalyzer.identityprobe;

import android.app.Activity;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Reads identity in a normal app forked from Android's zygote. */
public final class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            JSONObject identity = new JSONObject();
            identity.put("capture_id", getIntent().getStringExtra("capture_id"));
            identity.put("model", Build.MODEL);
            identity.put("brand", Build.BRAND);
            identity.put("manufacturer", Build.MANUFACTURER);
            identity.put("device", Build.DEVICE);
            identity.put("product", Build.PRODUCT);
            identity.put("hardware", Build.HARDWARE);
            identity.put("board", Build.BOARD);
            identity.put("fingerprint", Build.FINGERPRINT);
            identity.put("build_id", Build.ID);
            identity.put("display_id", Build.DISPLAY);
            identity.put("security_patch", Build.VERSION.SECURITY_PATCH);
            identity.put("device_name", Settings.Global.getString(getContentResolver(), "device_name"));
            identity.put("build_type", Build.TYPE);
            identity.put("build_tags", Build.TAGS);
            identity.put("android_version", Build.VERSION.RELEASE);
            identity.put("api_level", Build.VERSION.SDK_INT);
            identity.put("abis", new JSONArray(Arrays.asList(Build.SUPPORTED_ABIS)));
            identity.put("qemu_pipe_present", new File("/dev/qemu_pipe").exists());
            identity.put("goldfish_pipe_present", new File("/dev/goldfish_pipe").exists());
            try {
                TelephonyManager telephony = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
                String number = telephony == null ? null : telephony.getLine1Number();
                identity.put("phone_number", number == null ? JSONObject.NULL : number);
            } catch (SecurityException denied) {
                identity.put("phone_number", JSONObject.NULL);
                identity.put("phone_number_error", denied.toString());
            }
            identity.put("adb_enabled", Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, -1));
            try {
                Intent usb = registerReceiver(null, new IntentFilter("android.hardware.usb.action.USB_STATE"));
                identity.put("usb_state_available", usb != null);
                identity.put("usb_connected", usb == null ? JSONObject.NULL : usb.getBooleanExtra("connected", false));
                identity.put("usb_configured", usb == null ? JSONObject.NULL : usb.getBooleanExtra("configured", false));
                identity.put("usb_adb", usb == null ? JSONObject.NULL : usb.getBooleanExtra("adb", false));
            } catch (SecurityException denied) {
                identity.put("usb_state_available", false);
                identity.put("usb_connected", JSONObject.NULL);
                identity.put("usb_error", denied.toString());
            }
            try (FileOutputStream output = new FileOutputStream(new File(getFilesDir(), "identity.json"))) {
                output.write(identity.toString(2).getBytes(StandardCharsets.UTF_8));
            }
            Log.i("MegaIdentityProbe", identity.toString());
            TextView view = new TextView(this);
            view.setText(identity.toString(2));
            view.setPadding(24, 24, 24, 24);
            setContentView(view);
        } catch (Exception failure) {
            Log.e("MegaIdentityProbe", "Could not capture identity", failure);
        }
    }
}
