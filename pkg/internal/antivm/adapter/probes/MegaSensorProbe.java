import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

// Shell-side observation through Android's actual SensorManager event queues.
public final class MegaSensorProbe {
    private static final class Reading implements SensorEventListener {
        final String name;
        int samples;
        boolean changed;
        float[] first;
        Reading(String name) { this.name = name; }
        public synchronized void onSensorChanged(SensorEvent event) {
            samples++;
            if (first == null) { first = event.values.clone(); return; }
            for (int i = 0; i < 3; i++) {
                if (Math.abs(event.values[i] - first[i]) > 0.00001f) changed = true;
            }
        }
        public void onAccuracyChanged(Sensor sensor, int accuracy) {}
        synchronized void print(boolean available, boolean registered) {
            System.out.println("sensor." + name + ".available=" + available);
            System.out.println("sensor." + name + ".registered=" + registered);
            System.out.println("sensor." + name + ".samples=" + samples);
            System.out.println("sensor." + name + ".moving=" + (changed && samples > 1));
        }
    }
    public static void main(String[] args) {
        try {
            Looper.prepareMainLooper();
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Object thread = activityThread.getMethod("systemMain").invoke(null);
            Context context = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
            SensorManager manager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            HandlerThread callbacks = new HandlerThread("mega-sensor-probe");
            callbacks.start();
            Handler handler = new Handler(callbacks.getLooper());
            Sensor accel = manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
            Sensor gyro = manager.getDefaultSensor(Sensor.TYPE_GYROSCOPE);
            Reading ar = new Reading("acceleration"), gr = new Reading("gyroscope");
            boolean ac = accel != null && manager.registerListener(ar, accel, 100000, handler);
            boolean gc = gyro != null && manager.registerListener(gr, gyro, 100000, handler);
            int window = args.length == 0 ? 1200 : Integer.parseInt(args[0]);
            window = Math.max(200, Math.min(window, 10000));
            new CountDownLatch(1).await(window, TimeUnit.MILLISECONDS);
            manager.unregisterListener(ar);
            manager.unregisterListener(gr);
            callbacks.quitSafely();
            callbacks.join(2000);
            ar.print(accel != null, ac);
            gr.print(gyro != null, gc);
            System.exit(0);
        } catch (Throwable error) {
            error.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
