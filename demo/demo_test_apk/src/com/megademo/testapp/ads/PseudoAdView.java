package com.megademo.testapp.ads;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.View;

/** Canvas-only pseudo advertisement for the demo fixture. */
public final class PseudoAdView extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public PseudoAdView(Context context) {
        super(context);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float width = getWidth();
        float height = getHeight();

        paint.setColor(Color.rgb(24, 31, 45));
        canvas.drawRoundRect(16, 16, width - 16, height - 16, 20, 20, paint);

        paint.setColor(Color.rgb(255, 193, 7));
        canvas.drawCircle(width - 58, 58, 28, paint);

        paint.setColor(Color.WHITE);
        paint.setTextSize(22);
        canvas.drawText("PSEUDO AD", 34, 58, paint);

        paint.setTextSize(25);
        canvas.drawText("Купи гараж за 9฿", 34, 112, paint);
        paint.setTextSize(18);
        canvas.drawText("в Сан-Марино", 34, 144, paint);

        paint.setColor(Color.rgb(76, 175, 80));
        canvas.drawRoundRect(34, height - 74, width - 34, height - 30, 12, 12, paint);
        paint.setColor(Color.WHITE);
        paint.setTextSize(18);
        canvas.drawText("ОТКРЫТЬ ПРЕДЛОЖЕНИЕ", 54, height - 45, paint);
    }
}
