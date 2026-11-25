package com.afw.dexdemo;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.View;

public class DemoView extends View {
    private String banner;
    private int score;

    public DemoView(String banner, int score) {
        super();
        this.banner = banner;
        this.score = score;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        Paint p = new Paint();
        /* Emerald green background */
        canvas.drawColor(Color.rgb(24, 120, 64));

        /* Bright gold rectangle in upper half */
        p.setColor(Color.rgb(240, 200, 40));
        canvas.drawRect(80.0f, 60.0f, 560.0f, 200.0f, p);

        /* Bright red circle in center-bottom */
        p.setColor(Color.rgb(220, 48, 48));
        canvas.drawCircle(320.0f, 340.0f, 90.0f, p);

        /* White text inside gold banner */
        p.setColor(Color.rgb(20, 20, 20));
        p.setTextSize(28.0f);
        canvas.drawText(this.banner, 110.0f, 115.0f, p);
    }
}
