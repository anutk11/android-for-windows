package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;

public class ProgressBar extends View {
    protected int mMax = 100;
    protected int mProgress = 0;
    protected final Paint mPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public ProgressBar(Context ctx) {
        super(ctx);
        setMinimumHeight(24);
    }
    public ProgressBar(Context ctx, AttributeSet attrs) { this(ctx); }

    public int getMax() { return mMax; }
    public void setMax(int max) { mMax = Math.max(1, max); if (mProgress > mMax) mProgress = mMax; }
    public int getProgress() { return mProgress; }
    public void setProgress(int progress) { mProgress = Math.max(0, Math.min(mMax, progress)); }

    @Override
    protected void onDraw(Canvas canvas) {
        int w = getWidth() - mPadLeft - mPadRight;
        int h = getHeight();
        int cy = h / 2;
        int trackH = 8;
        mPaint.setStyle(Paint.Style.FILL);
        mPaint.setColor(0xFF374151);
        canvas.drawRoundRect(mPadLeft, cy - trackH / 2f, mPadLeft + w, cy + trackH / 2f, 4f, 4f, mPaint);
        float frac = (float) mProgress / (float) mMax;
        mPaint.setColor(0xFF38BDF8);
        canvas.drawRoundRect(mPadLeft, cy - trackH / 2f, mPadLeft + w * frac, cy + trackH / 2f, 4f, 4f, mPaint);
    }
}
