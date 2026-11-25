package android.graphics.drawable;

import android.graphics.Canvas;
import android.graphics.Paint;

public class ColorDrawable extends Drawable {
    private int mColor;
    private final Paint mPaint = new Paint();

    public ColorDrawable() { this(0); }
    public ColorDrawable(int color) { mColor = color; }

    public int getColor() { return mColor; }
    public void setColor(int color) { mColor = color; }

    @Override
    public void draw(Canvas canvas) {
        if ((mColor >>> 24) == 0) return;
        mPaint.setColor(mColor);
        canvas.drawRect(mBounds, mPaint);
    }
}
