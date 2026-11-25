package android.graphics.drawable;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;

public class GradientDrawable extends Drawable {
    public static final int RECTANGLE = 0;
    public static final int OVAL = 1;

    private int mColor = 0;
    private int mStrokeWidth = 0;
    private int mStrokeColor = 0;
    private float mRadius = 0f;
    private int mShape = RECTANGLE;
    private final Paint mPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public void setColor(int argb) { mColor = argb; }
    public void setCornerRadius(float radius) { mRadius = radius; }
    public void setShape(int shape) { mShape = shape; }
    public void setStroke(int width, int color) { mStrokeWidth = width; mStrokeColor = color; }

    @Override
    public void draw(Canvas canvas) {
        RectF rf = new RectF(mBounds);
        if ((mColor >>> 24) != 0) {
            mPaint.setStyle(Paint.Style.FILL);
            mPaint.setColor(mColor);
            if (mShape == OVAL) canvas.drawCircle(rf.centerX(), rf.centerY(), Math.min(rf.width(), rf.height()) * 0.5f, mPaint);
            else canvas.drawRoundRect(rf, mRadius, mRadius, mPaint);
        }
        if (mStrokeWidth > 0 && (mStrokeColor >>> 24) != 0) {
            mPaint.setStyle(Paint.Style.STROKE);
            mPaint.setStrokeWidth(mStrokeWidth);
            mPaint.setColor(mStrokeColor);
            if (mShape == OVAL) canvas.drawCircle(rf.centerX(), rf.centerY(), Math.min(rf.width(), rf.height()) * 0.5f, mPaint);
            else canvas.drawRoundRect(rf, mRadius, mRadius, mPaint);
        }
    }
}
