package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.View;

public class TextView extends View {
    protected CharSequence mText = "";
    protected final Paint mPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    protected int mGravity = Gravity.LEFT | Gravity.CENTER_VERTICAL;

    public TextView(Context ctx) {
        super(ctx);
        mPaint.setColor(Color.WHITE);
        mPaint.setTextSize(16f);
    }
    public TextView(Context ctx, AttributeSet attrs) { this(ctx); }

    public void setText(CharSequence text) { mText = (text != null) ? text : ""; }
    public void setText(int resId) {
        if (mContext != null && mContext.getResources() != null) setText(mContext.getString(resId));
    }
    public CharSequence getText() { return mText; }
    public void setTextColor(int color) { mPaint.setColor(color); }
    public int getCurrentTextColor() { return mPaint.getColor(); }
    public void setTextSize(float size) { mPaint.setTextSize(size); }
    public void setTextSize(int unit, float size) { mPaint.setTextSize(size); }
    public float getTextSize() { return mPaint.getTextSize(); }
    public void setTypeface(Typeface tf) { mPaint.setTypeface(tf); }
    public void setTypeface(Typeface tf, int style) { mPaint.setTypeface(Typeface.create(tf, style)); }
    public void setGravity(int gravity) { mGravity = gravity; }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        String s = mText.toString();
        String[] lines = s.isEmpty() ? new String[]{""} : s.split("\n", -1);
        float maxW = 0f;
        for (String line : lines) maxW = Math.max(maxW, mPaint.measureText(line));
        float lineH = mPaint.getTextSize() * 1.35f;
        int wantW = Math.max(mMinWidth, (int) Math.ceil(maxW) + mPadLeft + mPadRight + 8);
        int wantH = Math.max(mMinHeight, (int) Math.ceil(lines.length * lineH) + mPadTop + mPadBottom + 6);
        setMeasuredDimension(resolveSize(wantW, widthSpec), resolveSize(wantH, heightSpec));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        String s = mText.toString();
        if (s.isEmpty()) return;
        String[] lines = s.split("\n", -1);
        float lineH = mPaint.getTextSize() * 1.35f;
        float totalH = lines.length * lineH;
        float availW = Math.max(0, getWidth() - mPadLeft - mPadRight);
        float availH = Math.max(0, getHeight() - mPadTop - mPadBottom);
        float startY = mPadTop + mPaint.getTextSize();
        if ((mGravity & Gravity.CENTER_VERTICAL) == Gravity.CENTER_VERTICAL) {
            startY = mPadTop + (availH - totalH) * 0.5f + mPaint.getTextSize() * 0.85f;
        }
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            float tw = mPaint.measureText(line);
            float x = mPadLeft;
            if ((mGravity & Gravity.CENTER_HORIZONTAL) == Gravity.CENTER_HORIZONTAL)
                x = mPadLeft + (availW - tw) * 0.5f;
            else if ((mGravity & Gravity.RIGHT) == Gravity.RIGHT)
                x = getWidth() - mPadRight - tw;
            canvas.drawText(line, x, startY + i * lineH, mPaint);
        }
    }
}
