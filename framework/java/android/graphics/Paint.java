package android.graphics;

import com.afw.AfwFont;

public class Paint {
    public static final int ANTI_ALIAS_FLAG = 1;

    public enum Style { FILL, STROKE, FILL_AND_STROKE }
    public enum Align { LEFT, CENTER, RIGHT }

    private int mColor = Color.WHITE;
    private float mTextSize = 16f;
    private float mStrokeWidth = 2f;
    private Style mStyle = Style.FILL;
    private Align mAlign = Align.LEFT;
    private Typeface mTypeface = Typeface.DEFAULT;
    private boolean mAntiAlias = true;

    public Paint() {}
    public Paint(int flags) { mAntiAlias = (flags & ANTI_ALIAS_FLAG) != 0; }
    public Paint(Paint p) {
        if (p != null) {
            mColor = p.mColor; mTextSize = p.mTextSize; mStrokeWidth = p.mStrokeWidth;
            mStyle = p.mStyle; mAlign = p.mAlign; mTypeface = p.mTypeface; mAntiAlias = p.mAntiAlias;
        }
    }

    public void setColor(int color) { mColor = color; }
    public int getColor() { return mColor; }
    public void setAlpha(int a) { mColor = ((a & 0xFF) << 24) | (mColor & 0x00FFFFFF); }
    public int getAlpha() { return (mColor >>> 24) & 0xFF; }
    public void setARGB(int a, int r, int g, int b) { mColor = Color.argb(a, r, g, b); }
    public void setTextSize(float sz) { mTextSize = Math.max(8f, sz); }
    public float getTextSize() { return mTextSize; }
    public void setStrokeWidth(float w) { mStrokeWidth = Math.max(1f, w); }
    public float getStrokeWidth() { return mStrokeWidth; }
    public void setStyle(Style s) { if (s != null) mStyle = s; }
    public Style getStyle() { return mStyle; }
    public void setTextAlign(Align a) { if (a != null) mAlign = a; }
    public Align getTextAlign() { return mAlign; }
    public void setTypeface(Typeface tf) { mTypeface = tf != null ? tf : Typeface.DEFAULT; }
    public Typeface getTypeface() { return mTypeface; }
    public void setAntiAlias(boolean aa) { mAntiAlias = aa; }
    public boolean isAntiAlias() { return mAntiAlias; }
    public void setFakeBoldText(boolean bold) {
        mTypeface = bold ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT;
    }

    public float measureText(String text) {
        return AfwFont.measureText(text, mTextSize);
    }

    public float ascent() { return -mTextSize * 0.85f; }
    public float descent() { return mTextSize * 0.2f; }
}
