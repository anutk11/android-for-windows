package android.graphics.drawable;

import android.graphics.Canvas;
import android.graphics.Rect;

public abstract class Drawable {
    protected final Rect mBounds = new Rect();
    protected int mAlpha = 255;

    public abstract void draw(Canvas canvas);
    public void setBounds(int l, int t, int r, int b) { mBounds.set(l, t, r, b); }
    public void setBounds(Rect r) { if (r != null) mBounds.set(r); }
    public Rect getBounds() { return mBounds; }
    public void setAlpha(int alpha) { mAlpha = Math.max(0, Math.min(255, alpha)); }
    public int getAlpha() { return mAlpha; }
    public int getIntrinsicWidth() { return -1; }
    public int getIntrinsicHeight() { return -1; }
}
