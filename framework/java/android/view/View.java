package android.view;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;

public class View {
    public static final int VISIBLE   = 0x00000000;
    public static final int INVISIBLE = 0x00000004;
    public static final int GONE      = 0x00000008;
    public static final int NO_ID     = -1;

    public interface OnClickListener {
        void onClick(View v);
    }

    public interface OnTouchListener {
        boolean onTouch(View v, MotionEvent event);
    }

    public static class MeasureSpec {
        public static final int UNSPECIFIED = 0 << 30;
        public static final int EXACTLY     = 1 << 30;
        public static final int AT_MOST     = 2 << 30;
        private static final int MODE_MASK  = 0x3 << 30;

        public static int makeMeasureSpec(int size, int mode) {
            return (Math.max(0, size) & ~MODE_MASK) | (mode & MODE_MASK);
        }
        public static int getMode(int spec) { return spec & MODE_MASK; }
        public static int getSize(int spec) { return spec & ~MODE_MASK; }
    }

    protected Context mContext;
    protected ViewGroup mParent;
    protected ViewGroup.LayoutParams mLayoutParams;
    protected int mId = NO_ID;
    protected Object mTag;
    protected int mVisibility = VISIBLE;
    protected boolean mEnabled = true;
    protected boolean mClickable = false;
    protected boolean mPressed = false;
    protected boolean mFocused = false;
    protected Drawable mBackground;
    protected int mLeft, mTop, mRight, mBottom;
    protected int mMeasuredWidth, mMeasuredHeight;
    protected int mPadLeft, mPadTop, mPadRight, mPadBottom;
    protected int mMinWidth, mMinHeight;
    protected OnClickListener mOnClickListener;
    protected OnTouchListener mOnTouchListener;

    public View(Context context) { mContext = context; }
    public View(Context context, AttributeSet attrs) { mContext = context; }
    public View(Context context, AttributeSet attrs, int defStyle) { mContext = context; }

    public Context getContext() { return mContext; }
    public ViewGroup getParent() { return mParent; }
    public int getId() { return mId; }
    public void setId(int id) { mId = id; }
    public Object getTag() { return mTag; }
    public void setTag(Object tag) { mTag = tag; }
    public int getVisibility() { return mVisibility; }
    public void setVisibility(int v) { mVisibility = v; }
    public boolean isEnabled() { return mEnabled; }
    public void setEnabled(boolean e) { mEnabled = e; }
    public boolean isClickable() { return mClickable; }
    public void setClickable(boolean c) { mClickable = c; }
    public boolean isPressed() { return mPressed; }
    public boolean isFocused() { return mFocused; }
    public void setFocused(boolean f) { mFocused = f; }
    public void setMinimumWidth(int w) { mMinWidth = w; }
    public void setMinimumHeight(int h) { mMinHeight = h; }

    public void setPadding(int l, int t, int r, int b) {
        mPadLeft = l; mPadTop = t; mPadRight = r; mPadBottom = b;
    }
    public int getPaddingLeft() { return mPadLeft; }
    public int getPaddingTop() { return mPadTop; }
    public int getPaddingRight() { return mPadRight; }
    public int getPaddingBottom() { return mPadBottom; }

    public void setBackgroundColor(int color) { mBackground = new ColorDrawable(color); }
    public void setBackground(Drawable d) { mBackground = d; }
    public void setBackgroundDrawable(Drawable d) { mBackground = d; }
    public Drawable getBackground() { return mBackground; }

    public ViewGroup.LayoutParams getLayoutParams() { return mLayoutParams; }
    public void setLayoutParams(ViewGroup.LayoutParams lp) { mLayoutParams = lp; }

    public void setOnClickListener(OnClickListener l) {
        mOnClickListener = l;
        if (l != null) mClickable = true;
    }
    public void setOnTouchListener(OnTouchListener l) { mOnTouchListener = l; }

    public boolean performClick() {
        if (mOnClickListener != null && mEnabled) {
            mOnClickListener.onClick(this);
            return true;
        }
        return false;
    }

    public void invalidate() {}
    public void postInvalidate() {}
    public void requestLayout() {}

    public boolean post(Runnable r) {
        return new Handler(Looper.getMainLooper()).post(r);
    }

    public boolean postDelayed(Runnable r, long delayMs) {
        return new Handler(Looper.getMainLooper()).postDelayed(r, delayMs);
    }

    public View findViewById(int id) {
        return (id != NO_ID && id == mId) ? this : null;
    }

    public final int getMeasuredWidth() { return mMeasuredWidth; }
    public final int getMeasuredHeight() { return mMeasuredHeight; }
    public final int getLeft() { return mLeft; }
    public final int getTop() { return mTop; }
    public final int getRight() { return mRight; }
    public final int getBottom() { return mBottom; }
    public final int getWidth() { return Math.max(0, mRight - mLeft); }
    public final int getHeight() { return Math.max(0, mBottom - mTop); }

    protected final void setMeasuredDimension(int w, int h) {
        mMeasuredWidth = Math.max(0, w);
        mMeasuredHeight = Math.max(0, h);
    }

    public static int resolveSize(int desired, int spec) {
        int mode = MeasureSpec.getMode(spec);
        int size = MeasureSpec.getSize(spec);
        if (mode == MeasureSpec.EXACTLY) return size;
        if (mode == MeasureSpec.AT_MOST) return Math.min(desired, size);
        return desired;
    }

    public final void measure(int widthMeasureSpec, int heightMeasureSpec) {
        onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        setMeasuredDimension(
            resolveSize(Math.max(mMinWidth, mPadLeft + mPadRight), widthMeasureSpec),
            resolveSize(Math.max(mMinHeight, mPadTop + mPadBottom), heightMeasureSpec));
    }

    public final void layout(int l, int t, int r, int b) {
        boolean changed = (l != mLeft || t != mTop || r != mRight || b != mBottom);
        mLeft = l; mTop = t; mRight = r; mBottom = b;
        onLayout(changed, l, t, r, b);
    }

    protected void onLayout(boolean changed, int l, int t, int r, int b) {}

    public void draw(Canvas canvas) {
        if (mVisibility != VISIBLE) return;
        if (mBackground != null) {
            mBackground.setBounds(0, 0, getWidth(), getHeight());
            mBackground.draw(canvas);
        }
        onDraw(canvas);
        dispatchDraw(canvas);
    }

    protected void onDraw(Canvas canvas) {}
    protected void dispatchDraw(Canvas canvas) {}

    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (mVisibility != VISIBLE || !mEnabled) return false;
        if (mOnTouchListener != null && mOnTouchListener.onTouch(this, ev)) return true;
        return onTouchEvent(ev);
    }

    public boolean onTouchEvent(MotionEvent ev) {
        if (!mEnabled) return false;
        int act = ev.getActionMasked();
        if (mClickable || mOnClickListener != null) {
            if (act == MotionEvent.ACTION_DOWN) {
                mPressed = true;
                return true;
            } else if (act == MotionEvent.ACTION_UP) {
                boolean was = mPressed;
                mPressed = false;
                if (was && ev.getX() >= 0 && ev.getY() >= 0 && ev.getX() <= getWidth() && ev.getY() <= getHeight()) {
                    performClick();
                }
                return true;
            } else if (act == MotionEvent.ACTION_CANCEL) {
                mPressed = false;
                return true;
            }
            return true;
        }
        return false;
    }

    public boolean dispatchKeyEvent(KeyEvent ev) { return onKeyDown(ev.getKeyCode(), ev); }
    public boolean onKeyDown(int keyCode, KeyEvent ev) { return false; }
    public boolean onCharInput(char c) { return false; }
}
