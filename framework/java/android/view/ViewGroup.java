package android.view;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import java.util.ArrayList;
import java.util.List;

public abstract class ViewGroup extends View {
    public static class LayoutParams {
        public static final int MATCH_PARENT = -1;
        public static final int FILL_PARENT  = -1;
        public static final int WRAP_CONTENT = -2;

        public int width;
        public int height;

        public LayoutParams(int w, int h) { width = w; height = h; }
        public LayoutParams(LayoutParams src) {
            if (src != null) { width = src.width; height = src.height; }
        }
    }

    public static class MarginLayoutParams extends LayoutParams {
        public int leftMargin, topMargin, rightMargin, bottomMargin;

        public MarginLayoutParams(int w, int h) { super(w, h); }
        public MarginLayoutParams(LayoutParams src) { super(src); }
        public void setMargins(int l, int t, int r, int b) {
            leftMargin = l; topMargin = t; rightMargin = r; bottomMargin = b;
        }
    }

    protected final List<View> mChildren = new ArrayList<>();
    private View mTouchTarget;

    public ViewGroup(Context context) { super(context); }
    public ViewGroup(Context context, AttributeSet attrs) { super(context, attrs); }
    public ViewGroup(Context context, AttributeSet attrs, int defStyle) { super(context, attrs, defStyle); }

    public int getChildCount() { return mChildren.size(); }
    public View getChildAt(int idx) { return mChildren.get(idx); }

    public void addView(View child) {
        if (child == null) return;
        if (child.getLayoutParams() == null)
            child.setLayoutParams(generateDefaultLayoutParams());
        addView(child, child.getLayoutParams());
    }

    public void addView(View child, LayoutParams params) {
        if (child == null) return;
        if (child.mParent != null) child.mParent.removeView(child);
        child.mParent = this;
        child.setLayoutParams(params != null ? params : generateDefaultLayoutParams());
        mChildren.add(child);
    }

    public void removeView(View child) {
        if (mChildren.remove(child)) child.mParent = null;
    }

    public void removeAllViews() {
        for (View c : mChildren) c.mParent = null;
        mChildren.clear();
    }

    protected LayoutParams generateDefaultLayoutParams() {
        return new MarginLayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
    }

    public static int getChildMeasureSpec(int spec, int padding, int childDim) {
        int mode = MeasureSpec.getMode(spec);
        int size = Math.max(0, MeasureSpec.getSize(spec) - padding);
        if (childDim >= 0) return MeasureSpec.makeMeasureSpec(childDim, MeasureSpec.EXACTLY);
        if (childDim == LayoutParams.MATCH_PARENT) {
            if (mode == MeasureSpec.EXACTLY) return MeasureSpec.makeMeasureSpec(size, MeasureSpec.EXACTLY);
            if (mode == MeasureSpec.AT_MOST) return MeasureSpec.makeMeasureSpec(size, MeasureSpec.AT_MOST);
            return MeasureSpec.makeMeasureSpec(size, MeasureSpec.UNSPECIFIED);
        }
        // WRAP_CONTENT
        if (mode == MeasureSpec.EXACTLY || mode == MeasureSpec.AT_MOST)
            return MeasureSpec.makeMeasureSpec(size, MeasureSpec.AT_MOST);
        return MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED);
    }

    @Override
    public View findViewById(int id) {
        if (id == NO_ID) return null;
        if (mId == id) return this;
        for (View c : mChildren) {
            View f = c.findViewById(id);
            if (f != null) return f;
        }
        return null;
    }

    @Override
    protected void dispatchDraw(Canvas canvas) {
        for (int i = 0; i < mChildren.size(); i++) {
            View c = mChildren.get(i);
            if (c.getVisibility() != VISIBLE) continue;
            int sc = canvas.save();
            canvas.translate(c.getLeft(), c.getTop());
            canvas.clipRect(0, 0, c.getWidth(), c.getHeight());
            c.draw(canvas);
            canvas.restoreToCount(sc);
        }
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (mVisibility != VISIBLE || !mEnabled) return false;
        int act = ev.getActionMasked();
        if (act == MotionEvent.ACTION_DOWN) {
            mTouchTarget = null;
            float x = ev.getX(), y = ev.getY();
            for (int i = mChildren.size() - 1; i >= 0; i--) {
                View c = mChildren.get(i);
                if (c.getVisibility() != VISIBLE || !c.isEnabled()) continue;
                if (x >= c.getLeft() && x < c.getRight() && y >= c.getTop() && y < c.getBottom()) {
                    MotionEvent childEv = MotionEvent.obtain(ev);
                    childEv.offsetLocation(-c.getLeft(), -c.getTop());
                    if (c.dispatchTouchEvent(childEv)) {
                        mTouchTarget = c;
                        return true;
                    }
                }
            }
            return super.dispatchTouchEvent(ev);
        } else if (mTouchTarget != null) {
            View target = mTouchTarget;
            if (act == MotionEvent.ACTION_UP || act == MotionEvent.ACTION_CANCEL) mTouchTarget = null;
            MotionEvent childEv = MotionEvent.obtain(ev);
            childEv.offsetLocation(-target.getLeft(), -target.getTop());
            return target.dispatchTouchEvent(childEv);
        }
        return super.dispatchTouchEvent(ev);
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent ev) {
        for (int i = mChildren.size() - 1; i >= 0; i--) {
            if (mChildren.get(i).dispatchKeyEvent(ev)) return true;
        }
        return super.dispatchKeyEvent(ev);
    }

    @Override
    public boolean onCharInput(char ch) {
        for (int i = mChildren.size() - 1; i >= 0; i--) {
            if (mChildren.get(i).onCharInput(ch)) return true;
        }
        return false;
    }
}
