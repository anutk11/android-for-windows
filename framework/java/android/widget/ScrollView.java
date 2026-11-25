package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

public class ScrollView extends FrameLayout {
    private int mScrollY = 0;
    private float mLastY = 0f;
    private boolean mDragging = false;

    public ScrollView(Context ctx) { super(ctx); }
    public ScrollView(Context ctx, AttributeSet attrs) { super(ctx, attrs); }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        int unrestrictedH = MeasureSpec.makeMeasureSpec(16384, MeasureSpec.AT_MOST);
        for (int i = 0; i < mChildren.size(); i++) {
            View c = mChildren.get(i);
            if (c.getVisibility() == GONE) continue;
            c.measure(getChildMeasureSpec(widthSpec, mPadLeft + mPadRight, LayoutParams.MATCH_PARENT), unrestrictedH);
        }
        setMeasuredDimension(resolveSize(0, widthSpec), resolveSize(0, heightSpec));
    }

    @Override
    protected void dispatchDraw(Canvas canvas) {
        int sc = canvas.save();
        canvas.translate(0, -mScrollY);
        super.dispatchDraw(canvas);
        canvas.restoreToCount(sc);
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        int act = ev.getActionMasked();
        if (act == MotionEvent.ACTION_DOWN) {
            mLastY = ev.getY();
            mDragging = false;
        } else if (act == MotionEvent.ACTION_MOVE) {
            float dy = mLastY - ev.getY();
            if (Math.abs(dy) > 4f) mDragging = true;
            if (mDragging && !mChildren.isEmpty()) {
                int maxScroll = Math.max(0, mChildren.get(0).getMeasuredHeight() - getHeight());
                mScrollY = Math.max(0, Math.min(maxScroll, mScrollY + Math.round(dy)));
                mLastY = ev.getY();
                return true;
            }
        }
        MotionEvent shifted = MotionEvent.obtain(ev);
        shifted.offsetLocation(0, mScrollY);
        return super.dispatchTouchEvent(shifted);
    }
}
