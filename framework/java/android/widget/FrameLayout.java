package android.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;

public class FrameLayout extends ViewGroup {
    public static class LayoutParams extends MarginLayoutParams {
        public int gravity = Gravity.NO_GRAVITY;
        public LayoutParams(int w, int h) { super(w, h); }
        public LayoutParams(int w, int h, int grav) { super(w, h); gravity = grav; }
    }

    public FrameLayout(Context ctx) { super(ctx); }
    public FrameLayout(Context ctx, AttributeSet attrs) { super(ctx, attrs); }

    @Override
    protected LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        int maxW = 0, maxH = 0;
        for (int i = 0; i < mChildren.size(); i++) {
            View c = mChildren.get(i);
            if (c.getVisibility() == GONE) continue;
            ViewGroup.LayoutParams lp = c.getLayoutParams();
            int lm = 0, tm = 0, rm = 0, bm = 0;
            if (lp instanceof MarginLayoutParams) {
                MarginLayoutParams mlp = (MarginLayoutParams) lp;
                lm = mlp.leftMargin; tm = mlp.topMargin; rm = mlp.rightMargin; bm = mlp.bottomMargin;
            }
            int cw = getChildMeasureSpec(widthSpec, mPadLeft + mPadRight + lm + rm, lp != null ? lp.width : LayoutParams.MATCH_PARENT);
            int ch = getChildMeasureSpec(heightSpec, mPadTop + mPadBottom + tm + bm, lp != null ? lp.height : LayoutParams.MATCH_PARENT);
            c.measure(cw, ch);
            maxW = Math.max(maxW, c.getMeasuredWidth() + lm + rm);
            maxH = Math.max(maxH, c.getMeasuredHeight() + tm + bm);
        }
        setMeasuredDimension(
            resolveSize(Math.max(mMinWidth, maxW + mPadLeft + mPadRight), widthSpec),
            resolveSize(Math.max(mMinHeight, maxH + mPadTop + mPadBottom), heightSpec));
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        int availW = (r - l) - mPadLeft - mPadRight;
        int availH = (b - t) - mPadTop - mPadBottom;
        for (int i = 0; i < mChildren.size(); i++) {
            View c = mChildren.get(i);
            if (c.getVisibility() == GONE) continue;
            ViewGroup.LayoutParams lp = c.getLayoutParams();
            int lm = 0, tm = 0, rm = 0, bm = 0, grav = Gravity.TOP | Gravity.LEFT;
            if (lp instanceof MarginLayoutParams) {
                MarginLayoutParams mlp = (MarginLayoutParams) lp;
                lm = mlp.leftMargin; tm = mlp.topMargin; rm = mlp.rightMargin; bm = mlp.bottomMargin;
            }
            if (lp instanceof LayoutParams && ((LayoutParams) lp).gravity != Gravity.NO_GRAVITY)
                grav = ((LayoutParams) lp).gravity;
            int cw = c.getMeasuredWidth();
            int ch = c.getMeasuredHeight();
            int cx = mPadLeft + lm;
            int cy = mPadTop + tm;
            if ((grav & Gravity.CENTER_HORIZONTAL) == Gravity.CENTER_HORIZONTAL)
                cx = mPadLeft + (availW - cw) / 2;
            else if ((grav & Gravity.RIGHT) == Gravity.RIGHT)
                cx = (r - l) - mPadRight - rm - cw;
            if ((grav & Gravity.CENTER_VERTICAL) == Gravity.CENTER_VERTICAL)
                cy = mPadTop + (availH - ch) / 2;
            else if ((grav & Gravity.BOTTOM) == Gravity.BOTTOM)
                cy = (b - t) - mPadBottom - bm - ch;
            c.layout(cx, cy, cx + cw, cy + ch);
        }
    }
}
