package android.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;

public class LinearLayout extends ViewGroup {
    public static final int HORIZONTAL = 0;
    public static final int VERTICAL   = 1;

    public static class LayoutParams extends MarginLayoutParams {
        public float weight = 0f;
        public int gravity = Gravity.NO_GRAVITY;

        public LayoutParams(int w, int h) { super(w, h); }
        public LayoutParams(int w, int h, float weight) { super(w, h); this.weight = weight; }
    }

    private int mOrientation = HORIZONTAL;
    private int mGravity = Gravity.TOP | Gravity.LEFT;

    public LinearLayout(Context ctx) { super(ctx); }
    public LinearLayout(Context ctx, AttributeSet attrs) { super(ctx, attrs); }

    public void setOrientation(int orientation) { mOrientation = orientation; }
    public int getOrientation() { return mOrientation; }
    public void setGravity(int gravity) { mGravity = gravity; }

    @Override
    protected LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        if (mOrientation == VERTICAL) measureVertical(widthSpec, heightSpec);
        else measureHorizontal(widthSpec, heightSpec);
    }

    private void measureVertical(int widthSpec, int heightSpec) {
        int totalH = mPadTop + mPadBottom;
        int maxW = 0;
        float totalWeight = 0f;
        for (int i = 0; i < mChildren.size(); i++) {
            View c = mChildren.get(i);
            if (c.getVisibility() == GONE) continue;
            ViewGroup.LayoutParams lp = c.getLayoutParams();
            int lm = 0, tm = 0, rm = 0, bm = 0;
            float w = 0f;
            if (lp instanceof MarginLayoutParams) {
                MarginLayoutParams m = (MarginLayoutParams) lp;
                lm = m.leftMargin; tm = m.topMargin; rm = m.rightMargin; bm = m.bottomMargin;
            }
            if (lp instanceof LayoutParams) w = ((LayoutParams) lp).weight;
            totalWeight += w;
            if (w > 0f && lp.height == 0) {
                totalH += tm + bm;
                continue;
            }
            int cw = getChildMeasureSpec(widthSpec, mPadLeft + mPadRight + lm + rm, lp != null ? lp.width : LayoutParams.WRAP_CONTENT);
            int ch = getChildMeasureSpec(heightSpec, totalH + tm + bm, lp != null ? lp.height : LayoutParams.WRAP_CONTENT);
            c.measure(cw, ch);
            totalH += c.getMeasuredHeight() + tm + bm;
            maxW = Math.max(maxW, c.getMeasuredWidth() + lm + rm);
        }
        int finalH = resolveSize(Math.max(mMinHeight, totalH), heightSpec);
        int extra = finalH - totalH;
        if (totalWeight > 0f && extra > 0) {
            for (int i = 0; i < mChildren.size(); i++) {
                View c = mChildren.get(i);
                if (c.getVisibility() == GONE) continue;
                ViewGroup.LayoutParams lp = c.getLayoutParams();
                if (!(lp instanceof LayoutParams) || ((LayoutParams) lp).weight <= 0f) continue;
                LayoutParams llp = (LayoutParams) lp;
                int share = (int) (extra * (llp.weight / totalWeight));
                int baseH = (llp.height == 0) ? 0 : c.getMeasuredHeight();
                int cw = getChildMeasureSpec(widthSpec, mPadLeft + mPadRight + llp.leftMargin + llp.rightMargin, llp.width);
                int ch = MeasureSpec.makeMeasureSpec(Math.max(0, baseH + share), MeasureSpec.EXACTLY);
                c.measure(cw, ch);
                maxW = Math.max(maxW, c.getMeasuredWidth() + llp.leftMargin + llp.rightMargin);
            }
        }
        setMeasuredDimension(resolveSize(Math.max(mMinWidth, maxW + mPadLeft + mPadRight), widthSpec), finalH);
    }

    private void measureHorizontal(int widthSpec, int heightSpec) {
        int totalW = mPadLeft + mPadRight;
        int maxH = 0;
        float totalWeight = 0f;
        for (int i = 0; i < mChildren.size(); i++) {
            View c = mChildren.get(i);
            if (c.getVisibility() == GONE) continue;
            ViewGroup.LayoutParams lp = c.getLayoutParams();
            int lm = 0, tm = 0, rm = 0, bm = 0;
            float w = 0f;
            if (lp instanceof MarginLayoutParams) {
                MarginLayoutParams m = (MarginLayoutParams) lp;
                lm = m.leftMargin; tm = m.topMargin; rm = m.rightMargin; bm = m.bottomMargin;
            }
            if (lp instanceof LayoutParams) w = ((LayoutParams) lp).weight;
            totalWeight += w;
            if (w > 0f && lp.width == 0) {
                totalW += lm + rm;
                continue;
            }
            int cw = getChildMeasureSpec(widthSpec, totalW + lm + rm, lp != null ? lp.width : LayoutParams.WRAP_CONTENT);
            int ch = getChildMeasureSpec(heightSpec, mPadTop + mPadBottom + tm + bm, lp != null ? lp.height : LayoutParams.WRAP_CONTENT);
            c.measure(cw, ch);
            totalW += c.getMeasuredWidth() + lm + rm;
            maxH = Math.max(maxH, c.getMeasuredHeight() + tm + bm);
        }
        int finalW = resolveSize(Math.max(mMinWidth, totalW), widthSpec);
        int extra = finalW - totalW;
        if (totalWeight > 0f && extra > 0) {
            for (int i = 0; i < mChildren.size(); i++) {
                View c = mChildren.get(i);
                if (c.getVisibility() == GONE) continue;
                ViewGroup.LayoutParams lp = c.getLayoutParams();
                if (!(lp instanceof LayoutParams) || ((LayoutParams) lp).weight <= 0f) continue;
                LayoutParams llp = (LayoutParams) lp;
                int share = (int) (extra * (llp.weight / totalWeight));
                int baseW = (llp.width == 0) ? 0 : c.getMeasuredWidth();
                int cw = MeasureSpec.makeMeasureSpec(Math.max(0, baseW + share), MeasureSpec.EXACTLY);
                int ch = getChildMeasureSpec(heightSpec, mPadTop + mPadBottom + llp.topMargin + llp.bottomMargin, llp.height);
                c.measure(cw, ch);
                maxH = Math.max(maxH, c.getMeasuredHeight() + llp.topMargin + llp.bottomMargin);
            }
        }
        setMeasuredDimension(finalW, resolveSize(Math.max(mMinHeight, maxH + mPadTop + mPadBottom), heightSpec));
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        int availW = (r - l) - mPadLeft - mPadRight;
        int availH = (b - t) - mPadTop - mPadBottom;
        if (mOrientation == VERTICAL) {
            int y = mPadTop;
            for (int i = 0; i < mChildren.size(); i++) {
                View c = mChildren.get(i);
                if (c.getVisibility() == GONE) continue;
                ViewGroup.LayoutParams lp = c.getLayoutParams();
                int lm = 0, tm = 0, rm = 0, bm = 0, grav = mGravity;
                if (lp instanceof MarginLayoutParams) {
                    MarginLayoutParams m = (MarginLayoutParams) lp;
                    lm = m.leftMargin; tm = m.topMargin; rm = m.rightMargin; bm = m.bottomMargin;
                }
                if (lp instanceof LayoutParams && ((LayoutParams) lp).gravity != Gravity.NO_GRAVITY)
                    grav = ((LayoutParams) lp).gravity;
                int cw = c.getMeasuredWidth(), ch = c.getMeasuredHeight();
                int x = mPadLeft + lm;
                if ((grav & Gravity.CENTER_HORIZONTAL) == Gravity.CENTER_HORIZONTAL)
                    x = mPadLeft + (availW - cw) / 2;
                else if ((grav & Gravity.RIGHT) == Gravity.RIGHT)
                    x = (r - l) - mPadRight - rm - cw;
                y += tm;
                c.layout(x, y, x + cw, y + ch);
                y += ch + bm;
            }
        } else {
            int x = mPadLeft;
            for (int i = 0; i < mChildren.size(); i++) {
                View c = mChildren.get(i);
                if (c.getVisibility() == GONE) continue;
                ViewGroup.LayoutParams lp = c.getLayoutParams();
                int lm = 0, tm = 0, rm = 0, bm = 0, grav = mGravity;
                if (lp instanceof MarginLayoutParams) {
                    MarginLayoutParams m = (MarginLayoutParams) lp;
                    lm = m.leftMargin; tm = m.topMargin; rm = m.rightMargin; bm = m.bottomMargin;
                }
                if (lp instanceof LayoutParams && ((LayoutParams) lp).gravity != Gravity.NO_GRAVITY)
                    grav = ((LayoutParams) lp).gravity;
                int cw = c.getMeasuredWidth(), ch = c.getMeasuredHeight();
                int y = mPadTop + tm;
                if ((grav & Gravity.CENTER_VERTICAL) == Gravity.CENTER_VERTICAL)
                    y = mPadTop + (availH - ch) / 2;
                else if ((grav & Gravity.BOTTOM) == Gravity.BOTTOM)
                    y = (b - t) - mPadBottom - bm - ch;
                x += lm;
                c.layout(x, y, x + cw, y + ch);
                x += cw + rm;
            }
        }
    }
}
