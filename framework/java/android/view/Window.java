package android.view;

import android.content.Context;
import android.widget.FrameLayout;

public class Window {
    public static final int FEATURE_NO_TITLE = 1;
    private final FrameLayout mDecor;
    private int mFlags;

    public Window(Context context) {
        mDecor = new FrameLayout(context);
        mDecor.setLayoutParams(new ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    public View getDecorView() { return mDecor; }

    public void setContentView(View view) {
        mDecor.removeAllViews();
        if (view != null) {
            if (view.getLayoutParams() == null) {
                view.setLayoutParams(new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
            }
            mDecor.addView(view);
        }
    }

    public View findViewById(int id) { return mDecor.findViewById(id); }
    public boolean requestFeature(int featureId) { return true; }
    public void setFlags(int flags, int mask) { mFlags = (mFlags & ~mask) | (flags & mask); }
    public void addFlags(int flags) { mFlags |= flags; }
    public void clearFlags(int flags) { mFlags &= ~flags; }
    public void setStatusBarColor(int color) {}
    public void setNavigationBarColor(int color) {}
}
