package androidx.recyclerview.widget;

import android.content.Context;

public class LinearLayoutManager extends RecyclerView.LayoutManager {
    public static final int HORIZONTAL = 0;
    public static final int VERTICAL = 1;

    private final int mOrientation;

    public LinearLayoutManager(Context context) { this(context, VERTICAL, false); }
    public LinearLayoutManager(Context context, int orientation, boolean reverseLayout) {
        mOrientation = orientation;
    }
    public int getOrientation() { return mOrientation; }
}
