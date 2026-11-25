package androidx.recyclerview.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;

public class RecyclerView extends ScrollView {
    public abstract static class ViewHolder {
        public final View itemView;
        public ViewHolder(View itemView) { this.itemView = itemView; }
    }

    public abstract static class Adapter<VH extends ViewHolder> {
        RecyclerView mRv;
        public abstract VH onCreateViewHolder(ViewGroup parent, int viewType);
        public abstract void onBindViewHolder(VH holder, int position);
        public abstract int getItemCount();
        public int getItemViewType(int position) { return 0; }
        public final void notifyDataSetChanged() { if (mRv != null) mRv.rebuildItems(); }
    }

    public abstract static class LayoutManager {}

    private final LinearLayout mContainer;
    private Adapter<?> mAdapter;
    private LayoutManager mLm;

    public RecyclerView(Context ctx) {
        super(ctx);
        mContainer = new LinearLayout(ctx);
        mContainer.setOrientation(LinearLayout.VERTICAL);
        addView(mContainer, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    public RecyclerView(Context ctx, AttributeSet attrs) { this(ctx); }

    public void setLayoutManager(LayoutManager lm) { mLm = lm; }
    public LayoutManager getLayoutManager() { return mLm; }

    public void setAdapter(Adapter<?> adapter) {
        mAdapter = adapter;
        if (mAdapter != null) mAdapter.mRv = this;
        rebuildItems();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    void rebuildItems() {
        mContainer.removeAllViews();
        if (mAdapter == null) return;
        Adapter raw = mAdapter;
        int n = raw.getItemCount();
        for (int i = 0; i < n; i++) {
            ViewHolder vh = raw.onCreateViewHolder(mContainer, raw.getItemViewType(i));
            raw.onBindViewHolder(vh, i);
            if (vh != null && vh.itemView != null) mContainer.addView(vh.itemView);
        }
    }
}
