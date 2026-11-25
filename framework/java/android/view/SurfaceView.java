package android.view;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.util.AttributeSet;
import java.util.ArrayList;
import java.util.List;

public class SurfaceView extends View {
    private Bitmap mSurfaceBmp;
    private final List<SurfaceHolder.Callback> mCallbacks = new ArrayList<>();
    private boolean mCreated = false;

    private final SurfaceHolder mHolder = new SurfaceHolder() {
        @Override public void addCallback(Callback cb) {
            if (cb != null && !mCallbacks.contains(cb)) mCallbacks.add(cb);
        }
        @Override public void removeCallback(Callback cb) { mCallbacks.remove(cb); }
        @Override public synchronized Canvas lockCanvas() {
            int w = Math.max(1, getWidth()), h = Math.max(1, getHeight());
            if (mSurfaceBmp == null || mSurfaceBmp.getWidth() != w || mSurfaceBmp.getHeight() != h) {
                mSurfaceBmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
            }
            return new Canvas(mSurfaceBmp);
        }
        @Override public synchronized void unlockCanvasAndPost(Canvas canvas) {}
    };

    public SurfaceView(Context context) { super(context); }
    public SurfaceView(Context context, AttributeSet attrs) { super(context, attrs); }

    public SurfaceHolder getHolder() { return mHolder; }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        super.onLayout(changed, l, t, r, b);
        int w = r - l, h = b - t;
        if (w > 0 && h > 0) {
            if (!mCreated) {
                mCreated = true;
                for (SurfaceHolder.Callback cb : mCallbacks) cb.surfaceCreated(mHolder);
            }
            if (changed) {
                for (SurfaceHolder.Callback cb : mCallbacks) cb.surfaceChanged(mHolder, 1, w, h);
            }
        }
    }

    @Override
    protected void onDraw(Canvas canvas) {
        synchronized (mHolder) {
            if (mSurfaceBmp != null) canvas.drawBitmap(mSurfaceBmp, 0, 0, null);
        }
    }
}
