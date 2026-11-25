package android.widget;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;

public class ImageView extends View {
    private Bitmap mBitmap;
    private Drawable mDrawable;

    public ImageView(Context ctx) { super(ctx); }
    public ImageView(Context ctx, AttributeSet attrs) { super(ctx, attrs); }

    public void setImageBitmap(Bitmap bm) { mBitmap = bm; mDrawable = null; }
    public void setImageDrawable(Drawable d) { mDrawable = d; mBitmap = null; }

    @Override
    protected void onMeasure(int wSpec, int hSpec) {
        int dw = mBitmap != null ? mBitmap.getWidth() : (mDrawable != null ? Math.max(0, mDrawable.getIntrinsicWidth()) : 0);
        int dh = mBitmap != null ? mBitmap.getHeight() : (mDrawable != null ? Math.max(0, mDrawable.getIntrinsicHeight()) : 0);
        setMeasuredDimension(resolveSize(Math.max(mMinWidth, dw), wSpec), resolveSize(Math.max(mMinHeight, dh), hSpec));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (mBitmap != null) canvas.drawBitmap(mBitmap, mPadLeft, mPadTop, null);
        else if (mDrawable != null) {
            mDrawable.setBounds(mPadLeft, mPadTop, getWidth() - mPadRight, getHeight() - mPadBottom);
            mDrawable.draw(canvas);
        }
    }
}
