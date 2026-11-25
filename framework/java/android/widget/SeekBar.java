package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.MotionEvent;

public class SeekBar extends ProgressBar {
    public interface OnSeekBarChangeListener {
        void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser);
        void onStartTrackingTouch(SeekBar seekBar);
        void onStopTrackingTouch(SeekBar seekBar);
    }

    private OnSeekBarChangeListener mListener;

    public SeekBar(Context ctx) {
        super(ctx);
        mClickable = true;
        setMinimumHeight(36);
        setPadding(12, 6, 12, 6);
    }
    public SeekBar(Context ctx, AttributeSet attrs) { this(ctx); }

    public void setOnSeekBarChangeListener(OnSeekBarChangeListener l) { mListener = l; }

    @Override
    public boolean onTouchEvent(MotionEvent ev) {
        if (!mEnabled) return false;
        int act = ev.getActionMasked();
        int w = Math.max(1, getWidth() - mPadLeft - mPadRight);
        float frac = Math.max(0f, Math.min(1f, (ev.getX() - mPadLeft) / w));
        int newP = Math.round(frac * mMax);
        if (act == MotionEvent.ACTION_DOWN) {
            if (mListener != null) mListener.onStartTrackingTouch(this);
        }
        if (act == MotionEvent.ACTION_DOWN || act == MotionEvent.ACTION_MOVE || act == MotionEvent.ACTION_UP) {
            if (newP != mProgress) {
                mProgress = newP;
                if (mListener != null) mListener.onProgressChanged(this, mProgress, true);
            }
        }
        if (act == MotionEvent.ACTION_UP || act == MotionEvent.ACTION_CANCEL) {
            if (mListener != null) mListener.onStopTrackingTouch(this);
        }
        return true;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth() - mPadLeft - mPadRight;
        float frac = (float) mProgress / (float) mMax;
        float tx = mPadLeft + w * frac;
        float ty = getHeight() * 0.5f;
        mPaint.setStyle(Paint.Style.FILL);
        mPaint.setColor(0xFFFFFFFF);
        canvas.drawCircle(tx, ty, 10f, mPaint);
    }
}
