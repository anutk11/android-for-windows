package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;

public class CheckBox extends TextView {
    public interface OnCheckedChangeListener {
        void onCheckedChanged(CheckBox buttonView, boolean isChecked);
    }

    private boolean mChecked = false;
    private OnCheckedChangeListener mListener;
    private final Paint mBoxPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public CheckBox(Context ctx) {
        super(ctx);
        mClickable = true;
        setPadding(34, 8, 8, 8);
        setMinimumHeight(36);
    }
    public CheckBox(Context ctx, AttributeSet attrs) { this(ctx); }

    public boolean isChecked() { return mChecked; }
    public void setChecked(boolean c) {
        if (mChecked != c) {
            mChecked = c;
            if (mListener != null) mListener.onCheckedChanged(this, mChecked);
        }
    }
    public void setOnCheckedChangeListener(OnCheckedChangeListener l) { mListener = l; }

    @Override
    public boolean performClick() {
        setChecked(!mChecked);
        return super.performClick();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float cy = getHeight() * 0.5f;
        mBoxPaint.setStyle(Paint.Style.FILL);
        mBoxPaint.setColor(mChecked ? 0xFF3B82F6 : 0xFF374151);
        canvas.drawRoundRect(6, cy - 10, 26, cy + 10, 4f, 4f, mBoxPaint);
        if (mChecked) {
            mBoxPaint.setColor(0xFFFFFFFF);
            mBoxPaint.setStrokeWidth(2.5f);
            canvas.drawLine(10, cy, 15, cy + 5, mBoxPaint);
            canvas.drawLine(15, cy + 5, 22, cy - 5, mBoxPaint);
        }
        super.onDraw(canvas);
    }
}
