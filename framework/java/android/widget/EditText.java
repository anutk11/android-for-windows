package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;

public class EditText extends TextView {
    private String mHint = "";
    private final Paint mBoxPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public EditText(Context ctx) {
        super(ctx);
        mClickable = true;
        setPadding(12, 10, 12, 10);
        setMinimumHeight(42);
    }
    public EditText(Context ctx, AttributeSet attrs) { this(ctx); }

    public void setHint(CharSequence h) { mHint = h != null ? h.toString() : ""; }

    @Override
    public boolean onTouchEvent(MotionEvent ev) {
        if (ev.getActionMasked() == MotionEvent.ACTION_DOWN) mFocused = true;
        return super.onTouchEvent(ev);
    }

    @Override
    public boolean onCharInput(char c) {
        if (!mFocused) return false;
        String s = mText.toString();
        if (c == '\b') {
            if (!s.isEmpty()) mText = s.substring(0, s.length() - 1);
            return true;
        }
        if (c >= 32 && c < 127) {
            mText = s + c;
            return true;
        }
        return false;
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent ev) {
        if (!mFocused) return false;
        if (keyCode == KeyEvent.KEYCODE_DEL) {
            String s = mText.toString();
            if (!s.isEmpty()) mText = s.substring(0, s.length() - 1);
            return true;
        }
        return false;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        mBoxPaint.setStyle(Paint.Style.FILL);
        mBoxPaint.setColor(0xFF242430);
        canvas.drawRoundRect(0, 0, getWidth(), getHeight(), 8f, 8f, mBoxPaint);
        mBoxPaint.setStyle(Paint.Style.STROKE);
        mBoxPaint.setStrokeWidth(2f);
        mBoxPaint.setColor(mFocused ? 0xFF3B82F6 : 0xFF4B5563);
        canvas.drawRoundRect(0, 0, getWidth(), getHeight(), 8f, 8f, mBoxPaint);
        if (mText.length() == 0 && !mHint.isEmpty()) {
            Paint hp = new Paint(mPaint);
            hp.setColor(0xFF9CA3AF);
            canvas.drawText(mHint, mPadLeft, mPadTop + hp.getTextSize(), hp);
        } else {
            super.onDraw(canvas);
        }
    }
}
