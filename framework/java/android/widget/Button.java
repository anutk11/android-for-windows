package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.Gravity;

public class Button extends TextView {
    private int mBtnColor = 0xFF3B82F6;
    private int mPressedColor = 0xFF2563EB;
    private final Paint mBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public Button(Context ctx) {
        super(ctx);
        mClickable = true;
        mGravity = Gravity.CENTER;
        mPaint.setColor(Color.WHITE);
        mPaint.setTypeface(Typeface.DEFAULT_BOLD);
        setPadding(18, 12, 18, 12);
        setMinimumHeight(44);
    }

    public Button(Context ctx, AttributeSet attrs) { this(ctx); }

    @Override
    public void setBackgroundColor(int color) {
        mBtnColor = color;
        int r = Math.max(0, Color.red(color) - 24);
        int g = Math.max(0, Color.green(color) - 24);
        int b = Math.max(0, Color.blue(color) - 24);
        mPressedColor = Color.argb(Color.alpha(color), r, g, b);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (mBackground == null) {
            mBgPaint.setStyle(Paint.Style.FILL);
            mBgPaint.setColor(mPressed ? mPressedColor : mBtnColor);
            canvas.drawRoundRect(0, 0, getWidth(), getHeight(), 10f, 10f, mBgPaint);
        }
        super.onDraw(canvas);
    }
}
