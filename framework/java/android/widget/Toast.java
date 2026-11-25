package android.widget;

import android.content.Context;

public class Toast {
    public static final int LENGTH_SHORT = 0;
    public static final int LENGTH_LONG  = 1;

    private final CharSequence mText;

    private Toast(CharSequence text) { mText = text; }

    public static Toast makeText(Context ctx, CharSequence text, int duration) {
        return new Toast(text);
    }

    public static Toast makeText(Context ctx, int resId, int duration) {
        return new Toast(ctx != null ? ctx.getString(resId) : "");
    }

    public void show() {
        System.out.println("[Toast] " + mText);
    }
}
