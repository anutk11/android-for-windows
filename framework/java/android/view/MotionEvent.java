package android.view;

public final class MotionEvent {
    public static final int ACTION_DOWN   = 0;
    public static final int ACTION_UP     = 1;
    public static final int ACTION_MOVE   = 2;
    public static final int ACTION_CANCEL = 3;

    private final long mDownTime;
    private final long mEventTime;
    private final int mAction;
    private float mX;
    private float mY;
    private final int mMetaState;

    private MotionEvent(long downTime, long eventTime, int action, float x, float y, int metaState) {
        mDownTime = downTime; mEventTime = eventTime; mAction = action;
        mX = x; mY = y; mMetaState = metaState;
    }

    public static MotionEvent obtain(long downTime, long eventTime, int action, float x, float y, int metaState) {
        return new MotionEvent(downTime, eventTime, action, x, y, metaState);
    }

    public static MotionEvent obtain(MotionEvent o) {
        return new MotionEvent(o.mDownTime, o.mEventTime, o.mAction, o.mX, o.mY, o.mMetaState);
    }

    public int getAction() { return mAction; }
    public int getActionMasked() { return mAction & 0xFF; }
    public float getX() { return mX; }
    public float getY() { return mY; }
    public float getRawX() { return mX; }
    public float getRawY() { return mY; }
    public long getDownTime() { return mDownTime; }
    public long getEventTime() { return mEventTime; }
    public int getMetaState() { return mMetaState; }
    public void offsetLocation(float dx, float dy) { mX += dx; mY += dy; }
    public void recycle() {}
}
