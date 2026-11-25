package android.os;

public class Handler {
    public interface Callback {
        boolean handleMessage(Message msg);
    }

    private final Looper mLooper;
    private final Callback mCallback;

    public Handler() { this(Looper.myLooper() != null ? Looper.myLooper() : Looper.getMainLooper(), null); }
    public Handler(Callback cb) { this(Looper.myLooper() != null ? Looper.myLooper() : Looper.getMainLooper(), cb); }
    public Handler(Looper looper) { this(looper, null); }
    public Handler(Looper looper, Callback cb) {
        mLooper = (looper != null) ? looper : Looper.getMainLooper();
        mCallback = cb;
    }

    public Looper getLooper() { return mLooper; }
    public void handleMessage(Message msg) {}

    public void dispatchMessage(Message msg) {
        if (msg.callback != null) {
            msg.callback.run();
        } else {
            if (mCallback != null && mCallback.handleMessage(msg)) return;
            handleMessage(msg);
        }
    }

    public boolean post(Runnable r) { return postDelayed(r, 0); }
    public boolean postDelayed(Runnable r, long delayMillis) {
        if (r == null || mLooper == null) return false;
        Message m = Message.obtain(this, r);
        mLooper.enqueue(m, SystemClock.uptimeMillis() + Math.max(0, delayMillis));
        return true;
    }
    public boolean postAtTime(Runnable r, long uptimeMillis) {
        if (r == null || mLooper == null) return false;
        mLooper.enqueue(Message.obtain(this, r), uptimeMillis);
        return true;
    }
    public boolean sendEmptyMessage(int what) { return sendEmptyMessageDelayed(what, 0); }
    public boolean sendEmptyMessageDelayed(int what, long delayMillis) {
        return sendMessageDelayed(Message.obtain(this, what), delayMillis);
    }
    public boolean sendMessage(Message msg) { return sendMessageDelayed(msg, 0); }
    public boolean sendMessageDelayed(Message msg, long delayMillis) {
        if (msg == null || mLooper == null) return false;
        msg.target = this;
        mLooper.enqueue(msg, SystemClock.uptimeMillis() + Math.max(0, delayMillis));
        return true;
    }
    public void removeMessages(int what) { if (mLooper != null) mLooper.removeMessages(this, what); }
    public void removeCallbacks(Runnable r) { if (mLooper != null) mLooper.removeCallbacks(this, r); }
    public void removeCallbacksAndMessages(Object token) { if (mLooper != null) mLooper.removeAll(this); }
}
