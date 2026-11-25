package android.os;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public final class Looper {
    private static final ThreadLocal<Looper> sThreadLocal = new ThreadLocal<>();
    private static Looper sMainLooper;
    private final Thread mThread;
    private final List<Message> mQueue = new ArrayList<>();
    private boolean mQuit = false;

    private Looper(Thread t) { mThread = t; }

    public static void prepare() {
        if (sThreadLocal.get() == null) sThreadLocal.set(new Looper(Thread.currentThread()));
    }

    public static void prepareMainLooper() {
        prepare();
        synchronized (Looper.class) {
            if (sMainLooper == null) sMainLooper = myLooper();
        }
    }

    public static Looper getMainLooper() {
        synchronized (Looper.class) { return sMainLooper; }
    }

    public static Looper myLooper() { return sThreadLocal.get(); }
    public Thread getThread() { return mThread; }

    void enqueue(Message msg, long uptimeMillis) {
        synchronized (mQueue) {
            msg.when = uptimeMillis;
            int idx = mQueue.size();
            for (int i = 0; i < mQueue.size(); i++) {
                if (uptimeMillis < mQueue.get(i).when) { idx = i; break; }
            }
            mQueue.add(idx, msg);
            mQueue.notifyAll();
        }
    }

    void removeMessages(Handler h, int what) {
        synchronized (mQueue) {
            Iterator<Message> it = mQueue.iterator();
            while (it.hasNext()) {
                Message m = it.next();
                if (m.target == h && m.what == what) it.remove();
            }
        }
    }

    void removeCallbacks(Handler h, Runnable r) {
        synchronized (mQueue) {
            Iterator<Message> it = mQueue.iterator();
            while (it.hasNext()) {
                Message m = it.next();
                if (m.target == h && (r == null || m.callback == r)) it.remove();
            }
        }
    }

    void removeAll(Handler h) {
        synchronized (mQueue) {
            Iterator<Message> it = mQueue.iterator();
            while (it.hasNext()) {
                if (it.next().target == h) it.remove();
            }
        }
    }

    public void drainDueMessages() {
        long now = SystemClock.uptimeMillis();
        List<Message> due = new ArrayList<>();
        synchronized (mQueue) {
            Iterator<Message> it = mQueue.iterator();
            while (it.hasNext()) {
                Message m = it.next();
                if (m.when <= now) {
                    due.add(m);
                    it.remove();
                } else {
                    break;
                }
            }
        }
        for (Message m : due) {
            if (m.target != null) m.target.dispatchMessage(m);
            else if (m.callback != null) m.callback.run();
        }
    }

    public static void loop() {
        Looper looper = myLooper();
        if (looper == null) throw new RuntimeException("No Looper; Looper.prepare() wasn't called");
        while (!looper.mQuit) {
            looper.drainDueMessages();
            synchronized (looper.mQueue) {
                if (looper.mQuit) break;
                try {
                    long wait = 16;
                    if (!looper.mQueue.isEmpty()) {
                        long delta = looper.mQueue.get(0).when - SystemClock.uptimeMillis();
                        wait = Math.max(1, Math.min(wait, delta));
                    }
                    looper.mQueue.wait(wait);
                } catch (InterruptedException ignored) {}
            }
        }
    }

    public void quit() {
        synchronized (mQueue) { mQuit = true; mQueue.notifyAll(); }
    }
    public void quitSafely() { quit(); }
}
