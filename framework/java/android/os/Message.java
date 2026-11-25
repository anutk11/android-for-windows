package android.os;

public final class Message {
    public int what;
    public int arg1;
    public int arg2;
    public Object obj;
    public Bundle data;
    Handler target;
    Runnable callback;
    long when;

    public static Message obtain() { return new Message(); }
    public static Message obtain(Handler h) { Message m = new Message(); m.target = h; return m; }
    public static Message obtain(Handler h, int what) {
        Message m = new Message(); m.target = h; m.what = what; return m;
    }
    public static Message obtain(Handler h, int what, Object obj) {
        Message m = new Message(); m.target = h; m.what = what; m.obj = obj; return m;
    }
    public static Message obtain(Handler h, Runnable cb) {
        Message m = new Message(); m.target = h; m.callback = cb; return m;
    }
    public Bundle getData() {
        if (data == null) data = new Bundle();
        return data;
    }
    public void setData(Bundle b) { data = b; }
    public void sendToTarget() { if (target != null) target.sendMessage(this); }
    public void recycle() {}
}
