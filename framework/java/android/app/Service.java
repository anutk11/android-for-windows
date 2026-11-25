package android.app;

import android.content.ContextWrapper;
import android.content.Intent;
import android.os.IBinder;

public abstract class Service extends ContextWrapper {
    public static final int START_STICKY = 1;
    public static final int START_NOT_STICKY = 2;

    public Service() { super(null); }

    public void onCreate() {}
    public int onStartCommand(Intent intent, int flags, int startId) { return START_NOT_STICKY; }
    public void onDestroy() {}
    public IBinder onBind(Intent intent) { return null; }
    public void stopSelf() {}
}
