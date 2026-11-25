package android.content;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.Looper;
import java.io.File;

public abstract class Context {
    public static final int MODE_PRIVATE = 0;
    public static final String AUDIO_SERVICE = "audio";
    public static final String WINDOW_SERVICE = "window";
    public static final String LAYOUT_INFLATER_SERVICE = "layout_inflater";

    public abstract Context getApplicationContext();
    public abstract String getPackageName();
    public abstract Resources getResources();
    public abstract AssetManager getAssets();
    public abstract PackageManager getPackageManager();
    public abstract ApplicationInfo getApplicationInfo();
    public abstract ContentResolver getContentResolver();
    public abstract File getFilesDir();
    public abstract File getCacheDir();
    public abstract File getExternalFilesDir(String type);
    public abstract SharedPreferences getSharedPreferences(String name, int mode);
    public abstract Object getSystemService(String name);
    public abstract Looper getMainLooper();
    public abstract ClassLoader getClassLoader();

    public final String getString(int resId) {
        return getResources().getString(resId);
    }

    public final String getString(int resId, Object... formatArgs) {
        return getResources().getString(resId, formatArgs);
    }

    public int checkSelfPermission(String permission) {
        return PackageManager.PERMISSION_GRANTED;
    }

    public void startActivity(Intent intent) {}
}
