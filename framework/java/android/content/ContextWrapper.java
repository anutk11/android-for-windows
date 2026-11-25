package android.content;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.Looper;
import java.io.File;

public class ContextWrapper extends Context {
    protected Context mBase;

    public ContextWrapper(Context base) { mBase = base; }
    protected void attachBaseContext(Context base) { mBase = base; }
    public Context getBaseContext() { return mBase; }

    @Override public Context getApplicationContext() { return mBase != null ? mBase.getApplicationContext() : this; }
    @Override public String getPackageName() { return mBase != null ? mBase.getPackageName() : "com.afw.app"; }
    @Override public Resources getResources() { return mBase != null ? mBase.getResources() : null; }
    @Override public AssetManager getAssets() { return mBase != null ? mBase.getAssets() : null; }
    @Override public PackageManager getPackageManager() { return mBase != null ? mBase.getPackageManager() : new PackageManager(); }
    @Override public ApplicationInfo getApplicationInfo() { return mBase != null ? mBase.getApplicationInfo() : new ApplicationInfo(); }
    @Override public ContentResolver getContentResolver() { return mBase != null ? mBase.getContentResolver() : new ContentResolver(); }
    @Override public File getFilesDir() { return mBase != null ? mBase.getFilesDir() : new File("."); }
    @Override public File getCacheDir() { return mBase != null ? mBase.getCacheDir() : new File("."); }
    @Override public File getExternalFilesDir(String type) { return mBase != null ? mBase.getExternalFilesDir(type) : getFilesDir(); }
    @Override public SharedPreferences getSharedPreferences(String name, int mode) {
        return mBase != null ? mBase.getSharedPreferences(name, mode) : null;
    }
    @Override public Object getSystemService(String name) { return mBase != null ? mBase.getSystemService(name) : null; }
    @Override public Looper getMainLooper() { return Looper.getMainLooper(); }
    @Override public ClassLoader getClassLoader() { return getClass().getClassLoader(); }
    @Override public void startActivity(Intent intent) { if (mBase != null) mBase.startActivity(intent); }
}
