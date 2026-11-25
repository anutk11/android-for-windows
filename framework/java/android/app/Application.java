package android.app;

import android.content.AfwSharedPreferences;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.media.AudioManager;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.WindowManager;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class Application extends ContextWrapper {
    private String mPackageName = "com.afw.app";
    private File mDataDir = new File(".");
    private Resources mResources;
    private AssetManager mAssets;
    private final PackageManager mPm = new PackageManager();
    private final AudioManager mAudioManager = new AudioManager();
    private final WindowManager mWindowManager = new WindowManager() {
        private final Display mDisplay = new Display();
        @Override public Display getDefaultDisplay() { return mDisplay; }
    };
    private final Map<String, SharedPreferences> mPrefs = new HashMap<>();

    public Application() { super(null); }

    public void initAfw(String pkg, File dataDir, Resources res, AssetManager am) {
        mPackageName = pkg;
        mDataDir = dataDir;
        mResources = res;
        mAssets = am;
    }

    public void onCreate() {}
    public void onTerminate() {}
    public void onLowMemory() {}

    @Override public Context getApplicationContext() { return this; }
    @Override public String getPackageName() { return mPackageName; }
    @Override public Resources getResources() { return mResources; }
    @Override public AssetManager getAssets() { return mAssets; }
    @Override public PackageManager getPackageManager() { return mPm; }
    @Override public ApplicationInfo getApplicationInfo() { return mPm.getApplicationInfo(mPackageName, 0); }

    @Override public File getFilesDir() {
        File f = new File(mDataDir, "files");
        f.mkdirs();
        return f;
    }

    @Override public File getCacheDir() {
        File f = new File(mDataDir, "cache");
        f.mkdirs();
        return f;
    }

    @Override public File getExternalFilesDir(String type) {
        File f = new File(getFilesDir(), type != null ? type : "external");
        f.mkdirs();
        return f;
    }

    @Override
    public synchronized SharedPreferences getSharedPreferences(String name, int mode) {
        String key = (name != null && !name.isEmpty()) ? name : "default";
        SharedPreferences sp = mPrefs.get(key);
        if (sp == null) {
            File dir = new File(mDataDir, "shared_prefs");
            dir.mkdirs();
            sp = new AfwSharedPreferences(new File(dir, key + ".properties"));
            mPrefs.put(key, sp);
        }
        return sp;
    }

    @Override
    public Object getSystemService(String name) {
        if (AUDIO_SERVICE.equals(name)) return mAudioManager;
        if (WINDOW_SERVICE.equals(name)) return mWindowManager;
        if (LAYOUT_INFLATER_SERVICE.equals(name)) return new LayoutInflater(this);
        return null;
    }
}
