package android.content.pm;

import com.afw.AfwAxml;
import com.afw.AfwLauncher;
import java.io.File;

public class PackageManager {
    public static final int PERMISSION_GRANTED = 0;
    public static final int PERMISSION_DENIED = -1;

    public static class NameNotFoundException extends Exception {
        public NameNotFoundException(String msg) { super(msg); }
    }

    public PackageInfo getPackageInfo(String pkg, int flags) throws NameNotFoundException {
        AfwAxml.ManifestInfo mi = AfwLauncher.getManifest();
        PackageInfo pi = new PackageInfo();
        pi.packageName = (pkg != null) ? pkg : (mi != null ? mi.packageName : "com.afw.app");
        if (mi != null) {
            pi.versionCode = mi.versionCode;
            pi.versionName = mi.versionName;
        }
        pi.applicationInfo = getApplicationInfo(pi.packageName, flags);
        return pi;
    }

    public ApplicationInfo getApplicationInfo(String pkg, int flags) {
        ApplicationInfo ai = new ApplicationInfo();
        ai.packageName = pkg;
        ai.sourceDir = AfwLauncher.getApkPath();
        File d = AfwLauncher.getDataDir();
        ai.dataDir = d != null ? d.getPath() : ".";
        ai.nativeLibraryDir = new File(ai.dataDir, "lib64").getPath();
        return ai;
    }

    public boolean hasSystemFeature(String name) { return false; }
}
