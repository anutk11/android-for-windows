package android.os;

import com.afw.AfwHost;
import com.afw.AfwLauncher;
import java.io.File;

public class Environment {
    public static final String MEDIA_MOUNTED = "mounted";
    public static final String DIRECTORY_MUSIC = "Music";
    public static final String DIRECTORY_DOWNLOADS = "Downloads";
    public static final String DIRECTORY_DOCUMENTS = "Documents";
    public static final String DIRECTORY_PICTURES = "Pictures";

    public static String getExternalStorageState() { return MEDIA_MOUNTED; }

    public static File getExternalStorageDirectory() {
        try {
            String home = AfwHost.getUserDir("");
            if (home != null && !home.isEmpty()) {
                File f = new File(home);
                if (f.exists()) return f;
            }
        } catch (Throwable ignored) {}
        File d = AfwLauncher.getDataDir();
        File ext = new File(d != null ? d : new File("."), "sdcard");
        ext.mkdirs();
        return ext;
    }

    public static File getExternalStoragePublicDirectory(String type) {
        if (type != null && !type.isEmpty()) {
            try {
                String dir = AfwHost.getUserDir(type);
                if (dir != null && !dir.isEmpty()) {
                    File f = new File(dir);
                    if (f.exists()) return f;
                }
            } catch (Throwable ignored) {}
        }
        File f = new File(getExternalStorageDirectory(), type != null ? type : "Files");
        f.mkdirs();
        return f;
    }

    public static File getDataDirectory() {
        File d = AfwLauncher.getDataDir();
        return d != null ? d : new File(".");
    }
}
