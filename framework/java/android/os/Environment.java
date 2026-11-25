package android.os;

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
        File d = AfwLauncher.getDataDir();
        File ext = new File(d != null ? d : new File("."), "sdcard");
        ext.mkdirs();
        return ext;
    }

    public static File getExternalStoragePublicDirectory(String type) {
        File f = new File(getExternalStorageDirectory(), type != null ? type : "Files");
        f.mkdirs();
        return f;
    }

    public static File getDataDirectory() {
        File d = AfwLauncher.getDataDir();
        return d != null ? d : new File(".");
    }
}
