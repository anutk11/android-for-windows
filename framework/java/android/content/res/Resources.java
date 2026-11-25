package android.content.res;

import android.util.DisplayMetrics;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class Resources {
    private final AssetManager mAssets;
    private final DisplayMetrics mMetrics;
    private final Configuration mConfig = new Configuration();
    private final Map<Integer, String> mStrings;

    public Resources(AssetManager assets, DisplayMetrics metrics, Map<Integer, String> strings) {
        mAssets = assets;
        mMetrics = (metrics != null) ? metrics : new DisplayMetrics();
        mStrings = (strings != null) ? strings : new HashMap<>();
    }

    public DisplayMetrics getDisplayMetrics() { return mMetrics; }
    public Configuration getConfiguration() { return mConfig; }
    public AssetManager getAssets() { return mAssets; }

    public String getString(int id) {
        String s = mStrings.get(id);
        return s != null ? s : ("@0x" + Integer.toHexString(id));
    }

    public String getString(int id, Object... formatArgs) {
        String s = getString(id);
        try { return String.format(s, formatArgs); } catch (Throwable t) { return s; }
    }

    public String getResourceEntryPath(int id) {
        return mStrings.get(id);
    }

    public InputStream openRawResource(int id) throws IOException {
        String p = mStrings.get(id);
        if (p == null) throw new IOException("Unknown raw resource 0x" + Integer.toHexString(id));
        return mAssets.openRawPath(p);
    }

    public int getColor(int id) { return 0xFFFFFFFF; }
    public float getDimension(int id) { return 0f; }
    public int getDimensionPixelSize(int id) { return 0; }
}
