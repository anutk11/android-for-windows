package android.view;

import android.util.DisplayMetrics;
import com.afw.AfwHost;

public class Display {
    public void getMetrics(DisplayMetrics out) {
        if (out == null) return;
        out.widthPixels = AfwHost.getWidth();
        out.heightPixels = AfwHost.getHeight();
        out.density = 1.0f;
        out.scaledDensity = 1.0f;
        out.densityDpi = 160;
        out.xdpi = 160f;
        out.ydpi = 160f;
    }

    public int getWidth() { return AfwHost.getWidth(); }
    public int getHeight() { return AfwHost.getHeight(); }
}
