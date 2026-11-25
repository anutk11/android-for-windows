package android.graphics;

import java.util.Arrays;

public final class Bitmap {
    public enum Config { ALPHA_8, RGB_565, ARGB_8888 }

    private final int mWidth;
    private final int mHeight;
    private final Config mConfig;
    private final int[] mPixels;
    private boolean mRecycled = false;

    private Bitmap(int w, int h, Config cfg) {
        mWidth = Math.max(1, w);
        mHeight = Math.max(1, h);
        mConfig = cfg != null ? cfg : Config.ARGB_8888;
        mPixels = new int[mWidth * mHeight];
    }

    public static Bitmap createBitmap(int width, int height, Config config) {
        return new Bitmap(width, height, config);
    }

    public static Bitmap createBitmap(int[] colors, int width, int height, Config config) {
        Bitmap b = new Bitmap(width, height, config);
        if (colors != null) System.arraycopy(colors, 0, b.mPixels, 0, Math.min(colors.length, b.mPixels.length));
        return b;
    }

    public int getWidth() { return mWidth; }
    public int getHeight() { return mHeight; }
    public Config getConfig() { return mConfig; }
    public int[] getPixelsArray() { return mPixels; }

    public int getPixel(int x, int y) {
        if (x < 0 || y < 0 || x >= mWidth || y >= mHeight) return 0;
        return mPixels[y * mWidth + x];
    }

    public void setPixel(int x, int y, int color) {
        if (x < 0 || y < 0 || x >= mWidth || y >= mHeight) return;
        mPixels[y * mWidth + x] = color;
    }

    public void eraseColor(int c) { Arrays.fill(mPixels, c); }
    public void recycle() { mRecycled = true; }
    public boolean isRecycled() { return mRecycled; }
}
