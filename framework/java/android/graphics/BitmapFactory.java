package android.graphics;

import java.io.InputStream;

public class BitmapFactory {
    public static class Options {
        public int inSampleSize = 1;
        public boolean inJustDecodeBounds = false;
        public int outWidth;
        public int outHeight;
    }

    public static Bitmap decodeByteArray(byte[] data, int offset, int length) {
        return Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888);
    }

    public static Bitmap decodeStream(InputStream is) {
        return Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888);
    }
}
