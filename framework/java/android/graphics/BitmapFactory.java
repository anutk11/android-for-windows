package android.graphics;

import com.afw.AfwHost;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;

/** Decodes PNG, JPEG, GIF, BMP, ICO, and WebP via Windows Imaging Component (WIC). */
public class BitmapFactory {
    public static class Options {
        public int inSampleSize = 1;
        public boolean inJustDecodeBounds = false;
        public int outWidth;
        public int outHeight;
    }

    public static Bitmap decodeByteArray(byte[] data, int offset, int length) {
        return decodeByteArray(data, offset, length, null);
    }

    public static Bitmap decodeByteArray(byte[] data, int offset, int length, Options opts) {
        if (data == null || length <= 0 || offset < 0 || offset + length > data.length) return null;
        byte[] slice = (offset == 0 && length == data.length) ? data : new byte[length];
        if (slice != data) System.arraycopy(data, offset, slice, 0, length);
        int[] wh = new int[2];
        int[] px = AfwHost.decodeImage(slice, wh);
        if (px == null || wh[0] <= 0 || wh[1] <= 0) return null;
        if (opts != null) { opts.outWidth = wh[0]; opts.outHeight = wh[1]; }
        if (opts != null && opts.inJustDecodeBounds) return null;
        return Bitmap.createBitmap(px, wh[0], wh[1], Bitmap.Config.ARGB_8888);
    }

    public static Bitmap decodeStream(InputStream is) {
        return decodeStream(is, null, null);
    }

    public static Bitmap decodeStream(InputStream is, Rect outPadding, Options opts) {
        if (is == null) return null;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) out.write(buf, 0, n);
            byte[] all = out.toByteArray();
            return decodeByteArray(all, 0, all.length, opts);
        } catch (Throwable t) {
            return null;
        }
    }

    public static Bitmap decodeFile(String pathName) {
        return decodeFile(pathName, null);
    }

    public static Bitmap decodeFile(String pathName, Options opts) {
        if (pathName == null) return null;
        try (FileInputStream fis = new FileInputStream(pathName)) {
            return decodeStream(fis, null, opts);
        } catch (Throwable t) {
            return null;
        }
    }
}
