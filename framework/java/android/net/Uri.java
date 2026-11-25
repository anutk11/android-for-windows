package android.net;

import java.io.File;

public class Uri {
    private final String mUri;

    private Uri(String uri) { mUri = uri != null ? uri : ""; }

    public static Uri parse(String uriString) { return new Uri(uriString); }
    public static Uri fromFile(File file) { return new Uri("file://" + file.getAbsolutePath()); }

    public String getScheme() {
        int i = mUri.indexOf(':');
        return i > 0 ? mUri.substring(0, i) : null;
    }

    public String getPath() {
        int i = mUri.indexOf("://");
        if (i >= 0) {
            int s = mUri.indexOf('/', i + 3);
            return s >= 0 ? mUri.substring(s) : "";
        }
        return mUri;
    }

    @Override public String toString() { return mUri; }
    @Override public boolean equals(Object o) { return (o instanceof Uri) && mUri.equals(((Uri) o).mUri); }
    @Override public int hashCode() { return mUri.hashCode(); }
}
