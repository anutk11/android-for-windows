package android.content.res;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class AssetManager {
    private final ZipFile mZip;

    public AssetManager(ZipFile zip) { mZip = zip; }

    public InputStream open(String fileName) throws IOException {
        if (mZip == null || fileName == null) throw new FileNotFoundException(String.valueOf(fileName));
        String key = "assets/" + (fileName.startsWith("/") ? fileName.substring(1) : fileName);
        ZipEntry e = mZip.getEntry(key);
        if (e == null) throw new FileNotFoundException(key);
        return mZip.getInputStream(e);
    }

    public InputStream openRawPath(String zipEntryPath) throws IOException {
        if (mZip == null || zipEntryPath == null) throw new FileNotFoundException(String.valueOf(zipEntryPath));
        ZipEntry e = mZip.getEntry(zipEntryPath);
        if (e == null) throw new FileNotFoundException(zipEntryPath);
        return mZip.getInputStream(e);
    }

    public String[] list(String path) throws IOException {
        if (mZip == null) return new String[0];
        String prefix = "assets/";
        if (path != null && !path.isEmpty()) {
            prefix += path.endsWith("/") ? path : (path + "/");
        }
        List<String> out = new ArrayList<>();
        Enumeration<? extends ZipEntry> en = mZip.entries();
        while (en.hasMoreElements()) {
            String n = en.nextElement().getName();
            if (n.startsWith(prefix) && n.length() > prefix.length()) {
                String rest = n.substring(prefix.length());
                int sl = rest.indexOf('/');
                String item = sl >= 0 ? rest.substring(0, sl) : rest;
                if (!out.contains(item)) out.add(item);
            }
        }
        return out.toArray(new String[0]);
    }
}
