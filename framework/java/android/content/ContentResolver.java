package android.content;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * ContentResolver supporting MediaStore.Audio queries backed by the user's real
 * Windows Music directory (%USERPROFILE%\Music) and file/content InputStreams.
 */
public class ContentResolver {
    private static final String[] AUDIO_EXTS = { ".mp3", ".flac", ".m4a", ".wav", ".ogg", ".aac", ".wma" };

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        String u = uri != null ? uri.toString() : "";
        if (u.contains("audio/media")) {
            String[] cols = (projection != null && projection.length > 0) ? projection : new String[] {
                MediaStore.Audio.Media._ID, MediaStore.Audio.Media.DATA,
                MediaStore.Audio.Media.DISPLAY_NAME, MediaStore.Audio.Media.TITLE,
                MediaStore.Audio.Media.ARTIST, MediaStore.Audio.Media.ALBUM,
                MediaStore.Audio.Media.DURATION
            };
            MatrixCursor c = new MatrixCursor(cols);
            File musicDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MUSIC);
            List<File> found = new ArrayList<>();
            scanAudio(musicDir, found, 0);
            long id = 1;
            for (File f : found) {
                Object[] row = new Object[cols.length];
                String name = f.getName();
                int dot = name.lastIndexOf('.');
                String title = dot > 0 ? name.substring(0, dot) : name;
                for (int i = 0; i < cols.length; i++) {
                    String col = cols[i];
                    if (MediaStore.Audio.Media._ID.equals(col)) row[i] = id;
                    else if (MediaStore.Audio.Media.DATA.equals(col)) row[i] = f.getAbsolutePath();
                    else if (MediaStore.Audio.Media.DISPLAY_NAME.equals(col)) row[i] = name;
                    else if (MediaStore.Audio.Media.TITLE.equals(col)) row[i] = title;
                    else if (MediaStore.Audio.Media.ARTIST.equals(col)) row[i] = "Local Library";
                    else if (MediaStore.Audio.Media.ALBUM.equals(col)) row[i] = f.getParentFile() != null ? f.getParentFile().getName() : "Music";
                    else if (MediaStore.Audio.Media.DURATION.equals(col)) row[i] = 0L;
                    else row[i] = "";
                }
                c.addRow(row);
                id++;
            }
            return c;
        }
        return new MatrixCursor(projection != null ? projection : new String[0]);
    }

    private void scanAudio(File dir, List<File> out, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 4 || out.size() >= 500) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (out.size() >= 500) break;
            if (f.isDirectory()) {
                scanAudio(f, out, depth + 1);
            } else {
                String lo = f.getName().toLowerCase();
                for (String ext : AUDIO_EXTS) {
                    if (lo.endsWith(ext)) { out.add(f); break; }
                }
            }
        }
    }

    public InputStream openInputStream(Uri uri) throws IOException {
        if (uri == null) throw new IOException("Null URI");
        return new FileInputStream(uri.getPath());
    }
}
