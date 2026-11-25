package android.database.sqlite;

import android.content.Context;
import java.io.File;

public abstract class SQLiteOpenHelper {
    private final Context mContext;
    private final String mName;
    private final int mVersion;
    private SQLiteDatabase mDb;

    public SQLiteOpenHelper(Context ctx, String name, Object factory, int version) {
        mContext = ctx; mName = name; mVersion = version;
    }

    public abstract void onCreate(SQLiteDatabase db);
    public abstract void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion);

    public synchronized SQLiteDatabase getWritableDatabase() {
        if (mDb == null) {
            File dir = mContext != null ? mContext.getFilesDir() : new File(".");
            mDb = new SQLiteDatabase(new File(dir, mName != null ? mName : "app.db"));
            onCreate(mDb);
            mDb.setVersion(mVersion);
        }
        return mDb;
    }

    public SQLiteDatabase getReadableDatabase() { return getWritableDatabase(); }
    public synchronized void close() { if (mDb != null) { mDb.close(); mDb = null; } }
}
