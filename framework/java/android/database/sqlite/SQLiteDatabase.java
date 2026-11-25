package android.database.sqlite;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Lightweight in-process SQLiteDatabase implementation supporting basic tables/CRUD. */
public class SQLiteDatabase {
    private final File mFile;
    private final Map<String, List<Map<String, Object>>> mTables = new LinkedHashMap<>();
    private int mVersion = 0;

    public SQLiteDatabase(File file) { mFile = file; }

    public int getVersion() { return mVersion; }
    public void setVersion(int v) { mVersion = v; }
    public boolean isOpen() { return true; }
    public void close() {}
    public void beginTransaction() {}
    public void setTransactionSuccessful() {}
    public void endTransaction() {}

    public void execSQL(String sql) {
        if (sql == null) return;
        String up = sql.trim().toUpperCase();
        if (up.startsWith("CREATE TABLE")) {
            String[] toks = sql.trim().split("[\\s(]+");
            for (int i = 2; i < toks.length; i++) {
                if (!toks[i].equalsIgnoreCase("IF") && !toks[i].equalsIgnoreCase("NOT") && !toks[i].equalsIgnoreCase("EXISTS")) {
                    mTables.putIfAbsent(toks[i].replace("`", "").replace("\"", ""), new ArrayList<>());
                    break;
                }
            }
        } else if (up.startsWith("DROP TABLE")) {
            String[] toks = sql.trim().split("\\s+");
            if (toks.length > 0) mTables.remove(toks[toks.length - 1].replace(";", ""));
        }
    }

    public long insert(String table, String nullColumnHack, ContentValues values) {
        List<Map<String, Object>> rows = mTables.computeIfAbsent(table, k -> new ArrayList<>());
        Map<String, Object> row = new LinkedHashMap<>();
        long id = rows.size() + 1;
        row.put("_id", id);
        if (values != null) {
            for (String k : values.keySet()) row.put(k, values.get(k));
        }
        rows.add(row);
        return id;
    }

    public int delete(String table, String whereClause, String[] whereArgs) {
        List<Map<String, Object>> rows = mTables.get(table);
        if (rows == null) return 0;
        int n = rows.size();
        if (whereClause == null || whereClause.isEmpty()) { rows.clear(); return n; }
        return 0;
    }

    public Cursor query(String table, String[] columns, String selection, String[] selectionArgs,
                        String groupBy, String having, String orderBy) {
        List<Map<String, Object>> rows = mTables.get(table);
        if (rows == null || rows.isEmpty()) return new MatrixCursor(columns != null ? columns : new String[0]);
        String[] cols = columns;
        if (cols == null || cols.length == 0) cols = rows.get(0).keySet().toArray(new String[0]);
        MatrixCursor c = new MatrixCursor(cols);
        for (Map<String, Object> r : rows) {
            Object[] vals = new Object[cols.length];
            for (int i = 0; i < cols.length; i++) vals[i] = r.get(cols[i]);
            c.addRow(vals);
        }
        return c;
    }

    public Cursor rawQuery(String sql, String[] selectionArgs) {
        return new MatrixCursor(new String[0]);
    }
}
