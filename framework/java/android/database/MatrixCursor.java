package android.database;

import java.util.ArrayList;
import java.util.List;

public class MatrixCursor implements Cursor {
    private final String[] mCols;
    private final List<Object[]> mRows = new ArrayList<>();
    private int mPos = -1;
    private boolean mClosed = false;

    public MatrixCursor(String[] columnNames) {
        mCols = columnNames != null ? columnNames.clone() : new String[0];
    }

    public void addRow(Object[] columnValues) {
        Object[] row = new Object[mCols.length];
        if (columnValues != null) {
            System.arraycopy(columnValues, 0, row, 0, Math.min(row.length, columnValues.length));
        }
        mRows.add(row);
    }

    @Override public int getCount() { return mRows.size(); }
    @Override public int getPosition() { return mPos; }
    @Override public boolean moveToFirst() { return moveToPosition(0); }
    @Override public boolean moveToNext() { return moveToPosition(mPos + 1); }
    @Override public boolean moveToPosition(int pos) {
        if (pos < 0 || pos >= mRows.size()) { mPos = pos < 0 ? -1 : mRows.size(); return false; }
        mPos = pos;
        return true;
    }

    @Override public int getColumnIndex(String name) {
        if (name == null) return -1;
        for (int i = 0; i < mCols.length; i++) if (name.equalsIgnoreCase(mCols[i])) return i;
        return -1;
    }
    @Override public int getColumnIndexOrThrow(String name) {
        int i = getColumnIndex(name);
        if (i < 0) throw new IllegalArgumentException("Column not found: " + name);
        return i;
    }
    @Override public String getColumnName(int i) { return mCols[i]; }
    @Override public int getColumnCount() { return mCols.length; }

    private Object val(int i) {
        if (mPos < 0 || mPos >= mRows.size() || i < 0 || i >= mCols.length) return null;
        return mRows.get(mPos)[i];
    }

    @Override public String getString(int i) { Object v = val(i); return v != null ? v.toString() : null; }
    @Override public int getInt(int i) {
        Object v = val(i);
        if (v instanceof Number) return ((Number) v).intValue();
        try { return v != null ? Integer.parseInt(v.toString()) : 0; } catch (Throwable t) { return 0; }
    }
    @Override public long getLong(int i) {
        Object v = val(i);
        if (v instanceof Number) return ((Number) v).longValue();
        try { return v != null ? Long.parseLong(v.toString()) : 0L; } catch (Throwable t) { return 0L; }
    }
    @Override public float getFloat(int i) {
        Object v = val(i);
        if (v instanceof Number) return ((Number) v).floatValue();
        try { return v != null ? Float.parseFloat(v.toString()) : 0f; } catch (Throwable t) { return 0f; }
    }
    @Override public double getDouble(int i) {
        Object v = val(i);
        if (v instanceof Number) return ((Number) v).doubleValue();
        try { return v != null ? Double.parseDouble(v.toString()) : 0.0; } catch (Throwable t) { return 0.0; }
    }
    @Override public byte[] getBlob(int i) { Object v = val(i); return (v instanceof byte[]) ? (byte[]) v : null; }
    @Override public boolean isNull(int i) { return val(i) == null; }
    @Override public boolean isClosed() { return mClosed; }
    @Override public void close() { mClosed = true; }
}
