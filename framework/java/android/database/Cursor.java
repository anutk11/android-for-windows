package android.database;

import java.io.Closeable;

public interface Cursor extends Closeable {
    int getCount();
    int getPosition();
    boolean moveToFirst();
    boolean moveToNext();
    boolean moveToPosition(int position);
    int getColumnIndex(String columnName);
    int getColumnIndexOrThrow(String columnName);
    String getColumnName(int columnIndex);
    int getColumnCount();
    String getString(int columnIndex);
    int getInt(int columnIndex);
    long getLong(int columnIndex);
    float getFloat(int columnIndex);
    double getDouble(int columnIndex);
    byte[] getBlob(int columnIndex);
    boolean isNull(int columnIndex);
    boolean isClosed();
    @Override void close();
}
