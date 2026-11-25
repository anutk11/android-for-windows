package android.content;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public final class ContentValues {
    private final Map<String, Object> mValues = new HashMap<>();

    public ContentValues() {}
    public ContentValues(int size) {}

    public void put(String k, String v) { mValues.put(k, v); }
    public void put(String k, Integer v) { mValues.put(k, v); }
    public void put(String k, Long v) { mValues.put(k, v); }
    public void put(String k, Float v) { mValues.put(k, v); }
    public void put(String k, Double v) { mValues.put(k, v); }
    public void put(String k, Boolean v) { mValues.put(k, v); }
    public void put(String k, byte[] v) { mValues.put(k, v); }
    public void putNull(String k) { mValues.put(k, null); }

    public Object get(String k) { return mValues.get(k); }
    public String getAsString(String k) { Object v = mValues.get(k); return v != null ? v.toString() : null; }
    public Integer getAsInteger(String k) { Object v = mValues.get(k); return v instanceof Number ? ((Number) v).intValue() : null; }
    public Long getAsLong(String k) { Object v = mValues.get(k); return v instanceof Number ? ((Number) v).longValue() : null; }
    public boolean containsKey(String k) { return mValues.containsKey(k); }
    public Set<String> keySet() { return mValues.keySet(); }
    public int size() { return mValues.size(); }
    public void clear() { mValues.clear(); }
}
