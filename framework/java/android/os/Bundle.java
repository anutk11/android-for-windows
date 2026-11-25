package android.os;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Bundle {
    public static final Bundle EMPTY = new Bundle();
    private final Map<String, Object> mMap = new HashMap<>();

    public Bundle() {}
    public Bundle(Bundle other) {
        if (other != null) mMap.putAll(other.mMap);
    }

    public boolean containsKey(String key) { return mMap.containsKey(key); }
    public boolean isEmpty() { return mMap.isEmpty(); }
    public int size() { return mMap.size(); }
    public void clear() { mMap.clear(); }
    public void remove(String key) { mMap.remove(key); }
    public Set<String> keySet() { return mMap.keySet(); }
    public void putAll(Bundle b) { if (b != null) mMap.putAll(b.mMap); }

    public void putString(String k, String v) { mMap.put(k, v); }
    public String getString(String k) { return getString(k, null); }
    public String getString(String k, String def) {
        Object o = mMap.get(k);
        return (o instanceof String) ? (String) o : def;
    }

    public void putInt(String k, int v) { mMap.put(k, v); }
    public int getInt(String k) { return getInt(k, 0); }
    public int getInt(String k, int def) {
        Object o = mMap.get(k);
        return (o instanceof Number) ? ((Number) o).intValue() : def;
    }

    public void putLong(String k, long v) { mMap.put(k, v); }
    public long getLong(String k) { return getLong(k, 0L); }
    public long getLong(String k, long def) {
        Object o = mMap.get(k);
        return (o instanceof Number) ? ((Number) o).longValue() : def;
    }

    public void putFloat(String k, float v) { mMap.put(k, v); }
    public float getFloat(String k) { return getFloat(k, 0f); }
    public float getFloat(String k, float def) {
        Object o = mMap.get(k);
        return (o instanceof Number) ? ((Number) o).floatValue() : def;
    }

    public void putDouble(String k, double v) { mMap.put(k, v); }
    public double getDouble(String k) { return getDouble(k, 0.0); }
    public double getDouble(String k, double def) {
        Object o = mMap.get(k);
        return (o instanceof Number) ? ((Number) o).doubleValue() : def;
    }

    public void putBoolean(String k, boolean v) { mMap.put(k, v); }
    public boolean getBoolean(String k) { return getBoolean(k, false); }
    public boolean getBoolean(String k, boolean def) {
        Object o = mMap.get(k);
        return (o instanceof Boolean) ? (Boolean) o : def;
    }

    public void putByteArray(String k, byte[] v) { mMap.put(k, v); }
    public byte[] getByteArray(String k) {
        Object o = mMap.get(k);
        return (o instanceof byte[]) ? (byte[]) o : null;
    }

    public void putBundle(String k, Bundle v) { mMap.put(k, v); }
    public Bundle getBundle(String k) {
        Object o = mMap.get(k);
        return (o instanceof Bundle) ? (Bundle) o : null;
    }

    public void putSerializable(String k, Serializable v) { mMap.put(k, v); }
    public Serializable getSerializable(String k) {
        Object o = mMap.get(k);
        return (o instanceof Serializable) ? (Serializable) o : null;
    }

    public Object get(String k) { return mMap.get(k); }
}
