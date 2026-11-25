package android.content;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/** File-backed SharedPreferences implementation persisted as .properties in dataDir/shared_prefs. */
public final class AfwSharedPreferences implements SharedPreferences {
    private final File mFile;
    private final Map<String, Object> mValues = new HashMap<>();

    public AfwSharedPreferences(File file) {
        mFile = file;
        load();
    }

    private synchronized void load() {
        if (!mFile.exists()) return;
        Properties p = new Properties();
        try (FileInputStream fis = new FileInputStream(mFile)) {
            p.load(fis);
            for (String k : p.stringPropertyNames()) {
                String raw = p.getProperty(k);
                if (raw == null) continue;
                if (raw.startsWith("I:")) mValues.put(k, Integer.parseInt(raw.substring(2)));
                else if (raw.startsWith("L:")) mValues.put(k, Long.parseLong(raw.substring(2)));
                else if (raw.startsWith("F:")) mValues.put(k, Float.parseFloat(raw.substring(2)));
                else if (raw.startsWith("B:")) mValues.put(k, Boolean.parseBoolean(raw.substring(2)));
                else if (raw.startsWith("S:")) mValues.put(k, raw.substring(2));
                else mValues.put(k, raw);
            }
        } catch (Throwable ignored) {}
    }

    private synchronized boolean save() {
        try {
            File parent = mFile.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            Properties p = new Properties();
            for (Map.Entry<String, Object> e : mValues.entrySet()) {
                Object v = e.getValue();
                if (v instanceof Integer) p.setProperty(e.getKey(), "I:" + v);
                else if (v instanceof Long) p.setProperty(e.getKey(), "L:" + v);
                else if (v instanceof Float) p.setProperty(e.getKey(), "F:" + v);
                else if (v instanceof Boolean) p.setProperty(e.getKey(), "B:" + v);
                else if (v instanceof String) p.setProperty(e.getKey(), "S:" + v);
            }
            try (FileOutputStream fos = new FileOutputStream(mFile)) {
                p.store(fos, "AFW SharedPreferences");
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override public synchronized Map<String, ?> getAll() { return new HashMap<>(mValues); }
    @Override public synchronized String getString(String k, String def) {
        Object v = mValues.get(k); return (v instanceof String) ? (String) v : def;
    }
    @SuppressWarnings("unchecked")
    @Override public synchronized Set<String> getStringSet(String k, Set<String> def) {
        Object v = mValues.get(k); return (v instanceof Set) ? new HashSet<>((Set<String>) v) : def;
    }
    @Override public synchronized int getInt(String k, int def) {
        Object v = mValues.get(k); return (v instanceof Number) ? ((Number) v).intValue() : def;
    }
    @Override public synchronized long getLong(String k, long def) {
        Object v = mValues.get(k); return (v instanceof Number) ? ((Number) v).longValue() : def;
    }
    @Override public synchronized float getFloat(String k, float def) {
        Object v = mValues.get(k); return (v instanceof Number) ? ((Number) v).floatValue() : def;
    }
    @Override public synchronized boolean getBoolean(String k, boolean def) {
        Object v = mValues.get(k); return (v instanceof Boolean) ? (Boolean) v : def;
    }
    @Override public synchronized boolean contains(String k) { return mValues.containsKey(k); }

    @Override
    public Editor edit() {
        return new Editor() {
            private final Map<String, Object> mMod = new HashMap<>();
            private final Set<String> mRem = new HashSet<>();
            private boolean mClear = false;

            @Override public Editor putString(String k, String v) { mMod.put(k, v); return this; }
            @Override public Editor putStringSet(String k, Set<String> v) { mMod.put(k, v); return this; }
            @Override public Editor putInt(String k, int v) { mMod.put(k, v); return this; }
            @Override public Editor putLong(String k, long v) { mMod.put(k, v); return this; }
            @Override public Editor putFloat(String k, float v) { mMod.put(k, v); return this; }
            @Override public Editor putBoolean(String k, boolean v) { mMod.put(k, v); return this; }
            @Override public Editor remove(String k) { mRem.add(k); return this; }
            @Override public Editor clear() { mClear = true; return this; }
            @Override public boolean commit() {
                synchronized (AfwSharedPreferences.this) {
                    if (mClear) mValues.clear();
                    for (String r : mRem) mValues.remove(r);
                    mValues.putAll(mMod);
                    return save();
                }
            }
            @Override public void apply() { commit(); }
        };
    }
}
