package android.util;

import java.util.TreeMap;

public class SparseArray<E> {
    private final TreeMap<Integer, E> mMap = new TreeMap<>();

    public SparseArray() {}
    public SparseArray(int initialCapacity) {}

    public void put(int key, E value) { mMap.put(key, value); }
    public E get(int key) { return mMap.get(key); }
    public E get(int key, E def) { E v = mMap.get(key); return v != null ? v : def; }
    public void remove(int key) { mMap.remove(key); }
    public void delete(int key) { mMap.remove(key); }
    public int size() { return mMap.size(); }
    public void clear() { mMap.clear(); }
    public boolean contains(int key) { return mMap.containsKey(key); }
}
