package android.graphics;

public final class Rect {
    public int left, top, right, bottom;

    public Rect() {}
    public Rect(int l, int t, int r, int b) { left = l; top = t; right = r; bottom = b; }
    public Rect(Rect r) { if (r != null) { left = r.left; top = r.top; right = r.right; bottom = r.bottom; } }

    public void set(int l, int t, int r, int b) { left = l; top = t; right = r; bottom = b; }
    public void set(Rect r) { if (r != null) set(r.left, r.top, r.right, r.bottom); }
    public int width() { return right - left; }
    public int height() { return bottom - top; }
    public boolean isEmpty() { return left >= right || top >= bottom; }
    public boolean contains(int x, int y) { return x >= left && x < right && y >= top && y < bottom; }
    public int centerX() { return (left + right) >> 1; }
    public int centerY() { return (top + bottom) >> 1; }
}
