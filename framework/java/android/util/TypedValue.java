package android.util;

public class TypedValue {
    public static final int COMPLEX_UNIT_PX = 0;
    public static final int COMPLEX_UNIT_DIP = 1;
    public static final int COMPLEX_UNIT_SP = 2;
    public static final int COMPLEX_UNIT_PT = 3;
    public static final int COMPLEX_UNIT_IN = 4;
    public static final int COMPLEX_UNIT_MM = 5;

    public int type;
    public int data;
    public CharSequence string;
    public int resourceId;

    public static float applyDimension(int unit, float value, DisplayMetrics metrics) {
        if (metrics == null) return value;
        switch (unit) {
            case COMPLEX_UNIT_PX:  return value;
            case COMPLEX_UNIT_DIP: return value * metrics.density;
            case COMPLEX_UNIT_SP:  return value * metrics.scaledDensity;
            case COMPLEX_UNIT_PT:  return value * metrics.xdpi * (1.0f / 72f);
            case COMPLEX_UNIT_IN:  return value * metrics.xdpi;
            case COMPLEX_UNIT_MM:  return value * metrics.xdpi * (1.0f / 25.4f);
            default: return value;
        }
    }
}
