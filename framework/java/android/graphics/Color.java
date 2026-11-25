package android.graphics;

public class Color {
    public static final int BLACK       = 0xFF000000;
    public static final int DKGRAY      = 0xFF444444;
    public static final int GRAY        = 0xFF888888;
    public static final int LTGRAY      = 0xFFCCCCCC;
    public static final int WHITE       = 0xFFFFFFFF;
    public static final int RED         = 0xFFFF0000;
    public static final int GREEN       = 0xFF00FF00;
    public static final int BLUE        = 0xFF0000FF;
    public static final int YELLOW      = 0xFFFFFF00;
    public static final int CYAN        = 0xFF00FFFF;
    public static final int MAGENTA     = 0xFFFF00FF;
    public static final int TRANSPARENT = 0x00000000;

    public static int alpha(int c) { return (c >>> 24) & 0xFF; }
    public static int red(int c)   { return (c >>> 16) & 0xFF; }
    public static int green(int c) { return (c >>> 8) & 0xFF; }
    public static int blue(int c)  { return c & 0xFF; }

    public static int rgb(int r, int g, int b) {
        return 0xFF000000 | ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF);
    }

    public static int argb(int a, int r, int g, int b) {
        return ((a & 0xFF) << 24) | ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF);
    }

    public static int parseColor(String s) {
        if (s == null || s.isEmpty()) throw new IllegalArgumentException("Empty color");
        if (s.charAt(0) == '#') {
            long v = Long.parseLong(s.substring(1), 16);
            if (s.length() == 7) v |= 0xFF000000L;
            else if (s.length() == 4) {
                int r = (int)((v >> 8) & 0xF) * 17;
                int g = (int)((v >> 4) & 0xF) * 17;
                int b = (int)(v & 0xF) * 17;
                return rgb(r, g, b);
            }
            return (int) v;
        }
        String l = s.toLowerCase();
        if ("black".equals(l)) return BLACK;
        if ("white".equals(l)) return WHITE;
        if ("red".equals(l)) return RED;
        if ("green".equals(l)) return GREEN;
        if ("blue".equals(l)) return BLUE;
        if ("gray".equals(l) || "grey".equals(l)) return GRAY;
        if ("transparent".equals(l)) return TRANSPARENT;
        throw new IllegalArgumentException("Unknown color: " + s);
    }
}
