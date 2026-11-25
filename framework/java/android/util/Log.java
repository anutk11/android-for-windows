package android.util;

public final class Log {
    public static final int VERBOSE = 2;
    public static final int DEBUG   = 3;
    public static final int INFO    = 4;
    public static final int WARN    = 5;
    public static final int ERROR   = 6;
    public static final int ASSERT  = 7;

    private Log() {}

    public static int println(int prio, String tag, String msg) {
        char c = prio <= 2 ? 'V' : prio == 3 ? 'D' : prio == 4 ? 'I' : prio == 5 ? 'W' : 'E';
        String line = "[" + c + "/" + (tag != null ? tag : "App") + "] " + (msg != null ? msg : "");
        if (prio >= WARN) System.err.println(line);
        else System.out.println(line);
        return line.length();
    }

    public static int v(String tag, String msg) { return println(VERBOSE, tag, msg); }
    public static int d(String tag, String msg) { return println(DEBUG, tag, msg); }
    public static int i(String tag, String msg) { return println(INFO, tag, msg); }
    public static int w(String tag, String msg) { return println(WARN, tag, msg); }
    public static int w(String tag, String msg, Throwable tr) {
        int n = println(WARN, tag, msg + ": " + tr);
        if (tr != null) tr.printStackTrace(System.err);
        return n;
    }
    public static int e(String tag, String msg) { return println(ERROR, tag, msg); }
    public static int e(String tag, String msg, Throwable tr) {
        int n = println(ERROR, tag, msg + ": " + tr);
        if (tr != null) tr.printStackTrace(System.err);
        return n;
    }
    public static boolean isLoggable(String tag, int level) { return level >= DEBUG; }
}
