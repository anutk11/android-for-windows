package android.os;

public final class SystemClock {
    private static final long START_NS = System.nanoTime();
    private SystemClock() {}

    public static long uptimeMillis() { return (System.nanoTime() - START_NS) / 1_000_000L; }
    public static long elapsedRealtime() { return uptimeMillis(); }
    public static long elapsedRealtimeNanos() { return System.nanoTime() - START_NS; }
    public static void sleep(long ms) {
        try { Thread.sleep(Math.max(0, ms)); } catch (InterruptedException ignored) {}
    }
}
