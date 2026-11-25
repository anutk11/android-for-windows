package android.os;

public class Process {
    public static final int THREAD_PRIORITY_DEFAULT = 0;
    public static final int THREAD_PRIORITY_BACKGROUND = 10;
    public static final int THREAD_PRIORITY_AUDIO = -16;

    public static int myPid() { return 1000; }
    public static int myTid() { return (int) Thread.currentThread().getId(); }
    public static int myUid() { return 10000; }
    public static void setThreadPriority(int priority) {}
    public static void killProcess(int pid) { System.exit(0); }
}
