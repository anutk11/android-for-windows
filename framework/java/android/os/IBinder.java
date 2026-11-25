package android.os;

public interface IBinder {
    String getInterfaceDescriptor();
    boolean pingBinder();
    boolean isBinderAlive();
}
