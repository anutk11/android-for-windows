package android.media;

public class AudioManager {
    public static final int STREAM_MUSIC = 3;
    private int mVolume = 12;

    public int getStreamMaxVolume(int streamType) { return 15; }
    public int getStreamVolume(int streamType) { return mVolume; }
    public void setStreamVolume(int streamType, int index, int flags) {
        mVolume = Math.max(0, Math.min(15, index));
    }
}
