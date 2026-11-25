package android.media;

public final class AudioAttributes {
    public static final int USAGE_MEDIA = 1;
    public static final int USAGE_GAME  = 14;
    public static final int CONTENT_TYPE_MUSIC = 2;

    public static final class Builder {
        private int mUsage = USAGE_MEDIA;
        private int mContentType = CONTENT_TYPE_MUSIC;
        public Builder setUsage(int u) { mUsage = u; return this; }
        public Builder setContentType(int c) { mContentType = c; return this; }
        public AudioAttributes build() { return new AudioAttributes(mUsage, mContentType); }
    }

    private final int mUsage, mContentType;
    AudioAttributes(int u, int c) { mUsage = u; mContentType = c; }
    public int getUsage() { return mUsage; }
    public int getContentType() { return mContentType; }
}
