package android.media;

public final class AudioFormat {
    public static final int ENCODING_PCM_16BIT = 2;
    public static final int ENCODING_PCM_8BIT  = 3;
    public static final int CHANNEL_OUT_MONO   = 4;
    public static final int CHANNEL_OUT_STEREO = 12;

    public static final class Builder {
        private int mEncoding = ENCODING_PCM_16BIT;
        private int mSampleRate = 44100;
        private int mChannelMask = CHANNEL_OUT_STEREO;

        public Builder setEncoding(int enc) { mEncoding = enc; return this; }
        public Builder setSampleRate(int sr) { mSampleRate = sr; return this; }
        public Builder setChannelMask(int cm) { mChannelMask = cm; return this; }
        public AudioFormat build() { return new AudioFormat(mEncoding, mSampleRate, mChannelMask); }
    }

    private final int mEncoding, mSampleRate, mChannelMask;
    AudioFormat(int enc, int sr, int cm) { mEncoding = enc; mSampleRate = sr; mChannelMask = cm; }
    public int getEncoding() { return mEncoding; }
    public int getSampleRate() { return mSampleRate; }
    public int getChannelMask() { return mChannelMask; }
}
