package android.media;

import com.afw.AfwHost;

/** Real WinMM waveOut-backed android.media.AudioTrack. */
public class AudioTrack {
    public static final int MODE_STATIC = 0;
    public static final int MODE_STREAM = 1;
    public static final int PLAYSTATE_STOPPED = 1;
    public static final int PLAYSTATE_PAUSED  = 2;
    public static final int PLAYSTATE_PLAYING = 3;
    public static final int STATE_UNINITIALIZED = 0;
    public static final int STATE_INITIALIZED   = 1;

    private final int mSampleRate;
    private final int mChannels;
    private final int mBits;
    private int mHandle = -1;
    private int mState = STATE_UNINITIALIZED;
    private int mPlayState = PLAYSTATE_STOPPED;
    private float mGain = 1.0f;

    public AudioTrack(int streamType, int sampleRateInHz, int channelConfig,
                      int audioFormat, int bufferSizeInBytes, int mode) {
        mSampleRate = sampleRateInHz;
        mChannels = (channelConfig == AudioFormat.CHANNEL_OUT_MONO) ? 1 : 2;
        mBits = (audioFormat == AudioFormat.ENCODING_PCM_8BIT) ? 8 : 16;
        mHandle = AfwHost.audioOpen(mSampleRate, mChannels, mBits);
        if (mHandle > 0) mState = STATE_INITIALIZED;
    }

    public static int getMinBufferSize(int sampleRateInHz, int channelConfig, int audioFormat) {
        int ch = (channelConfig == AudioFormat.CHANNEL_OUT_MONO) ? 1 : 2;
        int bps = (audioFormat == AudioFormat.ENCODING_PCM_8BIT) ? 1 : 2;
        return Math.max(4096, (sampleRateInHz / 20) * ch * bps);
    }

    public int getState() { return mState; }
    public int getPlayState() { return mPlayState; }
    public int setVolume(float gain) { mGain = Math.max(0f, Math.min(1f, gain)); return 0; }

    public void play() {
        if (mState == STATE_INITIALIZED) mPlayState = PLAYSTATE_PLAYING;
    }

    public void pause() {
        if (mPlayState == PLAYSTATE_PLAYING) mPlayState = PLAYSTATE_PAUSED;
    }

    public void stop() {
        mPlayState = PLAYSTATE_STOPPED;
    }

    public int write(byte[] audioData, int offsetInBytes, int sizeInBytes) {
        if (mHandle <= 0 || audioData == null || sizeInBytes <= 0) return -1;
        return AfwHost.audioWrite(mHandle, audioData, offsetInBytes, sizeInBytes);
    }

    public int write(short[] audioData, int offsetInShorts, int sizeInShorts) {
        if (mHandle <= 0 || audioData == null || sizeInShorts <= 0) return -1;
        int n = Math.min(sizeInShorts, audioData.length - offsetInShorts);
        if (n <= 0) return 0;
        byte[] pcm = new byte[n * 2];
        for (int i = 0; i < n; i++) {
            int s = Math.round(audioData[offsetInShorts + i] * mGain);
            if (s > 32767) s = 32767;
            else if (s < -32768) s = -32768;
            pcm[i * 2]     = (byte) (s & 0xFF);
            pcm[i * 2 + 1] = (byte) ((s >> 8) & 0xFF);
        }
        int wb = AfwHost.audioWrite(mHandle, pcm, 0, pcm.length);
        return wb > 0 ? wb / 2 : wb;
    }

    public void flush() {}

    public void release() {
        mPlayState = PLAYSTATE_STOPPED;
        if (mHandle > 0) {
            AfwHost.audioClose(mHandle);
            mHandle = -1;
        }
        mState = STATE_UNINITIALIZED;
    }
}
