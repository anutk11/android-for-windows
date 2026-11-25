package android.media;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/** Lightweight MediaPlayer supporting uncompressed WAV/PCM playback via AudioTrack. */
public class MediaPlayer {
    public interface OnCompletionListener { void onCompletion(MediaPlayer mp); }

    private byte[] mPcmData;
    private int mSampleRate = 44100;
    private int mChannels = 1;
    private boolean mLooping = false;
    private volatile boolean mPlaying = false;
    private AudioTrack mTrack;
    private Thread mThread;
    private OnCompletionListener mCompletionListener;

    public void setLooping(boolean looping) { mLooping = looping; }
    public boolean isLooping() { return mLooping; }
    public boolean isPlaying() { return mPlaying; }
    public void setOnCompletionListener(OnCompletionListener l) { mCompletionListener = l; }

    public void setDataSource(String path) throws IOException {
        File f = new File(path);
        byte[] all = new byte[(int) f.length()];
        try (InputStream in = new FileInputStream(f)) {
            int off = 0, n;
            while (off < all.length && (n = in.read(all, off, all.length - off)) > 0) off += n;
        }
        parseWav(all);
    }

    private void parseWav(byte[] all) {
        if (all.length > 44 && all[0] == 'R' && all[1] == 'I' && all[2] == 'F' && all[3] == 'F') {
            mChannels = (all[22] & 0xFF) | ((all[23] & 0xFF) << 8);
            mSampleRate = (all[24] & 0xFF) | ((all[25] & 0xFF) << 8)
                        | ((all[26] & 0xFF) << 16) | ((all[27] & 0xFF) << 24);
            int pos = 12;
            while (pos + 8 <= all.length) {
                int sz = (all[pos + 4] & 0xFF) | ((all[pos + 5] & 0xFF) << 8)
                       | ((all[pos + 6] & 0xFF) << 16) | ((all[pos + 7] & 0xFF) << 24);
                if (all[pos] == 'd' && all[pos + 1] == 'a' && all[pos + 2] == 't' && all[pos + 3] == 'a') {
                    int len = Math.min(sz, all.length - (pos + 8));
                    mPcmData = new byte[Math.max(0, len)];
                    System.arraycopy(all, pos + 8, mPcmData, 0, mPcmData.length);
                    return;
                }
                pos += 8 + Math.max(0, sz);
            }
        }
        mPcmData = all;
    }

    public void prepare() {}

    public void start() {
        if (mPlaying || mPcmData == null) return;
        mPlaying = true;
        int chMask = (mChannels == 1) ? AudioFormat.CHANNEL_OUT_MONO : AudioFormat.CHANNEL_OUT_STEREO;
        int bufSz = AudioTrack.getMinBufferSize(mSampleRate, chMask, AudioFormat.ENCODING_PCM_16BIT);
        mTrack = new AudioTrack(AudioManager.STREAM_MUSIC, mSampleRate, chMask,
                                AudioFormat.ENCODING_PCM_16BIT, bufSz, AudioTrack.MODE_STREAM);
        mTrack.play();
        mThread = new Thread(new Runnable() {
            @Override public void run() {
                do {
                    int off = 0;
                    while (mPlaying && off < mPcmData.length) {
                        int chunk = Math.min(4096, mPcmData.length - off);
                        mTrack.write(mPcmData, off, chunk);
                        off += chunk;
                    }
                } while (mPlaying && mLooping);
                mPlaying = false;
                if (mCompletionListener != null) mCompletionListener.onCompletion(MediaPlayer.this);
            }
        }, "AFW-MediaPlayer");
        mThread.start();
    }

    public void pause() { mPlaying = false; }
    public void stop() { mPlaying = false; }

    public void release() {
        mPlaying = false;
        if (mTrack != null) { mTrack.release(); mTrack = null; }
    }
}
