package android.media;

import android.content.Context;
import android.net.Uri;
import com.afw.AfwHost;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * MediaPlayer backed by Windows Media Foundation (MP3, AAC, M4A, FLAC, OGG, WAV, WMA, MP4)
 * with pure-Java WAV fallback, playing through WinMM-backed AudioTrack.
 */
public class MediaPlayer {
    public interface OnCompletionListener { void onCompletion(MediaPlayer mp); }
    public interface OnPreparedListener { void onPrepared(MediaPlayer mp); }

    private String mPath;
    private byte[] mPcmData;
    private int mSampleRate = 44100;
    private int mChannels = 2;
    private int mPositionBytes = 0;
    private boolean mLooping = false;
    private volatile boolean mPlaying = false;
    private AudioTrack mTrack;
    private Thread mThread;
    private OnCompletionListener mCompletionListener;
    private OnPreparedListener mPreparedListener;

    public void setLooping(boolean looping) { mLooping = looping; }
    public boolean isLooping() { return mLooping; }
    public boolean isPlaying() { return mPlaying; }
    public void setOnCompletionListener(OnCompletionListener l) { mCompletionListener = l; }
    public void setOnPreparedListener(OnPreparedListener l) { mPreparedListener = l; }

    public int getDuration() {
        if (mPcmData == null || mSampleRate <= 0 || mChannels <= 0) return 0;
        long bytesPerSec = (long) mSampleRate * mChannels * 2L;
        return (int) ((mPcmData.length * 1000L) / bytesPerSec);
    }

    public int getCurrentPosition() {
        if (mSampleRate <= 0 || mChannels <= 0) return 0;
        long bytesPerSec = (long) mSampleRate * mChannels * 2L;
        return (int) ((mPositionBytes * 1000L) / bytesPerSec);
    }

    public void seekTo(int msec) {
        if (mPcmData == null) return;
        long bytesPerSec = (long) mSampleRate * mChannels * 2L;
        int target = (int) Math.max(0, Math.min(mPcmData.length, (msec * bytesPerSec) / 1000L));
        mPositionBytes = target & ~3;
    }

    public void setDataSource(Context context, Uri uri) throws IOException {
        if (uri == null) throw new IOException("Null URI");
        setDataSource(uri.getPath());
    }

    public void setDataSource(String path) throws IOException {
        mPath = path;
        mPositionBytes = 0;
        // 1. Try Windows Media Foundation (decodes MP3, AAC, M4A, FLAC, OGG, WAV, MP4 natively)
        int[] meta = new int[2];
        short[] decoded = AfwHost.decodeMedia(path, meta);
        if (decoded != null && decoded.length > 0) {
            mSampleRate = meta[0] > 0 ? meta[0] : 44100;
            mChannels   = meta[1] > 0 ? meta[1] : 2;
            mPcmData = new byte[decoded.length * 2];
            for (int i = 0; i < decoded.length; i++) {
                short s = decoded[i];
                mPcmData[i * 2]     = (byte) (s & 0xFF);
                mPcmData[i * 2 + 1] = (byte) ((s >> 8) & 0xFF);
            }
            return;
        }
        // 2. Fallback: raw WAV/RIFF parser
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

    public void prepare() {
        if (mPreparedListener != null) mPreparedListener.onPrepared(this);
    }

    public void prepareAsync() { prepare(); }

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
                    while (mPlaying && mPositionBytes < mPcmData.length) {
                        int chunk = Math.min(4096, mPcmData.length - mPositionBytes);
                        mTrack.write(mPcmData, mPositionBytes, chunk);
                        mPositionBytes += chunk;
                    }
                    if (mLooping && mPlaying) mPositionBytes = 0;
                } while (mPlaying && mLooping);
                mPlaying = false;
                if (mCompletionListener != null) mCompletionListener.onCompletion(MediaPlayer.this);
            }
        }, "AFW-MediaPlayer");
        mThread.start();
    }

    public void pause() { mPlaying = false; }
    public void stop() { mPlaying = false; mPositionBytes = 0; }
    public void reset() { stop(); mPcmData = null; mPath = null; }

    public void release() {
        mPlaying = false;
        if (mTrack != null) { mTrack.release(); mTrack = null; }
    }
}
