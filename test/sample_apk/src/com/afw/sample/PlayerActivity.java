package com.afw.sample;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.SeekBar;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Interactive Music Synthesizer & Oscilloscope Visualizer APK.
 * Exercises the full native Android-for-Windows stack inside real Android 14 libart.so:
 *   - Binary AXML AndroidManifest.xml launch
 *   - Native JNI library (lib/x86_64/libsample_jni.so) via System.loadLibrary()
 *   - APK AssetManager (assets/info.txt)
 *   - Persistent SharedPreferences
 *   - Real-time AudioTrack PCM audio streaming to Windows WinMM waveOut
 *   - Custom Canvas rendering + interactive LinearLayout / Button / SeekBar touch UI
 */
public class PlayerActivity extends Activity {
    private static final String TAG = "SampleMusicApp";
    private static final String[] NOTE_NAMES = { "C4", "E4", "G4", "A4", "C5" };
    private static final double[] NOTE_FREQS = { 261.63, 329.63, 392.00, 440.00, 523.25 };

    static {
        System.loadLibrary("sample_jni");
    }

    private static native String nativeDspVersion();
    private static native double nativeSynthWave(short[] outBuf, double freqHz, double phase, int sampleRate);

    private volatile boolean mPlaying = true;
    private volatile boolean mAlive = true;
    private volatile int mNoteIdx = 0;
    private volatile float mVolume = 0.8f;
    private volatile short[] mLastWave = new short[256];
    private volatile long mPcmSamplesWritten = 0;

    private int mTapCount = 0;
    private String mDspVersion = "unknown";
    private String mAssetInfo = "none";
    private TextView mStatusText;
    private Button mNextNoteBtn;
    private Button mPlayPauseBtn;
    private AudioTrack mTrack;
    private Thread mAudioThread;
    private Handler mMainHandler;

    private static final class WaveformView extends View {
        private final PlayerActivity mHost;
        private final Paint mBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mGridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mWavePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mBarPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mLabelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

        WaveformView(Context ctx, PlayerActivity host) {
            super(ctx);
            mHost = host;
            setMinimumHeight(210);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            int w = getWidth(), h = getHeight();
            if (w <= 0 || h <= 0) return;

            // Card background
            mBgPaint.setStyle(Paint.Style.FILL);
            mBgPaint.setColor(0xFF1A1E2E);
            canvas.drawRoundRect(0, 0, w, h, 14f, 14f, mBgPaint);

            // Subtle grid
            mGridPaint.setColor(0xFF283046);
            mGridPaint.setStrokeWidth(1f);
            float midY = h * 0.5f;
            canvas.drawLine(12, midY, w - 12, midY, mGridPaint);
            canvas.drawLine(12, h * 0.25f, w - 12, h * 0.25f, mGridPaint);
            canvas.drawLine(12, h * 0.75f, w - 12, h * 0.75f, mGridPaint);

            // Spectrum bars
            short[] samples = mHost.mLastWave;
            int bars = 24;
            float barW = (w - 32f) / bars;
            mBarPaint.setStyle(Paint.Style.FILL);
            for (int b = 0; b < bars; b++) {
                int sIdx = (b * samples.length) / bars;
                float amp = Math.abs(samples[sIdx]) / 24000f;
                float bh = Math.max(6f, Math.min(h * 0.42f, amp * h * 0.45f));
                float bx = 16f + b * barW;
                mBarPaint.setColor(mHost.mPlaying ? 0x5538BDF8 : 0x4464748B);
                canvas.drawRoundRect(bx + 2, midY - bh, bx + barW - 2, midY + bh, 3f, 3f, mBarPaint);
            }

            // Oscilloscope curve
            mWavePaint.setColor(mHost.mPlaying ? 0xFF38BDF8 : 0xFF94A3B8);
            mWavePaint.setStrokeWidth(3f);
            int pts = Math.min(128, samples.length);
            float prevX = 16f;
            float prevY = midY - (samples[0] / 32768f) * (h * 0.36f);
            for (int i = 1; i < pts; i++) {
                float x = 16f + (w - 32f) * i / (pts - 1f);
                float y = midY - (samples[i] / 32768f) * (h * 0.36f);
                canvas.drawLine(prevX, prevY, x, y, mWavePaint);
                prevX = x; prevY = y;
            }

            mLabelPaint.setColor(0xFF94A3B8);
            mLabelPaint.setTextSize(12f);
            canvas.drawText(mHost.mPlaying ? "LIVE PCM SYNTH (44.1 kHz)" : "PAUSED", 16f, 22f, mLabelPaint);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mMainHandler = new Handler(Looper.getMainLooper());
        mDspVersion = nativeDspVersion();

        // Read APK asset assets/info.txt
        try (InputStream in = getAssets().open("info.txt");
             BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            String line = br.readLine();
            if (line != null && !line.isEmpty()) mAssetInfo = line.trim();
        } catch (Throwable t) {
            Log.e(TAG, "Failed reading assets/info.txt", t);
        }

        SharedPreferences prefs = getSharedPreferences("synth_prefs", Context.MODE_PRIVATE);
        mNoteIdx = prefs.getInt("note_idx", 0) % NOTE_NAMES.length;
        int prevLaunches = prefs.getInt("launch_count", 0);
        prefs.edit().putInt("launch_count", prevLaunches + 1).apply();

        Log.i(TAG, "[SAMPLE_APK] BOOT dsp=" + mDspVersion + " asset=\"" + mAssetInfo +
                   "\" launches=" + (prevLaunches + 1));

        // Build modern dark-themed Android View hierarchy
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0F172A);
        root.setPadding(20, 20, 20, 20);

        TextView title = new TextView(this);
        title.setText("AFW Music Synth");
        title.setTextSize(24f);
        title.setTextColor(0xFFF8FAFC);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(title, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView sub = new TextView(this);
        sub.setText(mDspVersion + " | " + mAssetInfo);
        sub.setTextSize(12f);
        sub.setTextColor(0xFF94A3B8);
        sub.setGravity(Gravity.CENTER_HORIZONTAL);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subLp.setMargins(0, 4, 0, 16);
        root.addView(sub, subLp);

        WaveformView wave = new WaveformView(this, this);
        LinearLayout.LayoutParams waveLp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 210);
        waveLp.setMargins(0, 0, 0, 16);
        root.addView(wave, waveLp);

        mStatusText = new TextView(this);
        mStatusText.setTextSize(16f);
        mStatusText.setTextColor(0xFF38BDF8);
        mStatusText.setTypeface(Typeface.DEFAULT_BOLD);
        mStatusText.setGravity(Gravity.CENTER_HORIZONTAL);
        LinearLayout.LayoutParams stLp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stLp.setMargins(0, 0, 0, 16);
        root.addView(mStatusText, stLp);

        // Primary full-width action button (positioned around y=340..400 for easy tapping & CI click)
        mNextNoteBtn = new Button(this);
        mNextNoteBtn.setId(1001);
        mNextNoteBtn.setText("Next Note (C4 -> E4)");
        mNextNoteBtn.setBackgroundColor(0xFF3B82F6);
        mNextNoteBtn.setTextSize(16f);
        mNextNoteBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                mTapCount++;
                mNoteIdx = (mNoteIdx + 1) % NOTE_NAMES.length;
                getSharedPreferences("synth_prefs", Context.MODE_PRIVATE)
                    .edit().putInt("note_idx", mNoteIdx).putInt("taps", mTapCount).apply();
                updateLabels();
                Log.i(TAG, "[SAMPLE_APK] BUTTON_CLICKED taps=" + mTapCount +
                           " note=" + NOTE_NAMES[mNoteIdx]);
            }
        });
        LinearLayout.LayoutParams btn1Lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 58);
        btn1Lp.setMargins(0, 0, 0, 12);
        root.addView(mNextNoteBtn, btn1Lp);

        mPlayPauseBtn = new Button(this);
        mPlayPauseBtn.setId(1002);
        mPlayPauseBtn.setText("Pause Audio");
        mPlayPauseBtn.setBackgroundColor(0xFF10B981);
        mPlayPauseBtn.setTextSize(16f);
        mPlayPauseBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                mPlaying = !mPlaying;
                updateLabels();
            }
        });
        LinearLayout.LayoutParams btn2Lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 52);
        btn2Lp.setMargins(0, 0, 0, 18);
        root.addView(mPlayPauseBtn, btn2Lp);

        TextView volLbl = new TextView(this);
        volLbl.setText("Volume");
        volLbl.setTextSize(14f);
        volLbl.setTextColor(0xFFCBD5E1);
        root.addView(volLbl, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        SeekBar volBar = new SeekBar(this);
        volBar.setMax(100);
        volBar.setProgress(80);
        volBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override public void onProgressChanged(SeekBar sb, int p, boolean fromUser) {
                mVolume = p / 100f;
                if (mTrack != null) mTrack.setVolume(mVolume);
            }
            @Override public void onStartTrackingTouch(SeekBar sb) {}
            @Override public void onStopTrackingTouch(SeekBar sb) {}
        });
        LinearLayout.LayoutParams sbLp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 42);
        sbLp.setMargins(0, 6, 0, 16);
        root.addView(volBar, sbLp);

        TextView footer = new TextView(this);
        footer.setText("Android 14 ART | Zero VM | Native Win32");
        footer.setTextSize(12f);
        footer.setTextColor(0xFF64748B);
        footer.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(footer, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        updateLabels();
        setContentView(root);
        startAudioEngine();
    }

    private void updateLabels() {
        int nextIdx = (mNoteIdx + 1) % NOTE_NAMES.length;
        mStatusText.setText("Note: " + NOTE_NAMES[mNoteIdx] + " (" + NOTE_FREQS[mNoteIdx] +
                            " Hz) | Taps: " + mTapCount);
        mNextNoteBtn.setText("Next Note (" + NOTE_NAMES[mNoteIdx] + " -> " + NOTE_NAMES[nextIdx] + ")");
        mPlayPauseBtn.setText(mPlaying ? "Pause Audio" : "Play Audio");
        mPlayPauseBtn.setBackgroundColor(mPlaying ? 0xFF10B981 : 0xFFF59E0B);
    }

    private void startAudioEngine() {
        final int rate = 44100;
        int minBuf = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT);
        mTrack = new AudioTrack(AudioManager.STREAM_MUSIC, rate, AudioFormat.CHANNEL_OUT_MONO,
                                AudioFormat.ENCODING_PCM_16BIT, minBuf, AudioTrack.MODE_STREAM);
        mTrack.setVolume(mVolume);
        mTrack.play();

        mAudioThread = new Thread(new Runnable() {
            @Override public void run() {
                short[] chunk = new short[1024];
                double phase = 0.0;
                while (mAlive) {
                    if (mPlaying) {
                        phase = nativeSynthWave(chunk, NOTE_FREQS[mNoteIdx], phase, rate);
                        short[] vis = new short[256];
                        System.arraycopy(chunk, 0, vis, 0, vis.length);
                        mLastWave = vis;
                        int w = mTrack.write(chunk, 0, chunk.length);
                        if (w > 0) mPcmSamplesWritten += w;
                    }
                    try { Thread.sleep(20); } catch (InterruptedException ignored) {}
                }
            }
        }, "AFW-SynthAudio");
        mAudioThread.start();
    }

    @Override
    protected void onDestroy() {
        mAlive = false;
        if (mAudioThread != null) {
            try { mAudioThread.join(500); } catch (InterruptedException ignored) {}
        }
        if (mTrack != null) {
            mTrack.stop();
            mTrack.release();
            mTrack = null;
        }
        SharedPreferences prefs = getSharedPreferences("synth_prefs", Context.MODE_PRIVATE);
        int savedTaps = prefs.getInt("taps", -1);
        Log.i(TAG, "[SAMPLE_APK] SUMMARY dsp=" + mDspVersion +
                   " asset=" + mAssetInfo +
                   " taps=" + mTapCount +
                   " saved_taps=" + savedTaps +
                   " pcm_samples=" + mPcmSamplesWritten);
        super.onDestroy();
    }
}
