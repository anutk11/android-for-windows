package com.afw;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.os.Looper;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * APK runtime host inside real Android 14 libart.so.
 *
 * Opens the APK via java.util.zip.ZipFile, extracts native lib/x86_64/*.so,
 * parses AndroidManifest.xml + resources.arsc, boots Application & main Activity,
 * and drives the Win32 60 FPS render + input + Looper event loop.
 */
public final class AfwLauncher {
    private static ZipFile sApkZip;
    private static String sApkPath;
    private static File sDataDir;
    private static AfwAxml.ManifestInfo sManifest;
    private static Map<Integer, String> sResStrings = new HashMap<>();
    private static Application sApplication;
    private static final Deque<Activity> sActivityStack = new ArrayDeque<>();
    private static boolean sRunning = true;
    private static long sTouchDownTime = 0;

    private AfwLauncher() {}

    public static ZipFile getApkZip() { return sApkZip; }
    public static String getApkPath() { return sApkPath; }
    public static File getDataDir() { return sDataDir; }
    public static AfwAxml.ManifestInfo getManifest() { return sManifest; }
    public static Application getApplication() { return sApplication; }
    public static Map<Integer, String> getResourceStrings() { return sResStrings; }

    public static void requestFinish(Activity act) {
        if (sActivityStack.size() <= 1) {
            sRunning = false;
        } else {
            sActivityStack.remove(act);
            act.dispatchPause();
            act.dispatchStop();
            act.dispatchDestroy();
            Activity top = sActivityStack.peek();
            if (top != null) top.dispatchResume();
        }
    }

    public static void startActivity(Activity from, Intent intent) {
        if (intent == null || intent.getClassName() == null) return;
        try {
            Activity prev = sActivityStack.peek();
            if (prev != null) prev.dispatchPause();
            Class<?> cls = Class.forName(intent.getClassName());
            Activity next = (Activity) cls.getDeclaredConstructor().newInstance();
            next.attachAfw(sApplication, intent);
            sActivityStack.push(next);
            next.dispatchCreate(null);
            next.dispatchStart();
            next.dispatchResume();
        } catch (Throwable t) {
            System.err.println("[afw] startActivity failed: " + t);
            t.printStackTrace();
        }
    }

    private static byte[] readZipEntry(ZipFile zip, String name) {
        try {
            ZipEntry e = zip.getEntry(name);
            if (e == null) return null;
            try (InputStream in = zip.getInputStream(e);
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                return out.toByteArray();
            }
        } catch (Throwable t) {
            return null;
        }
    }

    private static int extractNativeLibs(ZipFile zip, File libDir) {
        int count = 0;
        if (!libDir.exists()) libDir.mkdirs();
        Enumeration<? extends ZipEntry> en = zip.entries();
        while (en.hasMoreElements()) {
            ZipEntry e = en.nextElement();
            String name = e.getName();
            if (e.isDirectory() || !name.startsWith("lib/x86_64/") || !name.endsWith(".so")) continue;
            String base = name.substring("lib/x86_64/".length());
            if (base.indexOf('/') >= 0) continue;
            File out = new File(libDir, base);
            try (InputStream in = zip.getInputStream(e);
                 FileOutputStream fos = new FileOutputStream(out)) {
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
                count++;
                System.out.println("[afw] extracted native lib: " + out.getPath());
            } catch (Throwable t) {
                System.err.println("[afw] warning: failed extracting " + name + ": " + t);
            }
        }
        return count;
    }

    public static int launch(String apkPath, String dataDirPath) {
        try {
            sApkPath = apkPath;
            sDataDir = new File(dataDirPath);
            if (!sDataDir.exists()) sDataDir.mkdirs();
            File filesDir = new File(sDataDir, "files");
            File cacheDir = new File(sDataDir, "cache");
            File prefsDir = new File(sDataDir, "shared_prefs");
            File libDir   = new File(sDataDir, "lib64");
            filesDir.mkdirs(); cacheDir.mkdirs(); prefsDir.mkdirs(); libDir.mkdirs();

            sApkZip = new ZipFile(apkPath);
            int nLibs = extractNativeLibs(sApkZip, libDir);

            byte[] arsc = readZipEntry(sApkZip, "resources.arsc");
            if (arsc != null) sResStrings = AfwAxml.parseResourcesArsc(arsc);

            byte[] manifestBytes = readZipEntry(sApkZip, "AndroidManifest.xml");
            sManifest = AfwAxml.parseManifest(manifestBytes, sResStrings);
            System.out.println("[afw] APK package:  " + sManifest.packageName);
            System.out.println("[afw] APK label:    " + sManifest.appLabel);
            System.out.println("[afw] APK activity: " + sManifest.mainActivity);
            System.out.println("[afw] Native libs:  " + nLibs);

            if (sManifest.mainActivity == null) {
                System.err.println("[afw] FAIL: no launchable Activity found in AndroidManifest.xml");
                return 1;
            }

            Looper.prepareMainLooper();

            int winRc = AfwHost.windowCreate(sManifest.appLabel, 420, 740);
            if (winRc != 0) {
                System.err.println("[afw] FAIL: windowCreate returned " + winRc);
                return 1;
            }
            int width = AfwHost.getWidth();
            int height = AfwHost.getHeight();

            DisplayMetrics dm = new DisplayMetrics();
            dm.widthPixels = width;
            dm.heightPixels = height;
            dm.density = 1.0f;
            dm.scaledDensity = 1.0f;
            dm.densityDpi = 160;
            dm.xdpi = 160f;
            dm.ydpi = 160f;

            AssetManager am = new AssetManager(sApkZip);
            Resources res = new Resources(am, dm, sResStrings);

            if (sManifest.applicationClass != null) {
                Class<?> appCls = Class.forName(sManifest.applicationClass);
                sApplication = (Application) appCls.getDeclaredConstructor().newInstance();
            } else {
                sApplication = new Application();
            }
            sApplication.initAfw(sManifest.packageName, sDataDir, res, am);
            sApplication.onCreate();

            Class<?> actCls = Class.forName(sManifest.mainActivity);
            Activity mainAct = (Activity) actCls.getDeclaredConstructor().newInstance();
            Intent launchIntent = new Intent(Intent.ACTION_MAIN);
            launchIntent.setClassName(sManifest.packageName, sManifest.mainActivity);
            mainAct.attachAfw(sApplication, launchIntent);
            sActivityStack.push(mainAct);

            mainAct.dispatchCreate(null);
            mainAct.dispatchStart();
            mainAct.dispatchResume();

            Bitmap fb = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
            Canvas canvas = new Canvas(fb);
            int[] ev = new int[4];
            sRunning = true;

            while (sRunning && !sActivityStack.isEmpty()) {
                Activity cur = sActivityStack.peek();

                // 1. Pump all pending Win32 input / resize / quit events
                while (AfwHost.pollEvent(ev) != 0) {
                    int type = ev[0];
                    if (type == AfwHost.EV_QUIT) {
                        sRunning = false;
                        break;
                    } else if (type == AfwHost.EV_RESIZE) {
                        int nw = Math.max(64, ev[1]);
                        int nh = Math.max(64, ev[2]);
                        if (nw != width || nh != height) {
                            width = nw; height = nh;
                            dm.widthPixels = width; dm.heightPixels = height;
                            fb = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
                            canvas = new Canvas(fb);
                        }
                    } else if (type == AfwHost.EV_TOUCH_DOWN || type == AfwHost.EV_TOUCH_MOVE || type == AfwHost.EV_TOUCH_UP) {
                        long now = SystemClock.uptimeMillis();
                        int action;
                        if (type == AfwHost.EV_TOUCH_DOWN) {
                            sTouchDownTime = now;
                            action = MotionEvent.ACTION_DOWN;
                        } else if (type == AfwHost.EV_TOUCH_MOVE) {
                            action = MotionEvent.ACTION_MOVE;
                        } else {
                            action = MotionEvent.ACTION_UP;
                        }
                        MotionEvent me = MotionEvent.obtain(sTouchDownTime, now, action, (float) ev[1], (float) ev[2], 0);
                        cur.dispatchTouchEvent(me);
                    } else if (type == AfwHost.EV_KEY_DOWN || type == AfwHost.EV_KEY_UP) {
                        int action = (type == AfwHost.EV_KEY_DOWN) ? KeyEvent.ACTION_DOWN : KeyEvent.ACTION_UP;
                        KeyEvent ke = new KeyEvent(action, ev[1]);
                        if (action == KeyEvent.ACTION_DOWN && ev[1] == KeyEvent.KEYCODE_BACK) {
                            cur.onBackPressed();
                        } else {
                            cur.dispatchKeyEvent(ke);
                        }
                    } else if (type == AfwHost.EV_CHAR) {
                        cur.dispatchCharInput((char) ev[1]);
                    }
                }
                if (!sRunning) break;

                // 2. Drain Android main Looper / Handler messages & posted Runnables
                Looper.getMainLooper().drainDueMessages();

                // 3. Measure, layout, and draw the Activity's root View hierarchy
                View root = cur.getWindow().getDecorView();
                if (root != null) {
                    int wSpec = View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY);
                    int hSpec = View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY);
                    root.measure(wSpec, hSpec);
                    root.layout(0, 0, width, height);
                    canvas.resetForFrame(0xFF121218);
                    root.draw(canvas);
                }

                // 4. Present ARGB_8888 framebuffer to Win32 window (and optional BMP screenshot)
                AfwHost.present(fb.getPixelsArray(), width, height);
                AfwHost.sleepMs(16);
            }

            while (!sActivityStack.isEmpty()) {
                Activity a = sActivityStack.pop();
                a.dispatchPause();
                a.dispatchStop();
                a.dispatchDestroy();
            }
            sApplication.onTerminate();
            System.out.println("[afw] clean shutdown (frames=" + AfwHost.getFrames() +
                               ", audio_bytes=" + AfwHost.getAudioBytes() + ")");
            return 0;
        } catch (Throwable t) {
            System.err.println("[afw] UNCAUGHT EXCEPTION in AfwLauncher:");
            t.printStackTrace();
            return 1;
        } finally {
            try { if (sApkZip != null) sApkZip.close(); } catch (Throwable ignored) {}
        }
    }
}
