package android.app;

import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import com.afw.AfwLauncher;

public class Activity extends ContextWrapper {
    private Application mApplication;
    private Intent mIntent;
    private Window mWindow;
    private CharSequence mTitle = "Android App";
    private boolean mFinishing = false;

    public Activity() { super(null); }

    public final void attachAfw(Application app, Intent intent) {
        attachBaseContext(app);
        mApplication = app;
        mIntent = intent;
        mWindow = new Window(this);
    }

    public final Application getApplication() { return mApplication; }
    public Intent getIntent() { return mIntent; }
    public void setIntent(Intent i) { mIntent = i; }
    public Window getWindow() { return mWindow; }
    public WindowManager getWindowManager() { return (WindowManager) getSystemService(WINDOW_SERVICE); }
    public LayoutInflater getLayoutInflater() { return new LayoutInflater(this); }

    public void setTitle(CharSequence title) { mTitle = title != null ? title : ""; }
    public CharSequence getTitle() { return mTitle; }

    public void setContentView(View view) { mWindow.setContentView(view); }
    public void setContentView(int layoutResID) {
        View v = getLayoutInflater().inflate(layoutResID, null, false);
        setContentView(v);
    }

    public <T extends View> T findViewById(int id) {
        @SuppressWarnings("unchecked")
        T v = (T) mWindow.findViewById(id);
        return v;
    }

    public final void runOnUiThread(Runnable action) {
        if (action == null) return;
        if (Thread.currentThread() == Looper.getMainLooper().getThread()) action.run();
        else new Handler(Looper.getMainLooper()).post(action);
    }

    @Override
    public void startActivity(Intent intent) {
        AfwLauncher.startActivity(this, intent);
    }

    public void finish() {
        mFinishing = true;
        AfwLauncher.requestFinish(this);
    }

    public boolean isFinishing() { return mFinishing; }

    public void onBackPressed() { finish(); }

    public boolean requestWindowFeature(int featureId) { return mWindow.requestFeature(featureId); }

    protected void onCreate(Bundle savedInstanceState) {}
    protected void onStart() {}
    protected void onResume() {}
    protected void onPause() {}
    protected void onStop() {}
    protected void onDestroy() {}

    public final void dispatchCreate(Bundle b) { onCreate(b); }
    public final void dispatchStart() { onStart(); }
    public final void dispatchResume() { onResume(); }
    public final void dispatchPause() { onPause(); }
    public final void dispatchStop() { onStop(); }
    public final void dispatchDestroy() { onDestroy(); }

    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (mWindow != null && mWindow.getDecorView().dispatchTouchEvent(ev)) return true;
        return onTouchEvent(ev);
    }

    public boolean onTouchEvent(MotionEvent ev) { return false; }

    public boolean dispatchKeyEvent(KeyEvent ev) {
        if (mWindow != null && mWindow.getDecorView().dispatchKeyEvent(ev)) return true;
        return onKeyDown(ev.getKeyCode(), ev);
    }

    public boolean onKeyDown(int keyCode, KeyEvent ev) { return false; }

    public void dispatchCharInput(char ch) {
        if (mWindow != null) mWindow.getDecorView().onCharInput(ch);
    }
}
