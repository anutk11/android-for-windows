package androidx.fragment.app;

import android.app.Activity;

public class FragmentActivity extends Activity {
    private final FragmentManager mFm = new FragmentManager(this);

    public FragmentManager getSupportFragmentManager() { return mFm; }
}
