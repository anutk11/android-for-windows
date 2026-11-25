package android.content;

import android.net.Uri;
import android.os.Bundle;
import java.io.Serializable;

public class Intent {
    public static final String ACTION_MAIN = "android.intent.action.MAIN";
    public static final String ACTION_VIEW = "android.intent.action.VIEW";
    public static final String CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER";

    private String mAction;
    private String mPackage;
    private String mClassName;
    private Uri mData;
    private int mFlags;
    private final Bundle mExtras = new Bundle();

    public Intent() {}
    public Intent(String action) { mAction = action; }
    public Intent(String action, Uri uri) { mAction = action; mData = uri; }
    public Intent(Context packageContext, Class<?> cls) {
        if (packageContext != null) mPackage = packageContext.getPackageName();
        if (cls != null) mClassName = cls.getName();
    }

    public String getAction() { return mAction; }
    public Intent setAction(String action) { mAction = action; return this; }
    public Uri getData() { return mData; }
    public Intent setData(Uri data) { mData = data; return this; }
    public Intent setClassName(String pkg, String cls) { mPackage = pkg; mClassName = cls; return this; }
    public String getPackage() { return mPackage; }
    public String getClassName() { return mClassName; }
    public int getFlags() { return mFlags; }
    public Intent setFlags(int flags) { mFlags = flags; return this; }
    public Intent addFlags(int flags) { mFlags |= flags; return this; }

    public Intent putExtra(String k, String v) { mExtras.putString(k, v); return this; }
    public Intent putExtra(String k, int v) { mExtras.putInt(k, v); return this; }
    public Intent putExtra(String k, long v) { mExtras.putLong(k, v); return this; }
    public Intent putExtra(String k, float v) { mExtras.putFloat(k, v); return this; }
    public Intent putExtra(String k, boolean v) { mExtras.putBoolean(k, v); return this; }
    public Intent putExtra(String k, Serializable v) { mExtras.putSerializable(k, v); return this; }
    public Intent putExtras(Bundle b) { mExtras.putAll(b); return this; }

    public String getStringExtra(String k) { return mExtras.getString(k); }
    public int getIntExtra(String k, int def) { return mExtras.getInt(k, def); }
    public long getLongExtra(String k, long def) { return mExtras.getLong(k, def); }
    public float getFloatExtra(String k, float def) { return mExtras.getFloat(k, def); }
    public boolean getBooleanExtra(String k, boolean def) { return mExtras.getBoolean(k, def); }
    public Bundle getExtras() { return mExtras; }
}
