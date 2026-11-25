package android.content;

public class ComponentName {
    private final String mPkg;
    private final String mCls;

    public ComponentName(String pkg, String cls) { mPkg = pkg; mCls = cls; }
    public String getPackageName() { return mPkg; }
    public String getClassName() { return mCls; }
}
