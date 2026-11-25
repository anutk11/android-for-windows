package androidx.fragment.app;

import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.List;

public class FragmentTransaction {
    private static final class Op {
        final int containerId;
        final Fragment fragment;
        final boolean replace;
        Op(int cid, Fragment f, boolean rep) { containerId = cid; fragment = f; replace = rep; }
    }

    private final FragmentManager mFm;
    private final List<Op> mOps = new ArrayList<>();

    FragmentTransaction(FragmentManager fm) { mFm = fm; }

    public FragmentTransaction add(int containerViewId, Fragment fragment) {
        mOps.add(new Op(containerViewId, fragment, false));
        return this;
    }

    public FragmentTransaction replace(int containerViewId, Fragment fragment) {
        mOps.add(new Op(containerViewId, fragment, true));
        return this;
    }

    public FragmentTransaction addToBackStack(String name) { return this; }

    public int commit() {
        FragmentActivity act = mFm.mActivity;
        for (Op op : mOps) {
            View target = act.findViewById(op.containerId);
            if (!(target instanceof ViewGroup)) continue;
            ViewGroup vg = (ViewGroup) target;
            if (op.replace) vg.removeAllViews();
            Fragment f = op.fragment;
            f.mActivity = act;
            f.onAttach(act);
            f.onCreate(null);
            f.mView = f.onCreateView(act.getLayoutInflater(), vg, null);
            if (f.mView != null) {
                vg.addView(f.mView);
                f.onViewCreated(f.mView, null);
            }
            f.onStart();
            f.onResume();
            mFm.mFragments.add(f);
        }
        return 0;
    }

    public int commitAllowingStateLoss() { return commit(); }
}
