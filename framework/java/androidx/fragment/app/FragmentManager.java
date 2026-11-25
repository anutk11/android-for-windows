package androidx.fragment.app;

import java.util.ArrayList;
import java.util.List;

public class FragmentManager {
    final FragmentActivity mActivity;
    final List<Fragment> mFragments = new ArrayList<>();

    FragmentManager(FragmentActivity act) { mActivity = act; }

    public FragmentTransaction beginTransaction() { return new FragmentTransaction(this); }
    public List<Fragment> getFragments() { return new ArrayList<>(mFragments); }
}
