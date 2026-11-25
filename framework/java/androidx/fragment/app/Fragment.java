package androidx.fragment.app;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

public class Fragment {
    FragmentActivity mActivity;
    View mView;
    Bundle mArguments;

    public void setArguments(Bundle args) { mArguments = args; }
    public Bundle getArguments() { return mArguments; }
    public FragmentActivity getActivity() { return mActivity; }
    public FragmentActivity requireActivity() { return mActivity; }
    public Context getContext() { return mActivity; }
    public Context requireContext() { return mActivity; }
    public View getView() { return mView; }

    public void onAttach(Context context) {}
    public void onCreate(Bundle savedInstanceState) {}
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) { return null; }
    public void onViewCreated(View view, Bundle savedInstanceState) {}
    public void onStart() {}
    public void onResume() {}
    public void onPause() {}
    public void onStop() {}
    public void onDestroyView() {}
    public void onDestroy() {}
}
