package android.app;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.view.View;
public class Activity {
    protected void onCreate(Bundle savedInstanceState) {}
    protected void onStart() {}
    protected void onResume() {}
    protected void onPause() {}
    protected void onStop() {}
    protected void onDestroy() {}
    public void setContentView(View view) {}
    public AssetManager getAssets() { return null; }
}
