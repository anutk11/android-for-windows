package com.afw.dexdemo;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    static {
        System.loadLibrary("dex_jni_demo");
    }

    public native String nativeRunCheck(int a, int b);

    public int javaCallback(int x) {
        return x * 7 + 3;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String cfg = getAssets().readText("config.txt");
        Log.i("DexDemo", "Loaded APK asset config.txt: " + cfg);

        String res = nativeRunCheck(10, 20);
        Log.i("DexDemo", "JNI nativeRunCheck(10, 20) -> " + res);

        if (res.equals("JNI_OK:75") && cfg.equals("AFW-DEX-CONFIG-OK")) {
            System.out.println("DEX_JNI_DEMO_APK_PASSED (" + res + ")");
        } else {
            System.out.println("DEX_JNI_DEMO_APK_FAILED (" + res + " / " + cfg + ")");
        }

        DemoView view = new DemoView("AFW DEX JNI 75", 75);
        setContentView(view);
    }
}
