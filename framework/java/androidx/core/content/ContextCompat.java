package androidx.core.content;

import android.content.Context;
import android.content.pm.PackageManager;

public class ContextCompat {
    public static int checkSelfPermission(Context context, String permission) {
        return PackageManager.PERMISSION_GRANTED;
    }
    public static int getColor(Context context, int id) {
        return context != null && context.getResources() != null ? context.getResources().getColor(id) : 0xFFFFFFFF;
    }
}
