package android.view;

import android.graphics.Canvas;

public interface SurfaceHolder {
    interface Callback {
        void surfaceCreated(SurfaceHolder holder);
        void surfaceChanged(SurfaceHolder holder, int format, int width, int height);
        void surfaceDestroyed(SurfaceHolder holder);
    }

    void addCallback(Callback cb);
    void removeCallback(Callback cb);
    Canvas lockCanvas();
    void unlockCanvasAndPost(Canvas canvas);
}
