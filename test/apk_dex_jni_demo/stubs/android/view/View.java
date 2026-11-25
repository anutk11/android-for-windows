package android.view;
import android.graphics.Canvas;
public class View {
    public View() {}
    public int getWidth() { return 0; }
    public int getHeight() { return 0; }
    public void invalidate() {}
    protected void onDraw(Canvas canvas) {}
}
