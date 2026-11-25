package android.graphics;

import java.util.ArrayList;
import java.util.List;

public class Path {
    static final int CMD_MOVE = 0;
    static final int CMD_LINE = 1;
    static final int CMD_CLOSE = 2;

    final List<int[]> mCmds = new ArrayList<>();
    final List<float[]> mPts = new ArrayList<>();

    public void reset() { mCmds.clear(); mPts.clear(); }
    public void moveTo(float x, float y) { mCmds.add(new int[]{CMD_MOVE}); mPts.add(new float[]{x, y}); }
    public void lineTo(float x, float y) { mCmds.add(new int[]{CMD_LINE}); mPts.add(new float[]{x, y}); }
    public void close() { mCmds.add(new int[]{CMD_CLOSE}); mPts.add(new float[]{0f, 0f}); }
}
