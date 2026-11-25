package android.graphics;

import com.afw.AfwFont;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

/** Software ARGB_8888 Canvas rasterizer writing directly to Bitmap's int[] pixel buffer. */
public class Canvas {
    private static final class State {
        float tx, ty;
        int cl, ct, cr, cb;
        State(float tx, float ty, int cl, int ct, int cr, int cb) {
            this.tx = tx; this.ty = ty;
            this.cl = cl; this.ct = ct; this.cr = cr; this.cb = cb;
        }
    }

    private Bitmap mBitmap;
    private int[] mPixels;
    private int mW, mH;
    private float mTx, mTy;
    private int mClipL, mClipT, mClipR, mClipB;
    private final Deque<State> mStack = new ArrayDeque<>();

    public Canvas() {}
    public Canvas(Bitmap bitmap) { setBitmap(bitmap); }

    public void setBitmap(Bitmap bitmap) {
        mBitmap = bitmap;
        if (bitmap != null) {
            mPixels = bitmap.getPixelsArray();
            mW = bitmap.getWidth();
            mH = bitmap.getHeight();
        } else {
            mPixels = null; mW = 0; mH = 0;
        }
        resetForFrame(0);
    }

    public void resetForFrame(int clearColor) {
        mStack.clear();
        mTx = 0f; mTy = 0f;
        mClipL = 0; mClipT = 0; mClipR = mW; mClipB = mH;
        if (mPixels != null && clearColor != 0) Arrays.fill(mPixels, clearColor);
    }

    public int getWidth() { return mW; }
    public int getHeight() { return mH; }

    public int save() {
        mStack.push(new State(mTx, mTy, mClipL, mClipT, mClipR, mClipB));
        return mStack.size();
    }

    public void restore() {
        if (!mStack.isEmpty()) {
            State s = mStack.pop();
            mTx = s.tx; mTy = s.ty;
            mClipL = s.cl; mClipT = s.ct; mClipR = s.cr; mClipB = s.cb;
        }
    }

    public void restoreToCount(int saveCount) {
        while (mStack.size() >= saveCount && !mStack.isEmpty()) restore();
    }

    public void translate(float dx, float dy) {
        mTx += dx;
        mTy += dy;
    }

    public boolean clipRect(float l, float t, float r, float b) {
        int il = Math.round(l + mTx);
        int it = Math.round(t + mTy);
        int ir = Math.round(r + mTx);
        int ib = Math.round(b + mTy);
        mClipL = Math.max(mClipL, il);
        mClipT = Math.max(mClipT, it);
        mClipR = Math.min(mClipR, ir);
        mClipB = Math.min(mClipB, ib);
        return mClipL < mClipR && mClipT < mClipB;
    }

    public boolean clipRect(int l, int t, int r, int b) {
        return clipRect((float) l, (float) t, (float) r, (float) b);
    }

    public boolean clipRect(Rect r) {
        return r != null && clipRect(r.left, r.top, r.right, r.bottom);
    }

    private void plot(int x, int y, int argb) {
        if (mPixels == null || x < mClipL || x >= mClipR || y < mClipT || y >= mClipB) return;
        if (x < 0 || x >= mW || y < 0 || y >= mH) return;
        mPixels[y * mW + x] = AfwFont.blend(mPixels[y * mW + x], argb);
    }

    public void drawColor(int color) {
        if (mPixels == null) return;
        int x0 = Math.max(0, mClipL), y0 = Math.max(0, mClipT);
        int x1 = Math.min(mW, mClipR), y1 = Math.min(mH, mClipB);
        int a = (color >>> 24) & 0xFF;
        if (a == 0) return;
        for (int y = y0; y < y1; y++) {
            int row = y * mW;
            if (a == 255) {
                Arrays.fill(mPixels, row + x0, row + x1, color);
            } else {
                for (int x = x0; x < x1; x++) mPixels[row + x] = AfwFont.blend(mPixels[row + x], color);
            }
        }
    }

    public void drawRect(Rect r, Paint p) {
        if (r != null) drawRect(r.left, r.top, r.right, r.bottom, p);
    }

    public void drawRect(RectF r, Paint p) {
        if (r != null) drawRect(r.left, r.top, r.right, r.bottom, p);
    }

    public void drawRect(float l, float t, float r, float b, Paint p) {
        if (mPixels == null || p == null) return;
        int color = p.getColor();
        int x0 = Math.round(l + mTx), y0 = Math.round(t + mTy);
        int x1 = Math.round(r + mTx), y1 = Math.round(b + mTy);
        if (x0 > x1) { int tmp = x0; x0 = x1; x1 = tmp; }
        if (y0 > y1) { int tmp = y0; y0 = y1; y1 = tmp; }
        if (p.getStyle() == Paint.Style.STROKE) {
            int sw = Math.max(1, Math.round(p.getStrokeWidth()));
            fillRaw(x0, y0, x1, y0 + sw, color);
            fillRaw(x0, y1 - sw, x1, y1, color);
            fillRaw(x0, y0, x0 + sw, y1, color);
            fillRaw(x1 - sw, y0, x1, y1, color);
        } else {
            fillRaw(x0, y0, x1, y1, color);
        }
    }

    private void fillRaw(int x0, int y0, int x1, int y1, int color) {
        int a = (color >>> 24) & 0xFF;
        if (a == 0) return;
        x0 = Math.max(Math.max(0, mClipL), x0);
        y0 = Math.max(Math.max(0, mClipT), y0);
        x1 = Math.min(Math.min(mW, mClipR), x1);
        y1 = Math.min(Math.min(mH, mClipB), y1);
        if (x0 >= x1 || y0 >= y1) return;
        for (int y = y0; y < y1; y++) {
            int row = y * mW;
            if (a == 255) Arrays.fill(mPixels, row + x0, row + x1, color);
            else for (int x = x0; x < x1; x++) mPixels[row + x] = AfwFont.blend(mPixels[row + x], color);
        }
    }

    public void drawRoundRect(RectF r, float rx, float ry, Paint p) {
        if (r != null) drawRoundRect(r.left, r.top, r.right, r.bottom, rx, ry, p);
    }

    public void drawRoundRect(float l, float t, float r, float b, float rx, float ry, Paint p) {
        if (mPixels == null || p == null) return;
        float rad = Math.max(0f, Math.min(Math.min(rx, ry), Math.min((r - l) * 0.5f, (b - t) * 0.5f)));
        if (rad < 1.5f) { drawRect(l, t, r, b, p); return; }
        int color = p.getColor();
        int x0 = Math.round(l + mTx), y0 = Math.round(t + mTy);
        int x1 = Math.round(r + mTx), y1 = Math.round(b + mTy);
        int ir = Math.round(rad);
        int r2 = ir * ir;
        int cx0 = Math.max(Math.max(0, mClipL), x0);
        int cy0 = Math.max(Math.max(0, mClipT), y0);
        int cx1 = Math.min(Math.min(mW, mClipR), x1);
        int cy1 = Math.min(Math.min(mH, mClipB), y1);
        boolean stroke = p.getStyle() == Paint.Style.STROKE;
        int sw = Math.max(1, Math.round(p.getStrokeWidth()));
        int innerR2 = Math.max(0, (ir - sw) * (ir - sw));
        for (int y = cy0; y < cy1; y++) {
            int dy = 0;
            if (y < y0 + ir) dy = (y0 + ir) - y;
            else if (y >= y1 - ir) dy = y - (y1 - ir - 1);
            int row = y * mW;
            for (int x = cx0; x < cx1; x++) {
                int dx = 0;
                if (x < x0 + ir) dx = (x0 + ir) - x;
                else if (x >= x1 - ir) dx = x - (x1 - ir - 1);
                if (dx > 0 && dy > 0) {
                    int d2 = dx * dx + dy * dy;
                    if (d2 > r2) continue;
                    if (stroke && d2 < innerR2) continue;
                } else if (stroke) {
                    if (x >= x0 + sw && x < x1 - sw && y >= y0 + sw && y < y1 - sw) continue;
                }
                mPixels[row + x] = AfwFont.blend(mPixels[row + x], color);
            }
        }
    }

    public void drawCircle(float cx, float cy, float radius, Paint p) {
        if (mPixels == null || p == null || radius <= 0f) return;
        int color = p.getColor();
        float fx = cx + mTx, fy = cy + mTy;
        int x0 = Math.max(Math.max(0, mClipL), (int) Math.floor(fx - radius));
        int y0 = Math.max(Math.max(0, mClipT), (int) Math.floor(fy - radius));
        int x1 = Math.min(Math.min(mW, mClipR), (int) Math.ceil(fx + radius) + 1);
        int y1 = Math.min(Math.min(mH, mClipB), (int) Math.ceil(fy + radius) + 1);
        float r2 = radius * radius;
        float ir = Math.max(0f, radius - p.getStrokeWidth());
        float ir2 = ir * ir;
        boolean stroke = p.getStyle() == Paint.Style.STROKE;
        for (int y = y0; y < y1; y++) {
            float dy = y - fy;
            int row = y * mW;
            for (int x = x0; x < x1; x++) {
                float dx = x - fx;
                float d2 = dx * dx + dy * dy;
                if (d2 <= r2 && (!stroke || d2 >= ir2)) {
                    mPixels[row + x] = AfwFont.blend(mPixels[row + x], color);
                }
            }
        }
    }

    public void drawLine(float x0, float y0, float x1, float y1, Paint p) {
        if (mPixels == null || p == null) return;
        int color = p.getColor();
        int sw = Math.max(1, Math.round(p.getStrokeWidth()));
        int half = sw / 2;
        float sx = x0 + mTx, sy = y0 + mTy, ex = x1 + mTx, ey = y1 + mTy;
        float dx = ex - sx, dy = ey - sy;
        int steps = Math.max(1, (int) Math.ceil(Math.max(Math.abs(dx), Math.abs(dy))));
        for (int i = 0; i <= steps; i++) {
            int px = Math.round(sx + dx * i / steps);
            int py = Math.round(sy + dy * i / steps);
            if (sw == 1) {
                plot(px, py, color);
            } else {
                for (int oy = -half; oy <= half; oy++)
                    for (int ox = -half; ox <= half; ox++)
                        plot(px + ox, py + oy, color);
            }
        }
    }

    public void drawPath(Path path, Paint p) {
        if (path == null || p == null) return;
        float cx = 0f, cy = 0f, sx = 0f, sy = 0f;
        boolean has = false;
        for (int i = 0; i < path.mCmds.size(); i++) {
            int cmd = path.mCmds.get(i)[0];
            float[] pt = path.mPts.get(i);
            if (cmd == Path.CMD_MOVE) {
                cx = sx = pt[0]; cy = sy = pt[1]; has = true;
            } else if (cmd == Path.CMD_LINE && has) {
                drawLine(cx, cy, pt[0], pt[1], p);
                cx = pt[0]; cy = pt[1];
            } else if (cmd == Path.CMD_CLOSE && has) {
                drawLine(cx, cy, sx, sy, p);
                cx = sx; cy = sy;
            }
        }
    }

    public void drawText(String text, float x, float y, Paint p) {
        if (mPixels == null || text == null || text.isEmpty() || p == null) return;
        float dx = x + mTx;
        if (p.getTextAlign() == Paint.Align.CENTER) dx -= p.measureText(text) * 0.5f;
        else if (p.getTextAlign() == Paint.Align.RIGHT) dx -= p.measureText(text);
        boolean bold = p.getTypeface() != null && p.getTypeface().isBold();
        try {
            if (com.afw.AfwHost.drawTextTtf(mPixels, mW, mH, mClipL, mClipT, mClipR, mClipB,
                                            text, dx, y + mTy, p.getTextSize(), p.getColor(), bold) == 0) {
                return;
            }
        } catch (Throwable ignored) {}
        AfwFont.drawText(mPixels, mW, mH, mClipL, mClipT, mClipR, mClipB,
                         text, dx, y + mTy, p.getTextSize(), p.getColor(), bold);
    }

    public void drawBitmap(Bitmap bmp, float left, float top, Paint p) {
        if (mPixels == null || bmp == null) return;
        int[] src = bmp.getPixelsArray();
        int bw = bmp.getWidth(), bh = bmp.getHeight();
        int ox = Math.round(left + mTx), oy = Math.round(top + mTy);
        for (int y = 0; y < bh; y++) {
            int dy = oy + y;
            if (dy < mClipT || dy >= mClipB || dy < 0 || dy >= mH) continue;
            int drow = dy * mW, srow = y * bw;
            for (int x = 0; x < bw; x++) {
                int dx = ox + x;
                if (dx < mClipL || dx >= mClipR || dx < 0 || dx >= mW) continue;
                mPixels[drow + dx] = AfwFont.blend(mPixels[drow + dx], src[srow + x]);
            }
        }
    }
}
