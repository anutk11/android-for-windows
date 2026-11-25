package android.view;

import android.content.Context;
import android.graphics.Color;
import android.widget.*;
import com.afw.AfwAxml;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/** Inflates binary AXML layout files (res/layout/*.xml) from the APK into live View trees. */
public class LayoutInflater {
    private final Context mContext;

    public LayoutInflater(Context ctx) { mContext = ctx; }

    public static LayoutInflater from(Context ctx) { return new LayoutInflater(ctx); }

    public View inflate(int resource, ViewGroup root) {
        return inflate(resource, root, root != null);
    }

    public View inflate(int resource, ViewGroup root, boolean attachToRoot) {
        try {
            String path = mContext.getResources().getResourceEntryPath(resource);
            if (path == null) return new FrameLayout(mContext);
            byte[] bytes;
            try (InputStream in = mContext.getAssets().openRawPath(path);
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                bytes = out.toByteArray();
            }
            AfwAxml.Node node = AfwAxml.parseXml(bytes);
            View v = buildView(node, root);
            if (v != null && root != null && attachToRoot) root.addView(v);
            return v != null ? v : new FrameLayout(mContext);
        } catch (Throwable t) {
            return new FrameLayout(mContext);
        }
    }

    private View buildView(AfwAxml.Node node, ViewGroup parent) {
        if (node == null) return null;
        String tag = node.tag;
        View v;
        if ("LinearLayout".equals(tag)) v = new LinearLayout(mContext);
        else if ("FrameLayout".equals(tag)) v = new FrameLayout(mContext);
        else if ("ScrollView".equals(tag)) v = new ScrollView(mContext);
        else if ("Button".equals(tag)) v = new Button(mContext);
        else if ("TextView".equals(tag)) v = new TextView(mContext);
        else if ("EditText".equals(tag)) v = new EditText(mContext);
        else if ("ImageView".equals(tag)) v = new ImageView(mContext);
        else if ("SeekBar".equals(tag)) v = new SeekBar(mContext);
        else if ("ProgressBar".equals(tag)) v = new ProgressBar(mContext);
        else if ("CheckBox".equals(tag)) v = new CheckBox(mContext);
        else if ("View".equals(tag)) v = new View(mContext);
        else {
            try {
                Class<?> c = Class.forName(tag, true, com.afw.AfwLauncher.getAppClassLoader());
                v = (View) c.getConstructor(Context.class).newInstance(mContext);
            } catch (Throwable ignored) {
                v = new FrameLayout(mContext);
            }
        }

        int w = ViewGroup.LayoutParams.WRAP_CONTENT;
        int h = ViewGroup.LayoutParams.WRAP_CONTENT;
        float weight = 0f;
        for (AfwAxml.Attr a : node.attrs) {
            String n = a.name;
            if ("id".equals(n)) v.setId(a.valueData);
            else if ("layout_width".equals(n)) w = decodeDim(a, w);
            else if ("layout_height".equals(n)) h = decodeDim(a, h);
            else if ("layout_weight".equals(n)) weight = Float.intBitsToFloat(a.valueData);
            else if ("orientation".equals(n) && v instanceof LinearLayout) ((LinearLayout) v).setOrientation(a.valueData);
            else if ("background".equals(n)) {
                if (a.valueType >= 0x1C && a.valueType <= 0x1F) v.setBackgroundColor(a.valueData);
                else if (a.stringValue != null && a.stringValue.startsWith("#")) v.setBackgroundColor(Color.parseColor(a.stringValue));
            } else if ("text".equals(n) && v instanceof TextView) {
                if (a.stringValue != null) ((TextView) v).setText(a.stringValue);
                else if (a.valueType == AfwAxml.TYPE_REFERENCE) ((TextView) v).setText(mContext.getString(a.valueData));
            } else if ("textColor".equals(n) && v instanceof TextView) {
                if (a.valueType >= 0x1C && a.valueType <= 0x1F) ((TextView) v).setTextColor(a.valueData);
            } else if ("padding".equals(n)) {
                int p = decodeDim(a, 0);
                if (p > 0) v.setPadding(p, p, p, p);
            }
        }

        if (parent instanceof LinearLayout) {
            v.setLayoutParams(new LinearLayout.LayoutParams(w, h, weight));
        } else {
            v.setLayoutParams(new ViewGroup.MarginLayoutParams(w, h));
        }

        if (v instanceof ViewGroup) {
            ViewGroup vg = (ViewGroup) v;
            for (AfwAxml.Node ch : node.children) {
                View cv = buildView(ch, vg);
                if (cv != null) vg.addView(cv);
            }
        }
        return v;
    }

    private int decodeDim(AfwAxml.Attr a, int def) {
        if (a.valueType == AfwAxml.TYPE_INT_DEC || a.valueType == AfwAxml.TYPE_INT_HEX) return a.valueData;
        if (a.valueType == AfwAxml.TYPE_DIMENSION) {
            int mantissa = (a.valueData >> 8);
            int radix = (a.valueData >> 4) & 3;
            float val = mantissa;
            if (radix == 1) val /= (1 << 7);
            else if (radix == 2) val /= (1 << 15);
            else if (radix == 3) val /= (1 << 23);
            return Math.round(val);
        }
        return def;
    }
}
