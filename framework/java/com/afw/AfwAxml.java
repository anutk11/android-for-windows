package com.afw;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure-Java binary Android AXML (AndroidManifest.xml / res/layout/*.xml) and
 * resources.arsc parser. Supports both UTF-8 and UTF-16 string pools.
 */
public final class AfwAxml {
    public static final int TYPE_NULL        = 0x00;
    public static final int TYPE_REFERENCE   = 0x01;
    public static final int TYPE_STRING      = 0x03;
    public static final int TYPE_FLOAT       = 0x04;
    public static final int TYPE_DIMENSION   = 0x05;
    public static final int TYPE_INT_DEC     = 0x10;
    public static final int TYPE_INT_HEX     = 0x11;
    public static final int TYPE_INT_BOOLEAN = 0x12;

    public static final class Attr {
        public final String name;
        public final int resourceId;
        public final int valueType;
        public final int valueData;
        public final String stringValue;

        public Attr(String name, int resourceId, int valueType, int valueData, String stringValue) {
            this.name = name;
            this.resourceId = resourceId;
            this.valueType = valueType;
            this.valueData = valueData;
            this.stringValue = stringValue;
        }
    }

    public static final class Node {
        public final String tag;
        public final List<Attr> attrs = new ArrayList<>();
        public final List<Node> children = new ArrayList<>();

        public Node(String tag) { this.tag = tag; }

        public String attrString(String name) {
            for (Attr a : attrs) {
                if (name.equals(a.name)) return a.stringValue;
            }
            return null;
        }

        public int attrInt(String name, int def) {
            for (Attr a : attrs) {
                if (name.equals(a.name)) return a.valueData;
            }
            return def;
        }

        public Attr attr(String name) {
            for (Attr a : attrs) {
                if (name.equals(a.name)) return a;
            }
            return null;
        }
    }

    public static final class ManifestInfo {
        public String packageName = "com.afw.app";
        public String appLabel = "Android App";
        public int appLabelResId = 0;
        public String applicationClass = null;
        public String mainActivity = null;
        public int versionCode = 1;
        public String versionName = "1.0";
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] b, int off) {
        return (b[off] & 0xFF)
             | ((b[off + 1] & 0xFF) << 8)
             | ((b[off + 2] & 0xFF) << 16)
             | ((b[off + 3] & 0xFF) << 24);
    }

    public static String[] parseStringPool(byte[] data, int chunkStart) {
        int headerSize = u16(data, chunkStart + 2);
        int stringCount = u32(data, chunkStart + 8);
        int flags = u32(data, chunkStart + 16);
        int stringsStart = u32(data, chunkStart + 20);
        boolean isUtf8 = (flags & (1 << 8)) != 0;
        String[] out = new String[Math.max(0, stringCount)];
        int offsetsBase = chunkStart + headerSize;
        int poolBase = chunkStart + stringsStart;
        for (int i = 0; i < stringCount; i++) {
            int rel = u32(data, offsetsBase + i * 4);
            int p = poolBase + rel;
            if (p < 0 || p >= data.length) { out[i] = ""; continue; }
            if (isUtf8) {
                // UTF-16 char len (1 or 2 bytes)
                int u16len = data[p++] & 0xFF;
                if ((u16len & 0x80) != 0 && p < data.length) p++;
                // UTF-8 byte len (1 or 2 bytes)
                int byteLen = data[p++] & 0xFF;
                if ((byteLen & 0x80) != 0 && p < data.length) {
                    byteLen = ((byteLen & 0x7F) << 8) | (data[p++] & 0xFF);
                }
                if (p + byteLen > data.length) byteLen = Math.max(0, data.length - p);
                out[i] = new String(data, p, byteLen, StandardCharsets.UTF_8);
            } else {
                int len = u16(data, p);
                p += 2;
                if ((len & 0x8000) != 0 && p + 2 <= data.length) {
                    len = ((len & 0x7FFF) << 16) | u16(data, p);
                    p += 2;
                }
                int bytes = len * 2;
                if (p + bytes > data.length) bytes = Math.max(0, data.length - p);
                out[i] = new String(data, p, bytes, StandardCharsets.UTF_16LE);
            }
        }
        return out;
    }

    public static Node parseXml(byte[] data) {
        if (data == null || data.length < 8) return null;
        int rootType = u16(data, 0);
        if (rootType != 0x0003) return null; // RES_XML_TYPE
        int pos = u16(data, 2);
        String[] strings = new String[0];
        int[] resIds = new int[0];
        List<Node> stack = new ArrayList<>();
        Node root = null;

        while (pos + 8 <= data.length) {
            int type = u16(data, pos);
            int hdrSize = u16(data, pos + 2);
            int chunkSize = u32(data, pos + 4);
            if (chunkSize < 8 || pos + chunkSize > data.length) break;

            if (type == 0x0001) { // RES_STRING_POOL_TYPE
                strings = parseStringPool(data, pos);
            } else if (type == 0x0180) { // RES_XML_RESOURCE_MAP_TYPE
                int count = (chunkSize - hdrSize) / 4;
                resIds = new int[Math.max(0, count)];
                for (int i = 0; i < count; i++) resIds[i] = u32(data, pos + hdrSize + i * 4);
            } else if (type == 0x0102) { // RES_XML_START_ELEMENT_TYPE
                int ext = pos + hdrSize;
                int nameIdx = u32(data, ext + 4);
                int attrStart = u16(data, ext + 8);
                int attrSize = u16(data, ext + 10);
                int attrCount = u16(data, ext + 12);
                String tag = (nameIdx >= 0 && nameIdx < strings.length) ? strings[nameIdx] : "";
                Node node = new Node(tag);
                int aOff = ext + attrStart;
                for (int i = 0; i < attrCount; i++) {
                    int p = aOff + i * attrSize;
                    if (p + 20 > pos + chunkSize) break;
                    int aNameIdx = u32(data, p + 4);
                    int aRawIdx = u32(data, p + 8);
                    int vType = data[p + 15] & 0xFF;
                    int vData = u32(data, p + 16);
                    String aName = (aNameIdx >= 0 && aNameIdx < strings.length) ? strings[aNameIdx] : "";
                    int resId = (aNameIdx >= 0 && aNameIdx < resIds.length) ? resIds[aNameIdx] : 0;
                    String sVal = null;
                    if (aRawIdx >= 0 && aRawIdx < strings.length) sVal = strings[aRawIdx];
                    else if (vType == TYPE_STRING && vData >= 0 && vData < strings.length) sVal = strings[vData];
                    node.attrs.add(new Attr(aName, resId, vType, vData, sVal));
                }
                if (!stack.isEmpty()) stack.get(stack.size() - 1).children.add(node);
                else root = node;
                stack.add(node);
            } else if (type == 0x0103) { // RES_XML_END_ELEMENT_TYPE
                if (!stack.isEmpty()) stack.remove(stack.size() - 1);
            }
            pos += chunkSize;
        }
        return root;
    }

    /** Parse resources.arsc into a map of resourceId -> string value (for @string/*, layouts, etc.). */
    public static Map<Integer, String> parseResourcesArsc(byte[] data) {
        Map<Integer, String> map = new HashMap<>();
        if (data == null || data.length < 12) return map;
        if (u16(data, 0) != 0x0002) return map; // RES_TABLE_TYPE
        int pos = u16(data, 2);
        String[] globalStrings = new String[0];

        while (pos + 8 <= data.length) {
            int type = u16(data, pos);
            int hdrSize = u16(data, pos + 2);
            int chunkSize = u32(data, pos + 4);
            if (chunkSize < 8 || pos + chunkSize > data.length) break;

            if (type == 0x0001) { // global string pool
                globalStrings = parseStringPool(data, pos);
            } else if (type == 0x0200) { // RES_TABLE_PACKAGE_TYPE
                int pkgId = u32(data, pos + 8);
                int sub = pos + hdrSize;
                int pkgEnd = pos + chunkSize;
                while (sub + 8 <= pkgEnd) {
                    int st = u16(data, sub);
                    int sh = u16(data, sub + 2);
                    int ss = u32(data, sub + 4);
                    if (ss < 8 || sub + ss > pkgEnd) break;
                    if (st == 0x0201) { // RES_TABLE_TYPE_TYPE
                        int typeId = data[sub + 8] & 0xFF;
                        int entryCount = u32(data, sub + 12);
                        int entriesStart = u32(data, sub + 16);
                        int offsetsBase = sub + sh;
                        int entriesBase = sub + entriesStart;
                        for (int i = 0; i < entryCount; i++) {
                            if (offsetsBase + i * 4 + 4 > sub + ss) break;
                            int off = u32(data, offsetsBase + i * 4);
                            if (off == -1) continue;
                            int ep = entriesBase + off;
                            if (ep + 16 > sub + ss) continue;
                            int eSize = u16(data, ep);
                            int eFlags = u16(data, ep + 2);
                            if ((eFlags & 1) == 0 && ep + eSize + 8 <= sub + ss) { // non-complex
                                int valType = data[ep + eSize + 3] & 0xFF;
                                int valData = u32(data, ep + eSize + 4);
                                int resId = (pkgId << 24) | (typeId << 16) | (i & 0xFFFF);
                                if (valType == TYPE_STRING && valData >= 0 && valData < globalStrings.length) {
                                    map.putIfAbsent(resId, globalStrings[valData]);
                                }
                            }
                        }
                    }
                    sub += ss;
                }
            }
            pos += chunkSize;
        }
        return map;
    }

    private static String resolveClassName(String pkg, String cls) {
        if (cls == null || cls.isEmpty()) return null;
        if (cls.startsWith(".")) return pkg + cls;
        if (cls.indexOf('.') < 0) return pkg + "." + cls;
        return cls;
    }

    public static ManifestInfo parseManifest(byte[] axmlBytes, Map<Integer, String> resStrings) {
        ManifestInfo info = new ManifestInfo();
        Node root = parseXml(axmlBytes);
        if (root == null) return info;
        String pkg = root.attrString("package");
        if (pkg != null && !pkg.isEmpty()) info.packageName = pkg;
        info.versionCode = root.attrInt("versionCode", 1);
        String vn = root.attrString("versionName");
        if (vn != null && !vn.isEmpty()) info.versionName = vn;

        String firstActivity = null;
        for (Node child : root.children) {
            if (!"application".equals(child.tag)) continue;
            Attr lbl = child.attr("label");
            if (lbl != null) {
                if (lbl.stringValue != null && !lbl.stringValue.isEmpty()) {
                    info.appLabel = lbl.stringValue;
                } else if (lbl.valueType == TYPE_REFERENCE) {
                    info.appLabelResId = lbl.valueData;
                    if (resStrings != null && resStrings.containsKey(lbl.valueData)) {
                        info.appLabel = resStrings.get(lbl.valueData);
                    }
                }
            }
            String appCls = child.attrString("name");
            if (appCls != null && !appCls.isEmpty()) {
                info.applicationClass = resolveClassName(info.packageName, appCls);
            }
            for (Node comp : child.children) {
                if (!"activity".equals(comp.tag) && !"activity-alias".equals(comp.tag)) continue;
                String name = comp.attrString("activity-alias".equals(comp.tag) ? "targetActivity" : "name");
                String full = resolveClassName(info.packageName, name);
                if (firstActivity == null && full != null) firstActivity = full;
                boolean hasMain = false, hasLauncher = false;
                for (Node f : comp.children) {
                    if (!"intent-filter".equals(f.tag)) continue;
                    for (Node item : f.children) {
                        String n = item.attrString("name");
                        if ("action".equals(item.tag) && "android.intent.action.MAIN".equals(n)) hasMain = true;
                        if ("category".equals(item.tag) && "android.intent.category.LAUNCHER".equals(n)) hasLauncher = true;
                    }
                }
                if (hasMain && hasLauncher && full != null) {
                    info.mainActivity = full;
                    break;
                }
            }
        }
        if (info.mainActivity == null) info.mainActivity = firstActivity;
        return info;
    }
}
