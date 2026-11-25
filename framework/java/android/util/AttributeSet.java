package android.util;

public interface AttributeSet {
    int getAttributeCount();
    String getAttributeName(int index);
    String getAttributeValue(int index);
    String getAttributeValue(String namespace, String name);
    int getAttributeIntValue(String namespace, String attribute, int defaultValue);
    boolean getAttributeBooleanValue(String namespace, String attribute, boolean defaultValue);
}
