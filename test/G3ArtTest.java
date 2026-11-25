import java.util.ArrayList;
import java.util.HashMap;

public class G3ArtTest {
    public static native int nativeCompute(int a, int b);

    public static int javaHelper(int x) {
        return x * 7 + 3;
    }

    public static String runAll() {
        /* 1. Collections & StringBuilder */
        ArrayList<Integer> list = new ArrayList<Integer>();
        for (int i = 1; i <= 5; i++) list.add(i * 10);
        HashMap<String, Integer> map = new HashMap<String, Integer>();
        map.put("sum", list.get(0) + list.get(4)); /* 10 + 50 = 60 */
        if (map.get("sum") != 60) return "FAIL_COLLECTIONS";

        /* 2. Java exception handling (ArithmeticException) */
        boolean caughtArith = false;
        try {
            int z = 0;
            int boom = 42 / z;
            if (boom == 0) return "FAIL_NO_ARITH";
        } catch (ArithmeticException e) {
            caughtArith = true;
        }
        if (!caughtArith) return "FAIL_ARITH";

        /* 3. Bidirectional JNI callback into C++ -> Java javaHelper(6) */
        int jniVal = nativeCompute(10, 20);
        if (jniVal != 75) return "FAIL_JNI:" + jniVal;

        StringBuilder sb = new StringBuilder();
        sb.append("G3_ART_OK:").append(jniVal);
        return sb.toString();
    }
}
