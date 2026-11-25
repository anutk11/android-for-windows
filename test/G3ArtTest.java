import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class G3ArtTest {
    public static native int nativeCompute(int a, int b);

    public static int javaHelper(int x) {
        return x * 7 + 3;
    }

    private static int syncCounter = 0;
    private static final Object syncLock = new Object();

    public static String runAll() {
        /* 1. Collections & StringBuilder */
        ArrayList<Integer> list = new ArrayList<Integer>();
        for (int i = 1; i <= 5; i++) list.add(i * 10);
        HashMap<String, Integer> map = new HashMap<String, Integer>();
        map.put("sum", list.get(0) + list.get(4)); /* 10 + 50 = 60 */
        if (map.get("sum") != 60) return "FAIL_COLLECTIONS";

        /* 2. Java exception handling (ArithmeticException, NullPointerException, AIOOBE) */
        boolean caughtArith = false;
        try {
            int z = 0;
            int boom = 42 / z;
            if (boom == 0) return "FAIL_NO_ARITH";
        } catch (ArithmeticException e) {
            caughtArith = true;
        }
        if (!caughtArith) return "FAIL_ARITH";

        boolean caughtNpe = false;
        try {
            String s = null;
            if (s.length() > 0) return "FAIL_NO_NPE";
        } catch (NullPointerException e) {
            caughtNpe = true;
        }
        if (!caughtNpe) return "FAIL_NPE";

        boolean caughtBounds = false;
        try {
            int[] arr = new int[3];
            if (arr[5] == 0) return "FAIL_NO_AIOOBE";
        } catch (ArrayIndexOutOfBoundsException e) {
            caughtBounds = true;
        }
        if (!caughtBounds) return "FAIL_AIOOBE";

        /* 3. Multi-threaded java.lang.Thread + synchronized + AtomicInteger */
        final AtomicInteger atomicSum = new AtomicInteger(0);
        syncCounter = 0;
        Thread[] workers = new Thread[4];
        for (int t = 0; t < workers.length; t++) {
            workers[t] = new Thread(new Runnable() {
                @Override
                public void run() {
                    for (int k = 0; k < 250; k++) {
                        atomicSum.incrementAndGet();
                        synchronized (syncLock) {
                            syncCounter++;
                        }
                    }
                }
            }, "g3-worker-" + t);
            workers[t].start();
        }
        for (int t = 0; t < workers.length; t++) {
            try {
                workers[t].join();
            } catch (InterruptedException e) {
                return "FAIL_JOIN";
            }
        }
        if (atomicSum.get() != 1000 || syncCounter != 1000) {
            return "FAIL_THREADS:" + atomicSum.get() + ":" + syncCounter;
        }

        /* 4. Crypto via real BoringSSL libcrypto.so (SHA-256 of "abc") */
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest("abc".getBytes("UTF-8"));
            if (dig.length != 32 || (dig[0] & 0xff) != 0xba || (dig[1] & 0xff) != 0x78) {
                return "FAIL_SHA256";
            }
        } catch (Exception e) {
            return "FAIL_CRYPTO:" + e.getClass().getSimpleName();
        }

        /* 5. Heap allocation pressure + explicit GC */
        long gcSum = 0;
        for (int i = 0; i < 200; i++) {
            byte[] b = new byte[4096];
            b[0] = (byte) (i & 0x7f);
            gcSum += b[0];
        }
        System.gc();
        if (gcSum == 0) return "FAIL_GC";

        /* 6. Bidirectional JNI callback into C++ -> Java javaHelper(6) */
        int jniVal = nativeCompute(10, 20);
        if (jniVal != 75) return "FAIL_JNI:" + jniVal;

        StringBuilder sb = new StringBuilder();
        sb.append("G3_ART_OK:").append(jniVal);
        return sb.toString();
    }
}
