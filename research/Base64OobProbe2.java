/*
 * Base64OobProbe2.java - low-allocation variant of the instrumentation probe.
 *
 * The first probe was polluted because Method.invoke allocated (args array + boxing)
 * between the call and the read of the 64 bytes after dst. Here the Object[] and all
 * boxed values are created once and reused, so the only allocation per measured call is
 * the destination array itself. If the stub writes past dst, the bytes after it change
 * with the decoded pattern and nothing else runs in between.
 *
 * Run: java --add-opens java.base/java.util=ALL-UNNAMED Base64OobProbe2.java [warmup]
 * Control: add -XX:-UseBASE64Intrinsics (scalar path, no vector store)
 */
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Base64;

public class Base64OobProbe2 {

    private static final int SRC_LEN = 130;                  // >128, tail = 2 ("==")
    private static final int DST_LEN = (SRC_LEN / 4) * 3;    // 96
    private static final int WATCH = 64;                     // one AVX-512 vector

    public static void main(String[] args) throws Exception {
        int warmup = args.length > 0 ? Integer.parseInt(args[0]) : 200_000;
        System.out.println("jdk=" + System.getProperty("java.version"));

        Class<?> decCls = Class.forName("java.util.Base64$Decoder");
        Base64.Decoder dec = Base64.getDecoder();
        Method decodeBlock = null;
        for (Method m : decCls.getDeclaredMethods()) {
            Class<?>[] p = m.getParameterTypes();
            if (m.getName().equals("decodeBlock") && p.length == 7
                    && p[0] == byte[].class && p[3] == byte[].class) {
                decodeBlock = m;
                break;
            }
        }
        if (decodeBlock == null) {
            System.out.println("decodeBlock not found");
            return;
        }
        decodeBlock.setAccessible(true);

        Field uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        sun.misc.Unsafe u = (sun.misc.Unsafe) uf.get(null);
        long base = u.arrayBaseOffset(byte[].class);

        byte[] src = new byte[SRC_LEN];
        Arrays.fill(src, (byte) '/');
        src[SRC_LEN - 1] = '=';
        src[SRC_LEN - 2] = '=';

        byte[] scratch = new byte[DST_LEN];

        // allocate everything ONCE
        Integer zero = Integer.valueOf(0);
        Integer slen = Integer.valueOf(SRC_LEN);
        Boolean no = Boolean.FALSE;
        Object[] call = new Object[]{src, zero, slen, scratch, zero, no, no};

        for (int i = 0; i < warmup; i++) {
            try {
                decodeBlock.invoke(dec, call);
            } catch (Throwable ignored) {
            }
        }
        System.out.println("warmup=" + warmup);

        byte[] dst = new byte[DST_LEN];          // the only allocation now
        byte[] before = new byte[WATCH];
        for (int i = 0; i < WATCH; i++) {
            before[i] = u.getByte(dst, base + DST_LEN + i);
        }

        call[3] = dst;
        int ret;
        try {
            ret = (Integer) decodeBlock.invoke(dec, call);
        } catch (Throwable t) {
            ret = -999;
            System.out.println("threw " + t.getCause());
        }

        int changed = 0, ff = 0;
        StringBuilder after = new StringBuilder();
        for (int i = 0; i < WATCH; i++) {
            byte b = u.getByte(dst, base + DST_LEN + i);
            if (before[i] != b) {
                changed++;
            }
            if (b == (byte) 0xFF) {
                ff++;
            }
            if (i < 32) {
                after.append(String.format("%02x ", b));
            }
        }
        System.out.println("decodeBlock returned " + ret);
        System.out.println("before : " + hex(before, 32));
        System.out.println("after  : " + after);
        System.out.println("changed=" + changed + " ff=" + ff + " of " + WATCH);
        System.out.println((changed > 0 && ff > 0)
                ? "VERDICT: OOB WRITE OBSERVED (decoded 0xff bytes past dst)"
                : (changed > 0 ? "VERDICT: bytes changed (inspect)" : "VERDICT: no write observed"));
    }

    private static String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x ", b[i]));
        }
        return sb.toString();
    }
}
