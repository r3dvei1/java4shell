/*
 * Base64OobProbe.java - INCONCLUSIVE instrumentation attempt (kept for transparency).
 *
 * WARNING: this probe does NOT prove the out-of-bounds write. Method.invoke allocates
 * its argument array and boxes primitives in the same TLAB as our destination array,
 * so the 64 bytes after dst change for reasons unrelated to the bug. See
 * docs/results.md section 3 for the measured output and why it is not evidence.
 *
 * Why it exists: the public decode() API allocates the destination internally and
 * throws on these lengths, so the reference is lost. Calling the intrinsic entry point
 * reflectively keeps the array, which is the right idea - it just needs heap
 * instrumentation (sentinel object pinned next to dst) to become conclusive.
 *
 * Requires:
 *   --add-opens java.base/java.util=ALL-UNNAMED
 *
 * Usage:
 *   java --add-opens java.base/java.util=ALL-UNNAMED Base64OobProbe.java [warmup]
 */
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Base64;

public class Base64OobDetector {

    private static final int SRC_LEN = 130;      // > 128, tail = 2
    private static final int DST_LEN = (SRC_LEN / 4) * 3;   // 96
    private static final int WATCH = 64;         // one AVX-512 vector

    public static void main(String[] args) throws Exception {
        int warmup = args.length > 0 ? Integer.parseInt(args[0]) : 200_000;

        System.out.println("jdk=" + System.getProperty("java.version"));

        Class<?> decCls = Class.forName("java.util.Base64$Decoder");
        Base64.Decoder dec = Base64.getDecoder();
        Method decodeBlock = null;
        for (Method m : decCls.getDeclaredMethods()) {
            if (!m.getName().equals("decodeBlock")) {
                continue;
            }
            Class<?>[] p = m.getParameterTypes();
            if (p.length == 7 && p[0] == byte[].class && p[3] == byte[].class) {
                decodeBlock = m;
                break;
            }
        }
        if (decodeBlock == null) {
            System.out.println("decodeBlock not found - JDK layout changed");
            return;
        }
        decodeBlock.setAccessible(true);
        System.out.println("target=" + decodeBlock);

        Field f = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        f.setAccessible(true);
        sun.misc.Unsafe u = (sun.misc.Unsafe) f.get(null);
        long base = u.arrayBaseOffset(byte[].class);

        byte[] src = new byte[SRC_LEN];
        Arrays.fill(src, (byte) '/');            // '/' decodes to 0xFF
        src[SRC_LEN - 1] = '=';
        src[SRC_LEN - 2] = '=';                  // padded 2-byte tail = the guarded case

        // ---- warm up so the intrinsic is compiled into a stub ----
        byte[] scratch = new byte[DST_LEN];
        for (int i = 0; i < warmup; i++) {
            try {
                decodeBlock.invoke(dec, src, 0, SRC_LEN, scratch, 0, false, false);
            } catch (Throwable ignored) {
                // the stub returns without throwing; Java-side fallback may throw
            }
        }
        System.out.println("warmup calls=" + warmup);

        // ---- measured call on a fresh destination ----
        byte[] dst = new byte[DST_LEN];
        byte[] before = new byte[WATCH];
        for (int i = 0; i < WATCH; i++) {
            before[i] = u.getByte(dst, base + DST_LEN + i);
        }

        int ret;
        try {
            ret = (Integer) decodeBlock.invoke(dec, src, 0, SRC_LEN, dst, 0, false, false);
            System.out.println("decodeBlock returned " + ret);
        } catch (Throwable t) {
            System.out.println("decodeBlock threw " + t.getCause());
        }

        int changed = 0;
        int ff = 0;
        System.out.print("after  : ");
        for (int i = 0; i < WATCH; i++) {
            byte b = u.getByte(dst, base + DST_LEN + i);
            if (before[i] != b) {
                changed++;
            }
            if (b == (byte) 0xFF) {
                ff++;
            }
            if (i < 32) {
                System.out.printf("%02x ", b);
            }
        }
        System.out.println();
        System.out.print("before : ");
        for (int i = 0; i < 32; i++) {
            System.out.printf("%02x ", before[i]);
        }
        System.out.println();

        System.out.println("changed_bytes=" + changed + " 0xff_bytes=" + ff
                + " (of " + WATCH + ")");
        if (changed > 0 && ff > 0) {
            System.out.println("VERDICT: OOB WRITE OBSERVED past dst[0.." + DST_LEN + ")");
        } else if (changed > 0) {
            System.out.println("VERDICT: bytes changed past dst (not 0xff) - inspect hexdump");
        } else {
            System.out.println("VERDICT: no write observed (scalar path, or dst not adjacent)");
        }
    }
}

