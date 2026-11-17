# Measured results

Environment: x86-64 host exposing `avx512vbmi`. JDKs ran in containers
(`eclipse-temurin:17.0.6_10`, `17.0.13_11`, `17.0.21_9`, `21.0.13_9`) plus Ubuntu 24.04
with `openjdk-21-jdk-headless` (21.0.13.0.3+1-1~24.04.1).
All runs are local and non-destructive.

## 1. Gate

```
cpu flags : avx512f avx512bw avx512vl avx512vbmi avx512_vbmi2
java      : UseAVX = 3, UseBASE64Intrinsics = true
verdict   : Base64/AVX-512 path ACTIVE
```

A server without `avx512vbmi` (measured: `avx512f` + `avx512bw` only) reports
`path inactive` and cannot trigger the code at all.

## 2. Reachability driver — `src/Base64Trigger.java`

Inputs: lengths 129/130/131/193/194/195, all `/`, driven 60,000 times.

```
jdk=17.0.21
DONE iters=60000 decoded=40000 rejected=20000 unexpected=0
```

* `rejected` = the expected `IllegalArgumentException` on invalid framing
* **no crash, no unexpected exception** — consistent with a silent 64-byte overwrite,
  and with the `AC:H` / "difficult to exploit" rating

The same run with `-XX:-UseBASE64Intrinsics` produces the same counters; the difference
is which code path executes, not what the application observes.

## 3. Instrumentation attempt — `research/Base64OobProbe.java` (INCONCLUSIVE)

Calling `Base64$Decoder.decodeBlock` through reflection with our own destination array
and reading the 64 bytes after it with `sun.misc.Unsafe`:

```
after  : 69 a6 9a 69 a6 9a ...
before : a6 9a 69 a6 9a 69 ...
changed_bytes=58 0xff_bytes=0
```

The region changed, but **not with the decoded pattern**, and `Method.invoke` itself
allocates (argument array, boxing) in the same TLAB, so allocation noise explains the
change. This probe is therefore **not evidence**. A deterministic proof needs one of:

* a fixed build (`17.0.21.1+`) to diff behaviour against (no public Temurin image yet), or
* heap instrumentation that pins the destination array next to a known sentinel object.

The file is kept for transparency, not as a claim.

## 4. OOB write → JVM crash reproduced (real AVX-512 host)

Host: PVE VM `java4shell`, Ryzen 7 PRO 8845HS (`avx512vbmi` present), Ubuntu 24.04.4,
`openjdk 21.0.13.0.3+1-1~24.04.1-Ubuntu` (the published affected build).

Probe `research/Base64OobProbe2.java` calls `Base64$Decoder.decodeBlock` across
reflection with **all arguments pre-allocated** (no boxing/no args array per call), so the
only allocation between the call and the post-call memory read is the destination array.

| run | JVM flags | result |
|---|---|---|
| 1 | default (intrinsic on) | **JVM crash** — `hs_err_pid1431.log` |
| 2 | default | **JVM crash** — `hs_err_pid1647.log` |
| 3 | default | **JVM crash** — `hs_err_pid1674.log` |
| 4 | default | no write observed (heap layout did not place a live object behind dst) |
| control | `-XX:-UseBASE64Intrinsics` | `changed=0 ff=0` — no write, no crash |

Crash signature (`hs_err`):

```
#  SIGSEGV (0xb) at pc=0x000072621bd53020, pid=1431, tid=1433
# Problematic frame:
# j  sun.invoke.util.ValueConversions.unboxInteger(Ljava/lang/Object;Z)I+1  java.base@21.0.13.0.3
siginfo: si_signo: 11 (SIGSEGV), si_code: 1 (SEGV_MAPERR), si_addr: 0x0000726251a669da
```

The fault is not at the store; it is the JVM dereferencing a **corrupted object** while
unboxing the reflected return value right after the decode call. That is the expected
downstream effect of a 64-byte overwrite landing on the object behind the destination
array, and it disappears when the intrinsic is disabled.

Reproduction rate on this host: **3 crashes / 4 attempts (75 %)** — heap-layout dependent,
which is exactly what `AC:H` describes.

## 5. What is proven vs not proven

| Claim | Status |
|---|---|
| Defect location and the exact 4-line fix | **proven** (upstream commit, source walk-through) |
| Gate conditions (`avx512vbmi` + `avx512bw`, `length > 128`, `isMIME == 0`) | **proven** (source + runtime gate) |
| The vulnerable path is reachable from Java `Base64.decode` on a real host | **proven** |
| Memory corruption past the destination array | **observed** — reproducible JVM crash in the reflection caller, 0 when the intrinsic is off |
| Byte-level capture of the 64-byte store itself | **not captured** (the JVM dies in the caller first in crashing runs) |
| Control-flow hijack / RCE chain | **not attempted, not claimed** |
| Hosts without `avx512vbmi` are unaffected | **proven by construction** (stub not generated) |


## 6. Remote trigger run (same vulnerable build)

Service: `src/DecodeServer.java` (decodes `?b=` with `Base64.getDecoder()`), JDK
`21.0.13.0.3` on the AVX-512 host. Client: `src/RemoteAttack.java` (`--target`).

| shape | attempts | result |
|---|---|---|
| control (short valid) | 200 | ok=200, no errors |
| padded 130B (`==` tail) | 30 000 | ok=30000, service healthy |
| badtail 130B (len%4!=0) | 60 000 + 60 000 | ok=120000, service healthy, no hs_err |

So the remote trigger reaches the decoder (`badtail` returns `200 len=94`) but the
64-byte overwrite lands in thread-local allocation slack and no crash surfaces at this
volume. The local probe (where the corrupted object is provably adjacent) crashes 3/4.

**Conclusion for remote exploitation:** the trigger is remotely reachable; converting the
overwrite into control flow requires in-process heap grooming that this kit does not
implement. No RCE chain is claimed.

## 7. Escalation step 1 - live-object field corruption (deterministic)

`research/Groom2.java`: allocate `dst` (96 B) then `victim` (96 B) back to back, call
`decodeBlock` through a **MethodHandle with an exact signature** (no boxed return value,
so the JVM does not die in `unboxInteger` before we can measure). Read victim's header
words through `sun.misc.Unsafe`.

| run | intrinsic | ret | victim.length | victim.klass |
|---|---|---|---|---|
| 0-5 | on | 94 | 96 -> **1771742825** | 0x2318 -> **0x9aa6699a** |
| 0-2 | off (control) | 96 | 96 -> 96 | unchanged |

6/6 deterministic with the intrinsic, 0/3 with it disabled. The 64-byte vector store lands
in the victim's header: **length field and klass pointer are overwritten with bytes derived
from the decoded input**.

This is the first real escalation primitive for this bug:

* corrupting only the 4-byte length gives an array whose `length` is ~1.7e9 - a plain
  Java OOB read/write window of up to 2 GiB, no Unsafe required;
* corrupting the klass word gives type confusion, but any GC or type check on the victim
  will fault, so a chain must hit the length field alone (tune the store offset with a
  padding array between dst and victim).

Not included: the tuned offset + OOB window construction + control-flow step. Those are
the remaining pieces between this primitive and code execution.
