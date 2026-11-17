# nginx → Tomcat lab stack (realistic deployment) — test report

Date: 2026-11-18 UTC. Host: PVE VM `java4shell`, Ryzen 7 PRO 8845HS (Zen 4, `avx512vbmi`),
Ubuntu 24.04.5, 7 GiB, 2 vCPU, `openjdk 21.0.13.0.3+1-1~24.04.1-Ubuntu` (affected build).

## Architecture

```
client ──HTTP──> nginx 1.24.0 (port 80, proxy_pass) ──> Tomcat 10.1.55 (port 8080)
                                                          └─ dec.war / DecodeServlet
                                                             /dec/decode   Base64.decode(b)
                                                             /dec/decode2  Base64.decode(src,dst)
                                                             /dec/decode3  decode2 + retains array
                                                             /dec/selfcheck decode2 + reads neighbour header
```

Tomcat JVM: `-Xms256m -Xmx512m -XX:+UseSerialGC`.

## What was run through nginx

| phase | endpoint | requests | result |
|---|---|---|---|
| sequential | `/dec/decode` | 300 + 30 000 + 100 000 + 100 000 | all answered, no 5xx, no error |
| concurrent (8 clients × 3 rounds) | `/dec/decode` | 600 000 | all answered, service stayed up |
| sequential | `/dec/decode2` (app-owned dst) | 240 000 | all answered, service stayed up |
| sequential | `/dec/decode3` (retained neighbour) | 300 000 | all answered, service stayed up |

Total ≈ **1.44 million** crafted requests. **Zero JVM crashes, zero `hs_err`, service
healthy throughout.** `badtail` responses were `200 len=94`, i.e. the vulnerable decode
path was reached on every request.

## Why no remote crash, while the local experiment corrupts deterministically

* Local (`research/Groom2.java`): we allocate the destination array ourselves and the
  neighbouring object **before** the call, so the 64-byte store lands in a live header -
  length and klass change 6/6 with the intrinsic, 0/3 with it disabled.
* Remote: the store lands at the end of the destination array, which in a running server
  is **free TLAB space**; the object that later occupies that space writes its own header
  afterwards, erasing the evidence. Heap layout is not attacker-controllable through the
  request, so the corruption stays silent.
* With `decode(src,dst)` the application owns the destination, but the neighbour is again
  allocated after the call; retaining it (`decode3`) did not surface a fault either.

So on this class of application the remote impact we could measure is: **trigger reachable,
no observable corruption**. This matches the vendor's `AC:H` / "difficult to exploit"
rating, and is consistent with the 8.1 score rather than a wormable RCE.

## What would still be needed for remote code execution

1. a target that allocates the destination *and* a victim object before the decode call
   (rare but possible in caches/pools), **or** an allocator state where the store crosses
   into a live region;
2. a store offset tuned so only the 4-byte length field is hit (klass corruption kills the
   process before it can be used);
3. an OOB window derived from the oversized length, then a control-flow step.

None of these are demonstrated here. The repository remains an analysis and reproduction
kit, not a remote exploit.
