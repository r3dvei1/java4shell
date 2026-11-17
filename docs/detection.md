# Detection, inventory and mitigation

## 1. Inventory (the only reliable gate)

```bash
bash tools/gate.sh
```

It prints, for every JDK on the host:

* `avx512vbmi` / `avx512bw` presence (hardware gate — absent means the stub is never generated)
* `UseAVX` and `UseBASE64Intrinsics` (JVM gate)
* a merged verdict: `Base64/AVX-512 path: ACTIVE | inactive`
* the runtime version, to compare against the affected builds

Vendored runtimes matter: application servers frequently bundle their own JDK
(`/usr/share/opensearch/jdk`, Tomcat distributions, IDE runtimes, container images).
`gate.sh` walks every `*/bin/java` it can find.

## 2. Where to look for reachable decoders

Anywhere attacker data is Base64-decoded in a single call larger than 128 bytes and the
non-MIME decoder is used:

* `Authorization: Basic ...` headers (usually short — under the 128-byte gate)
* JWT / signed-token segments, SAML assertions, cookie blobs
* bulk/attachment/import endpoints that accept encoded payloads
* message queues and RPC fields carrying encoded binaries
* protocols implemented on `Base64.getDecoder()` inside the service

Short values (<128 bytes) never enter the vector path, so typical credential headers are
not enough by themselves.

## 3. Mitigation before patching

| Control | Effect | Cost |
|---|---|---|
| Upgrade to a fixed build (`17.0.21.1+`, `21.0.13.0.4+`, ...) | removes the defect | requires restart |
| `-XX:-UseBASE64Intrinsics` | disables the intrinsic entirely; decode falls back to Java | measurable Base64 throughput loss |
| `-XX:UseAVX=2` | prevents the AVX-512 stub from being generated | affects all AVX-512 code paths |
| Remove/limit AVX-512 exposure in the VM (CPUID masking) | hardware gate closes | platform dependent |
| Input policy: reject non-multiple-of-4 Base64 at the edge | removes the trigger shape | may break lenient clients |

On hosts without `avx512vbmi` **none of the JVM flags are needed** — the stub is never
built, so the mitigations only cost performance.

## 4. Telemetry that would show an attempt

* `IllegalArgumentException: Input byte array has wrong 4-byte ending unit` spikes in
  application logs (the trigger needs an invalid tail; the fix path throws the same
  exception, so correlate with unpatched build IDs)
* JVM crashes with `SIGSEGV` in a `StubRoutines::_base64_decodeBlock` frame, or GC
  failures reporting impossible object headers shortly after such exceptions
* unusual request bodies that are Base64-like, longer than 128 bytes, and not a multiple
  of 4 in length

## 5. Verification after patching

```bash
bash tools/gate.sh          # version moves past the affected build
java src/Base64Trigger.java 100000
```

The driver must still run without a crash (this bug never crashes reliably), so the real
proof of remediation is the build number plus the upstream fix in the source of that
build (`8ea73158af` in 17u).
