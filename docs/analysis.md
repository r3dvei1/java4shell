# Root cause analysis — CVE-2026-114938

## 1. Where the defect lives

`src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`, in `generate_base64_decodeBlock()`.
The stub backs the intrinsic `java.util.Base64$Decoder.decodeBlock(byte[],int,int,byte[],int,boolean,boolean)`
(`@IntrinsicCandidate`). It is generated only when the CPU reports `avx512vbmi` and
`avx512bw`; the fast path is entered per call when `length > 128` and `isMIME == 0`.

Structure of the stub:

```
cmpl(length, 128)      ; <=126 bytes -> L_bruteForce (scalar 4-char loop)
cmpl(isMIME, 0)        ; MIME -> L_bruteForce
...
L_process256 / L_process64 loop   ; consumes 256- and 64-byte blocks
L_finalBit                        ; 1..63 bytes left
```

## 2. The arithmetic

At `L_finalBit` (pre-fix, JDK 17.0.21):

```c
__ movq(rax, -1);
__ bzhiq(rax, rax, length);            // input mask: low `length` bits
__ movl(output_size, length);
__ shrl(output_size, 2);               // length / 4
__ lea(output_size, Address(output_size, output_size, Address::times_2, 0));  // *3
...
__ cmpb(Address(source, length, Address::times_1, -1), '=');
__ jcc(Assembler::equal, L_padding);   // strip pad chars, adjust length and mask
L_donePadding:
__ kmovql(input_mask, rax);
__ movq(output_mask, -1);
__ bzhiq(output_mask, output_mask, output_size);   // mask of valid destination bytes
...
__ evmovdqub(dest, output_mask, tmp, AVX_512bit);  // vector store
```

With a **padded tail of 1..3 characters**:

| tail | `output_size = (len/4)*3` | after `L_padding` | `bzhiq(-1, output_size)` | effect |
|---|---|---|---|---|
| `==` (len 2) | 0 | -2 | index 254 -> no zeroing -> all ones | full 64-byte store |
| `A==` (len 3) | 0 | -1 | index 255 -> all ones | full 64-byte store |
| `AA==` (len 4) | 3 | 1 | 1 valid byte | correct |
| `AAAA` (len 4) | 3 | 3 | 3 valid bytes | correct |

So the mask loses its bound exactly when the tail is shorter than one 4-char atom,
and the store writes one full 64-byte vector at `dest + output_size`, i.e. up to 62
bytes past the end of the destination array that `Base64.decode()` allocated.

## 3. Why it is silent

`Base64.Decoder.decode0()` calls the block decoder first and validates the framing
afterwards. With an input length that is not a multiple of 4 the call still happens
(`sp < sl - 4`), the vector store executes, and only then does Java throw
`IllegalArgumentException: Input byte array has wrong 4-byte ending unit`.
The caller sees an exception and a log line, not a crash.

This is consistent with:

* CWE-122 (heap-based buffer overflow) as recorded by CISA ADP,
* CVSS `AC:H` — the overwrite is real but turning it into control requires heap shaping
  and a neighbouring object worth corrupting,
* "difficult to exploit" wording in the CVE description.

## 4. The upstream fix

`8393212: Base64 optimization improvements` (17u `8ea73158af`, backport of mainline
`e56f69c7`):

```diff
@@ L_finalBit @@
       // Now have 1 to 63 bytes left to decode
+
+      // A padded Base64 tail shorter than one complete block is handled by Java.
+      __ cmpl(length, 4);
+      __ jcc(Assembler::less, L_bruteForce);
```

Four instructions: bail out to the scalar loop before the vector tail path can run
with `length < 4`. After that the invalid framing is rejected by Java alone and no
store happens.

## 5. Trigger conditions (all must hold)

1. CPU: `avx512vbmi` + `avx512bw` (Intel Ice Lake 2019+, Sapphire Rapids; AMD Zen 4+).
   Skylake-SP / Cascade Lake have AVX-512 but **no VBMI** → stub not generated.
2. Hypervisor/container exposes those CPUID bits (many clouds mask AVX-512).
3. JVM: `UseAVX=3` (default when supported) and `UseBASE64Intrinsics=true` (default).
4. A single decode call with `length > 128` bytes, `isMIME == false`, and a padded tail
   of 1..3 characters — e.g. 130 bytes ending in `==`, or 131 ending in `A==`.
5. Attacker-controlled data reaching that call (web service, protocol field, token
   parser, attachment decoder ...).

## 6. Exploitability ceiling

The primitive is a bounded 64-byte write past a `byte[]` body, on a heap the attacker
only partially controls. Reaching control-flow hijack requires

* arranging a target object (array header, `klass` pointer, length field) immediately
  after the destination array, and
* surviving the subsequent `IllegalArgumentException` path without tripping GC.

We have not demonstrated that. Treat this repository as a reproduction and inventory
kit, not as a working exploit.
