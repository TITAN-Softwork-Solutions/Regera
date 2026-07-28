# Security Review

Date: 2026-07-26
Host: `marrakesh` (`aegis@100.112.93.83`)
Target: Valv v2.0

## Scope

This review checks what Valv protects in a compiled consumer binary, what
remains recoverable when the binary is stripped and no PDB/debug symbols are
available, and whether runtime-bound mode omits its external key material.

The test binary is `examples/security_probe.rs`. It embeds this literal only through `chacha!`:

```text
VALV_AUDIT_TOKEN: offline-recovery-check-2026-07-26
```

The binary intentionally prints only a digest derived from the plaintext, not the plaintext itself.

## Commands Used

```bash
cargo test --workspace --all-features
cargo test --all-features --test runtime_bound_macro -- --nocapture
cargo build --release --example security_probe
cp target/release/examples/security_probe /tmp/valv-security-probe.stripped
strip --strip-all /tmp/valv-security-probe.stripped
strings -a /tmp/valv-security-probe.stripped |
  grep -E 'VALV_AUDIT_TOKEN|offline-recovery-check'

VALV_DEBUGGER_PAUSE=1 \
  r2 -q -d /tmp/valv-security-probe.stripped -e scr.color=false

# Run these commands at the radare2 prompt:
dcs clock_nanosleep
e search.in=dbg.heap
/ VALV_AUDIT_TOKEN
/ offline-recovery-check
dc
q
```

## Captured Output

Environment and stripped-file check:

```text
$ r2 -v
radare2 6.1.9 +36696 abi:123 @ linux-x86_64
birth: git.6.1.8-250-g7c4e858f42 2026-07-19__07:02:37

$ file /tmp/valv-security-probe.stripped
/tmp/valv-security-probe.stripped: ELF 64-bit LSB pie executable, x86-64,
version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, BuildID[sha1]=e44493f4d458f71265fe96fa1579193ae2036dfd,
stripped

$ strings -a /tmp/valv-security-probe.stripped |
>   grep -E 'VALV_AUDIT_TOKEN|offline-recovery-check'
$ echo $?
1
```

Relevant lines from the interactive debugger run:

```text
> dcs clock_nanosleep
Running child until syscalls:230
INFO: --> SN 0x7ef37c8eca7a syscall 230 clock_nanosleep
    (0x0 0x0 0x7ffe7cfbbcb0 0x7ef37c8eca7a)

> e search.in=dbg.heap
> / VALV_AUDIT_TOKEN
0x6471d8cc2d60 hit0_0 "AVALV_AUDIT_TOKEN: offline-recove"

> / offline-recovery-check
0x6471d8cc2d72 hit1_0
    "LV_AUDIT_TOKEN: offline-recovery-check-2026-07-26"

> dc
(1838983) Process exited with status=0x4600
```

Linux encodes a normal process exit in the high byte of the wait status.
`0x4600 >> 8` is decimal 70, which is the timing guard's configured
fail-closed exit code.

Addresses, process IDs, and build IDs vary between runs. The plaintext matches
and exit status are the relevant results.

## Result

`strings` does not recover the protected audit token from the stripped binary.
That is the good result: Valv prevents naive static string extraction.

The debugger result confirms that no PDB or Rust debug symbols are needed for
runtime plaintext recovery once an attacker can stop or instrument the process
at the closure boundary. The timing guard notices the 30-second pause only
after execution resumes. It then terminates with exit code 70, but it cannot
undo the debugger's earlier read.

The important design weakness remains: Valv must embed all decryption material needed by the program. For ChaCha20, AES-GCM, and Ascon, the binary contains ciphertext, tag, key fragments, masks, seed, and the decrypt routine. For Stream Mask, the build key is carried in the `tag` field. For XOR Mask, the transform is deterministic XOR from the seed and is explicitly non-cryptographic.

A capable reverse engineer can recover plaintext by either:

1. locating the generated `SecretText` constants and reusing the public engine algorithm offline;
2. instrumenting the stripped program at the point where `SecretStr` is materialized; or
3. patching/hooking the closure boundary to copy plaintext before zeroization.

No PDB or Rust debug symbols are required for those attacks. Stripping raises
effort but does not remove the embedded-key design limit demonstrated by this
probe.

## Runtime-Bound Proof

`tests/runtime_bound_macro.rs` creates a separate release-mode consumer using
`bound!`. The test supplies `VALV_BUILD_PEPPER` only to the compiler, then:

1. searches the consumer binary for the protected plaintext and build pepper;
2. runs the binary with matching external runtime material; and
3. runs it again with different runtime material.

The test passes only when both static searches have no match, the matching
runtime key succeeds, and the wrong runtime key fails authentication.

Captured output:

```text
$ cargo test --all-features --test runtime_bound_macro -- --nocapture
running 1 test
test runtime_bound_macro_requires_external_material ... ok

test result: ok. 1 passed; 0 failed; 0 ignored
```
