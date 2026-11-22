# G3: ART's thread register (%gs:) on Windows - measurement

Status: **measured, decision pending (reviewers)**. Issue #15. Image: Android 14
`sdk_phone64_x86_64` (the pinned one), ART APEX `com.android.art.capex`.

## The problem

ART on Linux x86_64 keeps `art::Thread*` in the gs segment (`arch_prctl(ARCH_SET_GS)`)
and reaches thread state and runtime entrypoints as `gs:[offset]`. On Windows x64, gs is
the TEB: it can't be moved, and user mode can't write the gs base (Windows doesn't enable
`wrgsbase`). fs is no way out either: user mode can't set its base on Windows x64, and
bionic already uses fs (it's rewritten to TEB slots).

## Measured (bionic-probe, `tools/gs_count.c` with Zydis; libart cross-checked with objdump)

| File | gs: accesses | of which `call *gs:N` | distinct offsets | register-based | how measured |
|---|---|---|---|---|---|
| libart.so | 1,544 (objdump: 1,557) | 2 | 12 | 2 | exact (functions with CFI) |
| boot-framework.oat | ~157,000 | ~110,700 | 83 | 104 | approximate (linear sweep) |
| boot.oat | ~64,000 | ~46,200 | 70 | 19 | approximate |
| boot-core-icu4j.oat | ~18,000 | ~13,400 | 55 | 4 | approximate |
| boot-core-libart.oat | ~6,600 | ~4,300 | 53 | 1 | approximate |
| the other boot .oat files | a few thousand | most of them | | | approximate |

- **libart.so:** almost every access is in the hand-written assembly (`art_quick_*`
  entrypoints, nterp) at a fixed offset: `gs:0xe0` (683), `gs:0xb0` (573), `gs:0x28`
  (178)... Reads 961, writes 581. Same shape as `fs:[disp]` in bionic, so **the existing
  trampoline technique applies** (an instruction like `mov %gs:0xb0,%rax` is at least
  9 bytes, enough for a `jmp rel32`).
- **Compiled code (.oat):** about a quarter of a million accesses in the boot image alone,
  about 70% of them `call *%gs:N` (calls to runtime entrypoints through the
  `art::Thread` table). **The JIT emits the same thing at run time.**
- libart.so also has 10,006 `fs:` accesses, all reads of `fs:0x28` and `fs:0`, which the
  loader already handles (as in libc).

**A correction recorded on purpose:** a first measurement reported "0 gs:" in the .oat
files. objdump prints a .oat's code as data, because its only symbol, `oatexec`, is
an OBJECT, and the parser read the raw bytes as mnemonics. The bytes themselves showed
the truth (`65 ff 14 25` = `call *%gs:N`). `gs_count` ignores symbols.

## What the gate does now

Every gs: access blocks loading (`gs_unsupported`, `gs_outside_functions`). Before this,
the patcher didn't look at gs at all, so a library with gs: would have run with gs pointing
at the TEB. `test/gs_gate_test.c` locks this in, on Linux and Windows. libart.so today:
REFUSE (1,413 reachable gs:, 1 outside functions, 96 unproven).

## What the numbers mean for G3 (options, for the reviewers to decide)

1. **Rewrite at load time + a JIT hook.** libart (1.5K) is fine. The boot image means
   ~250K sites, mostly `call *gs:N`, which need a trampoline each, or a cheaper shared
   pattern. The JIT emits new code all the time, so it needs a hook (for example
   `mprotect(PROT_EXEC)` → patch, issue #15 item 8). Heavy and costly at cold start.
2. **ART built from source with a different thread-register ABI** (the Gesher direction,
   ADR 0006). Thread* is fetched from a TEB slot (`mov r, gs:[0x1480+8*k]`) and the
   access becomes `[r+N]`, in the code generator and in libart's assembly macros. dex2oat
   and the JIT then produce correct code from the start; the cost is one extra load per
   access. This means building ART and the boot image ourselves.
3. **Interpreter only** (no .oat, no JIT). Only libart's 1.5K sites remain. A possible
   first step for G3a, but slow.

The measurements favor **2** for compiled code: the volume and the JIT rule out
rewriting as the main solution, while 1 is suitable for libart until the build exists.
