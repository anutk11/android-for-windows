# G1: running the real libc.so's constructors

Status: in progress (PR #11). Everything below is **measured** on libc.so of the
pinned image (Build ID `fa337969c798946280caa45e2d71a2e7`, Android 14
`sdk_phone64_x86_64`, runtime APEX), unless marked *hypothesis*.

## Where it stood

The first real run on Windows (`afw-loader.exe libc.so --with-deps`):

| Step | Result |
|---|---|
| libdl.so, libc.so mapped and relocated | OK |
| patching | 224 syscalls + 2 moved, 972 fs:, 17 fs:[reg] trampolines, 0 refused |
| load gate | RUN |
| IFUNC resolvers (2) | ran on Windows |
| constructors (6) | started; stopped at `__loader_shared_globals` (not provided) |

Two loader bugs were found and fixed on the way:

1. **Dependency order closed the TLS layout too early.** libdl (no TLS) loaded first
   closed the static TLS layout; libc (with TLS) was then refused. Now the whole set is
   mapped and relocated first, then TLS closes once, then IFUNC/RELRO/constructors run
   in dependency order, like Android's linker. Imported IFUNCs are deferred too:
   `global_lookup` never runs library code.
2. **RELR under Android's tags was ignored silently.** Below API 30 the NDK writes
   `DT_ANDROID_RELR` (0x6fffe000...). Those tags were not read, so every relative
   relocation was skipped and a constructor was called at an unrelocated address.
   They are read now, and `DT_TEXTREL` is refused.

## libc_shared_globals: the measured fields

`tools/sg_uses.py` follows every call to `__loader_shared_globals`, made directly, through
the GOT, or through libc's own wrapper `__libc_shared_globals` (found by address: 0x52a00,
0xd5910). It then records the offsets read or written through the returned pointer. 43 call
sites were found.

| Offset | Used by | AOSP field (order matches the header) |
|---|---|---|
| 0x000, 0x004 | fdsan (`FdTable::at`, error level) | `fd_table` (first member) |
| 0x410 | `__libc_init` (executables) | `initial_linker_arg_count` |
| 0x418 | `getauxval` | `auxv` |
| 0x420 | `android_set_abort_message` (mutex) | `abort_msg_lock` |
| 0x448 | `android_set_abort_message` | `abort_msg` |
| 0x450-0x4f8 | static TLS bounds, `pthread_create`, `__tls_get_addr` slow path, thread-exit callbacks | `static_tls_layout`, `tls_modules`, `tls_allocator`... |
| 0x478, 0x480 | `__libc_preinit_impl` | `tls_modules.generation`, `generation_libc_so` |
| 0x628 | `__libc_preinit_impl` (before `netdClientInit`) | |
| 0x630, 0x638 | `__libc_init_common` | `init_progname`, `init_environ` |
| 0x640-0x660 | `MaybeInitGwpAsan` | gwp_asan state/metadata/hooks |
| 0x668-0x680 | `__libc_init_malloc` | scudo stack depot, region info, ring buffer |

What bionic-win provides (`src/bionic_shim.c`) is one zeroed page, which is the state the
linker's `constexpr` constructor leaves. On top of that:

- `auxv` (0x418): AT_PAGESZ 4096; AT_UID/EUID/GID/EGID 10000 (the first app uid);
  AT_HWCAP/HWCAP2 0; AT_SECURE 0; AT_RANDOM pointing at 16 bytes from the OS's
  cryptographic generator (the stack guard and the setjmp cookie are seeded from them);
  AT_NULL.
- `init_environ` (0x638): an empty environment.
- `init_progname` (0x630): "android-for-windows".

**Pinned:** the loader links `__loader_shared_globals` only into a library whose
NT_GNU_BUILD_ID is the pinned one, and refuses any other. A different build would read
and write the wrong fields.

## Result (measured on Windows CI)

**The real libc.so's six constructors finish, and Android code calls it.**
`test/real_libc_test.c`, built with the NDK against libc.so, passes all 11 checks with
the real bionic: snprintf, scudo malloc/free (small, and 8MB through mmap), qsort,
errno (strtol ERANGE), pthread_self, getpid, clock_gettime, strdup, printf to the
console, strerror. This is now a required CI step.

What it took, in the order the measurements showed:

| Stop | Cause | Fix |
|---|---|---|
| libc refused | the first library closed the TLS layout | two-phase loading |
| constructor at an unrelocated address | `DT_ANDROID_RELR` ignored | read it; refuse `DT_TEXTREL` |
| `__loader_shared_globals` missing | | measured layout, pinned to the Build ID |
| errno written to 0x260c | `tp[1]` held a thread id | pthread_internal_t / bionic_tls area |
| `WriteProtected mprotect` ENOMEM | the VMA layer did not know the image | `afw_vma_adopt` (reviewer 4, PR #14) |
| hang | futex ENOSYS | futex over WaitOnAddress, clock_gettime, getrandom, uid |
| hang (with no syscall) | the VEH deadlocked on its own lock on a non-fs fault | filter before the lock; per-thread guard |
| call through NULL | libdl's `__loader_*` imports are weak, ld-android not loaded | the linker API in `loader_api.c` |

Diagnosis tools that came out of this: `--watchdog=N` (native stack by name, last
syscall and caller), and safe crash reports.

## An executable up to main (PR #16)

An ordinary NDK executable (`test/hello_exe.c`) runs `main` on Windows with the real
bionic: its constructor runs first, printf and malloc work, `atexit` runs after `main`,
and the exit code (42) goes out through `exit_group`. This is a required CI step.

- `src/exec.c` builds the initial stack exactly as the kernel leaves it (argc | argv |
  NULL | envp | NULL | auxv) on the thread's real stack (`alloca`, which probes pages
  downward the way Windows grows a stack), passes libc the same auxv, environment and
  name through the shared globals, then jumps to `_start` with rbp = rdx = 0.
- `test/exec_min.c` (no libc) checks every field of the stack, with a separate exit code
  for each wrong field.
- Syscalls still answered with ENOSYS along this path: faccessat, newfstatat, openat (the
  property area `/dev/__properties__`), rt_sigaction, sched_getaffinity, fstat. libc lives
  with all of them; they're next in line (files, signals).

## Where it stood before

With the TCB fixed (below) and `writev` in place, the constructors no longer crash. libc
aborts on purpose and says why:

```
libc: WriteProtected mprotect 1 failed: Out of memory
```

`afw_mprotect` does not know the pages of a library the loader mapped (issue #12,
VMA extents, reviewer 4). This is the only blocker left before the constructors finish.

### The TCB (done, measured)

`__errno` is `[[fs:0] + 8] + 0x300`: libc reads slot 1 **through memory** and expects
a pointer. Slot 1 used to hold the Windows thread id (0x230c), so errno was written to
0x260c. Each thread's TLS allocation now also holds a zeroed bionic thread area:

- pthread_internal_t at `tp[1]`, with the tid at +0x10 (read by `gettid`);
- bionic_tls at `tp[9]`.

The area is freed together with the block. When the TLS layout closes, both slots are
re-pointed into the new allocation. libc uses only three fs: displacements: `fs:0` (129
times), `fs:0x28` (843) and `fs:0x4` (12, not yet explained).

## Next (hypothesis, to be measured the same way)

- The real sizes of `pthread_internal_t` and `bionic_tls` (now 64KB upper bounds each).
- `fs:0x4` (12 sites): what it is, and whether it is reached.
- `__loader_add_thread_local_dtor` / `remove` (weak): needed for C++ `thread_local`
  destructors.
- `__loader_android_get_exported_namespace` (weak): returning NULL is correct with no
  namespaces.
