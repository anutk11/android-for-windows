/*
 * platform.h - The thin layer between the loader and the host OS.
 *
 * The real target is Windows. The same code also builds on Linux so the
 * loader logic can be tested anywhere.
 */
#ifndef AFW_PLATFORM_H
#define AFW_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Calling convention bridge.
 *
 * Android x86_64 code uses the System V ABI (arguments in rdi, rsi, rdx...).
 * Windows code uses the Microsoft x64 ABI (arguments in rcx, rdx, r8...).
 * Every function that Android code calls, and every Android function we call,
 * must be marked SYSV so the compiler generates the right glue.
 * This needs clang / clang-cl (MSVC's cl.exe does not support it).
 */
#if defined(_WIN32)
#  if !defined(__clang__)
#    error "Build with clang-cl: MSVC cl.exe cannot call System V ABI code."
#  endif
#  define SYSV __attribute__((sysv_abi))
#else
#  define SYSV
#endif

/* Memory protection flags (same bits as ELF PF_*) */
#define AFW_PROT_X 1
#define AFW_PROT_W 2
#define AFW_PROT_R 4

#define AFW_PAGE_SIZE 4096

/* Reserve+commit zeroed read/write memory. Returns NULL on failure. */
void *afw_mem_alloc(size_t size);
/* Release memory from afw_mem_alloc. */
void afw_mem_free(void *addr, size_t size);
/* Change protection of a page-aligned range. Returns 0 on success. */
int afw_mem_protect(void *addr, size_t size, int prot);
/* Make sure the CPU sees freshly written code. */
void afw_flush_icache(void *addr, size_t size);

/* n bytes from the OS's cryptographic random generator; 0 on success */
int afw_random_bytes(void *buf, size_t n);

/* Check Windows exploit-protection policies that would block the engine
 * (ACG forbids creating or patching executable memory). Can be forced on a
 * program from outside, by an administrator. Returns 0 if we can run. */
int afw_check_security(void);

/* ---- OS file primitives (all Win32 calls stay inside platform.c, Rule 8) ---- */
typedef intptr_t afw_os_file;
#define AFW_OS_FILE_INVALID ((afw_os_file)-1)

#define AFW_O_RDONLY    0x0000
#define AFW_O_WRONLY    0x0001
#define AFW_O_RDWR      0x0002
#define AFW_O_ACCMODE   0x0003
#define AFW_O_CREAT     0x0040
#define AFW_O_EXCL      0x0080
#define AFW_O_TRUNC     0x0200
#define AFW_O_APPEND    0x0400
#define AFW_O_DIRECTORY 0x10000
#define AFW_O_NOFOLLOW  0x20000

#define AFW_SEEK_SET 0
#define AFW_SEEK_CUR 1
#define AFW_SEEK_END 2

typedef struct {
    uint64_t dev, ino, nlink;
    uint32_t mode;      /* POSIX S_IF* | permission bits */
    int64_t  size;
    int64_t  atime_s, atime_ns;
    int64_t  mtime_s, mtime_ns;
    int64_t  ctime_s, ctime_ns;
} afw_os_stat_info;

/* Each returns 0 (or non-negative count/offset) on success, or negative Linux errno. */
int     afw_os_open(const char *path, int flags, uint32_t mode, afw_os_file *out);
int     afw_os_close(afw_os_file f);
int64_t afw_os_read(afw_os_file f, void *buf, size_t len);
int64_t afw_os_write(afw_os_file f, const void *buf, size_t len, int append);
int64_t afw_os_lseek(afw_os_file f, int64_t off, int whence);
int     afw_os_fstat(afw_os_file f, afw_os_stat_info *out);
int     afw_os_stat(const char *path, int nofollow, afw_os_stat_info *out);
int     afw_os_unlink(const char *path, int rmdir_flag);
int     afw_os_rename(const char *oldpath, const char *newpath);
int     afw_os_mkdir(const char *path, uint32_t mode);
int     afw_os_setenv(const char *name, const char *val);
int     afw_os_symlink(const char *target, const char *linkpath);
int     afw_os_junction(const char *target, const char *linkpath);
int     afw_os_set_append(afw_os_file f, int append);
int64_t afw_os_stdio_read(void *buf, size_t len);
int64_t afw_os_stdio_write(int std_fd, const void *buf, size_t len, int append);
int     afw_os_stdio_stat(int std_fd, afw_os_stat_info *out);
int     afw_os_stdio_set_append(int std_fd, int append);
int     afw_os_stdio_swap(int std_fd, afw_os_file new_f, afw_os_file *saved);
int     afw_os_stdio_restore(int std_fd, afw_os_file saved);

/* Portable thread spawn/join (Win32 CreateThread / POSIX pthread). */
typedef intptr_t afw_os_thread;
int afw_os_thread_start(void (*fn)(void *), void *arg, afw_os_thread *out);
int afw_os_thread_join(afw_os_thread t);

/* Process-global FD table lock (SRWLOCK on Windows, pthread_mutex on Linux). */
void afw_fd_lock(void);
void afw_fd_unlock(void);

/* Read-only OS file-mapping primitives (all Win32 calls stay in platform.c, Rule 8).
 * aligned_off must be 64KB-aligned on Windows (4KB-aligned on Linux); view_len
 * is non-zero and bounded to file_size - aligned_off by the caller.
 * afw_os_filemap_protect accepts prot == 0 (PAGE_NOACCESS / PROT_NONE) or
 * AFW_PROT_R (PAGE_READONLY / PROT_READ). Returns 0 or negative Linux errno. */
int afw_os_filemap_ro(afw_os_file f, uint64_t aligned_off, size_t view_len,
                      int shared, void **view_base_out);
int afw_os_filemap_unmap(void *view_base, size_t view_len);
int afw_os_filemap_protect(void *addr, size_t len, int prot);

/* Anonymous VMA reservation + write-watch primitives (Win32 isolated in platform.c, Rule 8).
 * afw_os_ww_reserve reserves anonymous PROT_NONE space; on Windows tries
 * MEM_RESERVE | MEM_WRITE_WATCH first and falls back to plain MEM_RESERVE.
 * Sets *ww_out = 1 iff write-watch tracking is active on the reservation.
 * afw_os_ww_get queries dirty pages in [addr, addr + len) (src/vma.c passes
 * reset = 0 so dirty bits on accessible pages are never cleared; if reset != 0,
 * passes WRITE_WATCH_FLAG_RESET). Returns 0 on success, -1 on any OS failure
 * or unsupported platform.
 * afw_os_ww_reset clears write-watch state on freshly committed [addr, addr + len)
 * MEM_COMMIT pages under g_lock (never on MEM_RESERVE, never after memset on
 * accessible pages). Returns 0 on success, -1 on failure. */
int afw_os_ww_reserve(uint64_t addr, uint64_t size, uint64_t *out, int *ww_out);
int afw_os_ww_get(uint64_t addr, uint64_t len, int reset,
                  void **addrs, size_t *count_io, uint32_t *gran_out);
int afw_os_ww_reset(uint64_t addr, uint64_t len);

/* ---- G2-4b SYS_clone / thread-lifecycle OS primitives (isolated in platform.c, Rule 8) ---- */
typedef struct {
    uint64_t host_rsp;             /* 0x00: saved Windows host stack pointer (16-byte aligned) */
    uint64_t orig_tib_base;        /* 0x08: original gs:[0x08] NT_TIB StackBase */
    uint64_t orig_tib_limit;       /* 0x10: original gs:[0x10] NT_TIB StackLimit */
    uint64_t orig_teb_dealloc;     /* 0x18: original gs:[0x1478] TEB DeallocationStack */
    uint64_t bionic_stack_base;    /* 0x20: Bionic RW stack top */
    uint64_t bionic_stack_limit;   /* 0x28: Bionic RW stack bottom (above guard page) */
    uint64_t bionic_dealloc_stack; /* 0x30: underlying VMA allocation base */
    uint64_t child_rsp;            /* 0x38: Bionic child_stack (16-byte aligned) */
    uint64_t child_rip;            /* 0x40: patched clone stub return address */
    uint64_t rbx;                  /* 0x48 */
    uint64_t rbp;                  /* 0x50 */
    uint64_t r12;                  /* 0x58 */
    uint64_t r13;                  /* 0x60 */
    uint64_t r14;                  /* 0x68 */
    uint64_t r15;                  /* 0x70 */
} afw_os_clone_trampoline;

typedef intptr_t afw_os_event;

uint32_t  afw_os_current_tid(void);
int       afw_os_thread_spawn_detached(void (*fn)(void *), void *arg);
int       afw_os_event_init(afw_os_event *ev);
void      afw_os_event_signal(afw_os_event ev);
void      afw_os_event_wait(afw_os_event ev);
void      afw_os_event_destroy(afw_os_event ev);
int       afw_os_thread_ctx_fls_set(void (*release_cb)(void *), void *ctx);
void      afw_os_atomic_store_i32(void *addr, int32_t val);
int32_t   afw_os_atomic_xchg_i32(int32_t *addr, int32_t val);
int32_t   afw_os_atomic_add_i32(int32_t *addr, int32_t delta);
int32_t   afw_os_atomic_cmpxchg_i32(int32_t *addr, int32_t expected, int32_t desired);
int32_t   afw_os_atomic_load_i32(const int32_t *addr);
uintptr_t afw_os_atomic_xchg_uptr(uintptr_t *addr, uintptr_t val);
void      afw_os_atomic_store_uptr(uintptr_t *addr, uintptr_t val);
uintptr_t afw_os_atomic_load_uptr(const uintptr_t *addr);
void      afw_os_wake_address_all(void *addr);
void      afw_os_exit_thread(int code);
int       afw_os_clone_supported(void);
void      afw_os_clone_enter_bionic(afw_os_clone_trampoline *t);
void      afw_os_clone_exit_on_host(afw_os_clone_trampoline *t, void *ctx,
                                    int exit_code, void (*fn)(void *, int));

/* ---- G2-5a Loader registry RW lock & recursive dlopen lock (Rule 8) ----
 * Completely separate from VMA g_lock and NEVER acquired inside VEH. */
void afw_libs_rdlock(void);
void afw_libs_rdunlock(void);
void afw_libs_wrlock(void);
void afw_libs_wrunlock(void);
void afw_dlopen_lock(void);
void afw_dlopen_unlock(void);

/* ---- G2-5b Dynamic TLS (DTV) aligned alloc & per-thread FLS cleanup (Rule 8) ---- */
void *afw_os_aligned_alloc_zero(size_t align, size_t size);
void  afw_os_aligned_free(void *p);
int   afw_os_dtv_fls_set(void (*release_cb)(void *), void *dtv);
#ifdef AFW_TEST
void  afw_os_test_fail_dtv_fls_clear(int count);
#endif

/* ---- G3 ART /proc/self/maps synthesis & main-stack query (Rule 8) ---- */
int      afw_os_build_proc_maps(char **buf_out, size_t *len_out);
int      afw_os_is_current_stack(uint64_t addr, uint64_t len);
int      afw_os_current_stack_limits(uint64_t *lo_out, uint64_t *hi_out);
uint32_t afw_os_current_pid(void);

#endif
