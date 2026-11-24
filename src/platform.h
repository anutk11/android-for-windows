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
int     afw_os_mkdir(const char *path, uint32_t mode);
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
 * afw_os_ww_get queries dirty pages in [addr, addr + len) (if reset != 0, passes
 * WRITE_WATCH_FLAG_RESET atomically BEFORE caller zeroes pages). Returns 0 on
 * success, -1 on any OS failure or unsupported platform.
 * afw_os_ww_reset clears write-watch state on [addr, addr + len) (called ONLY
 * after os_decommit on inaccessible pages). Returns 0 on success, -1 on failure. */
int afw_os_ww_reserve(uint64_t addr, uint64_t size, uint64_t *out, int *ww_out);
int afw_os_ww_get(uint64_t addr, uint64_t len, int reset,
                  void **addrs, size_t *count_io, uint32_t *gran_out);
int afw_os_ww_reset(uint64_t addr, uint64_t len);

#endif
