/*
 * loader_api.c - the Android linker's API (__loader_*), provided by the loader.
 *
 * libdl.so is a thin forwarder: its dlopen is "jmp __loader_dlopen@plt",
 * and every one of its 12 imports is a WEAK import from the linker
 * (ld-android.so), which we do not load. Without these, each became NULL:
 * measured on Windows, the real libc's netdClientInit called dlopen and
 * crashed executing address 0 (PR #11).
 *
 * Semantics follow bionic's linker where it matters to callers:
 *   dlopen(NULL)          the "main program" handle: dlsym on it = RTLD_DEFAULT
 *   dlopen(loaded)        that library's handle (no second copy)
 *   dlopen(new)           loaded with its DT_NEEDED libraries, constructors run
 *   dlopen(missing)       NULL, dlerror() = 'dlopen failed: library "x" not found'
 *   dlsym                 RTLD_DEFAULT (0) / main = every library in load
 *                         order; RTLD_NEXT (-1) = only those loaded after the
 *                         caller's; unknown handle -> NULL + error
 *   dlerror               the last error once, then NULL (per thread)
 *   dlclose               0; libraries stay loaded (bionic keeps most too)
 *   dl_iterate_phdr       every finished library: base, name, program headers,
 *                         TLS module and this thread's block
 * Not yet (each documented where it returns): namespaces, versions in dlvsym,
 * android_dlextinfo flags, symbol names in dladdr.
 */
#include "loader_api.h"
#include "elf_loader.h"
#include "tls_static.h"
#include "callback_bridge.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local char t_err[512];
static _Thread_local int t_has_err;
static int g_main_handle;                  /* its address is dlopen(NULL) */

static void set_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t_err, sizeof t_err, fmt, ap);
    va_end(ap);
    t_has_err = 1;
}

/* Anchor retained deps[] blocks on an unbounded intrusive list (allocated up
 * front before afw_load_with_deps: linking on retention needs zero allocation,
 * cannot fail under OOM, and keeps the block base reachable for LSan even if
 * only an interior deps[i] stayed loaded or quarantined). */
typedef struct afw_deps_block_s {
    struct afw_deps_block_s *next;
    afw_lib deps[64];
} afw_deps_block;
static afw_deps_block *g_kept_deps_head;
static void keep_deps_block(afw_deps_block *blk) {
    blk->next = g_kept_deps_head;
    g_kept_deps_head = blk;
}

SYSV void *afw_l_dlopen(const char *name, int flags, const void *caller) {
    char path[1200];
    afw_lib *lib;
    afw_deps_block *dblk;
    int ndeps = 0;
    (void)flags; (void)caller;   /* RTLD_LAZY/NOW/LOCAL/GLOBAL: binding is always now, scope global */
    if (!name) return &g_main_handle;
    afw_dlopen_lock();
    if ((lib = afw_find_loaded(name)) != NULL) {
        afw_dlopen_unlock();
        return lib;
    }
    if (!afw_find_lib(name, path, sizeof path)) {
        afw_dlopen_unlock();
        set_err("dlopen failed: library \"%s\" not found", name);
        return NULL;
    }
    /* loaded libraries stay loaded: the registry keeps pointers into these */
    lib = (afw_lib *)calloc(1, sizeof *lib);
    dblk = (afw_deps_block *)calloc(1, sizeof *dblk);
    {
        char *p = (char *)malloc(strlen(path) + 1);
        if (!lib || !dblk || !p) {
            free(lib); free(dblk); free(p);
            afw_dlopen_unlock();
            set_err("dlopen failed: out of memory loading \"%s\"", name);
            return NULL;
        }
        strcpy(p, path);
        if (afw_load_with_deps(p, lib, dblk->deps, 64, &ndeps, 0) != 0) {
            int i, keep_deps = 0;
            /* Only free allocations that are neither loaded in g_libs[] nor
             * quarantined on the intrusive quarantine list (past point of no return). */
            set_err("dlopen failed: could not load \"%s\" (see the loader's message)", name);
            if (!afw_is_retained(lib)) { free(lib); free(p); }
            for (i = 0; i < ndeps; i++)
                if (afw_is_retained(&dblk->deps[i])) { keep_deps = 1; break; }
            if (keep_deps) keep_deps_block(dblk);
            else free(dblk);
            afw_dlopen_unlock();
            return NULL;
        }
    }
    if (ndeps == 0) free(dblk);
    else keep_deps_block(dblk);
    afw_dlopen_unlock();
    return lib;
}

SYSV void *afw_l_android_dlopen_ext(const char *name, int flags, const void *extinfo, const void *caller) {
    (void)extinfo;   /* android_dlextinfo (namespaces, reserved addresses, fds): not yet */
    return afw_l_dlopen(name, flags, caller);
}

/* RTLD_NEXT, as bionic: only libraries loaded AFTER the caller's. A caller
 * outside every library (the loader itself, a test) is the main program:
 * every library comes after it. Snapshots finished libs under afw_libs_rdlock
 * so afw_sym (which may invoke an IFUNC resolver) runs outside the lock. */
static void *next_sym(const char *sym, const void *caller) {
    afw_lib *snap[AFW_MAX_LIBS];
    int n = afw_libs_snapshot_finished(snap, AFW_MAX_LIBS, NULL);
    uintptr_t a = (uintptr_t)caller;
    int k, start = 0;
    for (k = 0; k < n; k++) {
        uintptr_t b = (uintptr_t)snap[k]->base;
        if (snap[k]->base && a >= b && a - b < snap[k]->size) {
            start = k + 1;
            break;
        }
    }
    for (k = start; k < n; k++) {
        void *p = afw_sym(snap[k], sym);
        if (p) return p;
    }
    return NULL;
}

/* Serialized under recursive afw_dlopen_lock so an external thread calling
 * dlsym() waits until any in-flight dlopen() and its constructors complete,
 * while a constructor calling dlsym() on the same thread re-enters cleanly. */
SYSV void *afw_l_dlsym(void *handle, const char *sym, const void *caller) {
    void *p = NULL;
    if (!sym) { set_err("dlsym failed: symbol name is null"); return NULL; }
    afw_dlopen_lock();
    if (handle == (void *)(intptr_t)-1) {
        p = next_sym(sym, caller);
    } else if (handle == NULL || handle == &g_main_handle) {
        p = afw_global_sym(sym);      /* RTLD_DEFAULT: every library in load order */
    } else if (!afw_is_loaded(handle)) {
        afw_dlopen_unlock();
        set_err("dlsym failed: invalid handle %p", handle);
        return NULL;
    } else {
        p = afw_sym((const afw_lib *)handle, sym);
    }
    afw_dlopen_unlock();
    if (!p) set_err("dlsym failed: undefined symbol: %s", sym);
    return p;
}

SYSV void *afw_l_dlvsym(void *handle, const char *sym, const char *version, const void *caller) {
    (void)version;   /* symbol versions: not checked yet */
    return afw_l_dlsym(handle, sym, caller);
}

SYSV char *afw_l_dlerror(void) {
    if (!t_has_err) return NULL;
    t_has_err = 0;
    return t_err;
}

SYSV int afw_l_dlclose(void *handle) {
    int ok;
    afw_dlopen_lock();
    ok = (handle == &g_main_handle) || afw_is_loaded(handle);
    afw_dlopen_unlock();
    if (!ok) {
        set_err("dlclose failed: invalid handle %p", handle);
        return -1;
    }
    return 0;
}

typedef struct {            /* bionic's Dl_info (LP64) */
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} afw_dl_info;

SYSV int afw_l_dladdr(const void *addr, void *vinfo) {
    afw_dl_info *info = (afw_dl_info *)vinfo;
    afw_lib *l;
    if (!info) return 0;
    l = afw_lib_containing(addr);
    if (!l) return 0;
    info->dli_fname = l->path;
    info->dli_fbase = l->base;
    info->dli_sname = NULL;   /* nearest symbol: not yet */
    info->dli_saddr = NULL;
    return 1;
}

typedef struct {            /* bionic's dl_phdr_info (LP64) */
    uint64_t dlpi_addr;
    const char *dlpi_name;
    const Elf64_Phdr *dlpi_phdr;
    uint16_t dlpi_phnum;
    unsigned long long dlpi_adds;
    unsigned long long dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
} afw_dl_phdr_info;

/* Snapshot finished libraries under afw_libs_rdlock(), then invoke cb()
 * OUTSIDE the lock: finished libraries are never unloaded/freed, so cb() may
 * safely call dl_iterate_phdr/dlopen/mmap without lock-ordering inversions. */
SYSV int afw_l_dl_iterate_phdr(SYSV int (*cb)(void *info, size_t size, void *data), void *data) {
    afw_lib *snap[AFW_MAX_LIBS];
    unsigned long long adds = 0;
    uint64_t bridge_addr = 0;
    const char *bridge_name = NULL;
    const Elf64_Phdr *bridge_phdr = NULL;
    uint16_t bridge_phnum = 0;
    int k, n, has_bridge, rc = 0;
    if (!cb) return 0;
    n = afw_libs_snapshot_finished(snap, AFW_MAX_LIBS, &adds);
    has_bridge = afw_callback_bridge_phdr(&bridge_addr, &bridge_name, &bridge_phdr, &bridge_phnum);
    if (has_bridge) adds++;
    for (k = 0; k < n && rc == 0; k++) {
        afw_lib *l = snap[k];
        afw_dl_phdr_info info;
        if (!l || !l->phdr) continue;
        memset(&info, 0, sizeof info);
        info.dlpi_addr = (uint64_t)l->bias;
        info.dlpi_name = l->path;
        info.dlpi_phdr = l->phdr;
        info.dlpi_phnum = (uint16_t)l->phnum;
        info.dlpi_adds = adds;
        info.dlpi_subs = 0;
        info.dlpi_tls_modid = (size_t)l->tls_module;
        info.dlpi_tls_data = l->tls_module ? afw_tls_resolve_existing((uint64_t)l->tls_module) : NULL;
        rc = cb(&info, sizeof info, data);
    }
    if (rc == 0 && has_bridge) {
        afw_dl_phdr_info info;
        memset(&info, 0, sizeof info);
        info.dlpi_addr = bridge_addr;
        info.dlpi_name = bridge_name;
        info.dlpi_phdr = bridge_phdr;
        info.dlpi_phnum = bridge_phnum;
        info.dlpi_adds = adds;
        info.dlpi_subs = 0;
        rc = cb(&info, sizeof info, data);
    }
    return rc;
}

/* Called by Bionic's __cxa_thread_atexit_impl / __cxa_thread_finalize to track
 * live per-thread thread_local destructors belonging to each loaded DSO. */
SYSV void afw_l_add_thread_local_dtor(void *dso_handle) {
    afw_lib *l = afw_lib_containing(dso_handle);
    if (l) (void)afw_os_atomic_add_i32(&l->tls_dtor_refcount, 1);
}

SYSV void afw_l_remove_thread_local_dtor(void *dso_handle) {
    afw_lib *l = afw_lib_containing(dso_handle);
    if (!l) return;
    for (;;) {
        int32_t cur = afw_os_atomic_load_i32(&l->tls_dtor_refcount);
        if (cur <= 0) return;
        if (afw_os_atomic_cmpxchg_i32(&l->tls_dtor_refcount, cur, cur - 1) == cur)
            return;
    }
}

SYSV void afw_l_android_get_LD_LIBRARY_PATH(char *buf, size_t sz) {
    const char *p = getenv("AFW_LIB_PATH");
    if (sz) snprintf(buf, sz, "%s", p ? p : "");
}

/* The image's API level until an app's own target SDK is known (G3). */
SYSV int afw_l_android_get_application_target_sdk_version(void) { return 34; }

/* The linker's signal hook (CFI and the like): not handled here. */
SYSV int afw_l_android_handle_signal(int sig, void *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    return 0;
}

SYSV void afw_l_cfi_fail(uint64_t id, void *ptr, void *diag, const void *caller) {
    (void)diag;
    fprintf(stderr, "[loader] CFI check failed (id 0x%llx, target %p, from %p): stopping\n",
            (unsigned long long)id, ptr, caller);
    fflush(stderr);
    abort();
}
