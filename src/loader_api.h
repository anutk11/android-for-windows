/*
 * loader_api.h - the Android linker's __loader_* API (see loader_api.c).
 */
#ifndef AFW_LOADER_API_H
#define AFW_LOADER_API_H
#include <stddef.h>
#include <stdint.h>
#include "platform.h"   /* SYSV */

SYSV void *afw_l_dlopen(const char *name, int flags, const void *caller);
SYSV void *afw_l_dlsym(void *handle, const char *sym, const void *caller);
SYSV char *afw_l_dlerror(void);
SYSV int afw_l_dlclose(void *handle);
SYSV void *afw_l_dlvsym(void *handle, const char *sym, const char *version, const void *caller);
SYSV void *afw_l_android_dlopen_ext(const char *name, int flags, const void *extinfo, const void *caller);
SYSV void afw_l_android_get_LD_LIBRARY_PATH(char *buf, size_t sz);
SYSV int afw_l_android_get_application_target_sdk_version(void);
SYSV int afw_l_android_handle_signal(int sig, void *info, void *ctx);
SYSV void afw_l_cfi_fail(uint64_t id, void *ptr, void *diag, const void *caller);
/* info: bionic's Dl_info / dl_phdr_info (LP64), laid out in loader_api.c */
SYSV int afw_l_dladdr(const void *addr, void *info);
SYSV int afw_l_dl_iterate_phdr(SYSV int (*cb)(void *info, size_t size, void *data), void *data);
SYSV void afw_l_add_thread_local_dtor(void *dso_handle);
SYSV void afw_l_remove_thread_local_dtor(void *dso_handle);
#endif
