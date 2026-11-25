/*
 * dex_vm.h - Self-contained Android DEX (classes.dex) parser, Dalvik bytecode
 * interpreter, and minimal Android Java Activity / View / Canvas runtime.
 *
 * Executes real Android DEX bytecode (compiled by javac + d8) and dispatches
 * native methods to loaded x86_64 NDK shared libraries via JNI 1.6.
 */
#ifndef AFW_DEX_VM_H
#define AFW_DEX_VM_H

#include <stddef.h>
#include <stdint.h>
#include "apk.h"
#include "win_gui.h"

typedef struct afw_dex_vm_s afw_dex_vm;

typedef int (*afw_dex_load_lib_fn)(const char *libname, void *ud);

/* Create a DEX VM from raw classes.dex bytes. Returns NULL on parse error. */
afw_dex_vm *afw_dex_vm_create(const unsigned char *dex_bytes, size_t dex_size,
                              const afw_apk *apk, afw_gui_surface *surface,
                              afw_dex_load_lib_fn load_lib_cb, void *load_lib_ud);
void        afw_dex_vm_destroy(afw_dex_vm *vm);

/* Return JavaVM* and JNIEnv* pointers (SysV ABI vtables) for native JNI code. */
void *afw_dex_vm_get_javavm(afw_dex_vm *vm);
void *afw_dex_vm_get_jnienv(afw_dex_vm *vm);

/* Object / string / array helpers used by jni_bridge.c and tests. */
uint32_t    afw_dex_new_string(afw_dex_vm *vm, const char *utf8);
const char *afw_dex_get_string(const afw_dex_vm *vm, uint32_t handle);
uint32_t    afw_dex_new_int_array(afw_dex_vm *vm, int32_t len);
int32_t    *afw_dex_int_array_data(afw_dex_vm *vm, uint32_t handle, int32_t *len_out);
uint32_t    afw_dex_find_class(afw_dex_vm *vm, const char *slash_or_desc);
const char *afw_dex_obj_class_desc(const afw_dex_vm *vm, uint32_t handle);
uint32_t    afw_dex_new_instance(afw_dex_vm *vm, const char *class_desc);

/* Method lookup & invocation (returns 0 on success, -1 on error). */
int afw_dex_find_method_id(const afw_dex_vm *vm, const char *class_desc,
                           const char *name, const char *sig);
const char *afw_dex_method_shorty(const afw_dex_vm *vm, int method_idx);
int afw_dex_invoke_method_id(afw_dex_vm *vm, int method_idx,
                             const uint64_t *args, int nargs, uint64_t *ret_out);
int afw_dex_invoke_by_name(afw_dex_vm *vm, const char *class_desc,
                           const char *name, const char *sig,
                           const uint64_t *args, int nargs, uint64_t *ret_out);

/* Register a native function pointer (SysV ABI) for JNI RegisterNatives. */
int afw_dex_register_native(afw_dex_vm *vm, const char *class_desc,
                            const char *name, const char *sig, void *fn_ptr);

/* Field accessors for JNI GetIntField/SetIntField/GetObjectField/SetObjectField. */
int      afw_dex_find_field_id(const afw_dex_vm *vm, const char *class_desc, const char *name);
uint64_t afw_dex_get_inst_field(const afw_dex_vm *vm, uint32_t obj, int field_id);
void     afw_dex_set_inst_field(afw_dex_vm *vm, uint32_t obj, int field_id, uint64_t val);

/* Run an Android Activity class lifecycle + render frames via View.onDraw(Canvas).
 * `activity_dotted` is e.g. "com.afw.dexdemo.MainActivity". */
int afw_dex_run_activity(afw_dex_vm *vm, const char *activity_dotted, int max_frames);

/* Return number of frames drawn via Canvas. */
int afw_dex_frames_drawn(const afw_dex_vm *vm);

#endif
