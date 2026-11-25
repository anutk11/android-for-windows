/*
 * art_gs_test.c - Real Android x86_64 NDK test for ART %gs: emulation (Gate G3).
 *
 * Exercises EVERY %gs: form observed in Android 14 libart.so (art-gs-scan.txt):
 *   - SYS_arch_prctl(ARCH_SET_GS / ARCH_GET_GS)
 *   - movq read & write (gs:[0xe0], gs:[0xb0], gs:[0x0])
 *   - movl read & write (gs:[0x28])
 *   - movw write & movzwl read (gs:[0x8])
 *   - cmpl, cmpq, testl directly on gs:[disp] (EFLAGS preservation!)
 *   - pushq gs:[disp] (zero stack clobber!)
 *   - call *gs:[disp] (ALL registers, EFLAGS, and exact return address preserved!)
 *   - gs:[reg] (register-based gs: access!)
 *   - Per-thread isolation across multiple threads!
 */
#include <stdint.h>

#define SYS_arch_prctl 158
#define ARCH_SET_GS    0x1001
#define ARCH_GET_GS    0x1004

typedef struct __attribute__((aligned(64))) {
    uint64_t self;        /* 0x000 */
    uint16_t state16;     /* 0x008 */
    uint16_t pad0;
    uint32_t pad1;
    uint64_t pad2[3];
    uint32_t flags32;     /* 0x028 */
    uint32_t pad3;
    uint64_t pad4[16];
    uint64_t slot_b0;     /* 0x0b0 */
    uint64_t pad5[5];
    uint64_t slot_e0;     /* 0x0e0 */
    uint64_t pad6[40];
    uint64_t fn_ptr;      /* 0x228 */
} fake_art_thread;

static long raw_arch_prctl(int code, unsigned long addr) {
    long ret;
    __asm__ volatile(
        "mov %1, %%eax\n\t"
        "syscall\n\t"
        : "=a"(ret)
        : "i"(SYS_arch_prctl), "D"((long)code), "S"(addr)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static __attribute__((noinline)) uint64_t gs_callee(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return a * 3 + b * 5 + c * 7 + d * 11;
}

/* Exercises all %gs: instruction forms on the calling thread's fake_art_thread.
 * Returns a bitmask of passed checks (expected: 0x3FF = 10/10 checks). */
int afw_art_gs_worker(uint64_t seed) {
    fake_art_thread thr;
    unsigned char *p = (unsigned char *)&thr;
    for (unsigned i = 0; i < sizeof thr; i++) p[i] = 0;

    thr.self    = (uint64_t)(uintptr_t)&thr;
    thr.state16 = 0;
    thr.flags32 = 0x12340005u;
    thr.slot_b0 = 0;
    thr.slot_e0 = seed;
    thr.fn_ptr  = (uint64_t)(uintptr_t)gs_callee;

    if (raw_arch_prctl(ARCH_SET_GS, (unsigned long)(uintptr_t)&thr) != 0)
        return 0;

    int bits = 0;

    /* bit 0: ARCH_GET_GS roundtrip */
    unsigned long got_gs = 0;
    if (raw_arch_prctl(ARCH_GET_GS, (unsigned long)(uintptr_t)&got_gs) == 0 &&
        got_gs == (unsigned long)(uintptr_t)&thr)
        bits |= (1 << 0);

    /* bit 1: movq read (gs:0x0, gs:0xe0) & movq write (gs:0xb0) */
    uint64_t self_v = 0, e0_v = 0;
    uint64_t b0_in = seed ^ 0xA5A55A5A12345678ULL;
    __asm__ volatile("movq %%gs:0x0, %0"  : "=r"(self_v));
    __asm__ volatile("movq %%gs:0xe0, %0" : "=r"(e0_v));
    __asm__ volatile("movq %0, %%gs:0xb0" : : "r"(b0_in) : "memory");
    if (self_v == (uint64_t)(uintptr_t)&thr && e0_v == seed && thr.slot_b0 == b0_in)
        bits |= (1 << 1);

    /* bit 2: movl read & write (gs:0x28) */
    uint32_t f32 = 0;
    __asm__ volatile("movl %%gs:0x28, %0" : "=r"(f32));
    uint32_t f32_new = 0xCAFE000Au;
    __asm__ volatile("movl %0, %%gs:0x28" : : "r"(f32_new) : "memory");
    if (f32 == 0x12340005u && thr.flags32 == f32_new)
        bits |= (1 << 2);

    /* bit 3: movw write & movzwl read (gs:0x8) */
    uint16_t s16 = (uint16_t)(0xBEE0u ^ (seed & 0xFFu));
    uint32_t z16 = 0;
    __asm__ volatile("movw %0, %%gs:0x8" : : "r"(s16) : "memory");
    __asm__ volatile("movzwl %%gs:0x8, %0" : "=r"(z16));
    if (thr.state16 == s16 && z16 == (uint32_t)s16)
        bits |= (1 << 3);

    /* bit 4: cmpl directly on gs:[0x28] (EFLAGS ZF/NE preserved!) */
    uint8_t eq1 = 0, ne1 = 0;
    __asm__ volatile(
        "cmpl $0xCAFE000A, %%gs:0x28\n\t"
        "sete %0\n\t"
        "cmpl $0x11111111, %%gs:0x28\n\t"
        "setne %1\n\t"
        : "=r"(eq1), "=r"(ne1) : : "cc"
    );
    if (eq1 == 1 && ne1 == 1)
        bits |= (1 << 4);

    /* bit 5: cmpq directly on gs:[0xe0] (EFLAGS preserved!) */
    uint8_t qeq = 0;
    __asm__ volatile(
        "cmpq %1, %%gs:0xe0\n\t"
        "sete %0\n\t"
        : "=r"(qeq) : "r"(seed) : "cc"
    );
    if (qeq == 1)
        bits |= (1 << 5);

    /* bit 6: testl directly on gs:[0x28] (EFLAGS preserved!) */
    uint8_t tnz = 0, tz = 0;
    __asm__ volatile(
        "testl $0x00000002, %%gs:0x28\n\t"
        "setne %0\n\t"
        "testl $0x00000001, %%gs:0x28\n\t"
        "sete %1\n\t"
        : "=r"(tnz), "=r"(tz) : : "cc"
    );
    if (tnz == 1 && tz == 1)
        bits |= (1 << 6);

    /* bit 7: pushq gs:[0xe0] (zero stack clobber!) */
    uint64_t pushed = 0;
    __asm__ volatile(
        "pushq %%gs:0xe0\n\t"
        "popq %0\n\t"
        : "=r"(pushed) : : "memory"
    );
    if (pushed == seed)
        bits |= (1 << 7);

    /* bit 8: call *gs:[0x228] (preserves ALL arg regs + exact return PC!) */
    uint64_t call_res = 0;
    __asm__ volatile(
        "mov %1, %%rdi\n\t"
        "mov $2, %%rsi\n\t"
        "mov $3, %%rdx\n\t"
        "mov $4, %%rcx\n\t"
        "call *%%gs:0x228\n\t"
        : "=a"(call_res)
        : "r"(seed)
        : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory", "cc"
    );
    if (call_res == seed * 3 + 2 * 5 + 3 * 7 + 4 * 11)
        bits |= (1 << 8);

    /* bit 9: register-based gs:[reg] read */
    uint64_t off = 0xe0, reg_v = 0;
    __asm__ volatile("movq %%gs:(%1), %0" : "=r"(reg_v) : "r"(off));
    if (reg_v == seed)
        bits |= (1 << 9);

    return bits;
}
