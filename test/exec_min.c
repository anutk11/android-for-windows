/* exec_min.c - an executable with no libc: its _start checks the initial
 * stack afw_exec builds, as the Linux kernel would (argc | argv | NULL |
 * envp | NULL | auxv), and ends with exit_group(42) only if all is right.
 * Each wrong field gives its own exit code. */
static long sys1(long n, long a) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}
static int eq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

extern char _start[];
__attribute__((used)) static void cstart(long *sp) {
    long argc = sp[0], i;
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    unsigned long *auxv;
    unsigned long phdr = 0, phent = 0, phnum = 0, pagesz = 0, base = 1, entry = 0;
    unsigned long uid = 0, euid = 0, gid = 0, egid = 0;
    unsigned long hwcap = 1, hwcap2 = 1, secure = 1, rnd = 0, execfn = 0;
    unsigned int seen = 0;   /* bitmask of tags actually present in auxv */
    int saw_env = 0, saw_ov = 0, saw_old_ov = 0;
    if (((unsigned long)sp & 15) != 0) sys1(231, 10);            /* rsp at argc: 16-aligned */
    if (argc != 3) sys1(231, 11);
    if (!eq(argv[1], "hello") || !eq(argv[2], "world")) sys1(231, 12);
    if (argv[3] != 0) sys1(231, 13);
    while (*envp) {
        if (eq(*envp, "AFW_EXEC_MIN=ok")) saw_env = 1;
        if (eq(*envp, "AFW_OVERRIDE=two")) saw_ov = 1;
        if (eq(*envp, "AFW_OVERRIDE=one")) saw_old_ov = 1;
        envp++;
    }
    auxv = (unsigned long *)(envp + 1);
    for (i = 0; auxv[i] != 0; i += 2) {
        unsigned long t = auxv[i], v = auxv[i + 1];
        if (t == 3)  { phdr = v;   seen |= 1u << 0; }
        if (t == 4)  { phent = v;  seen |= 1u << 1; }
        if (t == 5)  { phnum = v;  seen |= 1u << 2; }
        if (t == 6)  { pagesz = v; seen |= 1u << 3; }
        if (t == 7)  { base = v;   seen |= 1u << 4; }
        if (t == 9)  { entry = v;  seen |= 1u << 5; }
        if (t == 11) { uid = v;    seen |= 1u << 6; }
        if (t == 12) { euid = v;   seen |= 1u << 7; }
        if (t == 13) { gid = v;    seen |= 1u << 8; }
        if (t == 14) { egid = v;   seen |= 1u << 9; }
        if (t == 16) { hwcap = v;  seen |= 1u << 10; }
        if (t == 23) { secure = v; seen |= 1u << 11; }
        if (t == 25) { rnd = v;    seen |= 1u << 12; }
        if (t == 26) { hwcap2 = v; seen |= 1u << 13; }
        if (t == 31) { execfn = v; seen |= 1u << 14; }
    }
    if (entry != (unsigned long)_start) sys1(231, 14);                         /* AT_ENTRY */
    if (!rnd || pagesz != 4096) sys1(231, 15);                                 /* AT_RANDOM, AT_PAGESZ */
    if (!phdr || phnum < 2 || ((unsigned int *)phdr)[0] != 6) sys1(231, 16);   /* AT_PHDR -> PT_PHDR first */
    if (!saw_env) sys1(231, 17);                                               /* forwarded host env var */
    if (!saw_ov || saw_old_ov) sys1(231, 18);                                  /* --env override replaced host var */
    if (!(seen & (1u << 1)) || phent != 56) sys1(231, 19);                     /* AT_PHENT == sizeof(Elf64_Phdr) */
    if (!(seen & (1u << 4)) || base != 0) sys1(231, 20);                       /* AT_BASE == 0 */
    if ((seen & 0x3c0u) != 0x3c0u || uid != 10000 || euid != 10000 ||
        gid != 10000 || egid != 10000) sys1(231, 21);                          /* AT_UID/EUID/GID/EGID */
    if (!(seen & (1u << 10)) || !(seen & (1u << 13)) ||
        hwcap != 0 || hwcap2 != 0) sys1(231, 22);                              /* AT_HWCAP, AT_HWCAP2 */
    if (!(seen & (1u << 11)) || secure != 0) sys1(231, 23);                    /* AT_SECURE */
    if (!(seen & (1u << 14)) || !execfn || !eq((const char *)execfn, argv[0])) sys1(231, 24); /* AT_EXECFN */
    if (seen != 0x7fffu) sys1(231, 25);                                        /* all 15 tags present */
    sys1(231, 42);
}

__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n\t"
        "xor %ebp, %ebp\n\tmov %rsp, %rdi\n\tand $-16, %rsp\n\tcall cstart\n\thlt\n");
