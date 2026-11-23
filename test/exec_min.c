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
    unsigned long entry = 0, rnd = 0, pagesz = 0, phdr = 0, phnum = 0;
    if (((unsigned long)sp & 15) != 0) sys1(231, 10);            /* rsp at argc: 16-aligned */
    if (argc != 3) sys1(231, 11);
    if (!eq(argv[1], "hello") || !eq(argv[2], "world")) sys1(231, 12);
    if (argv[3] != 0) sys1(231, 13);
    while (*envp) envp++;
    auxv = (unsigned long *)(envp + 1);
    for (i = 0; auxv[i] != 0; i += 2) {
        if (auxv[i] == 9) entry = auxv[i + 1];
        if (auxv[i] == 25) rnd = auxv[i + 1];
        if (auxv[i] == 6) pagesz = auxv[i + 1];
        if (auxv[i] == 3) phdr = auxv[i + 1];
        if (auxv[i] == 5) phnum = auxv[i + 1];
    }
    if (entry != (unsigned long)_start) sys1(231, 14);           /* AT_ENTRY */
    if (!rnd || pagesz != 4096) sys1(231, 15);                    /* AT_RANDOM, AT_PAGESZ */
    if (!phdr || phnum < 2 || ((unsigned int *)phdr)[0] != 6) sys1(231, 16);  /* AT_PHDR -> PT_PHDR first */
    sys1(231, 42);
}

__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n\t"
        "xor %ebp, %ebp\n\tmov %rsp, %rdi\n\tand $-16, %rsp\n\tcall cstart\n\thlt\n");
