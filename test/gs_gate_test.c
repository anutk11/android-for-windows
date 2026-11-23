/* gs_gate_test.c - must be REFUSED by the load gate (issue #15):
 * ART keeps art::Thread* in gs on Linux x86_64; on Windows gs is the TEB,
 * and nothing rewrites gs: yet. A read, a write and a call through gs. */
long afw_gs_read(void) { long v; __asm__ volatile("mov %%gs:0xb0, %0" : "=r"(v)); return v; }
void afw_gs_write(long v) { __asm__ volatile("mov %0, %%gs:0xe0" : : "r"(v)); }
void afw_gs_call(void) { __asm__ volatile("call *%%gs:0x320" ::: "memory"); }
