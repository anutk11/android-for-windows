/*
 * crash.h - Readable crash reports: which Android function crashed and why.
 */
#ifndef AFW_CRASH_H
#define AFW_CRASH_H
void afw_crash_init(void);
/* After `seconds`, print where the main thread is (3 samples) and the
 * syscall counts, then end the process with 124. Windows only. 0 or -1. */
int afw_watchdog_start(unsigned seconds);
#endif
