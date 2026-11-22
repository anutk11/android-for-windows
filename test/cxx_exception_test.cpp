// cxx_exception_test.cpp - C++ exceptions, built with the NDK (reviewer 1).
//
// The catch block and the destructor cleanup are landing pads: the unwinder
// jumps there, no branch does. With -fstack-protector-strong the function
// also reads the stack canary (fs:[0x28]). Static check in CI (--strict):
// every landing pad is found, nothing is left unproven.
// Running it needs libc++ and an unwinder on Windows (gate G2).
#include <stdexcept>

struct Guard {
    volatile char buf[64];
    int *counter;
    explicit Guard(int *c) : counter(c) { buf[0] = 1; }
    ~Guard() { ++*counter; }
};

extern "C" int afw_cxx_throw_catch(int x) {
    volatile char local[64];
    int cleanups = 0;
    local[0] = (char)x;
    try {
        Guard g(&cleanups);
        if (x > 0) throw std::runtime_error("boom");
    } catch (const std::exception &) {
        return 100 + cleanups + local[0];
    }
    return cleanups;
}
