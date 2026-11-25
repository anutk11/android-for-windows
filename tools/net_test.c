/*
 * net_test.c - Host unit tests for src/net.c (TCP loopback client/server,
 * UDP datagrams, poll, epoll, pipe2, eventfd2, socketpair, getsockopt SO_ERROR,
 * fcntl O_NONBLOCK, ioctl FIONREAD).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/net.h"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

static int g_pass = 0, g_fail = 0;

static void check(const char *what, int ok) {
    if (ok) g_pass++;
    else { g_fail++; fprintf(stderr, "FAIL: %s\n", what); }
}

static int64_t sc(int64_t nr, int64_t a0, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5) {
    int64_t a[6] = { a0, a1, a2, a3, a4, a5 };
    int64_t ret = -38;
    (void)afw_net_syscall(nr, a, &ret);
    return ret;
}

typedef struct {
    uint16_t family;
    uint16_t port;
    uint32_t addr;
    uint8_t  zero[8];
} lnx_sockaddr_in;

typedef struct {
    int32_t fd;
    int16_t events;
    int16_t revents;
} lnx_pollfd;

#pragma pack(push, 1)
typedef struct {
    uint32_t events;
    uint64_t data;
} lnx_epoll_ev;
#pragma pack(pop)

int main(void) {
    check("afw_net_init succeeds", afw_net_init() == 0);

    /* 1. pipe2 + read/write + poll */
    {
        int32_t pfds[2] = { -1, -1 };
        char buf[16] = {0};
        lnx_pollfd pfd;
        check("pipe2 succeeds", sc(293, (intptr_t)pfds, 0, 0, 0, 0, 0) == 0 && pfds[0] >= 256 && pfds[1] >= 256);
        check("pipe write", sc(1, pfds[1], (intptr_t)"hello", 5, 0, 0, 0) == 5);
        pfd.fd = pfds[0]; pfd.events = 1 /* POLLIN */; pfd.revents = 0;
        check("poll detects pipe readable", sc(7, (intptr_t)&pfd, 1, 500, 0, 0, 0) == 1 && (pfd.revents & 1));
        check("pipe read", sc(0, pfds[0], (intptr_t)buf, 16, 0, 0, 0) == 5 && strcmp(buf, "hello") == 0);
        check("pipe close", sc(3, pfds[0], 0, 0, 0, 0, 0) == 0 && sc(3, pfds[1], 0, 0, 0, 0, 0) == 0);
    }

    /* 2. eventfd2 + epoll */
    {
        int64_t efd = sc(290, 0, 0x800 /* EFD_NONBLOCK */, 0, 0, 0, 0);
        int64_t ep = sc(291, 0, 0, 0, 0, 0, 0);
        uint64_t v = 7, outv = 0;
        lnx_epoll_ev ev = { 1 /* EPOLLIN */, 0xCAFEBABEULL };
        lnx_epoll_ev out_ev = { 0, 0 };
        check("eventfd2 + epoll_create1", efd >= 256 && ep >= 256);
        check("eventfd nonblock read when 0 -> -EAGAIN", sc(0, efd, (intptr_t)&outv, 8, 0, 0, 0) == -11);
        check("epoll_ctl ADD", sc(233, ep, 1, efd, (intptr_t)&ev, 0, 0) == 0);
        check("eventfd write 7", sc(1, efd, (intptr_t)&v, 8, 0, 0, 0) == 8);
        check("epoll_wait fires with user data", sc(232, ep, (intptr_t)&out_ev, 1, 500, 0, 0) == 1 && out_ev.data == 0xCAFEBABEULL);
        check("eventfd read returns 7", sc(0, efd, (intptr_t)&outv, 8, 0, 0, 0) == 8 && outv == 7);
        check("close epoll + eventfd", sc(3, ep, 0, 0, 0, 0, 0) == 0 && sc(3, efd, 0, 0, 0, 0, 0) == 0);
    }

    /* 3. TCP loopback socket + bind + listen + connect + accept4 + send/recv + FIONREAD + SO_ERROR */
    {
        int64_t srv = sc(41, 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0, 0, 0, 0);
        int64_t cli = sc(41, 2, 1, 0, 0, 0, 0);
        lnx_sockaddr_in sin;
        uint32_t slen = sizeof sin;
        int one = 1, soerr = 99;
        uint32_t errlen = 4;
        int32_t avail = 0;
        char buf[32] = {0};
        memset(&sin, 0, sizeof sin);
        sin.family = 2;
        sin.addr = htonl(0x7f000001u);
        sin.port = 0;

        check("socket TCP created", srv >= 256 && cli >= 256);
        check("setsockopt SO_REUSEADDR", sc(54, srv, 1, 2, (intptr_t)&one, 4, 0) == 0);
        check("bind 127.0.0.1:0", sc(49, srv, (intptr_t)&sin, sizeof sin, 0, 0, 0) == 0);
        check("listen", sc(50, srv, 4, 0, 0, 0, 0) == 0);
        check("getsockname retrieves bound port", sc(51, srv, (intptr_t)&sin, (intptr_t)&slen, 0, 0, 0) == 0 && sin.port != 0);
        check("connect client -> server", sc(42, cli, (intptr_t)&sin, sizeof sin, 0, 0, 0) == 0);
        int64_t acc = sc(288, srv, 0, 0, 0, 0, 0);
        check("accept4 returns client fd", acc >= 256);
        check("getsockopt SO_ERROR == 0", sc(55, cli, 1, 4, (intptr_t)&soerr, (intptr_t)&errlen, 0) == 0 && soerr == 0);
        check("TCP sendto", sc(44, cli, (intptr_t)"AFW-NET-OK", 10, 0, 0, 0) == 10);
        {
            lnx_pollfd pfd = { (int32_t)acc, 1, 0 };
            check("poll waits for TCP data", sc(7, (intptr_t)&pfd, 1, 1000, 0, 0, 0) == 1 && (pfd.revents & 1));
        }
        check("ioctl FIONREAD >= 10", sc(16, acc, 0x541B, (intptr_t)&avail, 0, 0, 0) == 0 && avail >= 10);
        check("TCP recvfrom", sc(45, acc, (intptr_t)buf, sizeof buf, 0, 0, 0) == 10 && strcmp(buf, "AFW-NET-OK") == 0);
        check("close TCP sockets", sc(3, acc, 0, 0, 0, 0, 0) == 0 && sc(3, cli, 0, 0, 0, 0, 0) == 0 && sc(3, srv, 0, 0, 0, 0, 0) == 0);
    }

    /* 4. UDP loopback sendto / recvfrom */
    {
        int64_t u1 = sc(41, 2, 2 /* SOCK_DGRAM */, 0, 0, 0, 0);
        int64_t u2 = sc(41, 2, 2, 0, 0, 0, 0);
        lnx_sockaddr_in s1, from;
        uint32_t l1 = sizeof s1, lfrom = sizeof from;
        char buf[32] = {0};
        memset(&s1, 0, sizeof s1);
        s1.family = 2; s1.addr = htonl(0x7f000001u); s1.port = 0;
        check("UDP bind + getsockname", sc(49, u1, (intptr_t)&s1, sizeof s1, 0, 0, 0) == 0 &&
              sc(51, u1, (intptr_t)&s1, (intptr_t)&l1, 0, 0, 0) == 0 && s1.port != 0);
        check("UDP sendto", sc(44, u2, (intptr_t)"UDP-PING", 8, 0, (intptr_t)&s1, sizeof s1) == 8);
        check("UDP recvfrom with sender addr",
              sc(45, u1, (intptr_t)buf, sizeof buf, 0, (intptr_t)&from, (intptr_t)&lfrom) == 8 &&
              strcmp(buf, "UDP-PING") == 0 && from.family == 2);
        check("close UDP sockets", sc(3, u1, 0, 0, 0, 0, 0) == 0 && sc(3, u2, 0, 0, 0, 0, 0) == 0);
    }

    /* 5. AF_UNIX returns -EAFNOSUPPORT (enables Bionic /etc/resolv.conf fallback) */
    check("AF_UNIX rejected with -EAFNOSUPPORT", sc(41, 1, 1, 0, 0, 0, 0) == -97);

    printf("net_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
