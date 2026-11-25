/*
 * net.c - Linux networking & event-multiplexing syscalls (socket, bind, listen,
 * connect, accept/accept4, sendto/recvfrom/sendmsg/recvmsg, shutdown,
 * getsockname/getpeername, setsockopt/getsockopt, socketpair, pipe/pipe2,
 * eventfd/eventfd2, poll/ppoll, epoll_create1/epoll_ctl/epoll_wait/epoll_pwait)
 * over Winsock2 on Windows and POSIX sockets on Linux.
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "net.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
typedef SOCKET os_sock_t;
#  define OS_SOCK_INVALID INVALID_SOCKET
typedef int os_socklen_t;
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <pthread.h>
#  include <sys/ioctl.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
typedef int os_sock_t;
#  define OS_SOCK_INVALID (-1)
typedef socklen_t os_socklen_t;
#endif

/* Linux x86_64 UAPI constants */
#define LNX_EPERM        1
#define LNX_ENOENT       2
#define LNX_EINTR        4
#define LNX_EBADF        9
#define LNX_EAGAIN       11
#define LNX_ENOMEM       12
#define LNX_EACCES       13
#define LNX_EFAULT       14
#define LNX_EEXIST       17
#define LNX_EINVAL       22
#define LNX_EMFILE       24
#define LNX_EPIPE        32
#define LNX_ENOSYS       38
#define LNX_ENOTSOCK     88
#define LNX_EMSGSIZE     90
#define LNX_EPROTONOSUPPORT 93
#define LNX_EOPNOTSUPP   95
#define LNX_EAFNOSUPPORT 97
#define LNX_EADDRINUSE   98
#define LNX_EADDRNOTAVAIL 99
#define LNX_ENETDOWN     100
#define LNX_ENETUNREACH  101
#define LNX_ECONNABORTED 103
#define LNX_ECONNRESET   104
#define LNX_ENOBUFS      105
#define LNX_EISCONN      106
#define LNX_ENOTCONN     107
#define LNX_ETIMEDOUT    110
#define LNX_ECONNREFUSED 111
#define LNX_EHOSTUNREACH 113
#define LNX_EALREADY     114
#define LNX_EINPROGRESS  115

#define LNX_AF_UNIX      1
#define LNX_AF_INET      2
#define LNX_AF_INET6     10

#define LNX_SOCK_STREAM  1
#define LNX_SOCK_DGRAM   2
#define LNX_SOCK_NONBLOCK 0x00000800
#define LNX_SOCK_CLOEXEC  0x00080000
#define LNX_O_NONBLOCK    0x00000800

#define LNX_SOL_SOCKET   1
#define LNX_IPPROTO_IP   0
#define LNX_IPPROTO_TCP  6
#define LNX_IPPROTO_IPV6 41

#define LNX_SO_REUSEADDR 2
#define LNX_SO_TYPE      3
#define LNX_SO_ERROR     4
#define LNX_SO_BROADCAST 6
#define LNX_SO_SNDBUF    7
#define LNX_SO_RCVBUF    8
#define LNX_SO_KEEPALIVE 9
#define LNX_SO_LINGER    13
#define LNX_SO_REUSEPORT 15
#define LNX_SO_RCVTIMEO  20
#define LNX_SO_SNDTIMEO  21

#define LNX_TCP_NODELAY  1
#define LNX_IPV6_V6ONLY  26

#define LNX_POLLIN       0x0001
#define LNX_POLLPRI      0x0002
#define LNX_POLLOUT      0x0004
#define LNX_POLLERR      0x0008
#define LNX_POLLHUP      0x0010
#define LNX_POLLNVAL     0x0020

#define LNX_EPOLL_CTL_ADD 1
#define LNX_EPOLL_CTL_DEL 2
#define LNX_EPOLL_CTL_MOD 3

#define LNX_F_DUPFD      0
#define LNX_F_GETFD      1
#define LNX_F_SETFD      2
#define LNX_F_GETFL      3
#define LNX_F_SETFL      4
#define LNX_F_DUPFD_CLOEXEC 1030

#define LNX_FIONREAD     0x541B
#define LNX_FIONBIO      0x5421

#define NET_MAX_SLOTS    (AFW_NET_FD_MAX - AFW_NET_FD_BASE)
#define MAX_EPOLL_WATCH  128

enum net_kind {
    NET_NONE = 0,
    NET_SOCK,
    NET_PIPE_RD,
    NET_PIPE_WR,
    NET_EVENTFD,
    NET_EPOLL
};

typedef struct {
    int      fd;
    uint32_t events;
    uint64_t data;
} epoll_watch;

typedef struct {
    enum net_kind kind;
    os_sock_t     sock;
    os_sock_t     peer_sock; /* for eventfd: writer end */
    int           domain;    /* LNX_AF_* */
    int           stype;     /* LNX_SOCK_* */
    int           nonblock;
    int           cloexec;
    int           ef_sema;
    uint64_t      ef_val;
    int           nwatch;
    epoll_watch   watch[MAX_EPOLL_WATCH];
} net_slot;

static net_slot g_net[NET_MAX_SLOTS];
static int g_net_inited = 0;

#if defined(_WIN32)
static SRWLOCK g_net_lock = SRWLOCK_INIT;
static void net_lock(void)   { AcquireSRWLockExclusive(&g_net_lock); }
static void net_unlock(void) { ReleaseSRWLockExclusive(&g_net_lock); }

static int wsa_err_to_lnx(int e) {
    switch (e) {
    case 0:                   return 0;
    case WSAEINTR:            return LNX_EINTR;
    case WSAEBADF:            return LNX_EBADF;
    case WSAEACCES:           return LNX_EACCES;
    case WSAEFAULT:           return LNX_EFAULT;
    case WSAEINVAL:           return LNX_EINVAL;
    case WSAEMFILE:           return LNX_EMFILE;
    case WSAEWOULDBLOCK:      return LNX_EAGAIN;
    case WSAEINPROGRESS:      return LNX_EINPROGRESS;
    case WSAEALREADY:         return LNX_EALREADY;
    case WSAENOTSOCK:         return LNX_ENOTSOCK;
    case WSAEMSGSIZE:         return LNX_EMSGSIZE;
    case WSAEPROTONOSUPPORT:  return LNX_EPROTONOSUPPORT;
    case WSAEOPNOTSUPP:       return LNX_EOPNOTSUPP;
    case WSAEAFNOSUPPORT:     return LNX_EAFNOSUPPORT;
    case WSAEADDRINUSE:       return LNX_EADDRINUSE;
    case WSAEADDRNOTAVAIL:    return LNX_EADDRNOTAVAIL;
    case WSAENETDOWN:         return LNX_ENETDOWN;
    case WSAENETUNREACH:      return LNX_ENETUNREACH;
    case WSAECONNABORTED:     return LNX_ECONNABORTED;
    case WSAECONNRESET:       return LNX_ECONNRESET;
    case WSAENOBUFS:          return LNX_ENOBUFS;
    case WSAEISCONN:          return LNX_EISCONN;
    case WSAENOTCONN:         return LNX_ENOTCONN;
    case WSAETIMEDOUT:        return LNX_ETIMEDOUT;
    case WSAECONNREFUSED:     return LNX_ECONNREFUSED;
    case WSAEHOSTUNREACH:     return LNX_EHOSTUNREACH;
    default:                  return LNX_EINVAL;
    }
}
static int last_sock_err(void) { return -wsa_err_to_lnx(WSAGetLastError()); }
static void os_close_sock(os_sock_t s) { if (s != OS_SOCK_INVALID) closesocket(s); }
static int os_set_nonblock(os_sock_t s, int nb) {
    u_long v = nb ? 1u : 0u;
    return ioctlsocket(s, FIONBIO, &v) == 0 ? 0 : last_sock_err();
}
#else
static pthread_mutex_t g_net_lock = PTHREAD_MUTEX_INITIALIZER;
static void net_lock(void)   { pthread_mutex_lock(&g_net_lock); }
static void net_unlock(void) { pthread_mutex_unlock(&g_net_lock); }
static int last_sock_err(void) { return -errno; }
static void os_close_sock(os_sock_t s) { if (s != OS_SOCK_INVALID) close(s); }
static int os_set_nonblock(os_sock_t s, int nb) {
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return -errno;
    if (nb) fl |= O_NONBLOCK; else fl &= ~O_NONBLOCK;
    return fcntl(s, F_SETFL, fl) == 0 ? 0 : -errno;
}
#endif

int afw_net_init(void) {
    net_lock();
    if (!g_net_inited) {
#if defined(_WIN32)
        WSADATA wd;
        if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
            net_unlock();
            return -1;
        }
#endif
        memset(g_net, 0, sizeof g_net);
        g_net_inited = 1;
    }
    net_unlock();
    return 0;
}

int afw_net_is_fd(int64_t fd) {
    return fd >= AFW_NET_FD_BASE && fd < AFW_NET_FD_MAX;
}

static int alloc_slot_locked(int min_fd) {
    int start = (min_fd > AFW_NET_FD_BASE) ? (min_fd - AFW_NET_FD_BASE) : 0;
    int i;
    if (start < 0) start = 0;
    for (i = start; i < NET_MAX_SLOTS; i++) {
        if (g_net[i].kind == NET_NONE) {
            memset(&g_net[i], 0, sizeof g_net[i]);
            g_net[i].sock = OS_SOCK_INVALID;
            g_net[i].peer_sock = OS_SOCK_INVALID;
            return i;
        }
    }
    return -1;
}

static net_slot *get_slot_locked(int64_t fd) {
    if (!afw_net_is_fd(fd)) return NULL;
    net_slot *s = &g_net[(int)(fd - AFW_NET_FD_BASE)];
    return s->kind != NET_NONE ? s : NULL;
}

/* Create a connected TCP loopback socket pair (pollable on both Windows and Linux). */
static int make_loopback_pair(os_sock_t out[2]) {
    os_sock_t lst = OS_SOCK_INVALID, c = OS_SOCK_INVALID, a = OS_SOCK_INVALID;
    struct sockaddr_in sin;
    os_socklen_t slen = (os_socklen_t)sizeof sin;
    int one = 1;

    out[0] = OS_SOCK_INVALID;
    out[1] = OS_SOCK_INVALID;
    lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lst == OS_SOCK_INVALID) return last_sock_err();
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (bind(lst, (struct sockaddr *)&sin, sizeof sin) != 0 ||
        listen(lst, 1) != 0 ||
        getsockname(lst, (struct sockaddr *)&sin, &slen) != 0) {
        int e = last_sock_err();
        os_close_sock(lst);
        return e;
    }
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == OS_SOCK_INVALID) {
        int e = last_sock_err();
        os_close_sock(lst);
        return e;
    }
    if (connect(c, (struct sockaddr *)&sin, sizeof sin) != 0) {
        int e = last_sock_err();
        os_close_sock(c);
        os_close_sock(lst);
        return e;
    }
    a = accept(lst, NULL, NULL);
    os_close_sock(lst);
    if (a == OS_SOCK_INVALID) {
        int e = last_sock_err();
        os_close_sock(c);
        return e;
    }
    (void)setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    (void)setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    out[0] = a; /* read end */
    out[1] = c; /* write end */
    return 0;
}

/* Translate Linux sockaddr -> host sockaddr (only AF_INET6 differs: 10 vs 23 on Win32). */
static int lnx_to_host_addr(const void *in, int inlen, struct sockaddr_storage *out, os_socklen_t *outlen) {
    uint16_t fam;
    if (!in || inlen < 2 || inlen > (int)sizeof *out) return -LNX_EINVAL;
    memset(out, 0, sizeof *out);
    memcpy(out, in, (size_t)inlen);
    memcpy(&fam, in, 2);
    if (fam == LNX_AF_INET) {
        ((struct sockaddr *)out)->sa_family = AF_INET;
    } else if (fam == LNX_AF_INET6) {
        ((struct sockaddr *)out)->sa_family = AF_INET6;
    } else {
        return -LNX_EAFNOSUPPORT;
    }
    *outlen = (os_socklen_t)inlen;
    return 0;
}

static void host_to_lnx_addr(const struct sockaddr_storage *in, os_socklen_t inlen,
                             void *out, uint32_t *outlen_io) {
    uint16_t fam = in->ss_family;
    struct sockaddr_storage tmp = *in;
    uint32_t copy;
    if (!out || !outlen_io) return;
    if (fam == AF_INET) fam = LNX_AF_INET;
    else if (fam == AF_INET6) fam = LNX_AF_INET6;
    memcpy(&tmp, &fam, 2);
    copy = (*outlen_io < (uint32_t)inlen) ? *outlen_io : (uint32_t)inlen;
    memcpy(out, &tmp, copy);
    *outlen_io = (uint32_t)inlen;
}

static int64_t net_socket(int64_t domain, int64_t type, int64_t proto) {
    int base_type = (int)(type & 0xFF);
    int nb = (type & LNX_SOCK_NONBLOCK) != 0;
    int cx = (type & LNX_SOCK_CLOEXEC) != 0;
    int hdom, htype, hproto = (int)proto;
    os_sock_t s;
    int idx;

    if (!g_net_inited) (void)afw_net_init();
    if (domain == LNX_AF_INET) hdom = AF_INET;
    else if (domain == LNX_AF_INET6) hdom = AF_INET6;
    else if (domain == LNX_AF_UNIX) return -LNX_EAFNOSUPPORT; /* forces Bionic DNS fallback to /etc/resolv.conf */
    else return -LNX_EAFNOSUPPORT;

    if (base_type == LNX_SOCK_STREAM) htype = SOCK_STREAM;
    else if (base_type == LNX_SOCK_DGRAM) htype = SOCK_DGRAM;
    else return -LNX_EPROTONOSUPPORT;

    s = socket(hdom, htype, hproto);
    if (s == OS_SOCK_INVALID) return last_sock_err();
    if (nb) (void)os_set_nonblock(s, 1);

    net_lock();
    idx = alloc_slot_locked(0);
    if (idx < 0) {
        net_unlock();
        os_close_sock(s);
        return -LNX_EMFILE;
    }
    g_net[idx].kind = NET_SOCK;
    g_net[idx].sock = s;
    g_net[idx].domain = (int)domain;
    g_net[idx].stype = base_type;
    g_net[idx].nonblock = nb;
    g_net[idx].cloexec = cx;
    net_unlock();
    return (int64_t)(AFW_NET_FD_BASE + idx);
}

static int64_t net_close(int64_t fd) {
    os_sock_t s1 = OS_SOCK_INVALID, s2 = OS_SOCK_INVALID;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl) { net_unlock(); return -LNX_EBADF; }
    s1 = sl->sock;
    s2 = sl->peer_sock;
    memset(sl, 0, sizeof *sl);
    sl->sock = OS_SOCK_INVALID;
    sl->peer_sock = OS_SOCK_INVALID;
    net_unlock();
    os_close_sock(s1);
    os_close_sock(s2);
    return 0;
}

static int64_t net_read(int64_t fd, void *buf, uint64_t len) {
    os_sock_t s;
    enum net_kind kind;
    int nb;
    if (!buf && len > 0) return -LNX_EFAULT;
    if (len > 0x7ffff000ULL) len = 0x7ffff000ULL;

    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl) { net_unlock(); return -LNX_EBADF; }
    kind = sl->kind;
    s = sl->sock;
    nb = sl->nonblock;
    if (kind == NET_EVENTFD) {
        if (len < 8) { net_unlock(); return -LNX_EINVAL; }
        if (sl->ef_val == 0) {
            net_unlock();
            if (nb) return -LNX_EAGAIN;
            /* Block until a byte is written to the eventfd socket pair */
            char b;
            int r = (int)recv(s, &b, 1, 0);
            if (r <= 0) return r == 0 ? 0 : last_sock_err();
            net_lock();
            sl = get_slot_locked(fd);
            if (!sl) { net_unlock(); return -LNX_EBADF; }
        } else {
            char drain[64];
            (void)os_set_nonblock(s, 1);
            while (recv(s, drain, sizeof drain, 0) > 0) {}
            if (!nb) (void)os_set_nonblock(s, 0);
        }
        uint64_t outv = sl->ef_sema ? (sl->ef_val ? 1 : 0) : sl->ef_val;
        if (sl->ef_sema && sl->ef_val > 0) sl->ef_val--;
        else sl->ef_val = 0;
        net_unlock();
        memcpy(buf, &outv, 8);
        return 8;
    }
    net_unlock();
    if (kind != NET_SOCK && kind != NET_PIPE_RD) return -LNX_EBADF;
    if (len == 0) return 0;
    {
        int r = (int)recv(s, (char *)buf, (int)len, 0);
        return r < 0 ? last_sock_err() : (int64_t)r;
    }
}

static int64_t net_write(int64_t fd, const void *buf, uint64_t len) {
    os_sock_t s;
    enum net_kind kind;
    if (!buf && len > 0) return -LNX_EFAULT;
    if (len > 0x7ffff000ULL) len = 0x7ffff000ULL;

    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl) { net_unlock(); return -LNX_EBADF; }
    kind = sl->kind;
    s = sl->sock;
    if (kind == NET_EVENTFD) {
        uint64_t add = 0;
        os_sock_t w = sl->peer_sock;
        if (len < 8) { net_unlock(); return -LNX_EINVAL; }
        memcpy(&add, buf, 8);
        if (add == UINT64_MAX) { net_unlock(); return -LNX_EINVAL; }
        sl->ef_val += add;
        net_unlock();
        if (add > 0) {
            char sig = 1;
            (void)send(w, &sig, 1, 0);
        }
        return 8;
    }
    net_unlock();
    if (kind != NET_SOCK && kind != NET_PIPE_WR) return -LNX_EBADF;
    if (len == 0) return 0;
    {
        int flags = 0;
#if !defined(_WIN32)
        flags = MSG_NOSIGNAL;
#endif
        int r = (int)send(s, (const char *)buf, (int)len, flags);
        return r < 0 ? last_sock_err() : (int64_t)r;
    }
}

static int64_t net_connect(int64_t fd, const void *addr, int64_t alen) {
    struct sockaddr_storage ss;
    os_socklen_t hlen = 0;
    os_sock_t s;
    int rc = lnx_to_host_addr(addr, (int)alen, &ss, &hlen);
    if (rc < 0) return rc;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    if (connect(s, (const struct sockaddr *)&ss, hlen) == 0) return 0;
    {
        int err = last_sock_err();
#if defined(_WIN32)
        /* On Windows, non-blocking connect returns WSAEWOULDBLOCK; Linux returns -EINPROGRESS. */
        if (err == -LNX_EAGAIN) return -LNX_EINPROGRESS;
#endif
        return err;
    }
}

static int64_t net_bind(int64_t fd, const void *addr, int64_t alen) {
    struct sockaddr_storage ss;
    os_socklen_t hlen = 0;
    os_sock_t s;
    int rc = lnx_to_host_addr(addr, (int)alen, &ss, &hlen);
    if (rc < 0) return rc;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    return bind(s, (const struct sockaddr *)&ss, hlen) == 0 ? 0 : last_sock_err();
}

static int64_t net_listen(int64_t fd, int64_t backlog) {
    os_sock_t s;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    return listen(s, (int)backlog) == 0 ? 0 : last_sock_err();
}

static int64_t net_accept4(int64_t fd, void *addr, uint32_t *alen_io, int64_t flags) {
    os_sock_t s, ns;
    int dom, stype, idx;
    struct sockaddr_storage ss;
    os_socklen_t hlen = (os_socklen_t)sizeof ss;

    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock; dom = sl->domain; stype = sl->stype;
    net_unlock();

    ns = accept(s, addr ? (struct sockaddr *)&ss : NULL, addr ? &hlen : NULL);
    if (ns == OS_SOCK_INVALID) return last_sock_err();
    if (addr && alen_io) host_to_lnx_addr(&ss, hlen, addr, alen_io);
    if (flags & LNX_SOCK_NONBLOCK) (void)os_set_nonblock(ns, 1);

    net_lock();
    idx = alloc_slot_locked(0);
    if (idx < 0) {
        net_unlock();
        os_close_sock(ns);
        return -LNX_EMFILE;
    }
    g_net[idx].kind = NET_SOCK;
    g_net[idx].sock = ns;
    g_net[idx].domain = dom;
    g_net[idx].stype = stype;
    g_net[idx].nonblock = (flags & LNX_SOCK_NONBLOCK) != 0;
    g_net[idx].cloexec = (flags & LNX_SOCK_CLOEXEC) != 0;
    net_unlock();
    return (int64_t)(AFW_NET_FD_BASE + idx);
}

static int64_t net_sendto(int64_t fd, const void *buf, uint64_t len, int64_t flags,
                          const void *addr, int64_t alen) {
    os_sock_t s;
    int hflags = 0;
    if (!buf && len > 0) return -LNX_EFAULT;
    if (len > 0x7ffff000ULL) len = 0x7ffff000ULL;
#if !defined(_WIN32)
    hflags = MSG_NOSIGNAL;
#endif
    if (flags & 0x01) hflags |= MSG_OOB;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    if (addr && alen > 0) {
        struct sockaddr_storage ss;
        os_socklen_t hlen = 0;
        int rc = lnx_to_host_addr(addr, (int)alen, &ss, &hlen);
        if (rc < 0) return rc;
        int r = (int)sendto(s, (const char *)buf, (int)len, hflags, (const struct sockaddr *)&ss, hlen);
        return r < 0 ? last_sock_err() : (int64_t)r;
    }
    {
        int r = (int)send(s, (const char *)buf, (int)len, hflags);
        return r < 0 ? last_sock_err() : (int64_t)r;
    }
}

static int64_t net_recvfrom(int64_t fd, void *buf, uint64_t len, int64_t flags,
                            void *addr, uint32_t *alen_io) {
    os_sock_t s;
    int hflags = 0;
    struct sockaddr_storage ss;
    os_socklen_t hlen = (os_socklen_t)sizeof ss;
    if (!buf && len > 0) return -LNX_EFAULT;
    if (len > 0x7ffff000ULL) len = 0x7ffff000ULL;
    if (flags & 0x02) hflags |= MSG_PEEK;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    {
        int r = (int)recvfrom(s, (char *)buf, (int)len, hflags,
                              addr ? (struct sockaddr *)&ss : NULL,
                              addr ? &hlen : NULL);
        if (r < 0) return last_sock_err();
        if (addr && alen_io) host_to_lnx_addr(&ss, hlen, addr, alen_io);
        return (int64_t)r;
    }
}

static int64_t net_shutdown(int64_t fd, int64_t how) {
    os_sock_t s;
    int hhow = (int)how;
#if defined(_WIN32)
    hhow = (how == 0) ? SD_RECEIVE : (how == 1) ? SD_SEND : SD_BOTH;
#endif
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    return shutdown(s, hhow) == 0 ? 0 : last_sock_err();
}

static int64_t net_sockname(int64_t fd, void *addr, uint32_t *alen_io, int peer) {
    os_sock_t s;
    struct sockaddr_storage ss;
    os_socklen_t hlen = (os_socklen_t)sizeof ss;
    if (!addr || !alen_io) return -LNX_EFAULT;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    if ((peer ? getpeername(s, (struct sockaddr *)&ss, &hlen)
              : getsockname(s, (struct sockaddr *)&ss, &hlen)) != 0)
        return last_sock_err();
    host_to_lnx_addr(&ss, hlen, addr, alen_io);
    return 0;
}

static int map_sockopt(int64_t lvl, int64_t opt, int *hlvl, int *hopt) {
    if (lvl == LNX_SOL_SOCKET) {
        *hlvl = SOL_SOCKET;
        switch (opt) {
        case LNX_SO_REUSEADDR: *hopt = SO_REUSEADDR; return 0;
        case LNX_SO_TYPE:      *hopt = SO_TYPE; return 0;
        case LNX_SO_ERROR:     *hopt = SO_ERROR; return 0;
        case LNX_SO_BROADCAST: *hopt = SO_BROADCAST; return 0;
        case LNX_SO_SNDBUF:    *hopt = SO_SNDBUF; return 0;
        case LNX_SO_RCVBUF:    *hopt = SO_RCVBUF; return 0;
        case LNX_SO_KEEPALIVE: *hopt = SO_KEEPALIVE; return 0;
        case LNX_SO_LINGER:    *hopt = SO_LINGER; return 0;
        case LNX_SO_RCVTIMEO:  *hopt = SO_RCVTIMEO; return 0;
        case LNX_SO_SNDTIMEO:  *hopt = SO_SNDTIMEO; return 0;
        case LNX_SO_REUSEPORT: *hopt = SO_REUSEADDR; return 0;
        default: return -1;
        }
    } else if (lvl == LNX_IPPROTO_TCP) {
        *hlvl = IPPROTO_TCP;
        if (opt == LNX_TCP_NODELAY) { *hopt = TCP_NODELAY; return 0; }
    } else if (lvl == LNX_IPPROTO_IPV6) {
        *hlvl = IPPROTO_IPV6;
        if (opt == LNX_IPV6_V6ONLY) { *hopt = IPV6_V6ONLY; return 0; }
    }
    return -1;
}

static int64_t net_setsockopt(int64_t fd, int64_t lvl, int64_t opt, const void *val, int64_t len) {
    os_sock_t s;
    int hlvl = 0, hopt = 0;
    if (!val && len > 0) return -LNX_EFAULT;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    if (map_sockopt(lvl, opt, &hlvl, &hopt) != 0) return 0; /* ignore benign unknown sockopts */
#if defined(_WIN32)
    if (lvl == LNX_SOL_SOCKET && (opt == LNX_SO_RCVTIMEO || opt == LNX_SO_SNDTIMEO) && len >= 16) {
        /* Linux struct timeval {int64_t tv_sec, tv_usec} -> Windows DWORD milliseconds */
        const int64_t *tv = (const int64_t *)val;
        DWORD ms = (DWORD)(tv[0] * 1000LL + tv[1] / 1000LL);
        return setsockopt(s, hlvl, hopt, (const char *)&ms, sizeof ms) == 0 ? 0 : last_sock_err();
    }
#endif
    return setsockopt(s, hlvl, hopt, (const char *)val, (os_socklen_t)len) == 0 ? 0 : last_sock_err();
}

static int64_t net_getsockopt(int64_t fd, int64_t lvl, int64_t opt, void *val, uint32_t *len_io) {
    os_sock_t s;
    int hlvl = 0, hopt = 0;
    os_socklen_t hlen;
    if (!val || !len_io) return -LNX_EFAULT;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->kind != NET_SOCK) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    if (map_sockopt(lvl, opt, &hlvl, &hopt) != 0) {
        if (*len_io >= 4) { int z = 0; memcpy(val, &z, 4); *len_io = 4; }
        return 0;
    }
    hlen = (os_socklen_t)*len_io;
    if (getsockopt(s, hlvl, hopt, (char *)val, &hlen) != 0) return last_sock_err();
#if defined(_WIN32)
    if (lvl == LNX_SOL_SOCKET && opt == LNX_SO_ERROR && hlen >= 4) {
        int we = 0, le;
        memcpy(&we, val, 4);
        le = wsa_err_to_lnx(we);
        memcpy(val, &le, 4);
    }
#endif
    *len_io = (uint32_t)hlen;
    return 0;
}

static int64_t net_pipe2(int32_t *fds_out, int64_t flags) {
    os_sock_t pair[2];
    int nb = (flags & LNX_O_NONBLOCK) != 0;
    int cx = (flags & LNX_SOCK_CLOEXEC) != 0;
    int i0, i1, rc;
    if (!fds_out) return -LNX_EFAULT;
    if (!g_net_inited) (void)afw_net_init();
    rc = make_loopback_pair(pair);
    if (rc < 0) return rc;
    if (nb) { (void)os_set_nonblock(pair[0], 1); (void)os_set_nonblock(pair[1], 1); }

    net_lock();
    i0 = alloc_slot_locked(0);
    if (i0 >= 0) g_net[i0].kind = NET_PIPE_RD;
    i1 = (i0 >= 0) ? alloc_slot_locked(0) : -1;
    if (i0 < 0 || i1 < 0) {
        if (i0 >= 0) g_net[i0].kind = NET_NONE;
        net_unlock();
        os_close_sock(pair[0]); os_close_sock(pair[1]);
        return -LNX_EMFILE;
    }
    g_net[i0].sock = pair[0]; g_net[i0].nonblock = nb; g_net[i0].cloexec = cx;
    g_net[i1].kind = NET_PIPE_WR;
    g_net[i1].sock = pair[1]; g_net[i1].nonblock = nb; g_net[i1].cloexec = cx;
    net_unlock();
    fds_out[0] = AFW_NET_FD_BASE + i0;
    fds_out[1] = AFW_NET_FD_BASE + i1;
    return 0;
}

static int64_t net_socketpair(int64_t domain, int64_t type, int32_t *fds_out) {
    os_sock_t pair[2];
    int nb = (type & LNX_SOCK_NONBLOCK) != 0;
    int cx = (type & LNX_SOCK_CLOEXEC) != 0;
    int i0, i1, rc;
    (void)domain;
    if (!fds_out) return -LNX_EFAULT;
    if (!g_net_inited) (void)afw_net_init();
    rc = make_loopback_pair(pair);
    if (rc < 0) return rc;
    if (nb) { (void)os_set_nonblock(pair[0], 1); (void)os_set_nonblock(pair[1], 1); }

    net_lock();
    i0 = alloc_slot_locked(0);
    if (i0 >= 0) g_net[i0].kind = NET_SOCK;
    i1 = (i0 >= 0) ? alloc_slot_locked(0) : -1;
    if (i0 < 0 || i1 < 0) {
        if (i0 >= 0) g_net[i0].kind = NET_NONE;
        net_unlock();
        os_close_sock(pair[0]); os_close_sock(pair[1]);
        return -LNX_EMFILE;
    }
    g_net[i0].sock = pair[0]; g_net[i0].domain = LNX_AF_INET; g_net[i0].stype = LNX_SOCK_STREAM;
    g_net[i0].nonblock = nb; g_net[i0].cloexec = cx;
    g_net[i1].kind = NET_SOCK;
    g_net[i1].sock = pair[1]; g_net[i1].domain = LNX_AF_INET; g_net[i1].stype = LNX_SOCK_STREAM;
    g_net[i1].nonblock = nb; g_net[i1].cloexec = cx;
    net_unlock();
    fds_out[0] = AFW_NET_FD_BASE + i0;
    fds_out[1] = AFW_NET_FD_BASE + i1;
    return 0;
}

static int64_t net_eventfd2(uint64_t initval, int64_t flags) {
    os_sock_t pair[2];
    int nb = (flags & LNX_O_NONBLOCK) != 0;
    int cx = (flags & LNX_SOCK_CLOEXEC) != 0;
    int idx, rc;
    if (!g_net_inited) (void)afw_net_init();
    rc = make_loopback_pair(pair);
    if (rc < 0) return rc;
    if (initval > 0) {
        char sig = 1;
        (void)send(pair[1], &sig, 1, 0);
    }
    net_lock();
    idx = alloc_slot_locked(0);
    if (idx < 0) {
        net_unlock();
        os_close_sock(pair[0]); os_close_sock(pair[1]);
        return -LNX_EMFILE;
    }
    g_net[idx].kind = NET_EVENTFD;
    g_net[idx].sock = pair[0];
    g_net[idx].peer_sock = pair[1];
    g_net[idx].nonblock = nb;
    g_net[idx].cloexec = cx;
    g_net[idx].ef_sema = (flags & 1) != 0; /* EFD_SEMAPHORE */
    g_net[idx].ef_val = initval;
    net_unlock();
    return (int64_t)(AFW_NET_FD_BASE + idx);
}

typedef struct {
    int32_t fd;
    int16_t events;
    int16_t revents;
} lnx_pollfd;

static int64_t net_poll(lnx_pollfd *fds, uint64_t nfds, int32_t timeout_ms) {
    struct pollfd stack_pfds[64];
    int map_idx[64];
    struct pollfd *pfds = stack_pfds;
    int *midx = map_idx;
    uint64_t i;
    int np = 0, ready = 0;

    if (nfds > 1024) return -LNX_EINVAL;
    if (nfds == 0) {
        if (timeout_ms > 0) {
#if defined(_WIN32)
            Sleep((DWORD)timeout_ms);
#else
            usleep((useconds_t)timeout_ms * 1000u);
#endif
        }
        return 0;
    }
    if (!fds) return -LNX_EFAULT;
    if (nfds > 64) {
        pfds = (struct pollfd *)calloc(nfds, sizeof *pfds);
        midx = (int *)calloc(nfds, sizeof *midx);
        if (!pfds || !midx) { free(pfds); free(midx); return -LNX_ENOMEM; }
    }

    net_lock();
    for (i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        if (fds[i].fd < 0) continue;
        if (afw_net_is_fd(fds[i].fd)) {
            net_slot *sl = get_slot_locked(fds[i].fd);
            if (!sl || sl->sock == OS_SOCK_INVALID) {
                fds[i].revents = LNX_POLLNVAL;
                ready++;
            } else {
                short ev = 0;
                if (fds[i].events & LNX_POLLIN)  ev |= POLLRDNORM;
                if (fds[i].events & LNX_POLLOUT) ev |= POLLWRNORM;
                pfds[np].fd = sl->sock;
                pfds[np].events = ev;
                pfds[np].revents = 0;
                midx[np] = (int)i;
                np++;
            }
        } else {
            /* Regular files / stdio are immediately ready for requested read/write */
            fds[i].revents = (int16_t)(fds[i].events & (LNX_POLLIN | LNX_POLLOUT));
            if (fds[i].revents) ready++;
        }
    }
    net_unlock();

    if (np > 0) {
        int t = ready > 0 ? 0 : timeout_ms;
#if defined(_WIN32)
        int pr = WSAPoll(pfds, (ULONG)np, t);
#else
        int pr = poll(pfds, (nfds_t)np, t);
#endif
        if (pr < 0) {
            int e = last_sock_err();
            if (pfds != stack_pfds) { free(pfds); free(midx); }
            return e;
        }
        for (int k = 0; k < np; k++) {
            int16_t rev = 0;
            if (pfds[k].revents & (POLLRDNORM | POLLIN)) rev |= LNX_POLLIN;
            if (pfds[k].revents & (POLLWRNORM | POLLOUT)) rev |= LNX_POLLOUT;
            if (pfds[k].revents & POLLERR)  rev |= LNX_POLLERR;
            if (pfds[k].revents & POLLHUP)  rev |= LNX_POLLHUP;
            if (pfds[k].revents & POLLNVAL) rev |= LNX_POLLNVAL;
            if (rev) {
                fds[midx[k]].revents = rev;
                ready++;
            }
        }
    }
    if (pfds != stack_pfds) { free(pfds); free(midx); }
    return (int64_t)ready;
}

static int64_t net_epoll_create1(int64_t flags) {
    int idx;
    if (!g_net_inited) (void)afw_net_init();
    net_lock();
    idx = alloc_slot_locked(0);
    if (idx < 0) { net_unlock(); return -LNX_EMFILE; }
    g_net[idx].kind = NET_EPOLL;
    g_net[idx].cloexec = (flags & LNX_SOCK_CLOEXEC) != 0;
    net_unlock();
    return (int64_t)(AFW_NET_FD_BASE + idx);
}

#pragma pack(push, 1)
typedef struct {
    uint32_t events;
    uint64_t data;
} lnx_epoll_event;
#pragma pack(pop)

static int64_t net_epoll_ctl(int64_t epfd, int64_t op, int64_t fd, const lnx_epoll_event *ev) {
    int i, found = -1;
    net_lock();
    net_slot *ep = get_slot_locked(epfd);
    if (!ep || ep->kind != NET_EPOLL) { net_unlock(); return -LNX_EBADF; }
    for (i = 0; i < ep->nwatch; i++) {
        if (ep->watch[i].fd == (int)fd) { found = i; break; }
    }
    if (op == LNX_EPOLL_CTL_ADD) {
        if (!ev) { net_unlock(); return -LNX_EFAULT; }
        if (found >= 0) { net_unlock(); return -LNX_EEXIST; }
        if (ep->nwatch >= MAX_EPOLL_WATCH) { net_unlock(); return -LNX_ENOMEM; }
        ep->watch[ep->nwatch].fd = (int)fd;
        ep->watch[ep->nwatch].events = ev->events;
        ep->watch[ep->nwatch].data = ev->data;
        ep->nwatch++;
    } else if (op == LNX_EPOLL_CTL_MOD) {
        if (!ev) { net_unlock(); return -LNX_EFAULT; }
        if (found < 0) { net_unlock(); return -LNX_ENOENT; }
        ep->watch[found].events = ev->events;
        ep->watch[found].data = ev->data;
    } else if (op == LNX_EPOLL_CTL_DEL) {
        if (found < 0) { net_unlock(); return -LNX_ENOENT; }
        ep->watch[found] = ep->watch[ep->nwatch - 1];
        ep->nwatch--;
    } else {
        net_unlock();
        return -LNX_EINVAL;
    }
    net_unlock();
    return 0;
}

static int64_t net_epoll_wait(int64_t epfd, lnx_epoll_event *events, int64_t maxevents, int32_t timeout_ms) {
    epoll_watch snap[MAX_EPOLL_WATCH];
    lnx_pollfd pfds[MAX_EPOLL_WATCH];
    int n = 0, i, out = 0;
    int64_t pr;

    if (maxevents <= 0) return -LNX_EINVAL;
    if (!events) return -LNX_EFAULT;
    net_lock();
    net_slot *ep = get_slot_locked(epfd);
    if (!ep || ep->kind != NET_EPOLL) { net_unlock(); return -LNX_EBADF; }
    n = ep->nwatch;
    if (n > 0) memcpy(snap, ep->watch, (size_t)n * sizeof snap[0]);
    net_unlock();

    for (i = 0; i < n; i++) {
        pfds[i].fd = snap[i].fd;
        pfds[i].events = (int16_t)(snap[i].events & (LNX_POLLIN | LNX_POLLOUT | LNX_POLLPRI));
        pfds[i].revents = 0;
    }
    pr = net_poll(pfds, (uint64_t)n, timeout_ms);
    if (pr < 0) return pr;
    for (i = 0; i < n && out < maxevents; i++) {
        if (pfds[i].revents) {
            events[out].events = (uint32_t)(uint16_t)pfds[i].revents;
            events[out].data = snap[i].data;
            out++;
        }
    }
    return (int64_t)out;
}

static int64_t net_fcntl(int64_t fd, int64_t cmd, int64_t arg) {
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl) { net_unlock(); return -LNX_EBADF; }
    if (cmd == LNX_F_GETFD) {
        int r = sl->cloexec ? 1 : 0;
        net_unlock();
        return r;
    }
    if (cmd == LNX_F_SETFD) {
        sl->cloexec = (arg & 1) != 0;
        net_unlock();
        return 0;
    }
    if (cmd == LNX_F_GETFL) {
        int r = (sl->kind == NET_PIPE_RD ? 0 : sl->kind == NET_PIPE_WR ? 1 : 2) |
                (sl->nonblock ? LNX_O_NONBLOCK : 0);
        net_unlock();
        return r;
    }
    if (cmd == LNX_F_SETFL) {
        int nb = (arg & LNX_O_NONBLOCK) != 0;
        os_sock_t s = sl->sock;
        sl->nonblock = nb;
        net_unlock();
        if (s != OS_SOCK_INVALID) (void)os_set_nonblock(s, nb);
        return 0;
    }
    net_unlock();
    return -LNX_EINVAL;
}

static int64_t net_ioctl(int64_t fd, int64_t req, int64_t arg) {
    os_sock_t s;
    net_lock();
    net_slot *sl = get_slot_locked(fd);
    if (!sl || sl->sock == OS_SOCK_INVALID) { net_unlock(); return -LNX_EBADF; }
    s = sl->sock;
    net_unlock();
    if (req == LNX_FIONREAD) {
        if (!arg) return -LNX_EFAULT;
#if defined(_WIN32)
        u_long avail = 0;
        if (ioctlsocket(s, FIONREAD, &avail) != 0) return last_sock_err();
        *(int32_t *)(uintptr_t)arg = (int32_t)avail;
#else
        int avail = 0;
        if (ioctl(s, FIONREAD, &avail) != 0) return last_sock_err();
        *(int32_t *)(uintptr_t)arg = (int32_t)avail;
#endif
        return 0;
    }
    if (req == LNX_FIONBIO) {
        int nb;
        if (!arg) return -LNX_EFAULT;
        nb = (*(const int32_t *)(uintptr_t)arg) != 0;
        net_lock();
        sl = get_slot_locked(fd);
        if (sl) sl->nonblock = nb;
        net_unlock();
        return os_set_nonblock(s, nb);
    }
    return -25; /* -ENOTTY */
}

int afw_net_syscall(int64_t nr, const int64_t *a, int64_t *ret_out) {
    switch (nr) {
    case 0: /* read */
        if (!afw_net_is_fd(a[0])) return 0;
        *ret_out = net_read(a[0], (void *)(uintptr_t)a[1], (uint64_t)a[2]);
        return 1;
    case 1: /* write */
        if (!afw_net_is_fd(a[0])) return 0;
        *ret_out = net_write(a[0], (const void *)(uintptr_t)a[1], (uint64_t)a[2]);
        return 1;
    case 3: /* close */
        if (!afw_net_is_fd(a[0])) return 0;
        *ret_out = net_close(a[0]);
        return 1;
    case 5: /* fstat */
        if (!afw_net_is_fd(a[0])) return 0;
        if (!a[1]) { *ret_out = -LNX_EFAULT; return 1; }
        memset((void *)(uintptr_t)a[1], 0, 144);
        *(uint32_t *)((unsigned char *)(uintptr_t)a[1] + 24) = 0140777u; /* S_IFSOCK */
        *ret_out = 0;
        return 1;
    case 7: /* poll */
        *ret_out = net_poll((lnx_pollfd *)(uintptr_t)a[0], (uint64_t)a[1], (int32_t)a[2]);
        return 1;
    case 16: /* ioctl */
        if (!afw_net_is_fd(a[0])) return 0;
        *ret_out = net_ioctl(a[0], a[1], a[2]);
        return 1;
    case 22: /* pipe */
        *ret_out = net_pipe2((int32_t *)(uintptr_t)a[0], 0);
        return 1;
    case 41: /* socket */
        *ret_out = net_socket(a[0], a[1], a[2]);
        return 1;
    case 42: /* connect */
        *ret_out = net_connect(a[0], (const void *)(uintptr_t)a[1], a[2]);
        return 1;
    case 43: /* accept */
        *ret_out = net_accept4(a[0], (void *)(uintptr_t)a[1], (uint32_t *)(uintptr_t)a[2], 0);
        return 1;
    case 44: /* sendto */
        *ret_out = net_sendto(a[0], (const void *)(uintptr_t)a[1], (uint64_t)a[2], a[3],
                              (const void *)(uintptr_t)a[4], a[5]);
        return 1;
    case 45: /* recvfrom */
        *ret_out = net_recvfrom(a[0], (void *)(uintptr_t)a[1], (uint64_t)a[2], a[3],
                                (void *)(uintptr_t)a[4], (uint32_t *)(uintptr_t)a[5]);
        return 1;
    case 48: /* shutdown */
        *ret_out = net_shutdown(a[0], a[1]);
        return 1;
    case 49: /* bind */
        *ret_out = net_bind(a[0], (const void *)(uintptr_t)a[1], a[2]);
        return 1;
    case 50: /* listen */
        *ret_out = net_listen(a[0], a[1]);
        return 1;
    case 51: /* getsockname */
        *ret_out = net_sockname(a[0], (void *)(uintptr_t)a[1], (uint32_t *)(uintptr_t)a[2], 0);
        return 1;
    case 52: /* getpeername */
        *ret_out = net_sockname(a[0], (void *)(uintptr_t)a[1], (uint32_t *)(uintptr_t)a[2], 1);
        return 1;
    case 53: /* socketpair */
        *ret_out = net_socketpair(a[0], a[1], (int32_t *)(uintptr_t)a[3]);
        return 1;
    case 54: /* setsockopt */
        *ret_out = net_setsockopt(a[0], a[1], a[2], (const void *)(uintptr_t)a[3], a[4]);
        return 1;
    case 55: /* getsockopt */
        *ret_out = net_getsockopt(a[0], a[1], a[2], (void *)(uintptr_t)a[3], (uint32_t *)(uintptr_t)a[4]);
        return 1;
    case 72: /* fcntl */
        if (!afw_net_is_fd(a[0])) return 0;
        *ret_out = net_fcntl(a[0], a[1], a[2]);
        return 1;
    case 213: /* epoll_create */
        *ret_out = net_epoll_create1(0);
        return 1;
    case 232: /* epoll_wait */
        *ret_out = net_epoll_wait(a[0], (lnx_epoll_event *)(uintptr_t)a[1], a[2], (int32_t)a[3]);
        return 1;
    case 233: /* epoll_ctl */
        *ret_out = net_epoll_ctl(a[0], a[1], a[2], (const lnx_epoll_event *)(uintptr_t)a[3]);
        return 1;
    case 271: { /* ppoll(fds, nfds, tmo_p, sigmask, sigsetsize) */
        int32_t ms = -1;
        if (a[2]) {
            const int64_t *ts = (const int64_t *)(uintptr_t)a[2];
            ms = (int32_t)(ts[0] * 1000LL + ts[1] / 1000000LL);
        }
        *ret_out = net_poll((lnx_pollfd *)(uintptr_t)a[0], (uint64_t)a[1], ms);
        return 1;
    }
    case 281: /* epoll_pwait */
        *ret_out = net_epoll_wait(a[0], (lnx_epoll_event *)(uintptr_t)a[1], a[2], (int32_t)a[3]);
        return 1;
    case 288: /* accept4 */
        *ret_out = net_accept4(a[0], (void *)(uintptr_t)a[1], (uint32_t *)(uintptr_t)a[2], a[3]);
        return 1;
    case 284: /* eventfd */
        *ret_out = net_eventfd2((uint64_t)a[0], 0);
        return 1;
    case 290: /* eventfd2 */
        *ret_out = net_eventfd2((uint64_t)a[0], a[1]);
        return 1;
    case 291: /* epoll_create1 */
        *ret_out = net_epoll_create1(a[0]);
        return 1;
    case 293: /* pipe2 */
        *ret_out = net_pipe2((int32_t *)(uintptr_t)a[0], a[1]);
        return 1;
    default:
        return 0;
    }
}
