/*
 * net.h - Linux socket, poll, epoll, pipe2, and eventfd2 syscall emulation
 * over Winsock2 (Windows) and POSIX sockets (Linux).
 *
 * Uses FD range [AFW_NET_FD_BASE, AFW_NET_FD_MAX) = [256, 512) so regular
 * file descriptors in src/fd.c (0..255) remain completely independent.
 * All Winsock2 calls are isolated inside src/net.c (Rule 8).
 */
#ifndef AFW_NET_H
#define AFW_NET_H

#include <stdint.h>

#define AFW_NET_FD_BASE 256
#define AFW_NET_FD_MAX  512

int afw_net_init(void);
int afw_net_is_fd(int64_t fd);

/* Syscall hook registered into src/syscall.c via afw_syscall_set_net_cb().
 * Returns 1 if handled (writing Linux syscall result into *ret_out), 0 otherwise. */
int afw_net_syscall(int64_t nr, const int64_t *a, int64_t *ret_out);

#endif
