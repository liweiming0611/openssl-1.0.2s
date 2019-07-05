#ifndef __INET_SOCK_H__
#define __INET_SOCK_H__

#include <sys/types.h>
#include <sys/socket.h>

typedef enum {
    SOCK_AF_UNIX = AF_UNIX,
    SOCK_AF_INET = AF_INET,
} inet_sock_t;

int init_nonblock(int fd);
int init_sock(inet_sock_t sock, int type);
int init_sockaddr(struct sockaddr *sockaddr, inet_sock_t sock, int sockfd, int utopt, int csopt);
int init_udp_sockaddr(struct sockaddr *sockaddr, inet_sock_t sock, int sockfd, int csopt);
int init_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

#endif
