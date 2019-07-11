#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <inet_sock.h>
#include <openssl.h>

int init_nonblock(int fd)
{
    int flags = -1;

    if(flags = fcntl(fd, F_GETFL, 0) < 0) {
        openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }

    flags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, flags) < 0) {
        openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int init_sock(inet_sock_t sock, int type)
{
    return socket(sock, type, 0);
}

int init_sockaddr(struct sockaddr *sockaddr, inet_sock_t sock, int sockfd, int utopt, int csopt)
{
    struct sockaddr_in addr;
    int on = 1;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = sock;

    if (csopt) {
        addr.sin_port = htons(7838);
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        addr.sin_port = htons(7838);
        if (!inet_aton("192.168.129.220", (struct in_addr *)&addr.sin_addr.s_addr)) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            return -1;
        }
    }

    if (sockaddr) {
        memcpy(sockaddr, &addr, sizeof(addr));
    }

    if (csopt) {
        if((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            return -1;
        }

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr))) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            return -1;
        }
        openssl_log(OPENSSL_LOG_NOT, "Bind sockaddr: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    }

    if (utopt) {
        if (listen(sockfd, 100)) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            return -1;
        }
    } else {
        if (!csopt) {
            if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
                openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
                return -1;
            }
            openssl_log(OPENSSL_LOG_NOT, "Connect sockaddr: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        }
    }

    return 0;
}

int init_udp_sockaddr(struct sockaddr *sockaddr, inet_sock_t sock, int sockfd, int csopt)
{
    struct sockaddr_in addr;
    int on = 1;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = sock;

    if (csopt) {
        addr.sin_port = htons(7838);
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        addr.sin_port = htons(7838);
        if (!inet_aton("192.168.129.220", (struct in_addr *)&addr.sin_addr.s_addr)) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            return -1;
        }
    }

    if (sockaddr) {
        memcpy(sockaddr, &addr, sizeof(addr));
    }

    if((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }

    if (csopt) {
        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr))) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            return -1;
        }
        openssl_log(OPENSSL_LOG_NOT, "Bind sockaddr: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    }

    return 0;
}


int init_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept(sockfd, addr, addrlen);
}
