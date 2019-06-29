#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <inet_sock.h>
#include <openssl.h>

int init_sock(inet_sock_t sock, int type)
{
    return socket(sock, type, 0);
}

int init_sockaddr(struct sockaddr *sockaddr, inet_sock_t sock, int sockfd)
{
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = sock;
    addr.sin_port = htons(7838);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (sockaddr) {
        memcpy(sockaddr, &addr, sizeof(addr));
    }

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr))) {
        openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }

    if (listen(sockfd, 100)) {
        openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int init_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept(sockfd, addr, addrlen);
}
