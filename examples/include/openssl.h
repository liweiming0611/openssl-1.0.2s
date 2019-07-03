#ifndef __OPENSSL_LOG_H__
#define __OPENSSL_LOG_H__

#ifdef GRANDSTREAM_NETWORKS
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl_log.h>

enum {
    OPENSSL_LOG_ERR = 1,
    OPENSSL_LOG_WAR = 2,
    OPENSSL_LOG_NOT = 3,
    OPENSSL_LOG_DEB = 4,
    OPENSSL_LOG_VEB = 5,
};

void openssl_log_init(void);

void openssl_log_vsprintf(int level, const char *file, int line, const char *format, ...);

#define openssl_log(level, ...) do {                                    \
    if (level) {                                                        \
        openssl_log_vsprintf(level, __FILE__, __LINE__, __VA_ARGS__);   \
    }                                                                   \
} while (0)

int openssl_init(void);
int openssl_load_cert_file(SSL_CTX *ctx, int csopt);
SSL_CTX *openssl_ctx_new(const SSL_METHOD *method);
SSL *openssl_ssl_new(SSL_CTX *ctx);
int openssl_set_fd(SSL *ssl, int sockfd);
int openssl_accept(SSL *ssl);

#endif
#endif
