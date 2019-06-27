#ifndef __OPENSSL_LOG_H__
#define __OPENSSL_LOG_H__

#ifdef GRANDSTREAM_NETWORKS
#include <stdio.h>

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

#endif
#endif
