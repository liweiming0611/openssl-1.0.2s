#ifndef __SSL_LOG_H__
#define __SSL_LOG_H__

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#ifdef GRANDSTREAM_NETWORKS

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

enum {
    SSL_LOG_ERR = 1,
    SSL_LOG_WAR = 2,
    SSL_LOG_NOT = 3,
    SSL_LOG_DEB = 4,
    SSL_LOG_VEB = 5,
};

typedef void (*ssl_log_cb)(int level, const char *file, int line, const char *msg);

void ssl_set_logger_cb(ssl_log_cb cb);
void ssl_log_vsprintf(int level, const char *file, int line, const char *format, ...);

#define ssl_log(level, ...) do {                                    \
    if (level) {                                                    \
        ssl_log_vsprintf(level, __FILE__, __LINE__, __VA_ARGS__);   \
    }                                                               \
} while (0)

#endif

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif
#endif
