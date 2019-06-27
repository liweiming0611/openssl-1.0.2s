#ifndef __SSLLOG_H__
#define __SSLLOG_H__

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

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

void ssl_set_logger_cb(ssl_log_cb cb)
{
    ssl_log_cb = cb;
}

static inline void __ssllog(int level, const char *file, int line, const char *format, ...)
{
    char *log_buffer = NULL;
    char *file_name = NULL;
    char *level_str = NULL;
    struct timeval tv_now;
    time_t tt;
    struct tm *t = NULL;

    va_list ap;
    va_start(ap, format);
    vasprintf(&log_buffer, format, ap);
    va_end(ap);

    if (file) {
        file_name = strrchr(file, '/');
    }

    if (NULL == ssl_log_cb){
        switch (level) {
        case SSL_LOG_ERR:
            level_str = "\033[31;1mERR\33[0m";
            break;
        case SSL_LOG_WAR:
            level_str = "\033[32;31;1mWAR\33[0m";
            break;
        case SSL_LOG_NOT:
            level_str = "\033[33;1mNOT\33[0m";
            break;
        case SSL_LOG_DEB:
            level_str = "\033[32;1mDEB\33[0m";
            break;
        case SSL_LOG_VEB:
            level_str = "\033[32mVEB\33[0m";
            break;
        default:
            level_str = "\033[32;1mDEB\33[0m";
            break;
        }

        tt = time(NULL);
        t = localtime(&tt);
        gettimeofday(&tv_now, NULL);

        fprintf(stderr, "[%4d-%02d-%02d %02d:%02d:%02d:%03ld] %s [%05ld]   -- %s:%d  %s",
            t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv_now.tv_usec,
            level_str, syscall(SYS_gettid), file_name ? ++file_name : file, line, log_buffer);
    } else {
        ssl_log_cb(level, file, line, log_buffer);
    }

    if (log_buffer) {
        free(log_buffer);
    }
}

#define ssllog(level, ...) do {                             \
    if (level) {                                            \
        __ssllog(level, __FILE__, __LINE__, __VA_ARGS__);   \
    }                                                       \
} while (0)

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif
#endif
