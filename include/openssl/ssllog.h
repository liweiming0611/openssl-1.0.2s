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
	LOG_ERR = 1,
	LOG_WAR = 2,
	LOG_NOT = 3,
	LOG_DEB = 4,
	LOG_VEB = 5,
};

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

    switch (level) {
    case LOG_ERR:
        level_str = "\033[31;1mERR\33[0m";
        break;
    case LOG_WAR:
        level_str = "\033[32;31;1mWAR\33[0m";
        break;
    case LOG_NOT:
        level_str = "\033[33;1mNOT\33[0m";
        break;
    case LOG_DEB:
        level_str = "\033[32;1mDEB\33[0m";
        break;
    case LOG_VEB:
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
        t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv_now.tv_usec / 1000,
        level_str, syscall(SYS_gettid), file_name ? ++file_name : file, line, log_buffer);
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
