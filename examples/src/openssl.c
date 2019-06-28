#ifdef GRANDSTREAM_NETWORKS

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <openssl/ssl_log.h>

#include <openssl_log.h>

static void openssl_log_format(int level, const char *file, int line, const char *msg)
{
    int openssl_level = 0;

    switch (level) {
    case SSL_LOG_ERR:
        openssl_level = OPENSSL_LOG_ERR;
        break;
    case SSL_LOG_WAR:
        openssl_level = OPENSSL_LOG_WAR;
        break;
    case SSL_LOG_NOT:
        openssl_level = OPENSSL_LOG_NOT;
        break;
    case SSL_LOG_DEB:
        openssl_level = OPENSSL_LOG_DEB;
        break;
    case SSL_LOG_VEB:
        openssl_level = OPENSSL_LOG_VEB;
        break;
    default:
        openssl_level = OPENSSL_LOG_DEB;
        break;
    }

    openssl_log(openssl_level, "[%s:%04d] %s", file, line, msg);
}

void openssl_log_init(void)
{
    ssl_set_logger_cb(openssl_log_format);
}

void openssl_log_vsprintf(int level, const char *file, int line, const char *format, ...)
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
    case OPENSSL_LOG_ERR:
        level_str = "\033[31;1mERR\33[0m";
        break;
    case OPENSSL_LOG_WAR:
        level_str = "\033[32;31;1mWAR\33[0m";
        break;
    case OPENSSL_LOG_NOT:
        level_str = "\033[33;1mNOT\33[0m";
        break;
    case OPENSSL_LOG_DEB:
        level_str = "\033[32;1mDEB\33[0m";
        break;
    case OPENSSL_LOG_VEB:
        level_str = "\033[32mVEB\33[0m";
        break;
    default:
        level_str = "\033[32;1mDEB\33[0m";
        break;
    }

    tt = time(NULL);
    t = localtime(&tt);
    gettimeofday(&tv_now, NULL);

    fprintf(stderr, "[%4d-%02d-%02d %02d:%02d:%02d:%03ld] %s [%05ld] -- %s:%d %s\n",
        t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv_now.tv_usec,
        level_str, syscall(SYS_gettid), file_name ? ++file_name : file, line, log_buffer);

    if (log_buffer) {
        free(log_buffer);
    }
}
#endif
