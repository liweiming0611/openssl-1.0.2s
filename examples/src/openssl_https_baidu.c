#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl_log.h>

#include <config.h>

#define CLIENT_CA   "ClientCAcert.pem"
#define CLIENT_KEY  "ClientPrivkey.pem"
#define CA          "ca.crt"

enum {
    LOG_ERR = 1,
    LOG_WAR = 2,
    LOG_NOT = 3,
    LOG_DEB = 4,
    LOG_VEB = 5,
};

static int openssl_elim_spec_string(char *data, char delim, char **array, int arraylen);
#define openssl_arraylen(array) (sizeof(array) / sizeof(array[0]))
#define openssl_elim_string(data, delim, array) openssl_elim_spec_string((data), (delim), (array), openssl_arraylen(array))

static int openssl_string_char_delim(char *data, char delim, char **array, int arraylen)
{
    int count = 0;
    char *ptr = data;

    enum tokenizer_state {
        START,
        FIND_DELIM
    } state = START;

    while (*ptr && (count < arraylen)) {
        switch (state) {
        case START:
            array[count++] = ptr;
            state = FIND_DELIM;
            break;
        case FIND_DELIM:
            if (delim == *ptr) {
                *ptr = '\0';
                state = START;
            }
            ++ptr;
            break;
        }
    }

    return count;
}

static int openssl_elim_spec_string(char *data, char delim, char **array, int arraylen)
{
    if (!data || !array || !arraylen) {
        return 0;
    }

    memset(array, 0, arraylen * sizeof(*array));

    return openssl_string_char_delim(data, delim, array, arraylen);
}

static void openssl_log_vsprintf(int level, const char *file, int line, const char *format, ...)
{
    char *log_buffer = NULL;
    char *file_name = NULL;
    char *level_str = NULL;
    struct timeval tv_now;
    time_t tt;
    struct tm *t = NULL;
    int i = 0;
    int argc = 0;
    char *dupstr = NULL;
    char *lines[1024] = {0};
    char buffer[65535] = {0};
    int bufferlen = 0;

    va_list ap;
    va_start(ap, format);
    int ret = vasprintf(&log_buffer, format, ap);
    va_end(ap);

    if (file) {
        file_name = strrchr(file, '/');
    }

    switch (level) {
    case LOG_ERR:
        level_str = "\033[31;1m  ERROR\33[0m";
        break;
    case LOG_WAR:
        level_str = "\033[32;31;1mWARRING\33[0m";
        break;
    case LOG_NOT:
        level_str = "\033[33;1m NOTICE\33[0m";
        break;
    case LOG_DEB:
        level_str = "\033[32;1m  DEBUG\33[0m";
        break;
    case LOG_VEB:
        level_str = "\033[32mVERBOSE\33[0m";
        break;
    default:
        level_str = "\033[32;1m  DEBUG\33[0m";
        break;
    }

    tt = time(NULL);
    t = localtime(&tt);
    gettimeofday(&tv_now, NULL);

    argc = openssl_elim_string((dupstr = strdup(log_buffer)), '\n', lines);
    for (i = 0; i < argc; i++) {
        if (strlen(lines[i])) {
            bufferlen += snprintf(buffer + bufferlen, sizeof(buffer) - bufferlen, "%s\n", lines[i]);
        }
    }
    fprintf(stderr, "[%4d-%02d-%02d %02d:%02d:%02d:%03ld] %s [%05ld] -- %s:%d %s",
        t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv_now.tv_usec,
        level_str, syscall(SYS_gettid), file_name ? ++file_name : file, line, buffer);

    if (dupstr) {
        free(dupstr);
    }

    if (log_buffer) {
        free(log_buffer);
    }
}

#define openssl_log(level, ...) do {                                    \
    if (level) {                                                        \
        openssl_log_vsprintf(level, __FILE__, __LINE__, __VA_ARGS__);   \
    }                                                                   \
} while (0)

static void openssl_log_format(int level, const char *file, int line, const char *msg)
{
    int openssl_level = 0;

    switch (level) {
    case SSL_LOG_ERR:
        openssl_level = LOG_ERR;
        break;
    case SSL_LOG_WAR:
        openssl_level = LOG_WAR;
        break;
    case SSL_LOG_NOT:
        openssl_level = LOG_NOT;
        break;
    case SSL_LOG_DEB:
        openssl_level = LOG_DEB;
        break;
    case SSL_LOG_VEB:
        openssl_level = LOG_VEB;
        break;
    default:
        openssl_level = LOG_DEB;
        break;
    }

    openssl_log(openssl_level, "[%6s:%04d] %s\n", file, line, msg);
}

static void openssl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    const char *str_write_p, *str_version, *str_content_type =
        "", *str_details1 = "", *str_details2 = "";

    char msg_buffer[65535] = {0};
    int msg_len = 0;

    str_write_p = write_p ? "[Write]" : "[Read]";

    switch (version) {
    case SSL2_VERSION:
        str_version = "SSL 2.0";
        break;
    case SSL3_VERSION:
        str_version = "SSL 3.0 ";
        break;
    case TLS1_VERSION:
        str_version = "TLS 1.0 ";
        break;
    case TLS1_1_VERSION:
        str_version = "TLS 1.1 ";
        break;
    case TLS1_2_VERSION:
        str_version = "TLS 1.2 ";
        break;
    case DTLS1_VERSION:
        str_version = "DTLS 1.0 ";
        break;
    case DTLS1_2_VERSION:
        str_version = "DTLS 1.2 ";
        break;
    case DTLS1_BAD_VER:
        str_version = "DTLS 1.0 (bad) ";
        break;
    default:
        str_version = "???";
    }

    if (version == SSL2_VERSION) {
        str_details1 = "???";

        if (len > 0) {
            switch (((const unsigned char *)buf)[0]) {
            case 0:
                str_details1 = ", ERROR:";
                str_details2 = " ???";
                if (len >= 3) {
                    unsigned err =
                        (((const unsigned char *)buf)[1] << 8) +
                        ((const unsigned char *)buf)[2];

                    switch (err) {
                    case 0x0001:
                        str_details2 = " NO-CIPHER-ERROR";
                        break;
                    case 0x0002:
                        str_details2 = " NO-CERTIFICATE-ERROR";
                        break;
                    case 0x0004:
                        str_details2 = " BAD-CERTIFICATE-ERROR";
                        break;
                    case 0x0006:
                        str_details2 = " UNSUPPORTED-CERTIFICATE-TYPE-ERROR";
                        break;
                    }
                }

                break;
            case 1:
                str_details1 = ", CLIENT-HELLO";
                break;
            case 2:
                str_details1 = ", CLIENT-MASTER-KEY";
                break;
            case 3:
                str_details1 = ", CLIENT-FINISHED";
                break;
            case 4:
                str_details1 = ", SERVER-HELLO";
                break;
            case 5:
                str_details1 = ", SERVER-VERIFY";
                break;
            case 6:
                str_details1 = ", SERVER-FINISHED";
                break;
            case 7:
                str_details1 = ", REQUEST-CERTIFICATE";
                break;
            case 8:
                str_details1 = ", CLIENT-CERTIFICATE";
                break;
            }
        }
    }

    if (version == SSL3_VERSION ||
        version == TLS1_VERSION ||
        version == TLS1_1_VERSION ||
        version == TLS1_2_VERSION ||
        version == DTLS1_VERSION ||
        version == DTLS1_2_VERSION ||
        version == DTLS1_BAD_VER) {
        switch (content_type) {
        case 20:
            str_content_type = "ChangeCipherSpec";
            break;
        case 21:
            str_content_type = "Alert";
            break;
        case 22:
            str_content_type = "Handshake";
            break;
        }

        if (content_type == 21) { /* Alert */
            str_details1 = ", ???";

            if (len == 2) {
                switch (((const unsigned char *)buf)[0]) {
                case 1:
                    str_details1 = ", warning";
                    break;
                case 2:
                    str_details1 = ", fatal";
                    break;
                }

                str_details2 = " ???";
                switch (((const unsigned char *)buf)[1]) {
                case 0:
                    str_details2 = " close_notify";
                    break;
                case 10:
                    str_details2 = " unexpected_message";
                    break;
                case 20:
                    str_details2 = " bad_record_mac";
                    break;
                case 21:
                    str_details2 = " decryption_failed";
                    break;
                case 22:
                    str_details2 = " record_overflow";
                    break;
                case 30:
                    str_details2 = " decompression_failure";
                    break;
                case 40:
                    str_details2 = " handshake_failure";
                    break;
                case 42:
                    str_details2 = " bad_certificate";
                    break;
                case 43:
                    str_details2 = " unsupported_certificate";
                    break;
                case 44:
                    str_details2 = " certificate_revoked";
                    break;
                case 45:
                    str_details2 = " certificate_expired";
                    break;
                case 46:
                    str_details2 = " certificate_unknown";
                    break;
                case 47:
                    str_details2 = " illegal_parameter";
                    break;
                case 48:
                    str_details2 = " unknown_ca";
                    break;
                case 49:
                    str_details2 = " access_denied";
                    break;
                case 50:
                    str_details2 = " decode_error";
                    break;
                case 51:
                    str_details2 = " decrypt_error";
                    break;
                case 60:
                    str_details2 = " export_restriction";
                    break;
                case 70:
                    str_details2 = " protocol_version";
                    break;
                case 71:
                    str_details2 = " insufficient_security";
                    break;
                case 80:
                    str_details2 = " internal_error";
                    break;
                case 90:
                    str_details2 = " user_canceled";
                    break;
                case 100:
                    str_details2 = " no_renegotiation";
                    break;
                case 110:
                    str_details2 = " unsupported_extension";
                    break;
                case 111:
                    str_details2 = " certificate_unobtainable";
                    break;
                case 112:
                    str_details2 = " unrecognized_name";
                    break;
                case 113:
                    str_details2 = " bad_certificate_status_response";
                    break;
                case 114:
                    str_details2 = " bad_certificate_hash_value";
                    break;
                case 115:
                    str_details2 = " unknown_psk_identity";
                    break;
                }
            }
        }

        if (content_type == 22) { /* Handshake */
            str_details1 = "???";

            if (len > 0) {
                switch (((const unsigned char *)buf)[0]) {
                case 0:
                    str_details1 = ", HelloRequest";
                    break;
                case 1:
                    str_details1 = ", ClientHello";
                    break;
                case 2:
                    str_details1 = ", ServerHello";
                    break;
                case 3:
                    str_details1 = ", HelloVerifyRequest";
                    break;
                case 11:
                    str_details1 = ", Certificate";
                    break;
                case 12:
                    str_details1 = ", ServerKeyExchange";
                    break;
                case 13:
                    str_details1 = ", CertificateRequest";
                    break;
                case 14:
                    str_details1 = ", ServerHelloDone";
                    break;
                case 15:
                    str_details1 = ", CertificateVerify";
                    break;
                case 16:
                    str_details1 = ", ClientKeyExchange";
                    break;
                case 20:
                    str_details1 = ", Finished";
                    break;
                }
            }
        }

#ifndef OPENSSL_NO_HEARTBEATS
        if (content_type == 24) { /* Heartbeat */
            str_details1 = ", Heartbeat";

            if (len > 0) {
                switch (((const unsigned char *)buf)[0]) {
                case 1:
                    str_details1 = ", HeartbeatRequest";
                    break;
                case 2:
                    str_details1 = ", HeartbeatResponse";
                    break;
                }
            }
        }
#endif
    }

    msg_len += snprintf(msg_buffer + msg_len, sizeof(msg_buffer) - msg_len - 1,
        "%s %s%s [length %04lx]%s%s\n", str_write_p, str_version,
        str_content_type, (unsigned long)len, str_details1, str_details2);

    if (len > 0) {
        size_t num, i;
        msg_len += snprintf(msg_buffer + msg_len, sizeof(msg_buffer) - msg_len - 1, "%s", "   ");
        num = len;

        for (i = 0; i < num; i++) {
            if (i % 32 == 0 && i > 0) {
                msg_len += snprintf(msg_buffer + msg_len, sizeof(msg_buffer) - msg_len - 1, "%s", "\n   ");
            }
            msg_len += snprintf(msg_buffer + msg_len, sizeof(msg_buffer) - msg_len - 1, " %02x", ((const unsigned char *)buf)[i]);
        }

        if (i < len) {

            msg_len += snprintf(msg_buffer + msg_len, sizeof(msg_buffer) - msg_len - 1, "%s", " ...");
        }

        msg_len += snprintf(msg_buffer + msg_len, sizeof(msg_buffer) - msg_len - 1, "%s", "\n");
    }

    openssl_log(LOG_DEB, "\n%s", msg_buffer);
}

static int connect_to_baidu(int sockfd, struct sockaddr *sockaddr, size_t len)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    if (connect(sockfd, sockaddr, len)) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }

    ssl_set_logger_cb(openssl_log_format);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_method());
    if (!ctx) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }

    if (SSL_CTX_use_certificate_file(ctx, OPENSSL_CLIENT_CA_PATH "/" CLIENT_CA, SSL_FILETYPE_PEM) <= 0) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, OPENSSL_CLIENT_CA_PATH "/" CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }

    
    if (!SSL_CTX_check_private_key(ctx)) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }

    if (!SSL_CTX_load_verify_locations(ctx, OPENSSL_CA_PATH "/" CA, NULL)) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        goto error;
    }
    SSL_set_fd(ssl, sockfd);
    SSL_set_msg_callback(ssl, openssl_msg_cb);

    if (-1 == SSL_connect(ssl)) {
        openssl_log(LOG_ERR, "error in %s\n", SSL_state_string_long(ssl));
        goto error;
    } else {
        openssl_log(LOG_DEB, "SSL connection using %s\n", SSL_get_cipher (ssl));
    }

    if (ssl) {
        SSL_free(ssl);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }

    return 0;

error:
    if (ssl) {
        SSL_free(ssl);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }
    return -1;
}

int main(int argc, char **argv)
{
    struct addrinfo hints, *result = NULL, *rp = NULL;
    struct sockaddr sockaddr;
    int sockfd = -1;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    if (getaddrinfo("www.baidu.com", NULL, &hints, &result)) {
        openssl_log(LOG_ERR, "%s\n", strerror(errno));
        return -1;
    }
    memset(&sockaddr, 0, sizeof(sockaddr));

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            openssl_log(LOG_ERR, "%s\n", strerror(errno));
            continue;
        }

        if (AF_INET == rp->ai_family) {
            memcpy(&addr4, rp->ai_addr, rp->ai_addrlen);
            addr4.sin_port = htons(443);
            openssl_log(LOG_DEB, "Get www.baidu.com ip address: %s:%d, sockfd: %d",
                inet_ntoa(addr4.sin_addr), ntohs(addr4.sin_port), sockfd);
            if (connect_to_baidu(sockfd, (struct sockaddr *)&addr4, sizeof(addr4))) {
                close(sockfd);
                continue;
            } else {
                break;
            }
        }
    }

    close(sockfd);
    freeaddrinfo(result);

    return 0;
}
