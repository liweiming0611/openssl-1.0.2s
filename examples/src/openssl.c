#ifdef GRANDSTREAM_NETWORKS

#include <openssl.h>

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
    int ret = vasprintf(&log_buffer, format, ap);
    va_end(ap);

    if (file) {
        file_name = strrchr(file, '/');
    }

    switch (level) {
    case OPENSSL_LOG_ERR:
        level_str = "\033[31;1m  ERROR\33[0m";
        break;
    case OPENSSL_LOG_WAR:
        level_str = "\033[32;31;1mWARRING\33[0m";
        break;
    case OPENSSL_LOG_NOT:
        level_str = "\033[33;1m NOTICE\33[0m";
        break;
    case OPENSSL_LOG_DEB:
        level_str = "\033[32;1m  DEBUG\33[0m";
        break;
    case OPENSSL_LOG_VEB:
        level_str = "\033[32mVERBOSE\33[0m";
        break;
    default:
        level_str = "\033[32;1m  DEBUG\33[0m";
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

    openssl_log(OPENSSL_LOG_DEB, "\n%s", msg_buffer);
}

int openssl_init(void)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

#define SERVER_CA   "ServerCAcert.pem"
#define SERVER_KEY  "ServerPrivkey.pem"

#define CLIENT_CA   "ClientCAcert.pem"
#define CLIENT_KEY  "ClientPrivkey.pem"

int openssl_load_cert_file(SSL_CTX *ctx, int csopt)
{
    if (csopt) {
        if (SSL_CTX_use_certificate_file(ctx, OPENSSL_SERVER_CA_PATH "/" SERVER_CA, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stdout);
            return -1;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, OPENSSL_SERVER_CA_PATH "/" SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stdout);
            return -1;
        }
    } else {
        if (SSL_CTX_use_certificate_file(ctx, OPENSSL_CLIENT_CA_PATH "/" CLIENT_CA, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stdout);
            return -1;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, OPENSSL_CLIENT_CA_PATH "/" CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stdout);
            return -1;
        }
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    return 0;
}

static void openssl_info_callback(const SSL *s, int where, int ret)
{
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    } else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    } else {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP) {
        openssl_log(SSL_LOG_DEB, "%s: %s\n", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        openssl_log(SSL_LOG_DEB, "SSL3 alert %s:%s:%s\n", str,
                   SSL_alert_type_string_long(ret),
                   SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            openssl_log(SSL_LOG_ERR, "%s:failed in %s\n", str, SSL_state_string_long(s));
        } else if (ret < 0) {
            openssl_log(SSL_LOG_ERR, "%s:error in %s\n", str, SSL_state_string_long(s));
        }
    }
}

SSL_CTX *openssl_ctx_new(const SSL_METHOD *method)
{
    SSL_CTX *ctx = NULL;

    ctx = SSL_CTX_new(method);
    if (NULL == ctx) {
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    SSL_CTX_set_info_callback(ctx, openssl_info_callback);

    return ctx;
}

SSL *openssl_ssl_new(SSL_CTX *ctx)
{
    SSL *ssl = NULL;

    ssl = SSL_new(ctx);
    if (NULL == ssl) {
        return NULL;
    }

    SSL_set_msg_callback(ssl, openssl_msg_cb);
    SSL_set_msg_callback_arg(ssl, NULL);

    return ssl;
}

int openssl_set_fd(SSL *ssl, int sockfd)
{
    return SSL_set_fd(ssl, sockfd);
}

int openssl_accept(SSL *ssl)
{
    return SSL_accept(ssl);
}
#endif
