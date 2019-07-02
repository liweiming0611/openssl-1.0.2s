#include <openssl.h>
#include <inet_sock.h>

int main(int argc, char **argv)
{
    SSL_CTX * ctx = NULL;
    int sockfd = -1;
    socklen_t socklen = 0;
    struct sockaddr_in my_addr, their_addr;
    SSL *ssl = NULL;
    int retval = -1;
    char readbuf[65535] = {0};

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(DTLS_client_method());
    if (NULL == ctx) {
        goto error;
    }

    if (openssl_load_cert_file(ctx)) {
        goto error;
    }

    sockfd = init_sock(SOCK_AF_INET, SOCK_DGRAM);
    if (sockfd < 0) {
        goto error;
    }

    if (init_sockaddr((struct sockaddr *)&their_addr, SOCK_AF_INET, sockfd, 0)) {
        goto error;
    }

    ssl = openssl_ssl_new(ctx);
    openssl_set_fd(ssl, sockfd);

    //SSL_set_connect_state(ssl);

    while (1) {
        retval = SSL_connect(ssl);
        if (0 == retval) {
            openssl_log(OPENSSL_LOG_WAR, "Handshake failure, reason: %s\n", SSL_get_error(ssl, retval));
            continue;
        } else {
            retval = SSL_read(ssl, readbuf, sizeof(readbuf) - 1);
            openssl_log(OPENSSL_LOG_DEB, "Read %d bytes, %s\n", retval, readbuf);
            sleep(1);
        }
    }

    return 0;

error:
    if (sockfd > 0) {
        close(sockfd);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

