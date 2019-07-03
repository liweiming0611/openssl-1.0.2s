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
    BIO * sbio = NULL;
    int read_from_sslcon = -1;

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(DTLS_method());
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

    if (init_sockaddr((struct sockaddr *)&their_addr, SOCK_AF_INET, sockfd, 0, 1)) {
        goto error;
    }

    ssl = openssl_ssl_new(ctx);
    if (NULL == ssl) {
        goto error;
    }

    sbio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
    if (NULL == sbio) {
        goto error;
    }

    SSL_set_bio(ssl, sbio, sbio);
    SSL_set_accept_state(ssl);

    while (1) {
        read_from_sslcon = SSL_read(ssl, readbuf, sizeof(readbuf) - 1);
        if (read_from_sslcon) {
            if (!SSL_is_init_finished(ssl)) {
                openssl_log(OPENSSL_LOG_WAR, "======================\n");
                continue;
            }

            openssl_log(OPENSSL_LOG_DEB, "Read %d bytes from '%s:%d', %s\n", read_from_sslcon,
                inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), readbuf);
        } else {
            openssl_log(OPENSSL_LOG_NOT, "read_from_sslcon: %d\n", read_from_sslcon);
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
