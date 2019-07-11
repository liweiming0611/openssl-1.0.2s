#include <openssl.h>
#include <inet_sock.h>

int main(int argc, char **argv)
{
    SSL_CTX * ctx = NULL;
    int sockfd = -1;
    socklen_t socklen = 0;
    struct sockaddr_in their_addr;
    struct sockaddr peer;
    SSL *ssl = NULL;
    int retval = -1;
    char readbuf[65535] = {0};
    BIO *sbio = NULL;
    int try = 0;

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(DTLSv1_client_method());
    if (NULL == ctx) {
        goto error;
    }

    if (openssl_load_cert_file(ctx, 0)) {
        goto error;
    }

    sockfd = init_sock(SOCK_AF_INET, SOCK_DGRAM);
    if (sockfd < 0) {
        goto error;
    }

    if (init_sockaddr((struct sockaddr *)&their_addr, SOCK_AF_INET, sockfd, 0, 0)) {
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

    BIO_ctrl_set_connected(sbio, 1, &peer);
    SSL_set_bio(ssl, sbio, sbio);
    SSL_set_connect_state(ssl);

    while (try++ < 10) {
        snprintf(readbuf, sizeof(readbuf) - 1, "%s", "This is a DTLS client!\n");
        retval = SSL_write(ssl, readbuf, strlen(readbuf));
        if (retval > 0) {
            openssl_log(OPENSSL_LOG_DEB, "Write '%d' bytes to '%s:%d'\n", retval, inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
            sleep(1);
        } else {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
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

