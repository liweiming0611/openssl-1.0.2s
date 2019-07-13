#include <openssl.h>
#include <inet_sock.h>

int main(int argc, char **argv)
{
    int sockfd = -1, new_fd = -1;
    socklen_t socklen = 0;
    struct sockaddr_in my_addr, their_addr;
    SSL_CTX *ctx = NULL;
    char readbuf[65535] = {0};
    int retval = -1;
    SSL *ssl = NULL;

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(TLSv1_client_method());
    if (NULL == ctx) {
        goto error;
    }

    if (openssl_load_cert_file(ctx, 0)) {
        goto error;
    }

    sockfd = init_sock(SOCK_AF_INET, SOCK_STREAM);
    if (sockfd < 0) {
        goto error;
    }

    if (init_sockaddr((struct sockaddr *)&their_addr, SOCK_AF_INET, sockfd, 0, 0)) {
        goto error;
    }

    ssl = openssl_ssl_new(ctx);
    if (!ssl) {
        openssl_log(SSL_LOG_ERR, "error in %s\n", SSL_state_string_long(ssl));
        goto error;
    }
    openssl_set_fd(ssl, sockfd);

    if (-1 == SSL_connect(ssl)) {
        openssl_log(SSL_LOG_ERR, "error in %s\n", SSL_state_string_long(ssl));
        goto error;
    } else {
        openssl_log(SSL_LOG_DEB, "SSL connection using %s\n", SSL_get_cipher (ssl));
    }

    while (1) {
        retval = SSL_read(ssl, readbuf, sizeof(readbuf) - 1);
        if (retval > 0) {
            openssl_log(OPENSSL_LOG_NOT, "Read: \n%s\n", readbuf);

            char response[256] = {
                "HTTP/1.1 404 Not Found\r\n"
                "\r\n\r\n"
            };
            SSL_write(ssl, response, strlen(response));
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
