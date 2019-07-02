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

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(SSLv23_server_method());
    if (NULL == ctx) {
        goto error;
    }

    if (openssl_load_cert_file(ctx)) {
        goto error;
    }

    sockfd = init_sock(SOCK_AF_INET, SOCK_STREAM);
    if (sockfd < 0) {
        goto error;
    }

    if (init_sockaddr((struct sockaddr *)&their_addr, SOCK_AF_INET, sockfd, 1)) {
        goto error;
    }

    while (1) {
        SSL *ssl = NULL;
        socklen = sizeof(struct sockaddr);

        if ((new_fd = init_accept(sockfd, (struct sockaddr *)&their_addr, &socklen)) < 0) {
            openssl_log(OPENSSL_LOG_ERR, "%s\n", strerror(errno));
            continue;
        } else {
            openssl_log(OPENSSL_LOG_DEB, "Server: get connect from %s:%d, socket: %d\n", 
                inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), new_fd);
        }

        ssl = openssl_ssl_new(ctx);
        openssl_set_fd(ssl, new_fd);

        if (openssl_accept(ssl) < -1) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_fd);
            continue;
        }

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
