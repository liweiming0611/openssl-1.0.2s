#include <poll.h>
#include <errno.h>
#include <string.h>

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
    struct pollfd fds = {0};
    struct timeval timeout;

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(DTLS_server_method());
    if (NULL == ctx) {
        goto error;
    }

    if (openssl_load_cert_file(ctx, 1)) {
        goto error;
    }

    sockfd = init_sock(SOCK_AF_INET, SOCK_DGRAM);
    if (sockfd < 0) {
        goto error;
    }

    if (init_sockaddr((struct sockaddr *)&my_addr, SOCK_AF_INET, sockfd, 0, 1)) {
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

    timeout.tv_sec = 0;
    timeout.tv_usec = 250000;
    BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    timeout.tv_sec = 0;
    timeout.tv_usec = 250000;
    BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

    SSL_set_bio(ssl, sbio, sbio);
    SSL_set_accept_state(ssl);

    while (1) {
        memset(&fds, 0, sizeof(fds));
        fds.fd = sockfd;
        fds.events = POLLIN;

        retval = poll(&fds, 1, 10000);

        if (retval && (fds.revents & POLLIN)) {
            read_from_sslcon = SSL_read(ssl, readbuf, sizeof(readbuf) - 1);
            if (read_from_sslcon > 0) {
                if (!SSL_is_init_finished(ssl)) {
                    openssl_log(OPENSSL_LOG_WAR, "SSL init failure ...\n");
                    continue;
                }

                BIO_dgram_get_peer(sbio, &my_addr);

                openssl_log(OPENSSL_LOG_DEB, "Read %d bytes from '%s:%d', %s\n", read_from_sslcon,
                    inet_ntoa(my_addr.sin_addr), ntohs(my_addr.sin_port), readbuf);
            }
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
