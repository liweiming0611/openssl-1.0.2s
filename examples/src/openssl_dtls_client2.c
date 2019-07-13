#include <poll.h>
#include <string.h>
#include <errno.h>

#include <openssl.h>
#include <inet_sock.h>

int main(int argc, char **argv)
{
    int sockfd = -1, len = -1;
    socklen_t socklen = sizeof(struct sockaddr_in);
    struct sockaddr_in my_addr, their_addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int retval = -1;
    char readbuf[65535] = {"This is a DTLS client!"};
    struct pollfd fds = {0};
    struct timeval timeout;
    BIO *read_bio = NULL, *write_bio = NULL;
    int readbytes = -1;

    openssl_log_init();
    openssl_init();

    ctx = openssl_ctx_new(DTLS_client_method());
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
    init_nonblock(sockfd);

    if (init_udp_sockaddr((struct sockaddr *)&my_addr, SOCK_AF_INET, sockfd, 0)) {
        goto error;
    }

    ssl = openssl_ssl_new(ctx);
    if (!ssl) {
        goto error;
    }

    read_bio = BIO_new(BIO_s_mem());
    if (!read_bio) {
        goto error;
    }
    BIO_set_mem_eof_return(read_bio, -1);

    
    write_bio = BIO_new(BIO_s_mem());
    if (!write_bio) {
        goto error;
    }
    BIO_set_mem_eof_return(write_bio, -1);

    SSL_set_bio(ssl, read_bio, write_bio);
    SSL_set_connect_state(ssl);
    SSL_write(ssl, readbuf, strlen(readbuf));

    while (1) {
        memset(&fds, 0, sizeof(fds));
        fds.fd = sockfd;
        fds.events = POLLIN | POLLOUT;

        retval = poll(&fds, 1, 10000);

        if (retval && (fds.revents & POLLIN)) {
            retval = recvfrom(sockfd, readbuf, sizeof(readbuf) - 1, 0, &their_addr, &socklen);
            if (retval > 0) {
                if ((readbuf[0] >= 20) && (readbuf[0] <= 63)) {
                    BIO_write(read_bio, readbuf, retval);

                    len = SSL_read(ssl, readbuf, sizeof(readbuf));
                    if ((len < 0) && (SSL_ERROR_SSL == SSL_get_error(ssl, len))) {
                        unsigned long errorstr = ERR_get_error();
                        openssl_log(OPENSSL_LOG_ERR, "DTLS failure occurred due to reason '%s', terminating\n", ERR_reason_error_string(errorstr));
                        break;
                    } else {
                        openssl_log(OPENSSL_LOG_DEB, "Read '%d' bytes from '%s:%d', first byte value: 0x%x(%d)\n",
                            retval, inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), readbuf[0], readbuf[0]);
                    }
                }
            }
            usleep(500);
        } else if (retval && (fds.revents & POLLOUT)) {
            if (!SSL_is_init_finished(ssl)) {
                readbytes = BIO_read(write_bio, readbuf, sizeof(readbuf));
                if (readbytes > 0) {
                    readbytes = sendto(sockfd, readbuf, readbytes, 0, &my_addr, socklen);
                    openssl_log(OPENSSL_LOG_DEB, "Write '%d' bytes to '%s:%d', sockfd: %d, first byte value: 0x%x, error: %s\n",
                        readbytes, inet_ntoa(my_addr.sin_addr), ntohs(my_addr.sin_port), sockfd, readbuf[0], strerror(errno));
                }
            } else {
                snprintf(readbuf, sizeof(readbuf) - 1, "%s", "This is a DTLS client!");
                SSL_write(ssl, readbuf, strlen(readbuf));
                readbytes = BIO_read(write_bio, readbuf, sizeof(readbuf));
                if (readbytes > 0) {
                    readbytes = sendto(sockfd, readbuf, readbytes, 0, &my_addr, socklen);
                    openssl_log(OPENSSL_LOG_DEB, "Write '%d' bytes to '%s:%d', values: %d, first byte value: 0x%x(%d)\n",
                        readbytes, inet_ntoa(my_addr.sin_addr), ntohs(my_addr.sin_port), readbuf[0], readbuf[0]);
                }
            }

            usleep(500000);
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
