#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl_log.h>

int main(int argc, char **argv)
{
    int sockfd = -1, new_fd = -1;
    socklen_t socklen = 0;
    struct sockaddr_in my_addr, thrie_addr;
    SSL_CTX *ctx = NULL;

    openssl_log_init();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (NULL == ctx) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, "./CAcert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./privkey.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    return 0;
}
