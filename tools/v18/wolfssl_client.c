#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(int argc, char **argv) {
    if (argc != 3) return fprintf(stderr, "usage: wolfssl_client HOST PORT\n"), 2;
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *result = NULL;
    if (getaddrinfo(argv[1], argv[2], &hints, &result) != 0) return 2;
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0 || connect(fd, result->ai_addr, result->ai_addrlen) != 0) return 2;
    freeaddrinfo(result);
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return 2;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    int rc = wolfSSL_connect(ssl);
    if (rc == WOLFSSL_SUCCESS) printf("TLS protocol: %s\n", wolfSSL_get_version(ssl));
    else fprintf(stderr, "wolfSSL_connect failed: %d\n", wolfSSL_get_error(ssl, rc));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(fd);
    return rc == WOLFSSL_SUCCESS ? 0 : 1;
}
