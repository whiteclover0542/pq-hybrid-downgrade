#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 3) return fprintf(stderr, "usage: mbedtls_client HOST PORT\n"), 2;
    int rc;
    char error[128];
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);
    if ((rc = mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) goto fail;
    if ((rc = mbedtls_net_connect(&net, argv[1], argv[2], MBEDTLS_NET_PROTO_TCP)) != 0 ||
        (rc = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) goto fail;
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &rng);
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    if ((rc = mbedtls_ssl_setup(&ssl, &config)) != 0) goto fail;
    mbedtls_ssl_set_hostname(&ssl, argv[1]);
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
    while ((rc = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) goto fail;
    }
    printf("TLS protocol: %s\n", mbedtls_ssl_get_version(&ssl));
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    mbedtls_net_free(&net);
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
    return 0;
fail:
    mbedtls_strerror(rc, error, sizeof(error));
    fprintf(stderr, "mbedTLS error: %s\n", error);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    mbedtls_net_free(&net);
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
    return 1;
}
