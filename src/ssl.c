#include "../include/https_server.h"

static SSL_CTX *ssl_ctx = NULL;

// Initialize SSL library and context
int ssl_init(server_config_t *config)
{
    // Initialize SSL library
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Create SSL context
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx == NULL)
    {
        LOG_ERROR("Failed to create SSL context: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Set minimum TLS version to 1.2
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1)
    {
        LOG_ERROR("Failed to set minimum TLS version: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Set cipher list
    if (SSL_CTX_set_cipher_list(ssl_ctx,
                                "HIGH:!aNULL:!MD5:!RC4:!3DES:!CAMELLIA:!AES128") != 1)
    {
        LOG_ERROR("Failed to set cipher list: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Load certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx, config->cert_file,
                                     SSL_FILETYPE_PEM) != 1)
    {
        LOG_ERROR("Failed to load certificate: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config->key_file,
                                    SSL_FILETYPE_PEM) != 1)
    {
        LOG_ERROR("Failed to load private key: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Verify private key
    if (SSL_CTX_check_private_key(ssl_ctx) != 1)
    {
        LOG_ERROR("Private key does not match certificate: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Set session cache mode
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(ssl_ctx, 128);

    // Set session ID context
    const char *session_id = "HTTPS_SERVER";
    if (SSL_CTX_set_session_id_context(ssl_ctx,
                                       (const unsigned char *)session_id, strlen(session_id)) != 1)
    {
        LOG_ERROR("Failed to set session ID context: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Enable OCSP stapling
    SSL_CTX_set_tlsext_status_type(ssl_ctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ssl_ctx, NULL); // TODO: Implement OCSP callback

    // Set security options
    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_NO_SSLv2 |
                            SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_TLSv1 |
                            SSL_OP_NO_TLSv1_1 |
                            SSL_OP_NO_COMPRESSION |
                            SSL_OP_SINGLE_DH_USE |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    LOG_DEBUG("SSL context initialized successfully: %s", "dummy");
    return 0;
}

// Get SSL context
SSL_CTX *ssl_get_context(void)
{
    return ssl_ctx;
}

// Clean up SSL
void ssl_cleanup(void)
{
    if (ssl_ctx != NULL)
    {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }

    // Clean up SSL library
    EVP_cleanup();
    ERR_free_strings();
}
