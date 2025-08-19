//Code with `echo_client_data` refactored to handle both QUIC and TLS servers, providing improved resource management, detailed logging, and enhanced handling for edge cases:

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#ifdef _WIN32
# include <winsock2.h>
#else
# include <netinet/in.h>
# include <unistd.h>
# include <sched.h>  // Add this for CPU affinity functions
#endif
#include <pthread.h>
#include <assert.h>
#include <string.h>

/* ALPN string for QUIC handshake */
static const unsigned char alpn_ossltest[] = { 0x08, 'o', 's', 's', 'l', 't', 'e', 's', 't' };

/* ALPN Selection Callback */
static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *out_len,
                       const unsigned char *in, unsigned int in_len, void *arg) 
{
    fprintf(stderr, "[DEBUG] Running ALPN selection callback...\n");

    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest, sizeof(alpn_ossltest), in, in_len) 
            != OPENSSL_NPN_NEGOTIATED) {
        fprintf(stderr, "[ERROR] ALPN selection failed\n");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    fprintf(stderr, "[INFO] ALPN negotiation successful: Protocol selected\n");
    return SSL_TLSEXT_ERR_OK;
}

/* Create QUIC SSL Context */
static SSL_CTX *create_quic_ctx(const char *cert_path, const char *key_path)
{
    fprintf(stderr, "[DEBUG] Initializing QUIC SSL context...\n");

    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) {
        fprintf(stderr, "[ERROR] Failed to create QUIC SSL context\n");
        return NULL;
    }

    // Set QUIC-specific optimizations
    SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
    // Remove max_early_data setting as it's causing protocol violation
    // SSL_CTX_set_max_early_data(ctx, 16384);
    
    // Optimize cipher suites for QUIC
    const char *cipher_list = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    if (!SSL_CTX_set_cipher_list(ctx, cipher_list)) {
        fprintf(stderr, "[ERROR] Failed to set QUIC cipher list\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Enable session tickets for better performance
    SSL_CTX_set_num_tickets(ctx, 4);

    fprintf(stderr, "[DEBUG] Loading certificate: %s\n", cert_path);
    fprintf(stderr, "[DEBUG] Loading private key: %s\n", key_path);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[ERROR] QUIC SSL context initialization failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Set ALPN callback */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    /* Set session id context for QUIC (required for tickets) */
    static const unsigned char sid_ctx[] = "ossltest";
    if (!SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx)-1)) {
        fprintf(stderr, "[ERROR] Failed to set QUIC session id context\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    fprintf(stderr, "[INFO] QUIC session id context configured\n");

    fprintf(stderr, "[INFO] QUIC SSL context created successfully\n");
    return ctx;
}

/* Create TLS SSL Context */
static SSL_CTX *create_tls_ctx(const char *cert_path, const char *key_path)
{
    fprintf(stderr, "[DEBUG] Initializing TLS SSL context...\n");

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "[ERROR] Failed to create TLS SSL context\n");
        return NULL;
    }

    fprintf(stderr, "[DEBUG] Loading certificate: %s\n", cert_path);
    fprintf(stderr, "[DEBUG] Loading private key: %s\n", key_path);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[ERROR] TLS SSL context initialization failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Set session cache mode and session id context for TLS */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    static const unsigned char sid_ctx[] = "ossltest";
    if (!SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx)-1)) {
        fprintf(stderr, "[ERROR] Failed to set TLS session id context\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    fprintf(stderr, "[INFO] TLS session id context configured\n");

    fprintf(stderr, "[INFO] TLS SSL context created successfully\n");
    return ctx;
}

/* Create UDP socket for QUIC with optimized settings */
static int create_udp_socket(uint16_t port)
{
    fprintf(stderr, "[DEBUG] Creating UDP socket for QUIC...\n");

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        fprintf(stderr, "[ERROR] Failed to create UDP socket\n");
        return -1;
    }

    // Set socket options for better performance
    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "[ERROR] Failed to set SO_REUSEADDR\n");
    }

    // Enable UDP checksum offloading if available
    #ifdef SO_NO_CHECK
    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NO_CHECK, &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "[WARNING] Failed to set SO_NO_CHECK\n");
    }
    #endif

    // Set receive buffer size
    int rcvbuf = 1024 * 1024; // 1MB
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        fprintf(stderr, "[WARNING] Failed to set SO_RCVBUF\n");
    }

    // Set send buffer size
    int sndbuf = 1024 * 1024; // 1MB
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        fprintf(stderr, "[WARNING] Failed to set SO_SNDBUF\n");
    }

    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "[ERROR] Failed to bind UDP socket to port %d\n", port);
        close(fd);
        return -1;
    }

    fprintf(stderr, "[INFO] UDP socket for QUIC bound to port %d\n", port);
    return fd;
}

/* Create TCP socket for TLS */
static int create_tcp_socket(uint16_t port)
{
    fprintf(stderr, "[DEBUG] Creating TCP socket for TLS...\n");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[ERROR] Failed to create TCP socket\n");
        return -1;
    }

    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, 10) < 0) {
        fprintf(stderr, "[ERROR] Failed to bind TCP socket to port %d\n", port);
        close(fd);
        return -1;
    }

    fprintf(stderr, "[INFO] TCP socket for TLS listening on port %d\n", port);
    return fd;
}

/* Reusable client handling function */
static void handle_client_data(SSL *ssl) {
    char buffer[1024];
    int bytes;
    size_t written;

    fprintf(stderr, "[DEBUG] Starting client data handling...\n");

    while (1) {
        // Read data from the client
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int err = SSL_get_error(ssl, bytes);
            if (err == SSL_ERROR_ZERO_RETURN) {
                fprintf(stderr, "[INFO] Client closed the connection\n");
                break;
            } else {
                fprintf(stderr, "[ERROR] SSL_read failed with error: %d\n", err);
                ERR_print_errors_fp(stderr);
                break;
            }
        }

        buffer[bytes] = '\0'; // Null-terminate the received data
        fprintf(stderr, "[INFO] Received from client: %s", buffer);

        // Check if the client wants to close the connection
        if (strncmp(buffer, "close", 5) == 0) {
            fprintf(stderr, "[INFO] Client requested to close the connection\n");

            // Check if the connection is QUIC
            if (SSL_is_quic(ssl)) {
                // Send "Goodbye" message and conclude the QUIC stream
                if (!SSL_write_ex2(ssl, "Goodbye!\n", 9, SSL_WRITE_FLAG_CONCLUDE, &written)) {
                    fprintf(stderr, "[ERROR] Final SSL_write_ex2 failed for QUIC\n");
                    ERR_print_errors_fp(stderr);
                } else {
                    fprintf(stderr, "[INFO] Sent 'Goodbye' to client on QUIC connection\n");
                }
            } else {
                // Send "Goodbye" message for TLS (no conclude flag)
                if (SSL_write(ssl, "Goodbye!\n", 9) <= 0) {
                    fprintf(stderr, "[ERROR] Final SSL_write failed for TLS\n");
                    ERR_print_errors_fp(stderr);
                } else {
                    fprintf(stderr, "[INFO] Sent 'Goodbye' to client on TLS connection\n");
                }
            }
            break;
        }

        // Echo the data back to the client
        if (!SSL_write_ex2(ssl, buffer, strlen(buffer), 0, &written)) {
            fprintf(stderr, "[ERROR] SSL_write_ex2 failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        fprintf(stderr, "[INFO] Echoed back to client: %s", buffer);
    }
}

/* Handle QUIC Connections with optimized thread handling */
static void *run_quic_server(void *arg)
{
    SSL_CTX *ctx = (SSL_CTX *)arg;

    SSL *listener = SSL_new_listener(ctx, 0);
    if (!listener) {
        fprintf(stderr, "[FATAL] Failed to create QUIC listener. Exiting QUIC server thread.\n");
        return NULL;
    }

    int fd = create_udp_socket(4433);
    if (!SSL_set_fd(listener, fd)) {
        fprintf(stderr, "[FATAL] Failed to assign UDP socket to QUIC listener. Exiting QUIC server thread.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        return NULL;
    }

    if (!SSL_listen(listener)) {
        fprintf(stderr, "[FATAL] QUIC SSL listener failed. Exiting QUIC server thread.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        return NULL;
    }

    fprintf(stderr, "[INFO] QUIC listener is running...\n");

    while (1) {
        // Accept new QUIC connection
        SSL *conn = SSL_accept_connection(listener, 0);
        if (!conn) {
            fprintf(stderr, "[ERROR] Failed to accept QUIC connection. Continuing...\n");
            ERR_print_errors_fp(stderr);
            continue;
        }

        fprintf(stderr, "[INFO] QUIC handshake successful\n");

        // Print session details for QUIC
        SSL_SESSION *quic_session = SSL_get0_session(conn);
        if (quic_session) {
            const unsigned char *sid = NULL;
            unsigned int sid_len = 0;
            sid = SSL_SESSION_get_id(quic_session, &sid_len);
            fprintf(stderr, "[INFO] QUIC Session ID: ");
            for (unsigned int i = 0; i < sid_len; ++i) fprintf(stderr, "%02X", sid[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "[INFO] QUIC Protocol Version: 0x%04X\n", SSL_SESSION_get_protocol_version(quic_session));
            fprintf(stderr, "[INFO] QUIC Session Timeout: %ld seconds\n", SSL_SESSION_get_timeout(quic_session));
            fprintf(stderr, "[INFO] QUIC session reused: %s\n", SSL_session_reused(conn) ? "Yes" : "No");
        }

        // Reuse shared client handling function
        handle_client_data(conn);

        // Clean up the connection
        SSL_shutdown(conn);
        SSL_free(conn);
        fprintf(stderr, "[INFO] QUIC connection cleaned up\n");
        fprintf(stderr, "[INFO] QUIC server still running and ready for new connections.\n");
    }
    // This point should never be reached unless the thread is explicitly cancelled
    fprintf(stderr, "[FATAL] QUIC server thread exiting unexpectedly!\n");
    SSL_free(listener);
    return NULL;
}

/* Handle TLS Connections */
static void *run_tls_server(void *arg)
{
    SSL_CTX *ctx = (SSL_CTX *)arg;
    int fd = create_tcp_socket(4433);
    if (fd < 0) {
        fprintf(stderr, "[FATAL] Failed to create TCP socket for TLS. Exiting TLS server thread.\n");
        return NULL;
    }
    fprintf(stderr, "[INFO] TLS server is running...\n");

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        int client_fd = accept(fd, (struct sockaddr *)&client, &len);
        if (client_fd < 0) {
            fprintf(stderr, "[ERROR] Failed to accept TLS connection (errno=%d). Continuing...\n", errno);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "[ERROR] Failed to allocate SSL object. Closing client_fd and continuing...\n");
            close(client_fd);
            continue;
        }
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) != 1) {
            fprintf(stderr, "[ERROR] TLS handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        fprintf(stderr, "[INFO] TLS handshake successful\n");

        // Print session details for TLS
        SSL_SESSION *tls_session = SSL_get0_session(ssl);
        if (tls_session) {
            const unsigned char *sid = NULL;
            unsigned int sid_len = 0;
            sid = SSL_SESSION_get_id(tls_session, &sid_len);
            fprintf(stderr, "[INFO] TLS Session ID: ");
            for (unsigned int i = 0; i < sid_len; ++i) fprintf(stderr, "%02X", sid[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "[INFO] TLS Protocol Version: 0x%04X\n", SSL_SESSION_get_protocol_version(tls_session));
            fprintf(stderr, "[INFO] TLS Session Timeout: %ld seconds\n", SSL_SESSION_get_timeout(tls_session));
            fprintf(stderr, "[INFO] TLS session reused: %s\n", SSL_session_reused(ssl) ? "Yes" : "No");
        }

        // Reuse the shared client handling function
        handle_client_data(ssl);

        // Properly shutdown the connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        fprintf(stderr, "[INFO] TLS connection cleaned up\n");
        fprintf(stderr, "[INFO] TLS server still running and ready for new connections.\n");
    }
    // This point should never be reached unless the thread is explicitly cancelled
    fprintf(stderr, "[FATAL] TLS server thread exiting unexpectedly!\n");
    return NULL;
}

/* Entry Point */
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: %s <server.crt> <server.key>\n", argv[0]);
        return 1;
    }

    // Initialize QUIC and TLS contexts
    SSL_CTX *quic_ctx = create_quic_ctx(argv[1], argv[2]);
    SSL_CTX *tls_ctx = create_tls_ctx(argv[1], argv[2]);

    if (!quic_ctx || !tls_ctx) {
        fprintf(stderr, "[ERROR] Failed to initialize QUIC or TLS contexts\n");
        return 1;
    }

    // Launch QUIC and TLS server threads
    pthread_t quic_thread, tls_thread;
    pthread_create(&quic_thread, NULL, run_quic_server, quic_ctx);
    pthread_create(&tls_thread, NULL, run_tls_server, tls_ctx);

    // Wait for threads to finish
    int quic_ret, tls_ret;
    pthread_join(quic_thread, (void**)&quic_ret);
    pthread_join(tls_thread, (void**)&tls_ret);

    if (quic_ret != 0) {
        fprintf(stderr, "[FATAL] QUIC server thread exited unexpectedly with code %d!\n", quic_ret);
    }
    if (tls_ret != 0) {
        fprintf(stderr, "[FATAL] TLS server thread exited unexpectedly with code %d!\n", tls_ret);
    }

    // Free SSL contexts
    SSL_CTX_free(quic_ctx);
    SSL_CTX_free(tls_ctx);

    // Watchdog loop: keep process alive and print heartbeats if threads exited
    fprintf(stderr, "[FATAL] Both server threads exited. Entering watchdog loop.\n");
    while (1) {
        fprintf(stderr, "[HEARTBEAT] Server main process still alive, but threads exited.\n");
        sleep(5);
    }
    return 1;
}

