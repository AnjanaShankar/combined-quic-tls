/**
 * QUIC client for combined server
 * Compatible with OpenSSL 3.5+ (OSSL_QUIC_client_method)
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define MAX_BUFFER_SIZE 1024

// ALPN string for QUIC handshake
static const unsigned char alpn_ossltest[] = { 0x08, 'o', 's', 's', 'l', 't', 'e', 's', 't' };

// Utility function to print SSL errors
void print_ssl_error(const char *message) {
    fprintf(stderr, "%s: ", message);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
}

// Get current time in seconds
double get_current_time();
SSL_SESSION *load_session_from_file(const char *filename);
int save_session_to_file(SSL_SESSION *session, const char *filename);

// Get current time in seconds
double get_current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

int save_session_to_file(SSL_SESSION *session, const char *filename) {
    int len = i2d_SSL_SESSION(session, NULL);
    if (len <= 0) return 0;
    unsigned char *buf = malloc(len);
    if (!buf) return 0;
    unsigned char *p = buf;
    if (i2d_SSL_SESSION(session, &p) != len) {
        free(buf);
        return 0;
    }
    FILE *f = fopen(filename, "wb");
    if (!f) {
        free(buf);
        return 0;
    }
    size_t written = fwrite(buf, 1, len, f);
    fclose(f);
    free(buf);
    return written == (size_t)len;
}

SSL_SESSION *load_session_from_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) {
        fclose(f);
        return NULL;
    }
    unsigned char *buf = malloc(len);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    const unsigned char *p = buf;
    SSL_SESSION *sess = d2i_SSL_SESSION(NULL, &p, len);
    free(buf);
    return sess;
}


// Create a UDP socket
static int create_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        perror("Socket creation failed");
    }
    return fd;
}

int main(int argc, char **argv) {
    int write_result;
    int fd = -1;
    int ret = 1; // Assume failure
    SSL_CTX *ctx = NULL;
    SSL *conn = NULL;
    struct sockaddr_in peer_addr;
    BIO_ADDR *peer_bio = NULL;
    char buffer[MAX_BUFFER_SIZE];
    size_t readbytes = 0;
    double start_time, end_time;
    const char *hostname = SERVER_IP;
    unsigned short port = SERVER_PORT;
    
    // Parse command-line arguments if provided
    if (argc >= 2) {
        hostname = argv[1];
    }
    if (argc >= 3) {
        port = (unsigned short)atoi(argv[2]);
    }
    
    // Print OpenSSL version information
    printf("[QUIC] Client connecting to %s:%u\n", hostname, port);
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Initialize QUIC SSL context with optimizations
    ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (ctx == NULL) {
        print_ssl_error("Failed to create QUIC SSL context");
        goto cleanup;
    }
    
    // Set QUIC-specific optimizations
    SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
    
    // Optimize cipher suites for QUIC
    const char *cipher_list = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    if (!SSL_CTX_set_cipher_list(ctx, cipher_list)) {
        print_ssl_error("Failed to set QUIC cipher list");
        goto cleanup;
    }
    
    // Disable certificate verification for testing
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    // Create UDP socket with optimized settings
    fd = create_socket();
    if (fd < 0) {
        goto cleanup;
    }
    
    // Set socket options for better performance
    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Failed to set SO_REUSEADDR");
    }
    
    // Enable UDP checksum offloading if available
    #ifdef SO_NO_CHECK
    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NO_CHECK, &optval, sizeof(optval)) < 0) {
        perror("Failed to set SO_NO_CHECK");
    }
    #endif
    
    // Set receive buffer size
    int rcvbuf = 1024 * 1024; // 1MB
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("Failed to set SO_RCVBUF");
    }
    
    // Set send buffer size
    int sndbuf = 1024 * 1024; // 1MB
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        perror("Failed to set SO_SNDBUF");
    }
    
    // Set socket timeout (5 seconds)
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket receive timeout");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket send timeout");
    }
    
    // Set up peer (server) address
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &peer_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        goto cleanup;
    }
    
    // Connect UDP socket to server
    printf("[QUIC] Connecting to %s:%u...\n", hostname, port);
    if (connect(fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("UDP connect failed");
        goto cleanup;
    }
    
    // Try to load session from file
    const char *session_file = "quic_session.bin";
    SSL_SESSION *session = load_session_from_file(session_file);
    if (session) {
        printf("[QUIC] Loaded session from file. Will attempt session resumption.\n");
    }

    // Create new QUIC SSL connection
    conn = SSL_new(ctx);
    if (conn == NULL) {
        print_ssl_error("SSL_new failed");
        goto cleanup;
    }
    
    // Attach UDP socket to SSL object
    if (!SSL_set_fd(conn, fd)) {
        print_ssl_error("SSL_set_fd failed");
        goto cleanup;
    }

    // If session loaded, set it for resumption
    if (session) {
        SSL_set_session(conn, session);
        // SSL_connect will attempt to resume
    }
    
    // Set ALPN protocol to match server
    if (SSL_set_alpn_protos(conn, alpn_ossltest, sizeof(alpn_ossltest)) != 0) {
        print_ssl_error("SSL_set_alpn_protos failed");
        goto cleanup;
    }
    
    // Create and set initial peer address for QUIC
    peer_bio = BIO_ADDR_new();
    if (peer_bio == NULL) {
        print_ssl_error("BIO_ADDR_new failed");
        goto cleanup;
    }
    
    if (!BIO_ADDR_rawmake(peer_bio, AF_INET,
                         (const void *)&(peer_addr.sin_addr.s_addr),
                         sizeof(peer_addr.sin_addr.s_addr),
                         ntohs(peer_addr.sin_port))) {
        print_ssl_error("BIO_ADDR_rawmake failed");
        goto cleanup;
    }
    
    if (!SSL_set1_initial_peer_addr(conn, peer_bio)) {
        print_ssl_error("SSL_set1_initial_peer_addr failed");
        goto cleanup;
    }
    
    // Set SNI hostname
    if (!SSL_set_tlsext_host_name(conn, hostname)) {
        print_ssl_error("SSL_set_tlsext_host_name failed");
        goto cleanup;
    }
    
    // Start timing the connection
    start_time = get_current_time();
    
    // Perform QUIC handshake
    printf("[QUIC] Starting handshake...\n");
    if (!SSL_connect(conn)) {
        print_ssl_error("QUIC handshake (SSL_connect) failed");
        goto cleanup;
    }
    
    // Calculate connection time
    end_time = get_current_time();
    printf("[QUIC] Connection established in %.2f ms\n", (end_time - start_time) * 1000.0);
    
    // Display connection info
    printf("[QUIC] Connected with %s encryption\n", SSL_get_cipher(conn));
    printf("[QUIC] Session reused: %s\n", SSL_session_reused(conn) ? "Yes" : "No");
    
    // Get ALPN protocol
    const unsigned char *alpn_data;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(conn, &alpn_data, &alpn_len);
    if (alpn_len > 0) {
        printf("[QUIC] ALPN protocol: ");
        for (unsigned int i = 0; i < alpn_len; i++) {
            printf("%c", alpn_data[i]);
        }
        printf("\n");
    }
    
    // Send initial hello message before interactive loop
    const char *hello_message = "Hello server, I am QUIC client!\n";
    printf("[QUIC] Sending hello message to server...\n");
    write_result = SSL_write(conn, hello_message, strlen(hello_message));
    if (write_result <= 0) {
        int write_err = SSL_get_error(conn, write_result);
        printf("[QUIC] Write error code: %d\n", write_err);
        print_ssl_error("Failed to write hello message to server");
        goto cleanup;
    }
    printf("[QUIC] Sent: %s", hello_message);
    // Wait for server response to hello message
    int read_result;
    int read_attempts = 0;
    const int max_attempts = 3;
    double reply_start_time = get_current_time();
    while (read_attempts < max_attempts) {
        read_result = SSL_read_ex(conn, buffer, sizeof(buffer) - 1, &readbytes);
        if (read_result > 0) {
            buffer[readbytes] = '\0';
            double reply_end_time = get_current_time();
            printf("[QUIC] Server response: %s", buffer);
            printf("[QUIC] Time to receive reply: %.2f ms\n", (reply_end_time - reply_start_time) * 1000.0);
            break;
        } else {
            int err = SSL_get_error(conn, 0);
            if (err == SSL_ERROR_ZERO_RETURN) {
                printf("[QUIC] Connection closed cleanly by server\n");
                break;
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                printf("[QUIC] Read operation would block, retrying (%d of %d)...\n", read_attempts+1, max_attempts);
                read_attempts++;
                usleep(500000); // Wait 500ms before retrying
            } else {
                printf("[QUIC] SSL_read failed with error: %d\n", err);
                ERR_print_errors_fp(stderr);
                if (err == 1) {
                    printf("[QUIC] Protocol is in shutdown state, proceeding anyway...\n");
                    break;
                }
                goto cleanup;
            }
        }
    }

    // Interactive message sending loop
    char message[MAX_BUFFER_SIZE];
    while (1) {
        printf("[QUIC] Enter message to send (or 'quit' to exit): ");
        if (!fgets(message, sizeof(message), stdin)) {
            printf("[QUIC] Input error or EOF. Exiting.\n");
            break;
        }
        // Remove newline if present
        size_t len = strlen(message);
        if (len > 0 && message[len-1] == '\n') message[len-1] = '\0';
        if (strcmp(message, "quit") == 0) {
            printf("[QUIC] Quitting message loop.\n");
            break;
        }
        // Send message
        write_result = SSL_write(conn, message, strlen(message));
        if (write_result <= 0) {
            int write_err = SSL_get_error(conn, write_result);
            printf("[QUIC] Write error code: %d\n", write_err);
            print_ssl_error("Failed to write to server");
            break;
        }
        printf("[QUIC] Sent: %s\n", message);
        // Wait for server response
        read_result = 0;
        read_attempts = 0;
        reply_start_time = get_current_time();
        while (read_attempts < max_attempts) {
            read_result = SSL_read_ex(conn, buffer, sizeof(buffer) - 1, &readbytes);
            if (read_result > 0) {
                buffer[readbytes] = '\0';
                double reply_end_time = get_current_time();
                printf("[QUIC] Server response: %s\n", buffer);
                printf("[QUIC] Time to receive reply: %.2f ms\n", (reply_end_time - reply_start_time) * 1000.0);
                break;
            } else {
                int err = SSL_get_error(conn, 0);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("[QUIC] Connection closed cleanly by server\n");
                    break;
                } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    printf("[QUIC] Read operation would block, retrying (%d of %d)...\n", read_attempts+1, max_attempts);
                    read_attempts++;
                    usleep(500000); // Wait 500ms before retrying
                } else {
                    printf("[QUIC] SSL_read failed with error: %d\n", err);
                    ERR_print_errors_fp(stderr);
                    if (err == 1) {
                        printf("[QUIC] Protocol is in shutdown state, proceeding anyway...\n");
                        break;
                    }
                    goto cleanup;
                }
            }
        }
    }
    
    // Send "close" to gracefully disconnect
    const char *close_msg = "close\n";
    printf("[QUIC] Sending close message...\n");
    
    int close_result = SSL_write(conn, close_msg, strlen(close_msg));
    if (close_result <= 0) {
        int err = SSL_get_error(conn, close_result);
        if (err == 1) { // Protocol shutdown
            printf("[QUIC] Protocol already in shutdown state, skipping close message\n");
        } else {
            print_ssl_error("Failed to send close message");
        }
    } else {
        printf("[QUIC] Close message sent successfully\n");
        
        // Add delay before trying to read the farewell
        usleep(200000); // 200ms delay
        
        // Read farewell message with timeout handling
        printf("[QUIC] Waiting for farewell message...\n");
        
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int select_result = select(fd + 1, &readfds, NULL, NULL, &tv);
        
        if (select_result > 0) {
            if (SSL_read_ex(conn, buffer, sizeof(buffer) - 1, &readbytes)) {
                buffer[readbytes] = '\0';
                printf("[QUIC] Server farewell: %s", buffer);
            } else {
                int err = SSL_get_error(conn, 0);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("[QUIC] Connection closed by server after farewell\n");
                } else if (err == 1) { // Protocol shutdown
                    printf("[QUIC] Protocol in shutdown state, connection closing\n");
                } else {
                    print_ssl_error("Failed to read farewell message");
                }
            }
        } else if (select_result == 0) {
            printf("[QUIC] Timeout waiting for farewell message\n");
        } else {
            perror("select() error");
        }
    }
    
    // Success
    ret = 0;

cleanup:
    // Clean up
    // Always save the latest session ticket after connection (QUIC/TLS 1.3 tickets are single-use)
    SSL_SESSION *new_session = NULL;
    if (conn != NULL) {
        new_session = SSL_get1_session(conn);
        if (new_session) {
            if (save_session_to_file(new_session, session_file)) {
                printf("[QUIC] Latest session ticket saved to file for next resumption.\n");
            } else {
                printf("[QUIC] Failed to save latest session ticket to file.\n");
            }
        }
    }
    if (new_session) SSL_SESSION_free(new_session);
    if (session) SSL_SESSION_free(session);
    if (peer_bio != NULL)
        BIO_ADDR_free(peer_bio);
    if (conn != NULL)
        SSL_shutdown(conn);
    if (conn != NULL)
        SSL_free(conn);
    if (fd >= 0)
        close(fd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    return ret;
}
