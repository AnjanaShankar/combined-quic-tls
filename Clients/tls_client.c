/**
 * Simple TLS client that connects to the combined server
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define MAX_BUFFER_SIZE 1024

// Utility function to print SSL errors
void print_ssl_error(const char *message) {
    fprintf(stderr, "%s: ", message);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
}

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

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    struct sockaddr_in server_addr;
    char buffer[MAX_BUFFER_SIZE];
    int bytes;
    double start_time, end_time;
    
    // Print OpenSSL version information
    printf("[TLS] Client connecting to %s:%d\n", SERVER_IP, SERVER_PORT);
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        print_ssl_error("Failed to create SSL context");
        return 1;
    }
    
    // Set TLS 1.3 as the minimum version
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    
    // Disable certificate verification for testing
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // Prepare server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // Start timing the connection
    start_time = get_current_time();
    
    // Connect to server
    printf("[TLS] Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[TLS] Connection failed");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // Try to load session from file
    const char *session_file = "tls_session.bin";
    SSL_SESSION *session = load_session_from_file(session_file);
    if (session) {
        printf("[TLS] Loaded session from file. Will attempt session resumption.\n");
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        print_ssl_error("Failed to create SSL object");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // Set the socket for SSL
    SSL_set_fd(ssl, sock);

    // If session loaded, set it for resumption
    if (session) {
        SSL_set_session(ssl, session);
        // SSL_connect will attempt to resume
    }
    
    // Perform SSL handshake
    printf("[TLS] Starting handshake...\n");
    if (SSL_connect(ssl) <= 0) {
        print_ssl_error("SSL handshake failed");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // Calculate connection time
    end_time = get_current_time();
    // Display connection info in milliseconds
    printf("[TLS] Connection established in %.2f ms\n", (end_time - start_time) * 1000.0);
    printf("[TLS] Connected with %s encryption\n", SSL_get_cipher(ssl));
    printf("[TLS] Session reused: %s\n", SSL_session_reused(ssl) ? "Yes" : "No");
    printf("[TLS] TLS Version: %s\n", SSL_get_version(ssl));
    
    // Send initial hello message before interactive loop
    const char *hello_message = "Hello server, I am TLS client!\n";
    int write_result;
    printf("[TLS] Sending hello message to server...\n");
    write_result = SSL_write(ssl, hello_message, strlen(hello_message));
    if (write_result <= 0) {
        int write_err = SSL_get_error(ssl, write_result);
        printf("[TLS] Write error code: %d\n", write_err);
        print_ssl_error("Failed to write hello message to server");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("[TLS] Sent: %s", hello_message);
    // Wait for server response to hello message
    double reply_start_time = get_current_time();
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    double reply_end_time = get_current_time();
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[TLS] Server response: %s", buffer);
        printf("[TLS] Time to receive reply: %.2f ms\n", (reply_end_time - reply_start_time) * 1000.0);
    } else {
        print_ssl_error("Failed to read hello response from server");
    }

    // Interactive message sending loop
    char message[MAX_BUFFER_SIZE];
    while (1) {
        printf("[TLS] Enter message to send (or 'quit' to exit): ");
        if (!fgets(message, sizeof(message), stdin)) {
            printf("[TLS] Input error or EOF. Exiting.\n");
            break;
        }
        // Remove newline if present
        size_t len = strlen(message);
        if (len > 0 && message[len-1] == '\n') message[len-1] = '\0';
        if (strcmp(message, "quit") == 0) {
            printf("[TLS] Quitting message loop.\n");
            break;
        }
        // Send message
        write_result = SSL_write(ssl, message, strlen(message));
        if (write_result <= 0) {
            int write_err = SSL_get_error(ssl, write_result);
            printf("[TLS] Write error code: %d\n", write_err);
            print_ssl_error("Failed to write to server");
            break;
        }
        printf("[TLS] Sent: %s\n", message);
        // Wait for server response
        reply_start_time = get_current_time();
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        reply_end_time = get_current_time();
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("[TLS] Server response: %s\n", buffer);
            printf("[TLS] Time to receive reply: %.2f ms\n", (reply_end_time - reply_start_time) * 1000.0);
        } else {
            print_ssl_error("Failed to read from server");
            break;
        }
    }
    
    // Send "close" to gracefully disconnect
    const char *close_msg = "close\n";
    printf("[TLS] Sending close message...\n");
    SSL_write(ssl, close_msg, strlen(close_msg));
    printf("[TLS] Close message sent successfully\n");
    
    // Add delay before trying to read the farewell
    usleep(200000); // 200ms delay
    
    // Read farewell message
    printf("[TLS] Waiting for farewell message...\n");
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[TLS] Server farewell: %s", buffer);
    } else {
        int err = SSL_get_error(ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN) {
            printf("[TLS] Connection closed by server after farewell\n");
        } else {
            print_ssl_error("Failed to read farewell message");
        }
    }
    
    // Clean up
    // Save session if new session was negotiated
    SSL_SESSION *new_session = SSL_get1_session(ssl);
    if (new_session && !SSL_session_reused(ssl)) {
        if (save_session_to_file(new_session, session_file)) {
            printf("[TLS] Session saved to file for future resumption.\n");
        } else {
            printf("[TLS] Failed to save session to file.\n");
        }
    } else if (SSL_session_reused(ssl)) {
        printf("[TLS] Session was reused from file.\n");
    }
    if (new_session) SSL_SESSION_free(new_session);
    if (session) SSL_SESSION_free(session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

