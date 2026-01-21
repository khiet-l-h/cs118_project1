#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // TODO: Initialize OpenSSL library
    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    // TODO: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"

    // create SSL context 
    const SSL_METHOD *method = TLS_server_method(); // modern method supporting TLS 1.2/1.3
    SSL_CTX *ssl_ctx = SSL_CTX_new(method); 
    
    // check if SSL context is valid 
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    // load certificate key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to load server.crt\n");
        exit(EXIT_FAILURE);
    }
 
    // load private key 
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to load server.key\n");
        exit(EXIT_FAILURE);
    }

    // verify certificate and private keys match
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Error: Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    // given 
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1) {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);

        if (ssl == NULL) {
            // handle_request(ssl);
            fprintf(stderr, "Error creating SSL object\n");
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket); // bind SSL to client socket fd

        // 3 way handshake 
        if (SSL_accept(ssl) <= 0) {  
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        handle_request(ssl);
        
        // TODO: Clean up SSL connection
        SSL_shutdown(ssl);  
        SSL_free(ssl);      
 
        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();         
    ERR_free_strings();    
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) { // error reading file
        return;
    }

    buffer[bytes_read] = '\0';

    char *request = malloc(strlen(buffer) + 1);

    // make a copy of buffer 
    strcpy(request, buffer);
    
    // parse HTTP request 
    char *method = strtok(request, " ");

    // char *file_name = strtok(NULL, " ");
    // file_name++;
    // if (strlen(file_name) == 0) {
    //     strcat(file_name, "index.html");
    // }

    char *path = strtok(NULL, " ");
    char *http_version = strtok(NULL, " ");

    if (!method || !path || !http_version) {
        fprintf(stderr, "Invalid HTTP request\n");
        free(request);
        return;
    }

    // GET method
    if (strcmp(method, "GET") != 0) {
        fprintf(stderr, "Unsupported method: %s\n", method);
        free(request);
        return;
    }

    // If path is "/", serve "index.html"
    char *file_name;
    if (strcmp(path, "/") == 0) {
        file_name = "index.html";
    } else {
        // Skip leading slash '/'
        file_name = path[0] == '/' ? path + 1 : path;
    }

    // check if the file exists locally 
    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }

    free(request); 
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";

        // TODO: Send response via SSL
        SSL_write(ssl, response, strlen(response)); 

        return;
    }

    char *response;
    // html 
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    } 

    // plain text 
    else if (strstr(path, ".txt")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    }

    // jpg 
    else if (strstr(path, ".jpg")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: image/jpeg\r\n\r\n";
    }

    // m3u8 
    else if (strstr(path, ".m3u8")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/vnd.apple.mpegurl\r\n\r\n";
    }

    // other 
    else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/octet-stream\r\n\r\n";
    }

    // TODO: Send response header and file content via SSL
    SSL_write(ssl, response, strlen(response)); 

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // TODO: Send file data via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    close(remote_socket);
}
