/**
 * 範例名稱: tls_client.c
 * 編譯方式: gcc tls_client.c -lssl -lcrypto -o client
 * 執行方式:
 *   ./client -h 127.0.0.1 -p 4433 -P 2025/05/01 -f test.txt [-r]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>

#define BUFSIZE 4096

int main(int argc, char *argv[])
{
    if (argc < 9) {
        fprintf(stderr, "用法: %s -h <ServerIP> -p <埠號> -P <上傳邏輯路徑> -f <檔名> [-r]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char server_ip[256] = {0};
    int port = 0;
    char upload_path[512] = {0};
    char upload_file[512] = {0};
    int overwrite = 0; // 預設不覆蓋

    // 解析參數
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") && i+1 < argc) {
            strncpy(server_ip, argv[++i], sizeof(server_ip) - 1);
        } else if (!strcmp(argv[i], "-p") && i+1 < argc) {
            port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-P") && i+1 < argc) {
            strncpy(upload_path, argv[++i], sizeof(upload_path) - 1);
        } else if (!strcmp(argv[i], "-f") && i+1 < argc) {
            strncpy(upload_file, argv[++i], sizeof(upload_file) - 1);
        } else if (!strcmp(argv[i], "-r")) {
            overwrite = 1;
        }
    }

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 僅啟用 TLS 1.3 (可視需求調整)
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // 建立 socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_port        = htons(port);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // 連線
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // -----------------------------
    // 1. 傳送控制資訊: 路徑、檔名、是否覆蓋
    //    格式(示例): "<path>\n<filename>\n<YES|NO>\n"
    // -----------------------------
    char ctrl_msg[1024];
    snprintf(ctrl_msg, sizeof(ctrl_msg), "%s\n%s\n%s\n",
             upload_path,
             upload_file,
             (overwrite ? "YES" : "NO"));

    if (SSL_write(ssl, ctrl_msg, strlen(ctrl_msg)) <= 0) {
        fprintf(stderr, "SSL_write error\n");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // -----------------------------
    // 2. 傳送檔案內容
    // -----------------------------
    FILE *fp = fopen(upload_file, "rb");
    if (!fp) {
        perror("fopen");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    char buffer[BUFSIZE];
    int bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, BUFSIZE, fp)) > 0) {
        int ret = SSL_write(ssl, buffer, bytes_read);
        if (ret <= 0) {
            fprintf(stderr, "SSL_write error during file upload\n");
            fclose(fp);
            close(sockfd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);

    // -----------------------------
    // 3. 等待 Server 回應成功或失敗
    // -----------------------------
    memset(buffer, 0, sizeof(buffer));
    int len = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Server回應: %s\n", buffer);
    } else {
        fprintf(stderr, "SSL_read error or no response\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

