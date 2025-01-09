/**
 * 範例名稱: tls_client.c (需驗證 server.crt)
 * 編譯方式: gcc tls_client.c -lssl -lcrypto -o client
 * 執行方式:
 *   ./client -h 127.0.0.1 -p 4433 -P 2025/05/01 -f test.txt [-r] -C server.crt
 *
 * 主要差異:
 *   1. SSL_CTX_load_verify_locations(ctx, <server.crt路徑>, NULL)
 *   2. SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)
 *   3. SSL_CTX_set_verify_depth(ctx, 4) (可依需求調整)
 *   4. 驗證伺服器憑證, 若不符則終止連線
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <fcntl.h>

#define BUFSIZE 4096

int main(int argc, char *argv[])
{
    if (argc < 11) {
        fprintf(stderr, "用法: %s -h <ServerIP> -p <埠號> -P <上傳邏輯路徑> -f <檔名> [-r] -C <server.crt>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char server_ip[256]    = {0};
    int  port              = 0;
    char upload_path[512]  = {0};
    char upload_file[512]  = {0};
    char ca_file[512]      = {0}; // 這裡用來指向 server.crt
    int  overwrite         = 0;   // 預設不覆蓋

    // -----------------------------
    // 1. 解析命令列參數
    // -----------------------------
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
            overwrite = 1; // 覆蓋
        } else if (!strcmp(argv[i], "-C") && i+1 < argc) {
            strncpy(ca_file, argv[++i], sizeof(ca_file) - 1); // 指定server.crt
        }
    }

    // -----------------------------
    // 2. 初始化 OpenSSL
    // -----------------------------
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

    // 核心: 載入 CA/憑證檔
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        fprintf(stderr, "無法載入憑證檔: %s\n", ca_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // 啟用對 Server 證書的驗證
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // 驗證深度(若有中繼憑證鏈可視需求調整)
    SSL_CTX_set_verify_depth(ctx, 4);

    // -----------------------------
    // 3. 建立 SSL 並與 Server 建立連線
    // -----------------------------
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

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
        fprintf(stderr, "SSL_connect failed\n");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // -----------------------------
    // 4. 檢查伺服器的憑證 (Verify Peer)
    // -----------------------------
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (!server_cert) {
        fprintf(stderr, "Server未提供憑證，驗證失敗\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    // 這裡可再做進一步檢查，如主機名等
    X509_free(server_cert);

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "憑證驗證失敗: %ld\n", verify_result);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // -----------------------------
    // 5. 傳送控制資訊: 路徑、檔名、是否覆蓋
    // -----------------------------
    char ctrl_msg[1024];
    snprintf(ctrl_msg, sizeof(ctrl_msg), "%s\n%s\n%s\n",
             upload_path,
             upload_file,
             (overwrite ? "YES" : "NO"));

    if (SSL_write(ssl, ctrl_msg, strlen(ctrl_msg)) <= 0) {
        fprintf(stderr, "SSL_write error: 傳送控制訊息失敗\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // -----------------------------
    // 6. 傳送檔案內容
    // -----------------------------
    FILE *fp = fopen(upload_file, "rb");
    if (!fp) {
        perror("fopen");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
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
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);

    // -----------------------------
    // 7. 等待 Server 回應成功或失敗
    // -----------------------------
    memset(buffer, 0, sizeof(buffer));
    int len = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Server回應: %s\n", buffer);
    } else {
        fprintf(stderr, "SSL_read error or no response\n");
    }

    // -----------------------------
    // 8. 結束
    // -----------------------------
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

