/**
 * 範例名稱: tls_client.c
 * 編譯方式: gcc tls_client.c -lssl -lcrypto -o client
 * 執行方式:
 *   ./client -h <ServerIP> -p <埠號> -P <上傳邏輯路徑> -f <檔名> [-r] -C <server.crt>
 *
 * 修改重點:
 *   1. 新增 log_message() 函式，將訊息輸出到螢幕 (stdout)。
 *   2. 在適當位置呼叫 log_message()，便於除錯與追蹤。
 *   3. 若需同時寫入日誌檔，可參考先前 server 範例，增加檔案寫入邏輯 (init_log_file / close_log_file)。
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
#include <time.h>
#include <stdarg.h>  // for va_list, va_start, va_end

#define BUFSIZE 4096

/**
 * log_message: 將訊息輸出到螢幕 (stdout)。可加上檔案寫入機制如需寫日誌檔。
 */
static void log_message(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // 取得當下時間字串
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);

    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

    // 螢幕顯示
    fprintf(stdout, "[%s] ", time_str);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");

    fflush(stdout);
    va_end(args);
}

// ---------------------------------------------------------------

int main(int argc, char *argv[])
{
    // 參數檢查 (最少需要: -h, -p, -P, -f, -C)
    if (argc < 11) {
        fprintf(stderr, "用法: %s -h <ServerIP> -p <埠號> -P <上傳邏輯路徑> -f <檔名> [-r] -C <server.crt>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char server_ip[256]   = {0};
    int  port             = 0;
    char upload_path[512] = {0};
    char upload_file[512] = {0};
    char ca_file[512]     = {0}; // 用於驗證 server.crt
    int  overwrite        = 0;   // 預設不覆蓋

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
            strncpy(ca_file, argv[++i], sizeof(ca_file) - 1); // 指定 server.crt
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

    // 載入並驗證 server.crt
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        fprintf(stderr, "無法載入憑證檔案: %s\n", ca_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // 啟用對 Server 證書的驗證
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // 驗證深度(若有中繼憑證鏈可視需求調整)
    SSL_CTX_set_verify_depth(ctx, 4);

    // -----------------------------
    // 3. 建立 socket 並與 Server 建立連線
    // -----------------------------
    log_message("嘗試連線到伺服器 %s:%d", server_ip, port);
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

    log_message("成功建立 TCP 連線，進行 SSL/TLS handshake...");
    fprintf(stdout, " 1-----------------------\n");
    SSL_set_fd(ssl, sockfd);
    fprintf(stdout, " 2-----------------------\n");

    if (SSL_connect(ssl) <= 0) {
    	fprintf(stdout, " 3.1-----------------------\n");
        ERR_print_errors_fp(stderr);
        log_message("SSL_connect 失敗，結束程式");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, " 4-----------------------\n");
    log_message("SSL/TLS handshake 完成");

    // -----------------------------
    // 4. 檢查伺服器的憑證 (Verify Peer)
    // -----------------------------
    fprintf(stdout, " 5-----------------------\n");
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (!server_cert) {
    	fprintf(stdout, " 6.1-----------------------\n");
        log_message("Server未提供憑證，驗證失敗");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, " 7-----------------------\n");
    X509_free(server_cert);

    long verify_result = SSL_get_verify_result(ssl);
    fprintf(stdout, " 8-----------------------\n");
    if (verify_result != X509_V_OK) {
        log_message("憑證驗證失敗: %ld", verify_result);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    log_message("Server憑證驗證通過");

    fprintf(stdout, " 9-----------------------\n");
    // -----------------------------
    // 5. 傳送控制資訊: 路徑、檔名、是否覆蓋
    // -----------------------------
    log_message("開始上傳檔案資訊: upload_path=%s, upload_file=%s, overwrite=%s",
                upload_path, upload_file, (overwrite ? "YES" : "NO"));

    char ctrl_msg[1024];
    snprintf(ctrl_msg, sizeof(ctrl_msg), "%s\n%s\n%s\n",
             upload_path,
             upload_file,
             (overwrite ? "YES" : "NO"));

    if (SSL_write(ssl, ctrl_msg, strlen(ctrl_msg)) <= 0) {
        log_message("傳送控制資訊時 SSL_write 發生錯誤");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // -----------------------------
    // 6. 傳送檔案內容
    // -----------------------------
    FILE *fp = fopen(upload_file, "rb");
    if (!fp) {
        perror("fopen");
        log_message("無法開啟要上傳的檔案: %s", upload_file);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    log_message("開始上傳檔案內容...");

    char buffer[BUFSIZE];
    int bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, BUFSIZE, fp)) > 0) {
        int ret = SSL_write(ssl, buffer, bytes_read);
        if (ret <= 0) {
            log_message("上傳中斷，SSL_write 發生錯誤");
            fclose(fp);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);
    log_message("檔案內容上傳完成，等待伺服器回應...");

    // -----------------------------
    // 7. 等待 Server 回應成功或失敗
    // -----------------------------
    memset(buffer, 0, sizeof(buffer));
    int len = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (len > 0) {
        buffer[len] = '\0';
        log_message("伺服器回應: %s", buffer);
    } else {
        log_message("等待伺服器回應時，SSL_read 發生錯誤或無回應");
    }

    // -----------------------------
    // 8. 結束
    // -----------------------------
    log_message("關閉連線，結束程式");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

