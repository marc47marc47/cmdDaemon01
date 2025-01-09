/**
 * 範例名稱: tls_server.c
 * 編譯方式: gcc tls_server.c -lssl -lcrypto -lpthread -o server
 * 執行方式: ./server -d /myfiles -p 4433 -k server.key -c server.crt
 *
 * 需求:
 *  1) 使用 TLS 1.3
 *  2) 可同時接受多位客戶端
 *  3) 根目錄(例如 /myfiles)作為存放檔案的絕對路徑
 *  4) 上傳過程先用臨時檔案 _tmp.$filename
 *  5) 上傳成功後再改名為最終檔名
 *  6) 判斷是否需要覆蓋檔案(預設不覆蓋)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define BACKLOG 10
#define BUFSIZE 4096

typedef struct {
    SSL_CTX *ctx;
    int sockfd;
    char base_dir[1024]; // 伺服器端儲存檔案的絕對根目錄
} ServerConfig;

void *handle_client(void *arg);
int create_directory_recursively(const char *path);

int main(int argc, char *argv[])
{
    if (argc < 7) {
        fprintf(stderr, "用法: %s -d <絕對目錄> -p <埠號> -k <ServerKey> -c <ServerCert>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char base_dir[1024] = {0};
    int port = 0;
    char key_file[1024] = {0};
    char cert_file[1024] = {0};

    // 簡易解析命令列參數
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") && i+1 < argc) {
            strncpy(base_dir, argv[++i], sizeof(base_dir) - 1);
        } else if (!strcmp(argv[i], "-p") && i+1 < argc) {
            port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-k") && i+1 < argc) {
            strncpy(key_file, argv[++i], sizeof(key_file) - 1);
        } else if (!strcmp(argv[i], "-c") && i+1 < argc) {
            strncpy(cert_file, argv[++i], sizeof(cert_file) - 1);
        }
    }

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 僅啟用 TLS 1.3 (可再視需求調整)
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // 設定憑證和私鑰
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "私鑰與憑證不匹配\n");
        exit(EXIT_FAILURE);
    }

    // 建立 socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 綁定埠口
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port        = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // 監聽
    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("TLS Server啟動，正在監聽埠號 %d, 根目錄: %s\n", port, base_dir);

    // 準備 ServerConfig 結構給後續多執行緒使用
    ServerConfig config;
    config.ctx = ctx;
    config.sockfd = sockfd;
    strncpy(config.base_dir, base_dir, sizeof(config.base_dir)-1);

    while (1) {
        // 等待客戶端連線
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_sock = accept(sockfd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_sock < 0) {
            perror("accept");
            continue; // 繼續等待下一位客戶端
        }

        // 建立執行緒處理該客戶端
        pthread_t tid;
        int *thread_sock = malloc(sizeof(int));
        *thread_sock = client_sock;

        // 使用多執行緒處理
        if (pthread_create(&tid, NULL, handle_client, (void *)&config) != 0) {
            perror("pthread_create");
            close(client_sock);
            free(thread_sock);
        }
        // detach 使執行緒結束後自行釋放資源
        pthread_detach(tid);
    }

    // 關閉
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

/**
 * 處理每個連線的函式
 */
void *handle_client(void *arg)
{
    // 由於 pthread_create 無法直接傳遞多個參數，這裡示範以全域 config + thread local socketID
    // 實務上可以用結構包起來傳遞
    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

    // 先做淺層 copy
    ServerConfig config = *(ServerConfig *)arg;

    // 取得 socket
    // (這裡簡化示範，實際上應該在 pthread_create 參數中傳遞 client_sock)
    pthread_mutex_lock(&mtx);
    int client_sock = accept(config.sockfd, NULL, NULL);
    pthread_mutex_unlock(&mtx);

    if (client_sock < 0) {
        pthread_exit(NULL);
    }

    SSL *ssl = SSL_new(config.ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }

    // -----------------------------
    // 1. 接收上傳參數 (path, filename, 是否覆蓋)
    //    這裡示範簡化版本：先接收固定長度的指令字串
    // -----------------------------
    char buffer[BUFSIZE] = {0};
    int len = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (len <= 0) {
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }
    buffer[len] = '\0';

    // 假設Client端傳上來的格式為: "<path>\n<filename>\n<overwriteFlag>\n"
    char client_path[512] = {0}, client_filename[512] = {0}, overwrite_flag[8] = {0};
    // 簡易切割
    sscanf(buffer, "%s\n%s\n%s", client_path, client_filename, overwrite_flag);

    // -----------------------------
    // 2. 決定最終儲存檔案路徑: base_dir + client_path + client_filename
    // -----------------------------
    char final_path[1024] = {0};
    snprintf(final_path, sizeof(final_path), "%s/%s/%s",
             config.base_dir, client_path, client_filename);

    // 先建立路徑資料夾
    // create_directory_recursively(config.base_dir + client_path)
    char dir_to_create[1024] = {0};
    snprintf(dir_to_create, sizeof(dir_to_create), "%s/%s",
             config.base_dir, client_path);

    if (create_directory_recursively(dir_to_create) != 0) {
        // 回傳失敗
        const char *msg = "FAIL: Create directory error\n";
        SSL_write(ssl, msg, strlen(msg));
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }

    // -----------------------------
    // 3. 檔案已存在時是否覆蓋檢查
    // -----------------------------
    int overwrite = (!strcmp(overwrite_flag, "YES") ? 1 : 0);

    if (!overwrite) {
        // 如果不覆蓋，檢查是否已存在
        if (access(final_path, F_OK) == 0) {
            // 檔案已存在
            const char *msg = "FAIL: File exists, not overwritten\n";
            SSL_write(ssl, msg, strlen(msg));
            SSL_free(ssl);
            close(client_sock);
            pthread_exit(NULL);
        }
    }

    // -----------------------------
    // 4. 建立臨時檔案
    // -----------------------------
    char tmp_path[1024];
    snprintf(tmp_path, sizeof(tmp_path), "%s/_tmp.%s", dir_to_create, client_filename);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        const char *msg = "FAIL: Cannot open temp file\n";
        SSL_write(ssl, msg, strlen(msg));
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }

    // -----------------------------
    // 5. 接收檔案內容
    // -----------------------------
    int bytes_read = 0;
    while ((bytes_read = SSL_read(ssl, buffer, BUFSIZE)) > 0) {
        fwrite(buffer, 1, bytes_read, fp);
    }
    fclose(fp);

    // -----------------------------
    // 6. 將臨時檔案改名為最終檔名
    // -----------------------------
    if (rename(tmp_path, final_path) != 0) {
        const char *msg = "FAIL: Rename file error\n";
        SSL_write(ssl, msg, strlen(msg));
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }

    // 回傳成功
    const char *msg = "OK: Upload success\n";
    SSL_write(ssl, msg, strlen(msg));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);

    pthread_exit(NULL);
}

/**
 * 建立多層目錄的示範函式 (簡易示例)
 */
int create_directory_recursively(const char *path)
{
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp)-1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) && errno != EEXIST) {
        return -1;
    }
    return 0;
}

