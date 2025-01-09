/**
 * 範例名稱: tls_server.c
 * 編譯方式: gcc tls_server.c -lssl -lcrypto -lpthread -o server
 * 執行方式: ./server -d /myfiles -p 4433 -k server.key -c server.crt
 *
 * 修改重點:
 *   1. 新增 log_message() 函式，將訊息同時輸出到螢幕與每日 log 檔案 server-YYYYMMDD.log。
 *   2. 以 pthread_mutex 鎖定 log 操作，避免多執行緒寫入衝突。
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
#include <time.h>
#include <errno.h>

#define BACKLOG 10
#define BUFSIZE 4096

typedef struct {
    SSL_CTX *ctx;
    int sockfd;
    char base_dir[1024]; // 伺服器端儲存檔案的絕對根目錄
} ServerConfig;

// 全域 log 檔相關參數 (示範用，實務可用更完善作法)
static FILE *g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * log_message: 同時輸出日誌到螢幕與日誌檔
 */
void log_message(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // 取得時間字串
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);

    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

    // 上鎖
    pthread_mutex_lock(&g_log_mutex);

    // 1) 先輸出到螢幕
    fprintf(stdout, "[%s] ", time_str);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    fflush(stdout);

    // 2) 同步寫入 log 檔案
    if (g_log_file) {
        fprintf(g_log_file, "[%s] ", time_str);
        //vfprintf(g_log_file, format, args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }

    pthread_mutex_unlock(&g_log_mutex);

    va_end(args);
}

/**
 * 根據當天日期開啟 log 檔案 (如 server-20250109.log)
 */
int init_log_file()
{
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);

    char filename[128];
    strftime(filename, sizeof(filename), "server-%Y%m%d.log", &tm_info);

    g_log_file = fopen(filename, "a"); // 以 "追加" 模式開檔
    if (!g_log_file) {
        fprintf(stderr, "無法開啟日誌檔案 %s: %s\n", filename, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * 關閉 log 檔案
 */
void close_log_file()
{
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

// -----------------------------------------------------------------

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

    // 初始化 log 檔
    if (init_log_file() != 0) {
        fprintf(stderr, "初始化 log 檔案失敗，程式退出\n");
        exit(EXIT_FAILURE);
    }
    log_message("Server啟動: base_dir=%s, port=%d, key=%s, cert=%s", base_dir, port, key_file, cert_file);

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        close_log_file();
        exit(EXIT_FAILURE);
    }

    // 僅啟用 TLS 1.3 (可再視需求調整)
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // 設定憑證和私鑰
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        close_log_file();
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        close_log_file();
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        log_message("私鑰與憑證不匹配");
        close_log_file();
        exit(EXIT_FAILURE);
    }

    // 建立 socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        log_message("socket建立失敗");
        close_log_file();
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
        log_message("bind失敗");
        close(sockfd);
        close_log_file();
        exit(EXIT_FAILURE);
    }

    // 監聽
    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen");
        log_message("listen失敗");
        close(sockfd);
        close_log_file();
        exit(EXIT_FAILURE);
    }

    log_message("TLS Server啟動，正在監聽埠號 %d, 根目錄: %s", port, base_dir);

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
            log_message("accept失敗，繼續等待下一位客戶端");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        log_message("客戶端連線: %s:%d", client_ip, ntohs(cli_addr.sin_port));

        log_message("1----------------");
        // 建立執行緒處理該客戶端
        pthread_t tid;
        log_message("2----------------");
        // 為了簡化，直接把 client_sock 包裝成指標傳遞給執行緒
        // 注意: handle_client 也需要拿到 config，所以這裡用 trick(全域或複合結構)
        // 為了示範，這裡先只傳 client_sock，config 以全域方式簡易示範(不太嚴謹)
        int *pclient_sock = malloc(sizeof(int));
        *pclient_sock = client_sock;
        log_message("3----------------");

        if (pthread_create(&tid, NULL, handle_client, (void *)&config) != 0) {
            log_message("4.1----------------");
            perror("pthread_create");
            log_message("建立執行緒失敗");
            close(client_sock);
            free(pclient_sock);
            continue;
        }
        log_message("5----------------");
        pthread_detach(tid);
        log_message("6----------------");
    }

    // 關閉
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    close_log_file();
    return 0;
}

/**
 * 處理每個連線的函式
 */
void *handle_client(void *arg)
{
    // 注意: 此示例直接使用*(ServerConfig*)arg，是同一份 config，
    //        不適合真正生產環境(需要更嚴謹的參數傳遞)。
    //        不過此處為教學示例，故暫時如此。
    log_message("3.1----------------");
    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

    log_message("3.2----------------");
    ServerConfig config = *(ServerConfig *)arg;

    // 先取得真正的 client_sock
    // (示例中我們其實應該用 pthread_create 傳遞 struct 結構包含 config + client_sock)
    pthread_mutex_lock(&mtx);
    log_message("3.3----------------");
    int client_sock = accept(config.sockfd, NULL, NULL);
    log_message("3.3-1 ----------------");
    pthread_mutex_unlock(&mtx);

    log_message("3.4----------------");
    if (client_sock < 0) {
        log_message("client_sock accept失敗(執行緒內)");
        pthread_exit(NULL);
    }

    log_message("3.5----------------");
    SSL *ssl = SSL_new(config.ctx);
    SSL_set_fd(ssl, client_sock);

    log_message("3.6----------------");
    if (SSL_accept(ssl) <= 0) {
    	log_message("3.6.1----------------");
        ERR_print_errors_fp(stderr);
        log_message("SSL_accept 失敗");
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }

    log_message("3.7----------------");
    // -----------------------------
    // 1. 接收上傳參數 (path, filename, 是否覆蓋)
    //    這裡示範簡化版本：先接收固定長度的指令字串
    // -----------------------------
    char buffer[BUFSIZE] = {0};
    int len = SSL_read(ssl, buffer, sizeof(buffer)-1);
    log_message("3.8----------------");
    if (len <= 0) {
        log_message("SSL_read 失敗或對端關閉連線");
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }
    buffer[len] = '\0';

    log_message("3.9----------------");
    // 假設Client端傳上來的格式為: "<path>\n<filename>\n<overwriteFlag>\n"
    char client_path[512] = {0}, client_filename[512] = {0}, overwrite_flag[8] = {0};
    sscanf(buffer, "%s\n%s\n%s", client_path, client_filename, overwrite_flag);

    log_message("3.10----------------");
    log_message("接收到上傳資訊: path=%s, filename=%s, overwrite=%s", client_path, client_filename, overwrite_flag);

    // -----------------------------
    // 2. 決定最終儲存檔案路徑: base_dir + client_path + client_filename
    // -----------------------------
    char final_path[1024] = {0};
    snprintf(final_path, sizeof(final_path), "%s/%s/%s",
             config.base_dir, client_path, client_filename);

    // 先建立路徑資料夾
    char dir_to_create[1024] = {0};
    snprintf(dir_to_create, sizeof(dir_to_create), "%s/%s",
             config.base_dir, client_path);

    if (create_directory_recursively(dir_to_create) != 0) {
        // 回傳失敗
        const char *msg = "FAIL: Create directory error\n";
        SSL_write(ssl, msg, strlen(msg));
        log_message("建立目錄失敗: %s", dir_to_create);
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
            log_message("檔案已存在，不覆蓋: %s", final_path);
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
        log_message("無法開啟臨時檔案: %s", tmp_path);
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

    if (bytes_read < 0) {
        // 表示讀取途中失敗
        log_message("檔案接收中 SSL_read 失敗");
        const char *msg = "FAIL: File transfer error\n";
        SSL_write(ssl, msg, strlen(msg));
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }

    // -----------------------------
    // 6. 將臨時檔案改名為最終檔名
    // -----------------------------
    if (rename(tmp_path, final_path) != 0) {
        const char *msg = "FAIL: Rename file error\n";
        SSL_write(ssl, msg, strlen(msg));
        log_message("檔案改名失敗, tmp=%s, final=%s", tmp_path, final_path);
        SSL_free(ssl);
        close(client_sock);
        pthread_exit(NULL);
    }
    log_message("上傳完成: %s", final_path);

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

