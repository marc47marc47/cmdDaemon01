# 編譯
rm -f server
gcc tls_server.c -lssl -lcrypto -lpthread -o server
#gcc tls_server.c -g -O0 -Wall -Wextra -lssl -lcrypto -lpthread -o server

# 編譯
rm -f client
gcc tls_client.c -lssl -lcrypto -o client
