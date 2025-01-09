#test: server server.cert + server.key for client
openssl s_server -accept 4433 -cert server.crt -key server.key -www
