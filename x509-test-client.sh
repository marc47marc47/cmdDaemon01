#test server.crt from client is pair to server's server.cert + server.key
openssl s_client -connect 127.0.0.1:4433 -CAfile server.crt
