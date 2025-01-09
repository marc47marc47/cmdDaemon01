# 產生自簽名憑證 & 私鑰 (示例)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes


