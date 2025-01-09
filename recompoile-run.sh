rm -f server; sh makeall.sh; sleep 2; ./server -d `pwd`/download -p 4433 -k ./server.key -c ./server.crt
