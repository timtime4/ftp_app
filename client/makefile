all:	tcpclient

tcpclient:		tcpclient.o tcp_shared.o
					gcc tcpclient.o tcp_shared.o -o tcpclient -lmhash

tcpclient.o:	tcpclient.c
					gcc -c -g -O -Wall tcpclient.c
tcp_shared.o:	tcp_shared.h tcp_shared.c
					gcc -c -g -O -Wall tcp_shared.c

clean:
					rm -f *.o tcpclient
