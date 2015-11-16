all:	tcpserver

tcpserver:		tcpserver.o tcp_shared.o
					gcc tcpserver.o tcp_shared.o -o myftpd -lmhash

tcpserver.o:	tcpserver.c
					gcc -c -g -O -Wall tcpserver.c
tcp_shared.o:	tcp_shared.h tcp_shared.c
					gcc -c -g -O -Wall tcp_shared.c

clean:
					rm -f *.o tcpserver
