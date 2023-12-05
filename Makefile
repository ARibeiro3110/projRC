CC = gcc

all:
	$(CC) user.c common.c -o user
	$(CC) udpserver.c -o udpserver
	$(CC) tcpserver.c -o tcpserver

clean:
	rm user AS