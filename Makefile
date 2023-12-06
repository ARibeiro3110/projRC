CC = gcc

all:
	$(CC) user.c common.c -o user
	$(CC) AS.c common.c -o AS
	$(CC) udpserver.c -o udpserver
	$(CC) tcpserver.c -o tcpserver

clean:
	rm user AS