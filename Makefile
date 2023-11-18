CC = gcc

all:
	$(CC) user.c -o user

clean:
	rm $(TARGET)