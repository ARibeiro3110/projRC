CC = gcc
TARGETS = user udpserver

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) $^ -o $@

clean:
	rm -f $(TARGETS)
