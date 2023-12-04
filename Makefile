CC = gcc
TARGETS = common user udpserver AS

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) $^ -o $@

clean:
	rm -f $(TARGETS)
