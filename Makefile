CC = gcc
CFLAGS = -pthread
TARGETS = user AS
COMMON_SRC = common.c

all: $(TARGETS)

$(TARGETS): %: $(COMMON_SRC) %.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(TARGETS)
