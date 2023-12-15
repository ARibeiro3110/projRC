CC = gcc
TARGETS = user AS

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) common.c $^ -o $@

clean:
	rm -f $(TARGETS)