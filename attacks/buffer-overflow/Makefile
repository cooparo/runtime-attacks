CC=gcc
CFLAGS=-fno-stack-protector -z execstack -no-pie

SOURCES=function-pointer-overwrite.c gets.c integer-overflow.c read-overflow.c scanf.c strcat.c strcopy.c
TARGETS=function-pointer-overwrite gets integer-overflow read-overflow scanf strcat strcopy

all: $(TARGETS)

function-pointer-overwrite: function-pointer-overwrite.c
	$(CC) $< -o $@ $(CFLAGS)

gets: gets.c
	$(CC) $< -o $@ $(CFLAGS)

integer-overflow: integer-overflow.c
	$(CC) $< -o $@ $(CFLAGS)

read-overflow: read-overflow.c
	$(CC) $< -o $@ $(CFLAGS)

scanf: scanf.c
	$(CC) $< -o $@ $(CFLAGS)

strcat: strcat.c
	$(CC) $< -o $@ $(CFLAGS)

strcopy: strcopy.c
	$(CC) $< -o $@ $(CFLAGS)

clean:
	rm -f $(TARGETS)
