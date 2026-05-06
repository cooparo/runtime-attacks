CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -g
SRCS    = tracer.c shadow_stack.c
OBJS    = $(SRCS:.c=.o)

all: tracer

tracer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c shadow_stack.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f tracer $(OBJS)

.PHONY: all clean
