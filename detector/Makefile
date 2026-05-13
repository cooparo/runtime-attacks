CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -g
SRCS    = tracer.c cfg.c hashchain.c shadow_stack.c
OBJS    = $(SRCS:.c=.o)
HDRS    = cfg.h hashchain.h shadow_stack.h

all: tracer

tracer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f tracer $(OBJS)

.PHONY: all clean
