CC      = gcc
CFLAGS  = -O0 -g -fno-stack-protector -fno-pie -z execstack -z norelro
LDFLAGS = -no-pie -z execstack -z norelro

all: victim

victim: victim.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

disasm: victim
	objdump -d --no-show-raw-insn -M no-aliases victim | sed -n \
	    '/<main>:/,/^$$/p; /<greet>:/,/^$$/p; /<admin_panel>:/,/^$$/p'

clean:
	rm -f victim victim.cfg victim.dot

.PHONY: all clean disasm
