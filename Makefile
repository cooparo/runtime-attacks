# Top-level Makefile.
#
# Delegates to per-component Makefiles (detector + every attacks/*/).
# Use `make test` to build everything and run the local test harness.

ATTACK_DIRS := $(wildcard attacks/*/)

.PHONY: all build test clean

all: build

build:
	$(MAKE) -C detector
	@for d in $(ATTACK_DIRS); do \
		echo "==> $(MAKE) -C $$d"; \
		$(MAKE) -C $$d || exit 1; \
	done

test: build
	@python3 tools/run_tests.py

clean:
	-$(MAKE) -C detector clean
	@for d in $(ATTACK_DIRS); do \
		echo "==> $(MAKE) -C $$d clean"; \
		$(MAKE) -C $$d clean; \
	done
