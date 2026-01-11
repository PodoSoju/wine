# soju-extract-icon - Pure C PE icon extractor
# Works on Unix/Linux/macOS

CC ?= cc
CFLAGS = -Wall -Wextra -O2 -std=c99

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

all: soju-extract-icon

soju-extract-icon: soju-extract-icon.c
	$(CC) $(CFLAGS) -o $@ $<

install: soju-extract-icon
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 soju-extract-icon $(DESTDIR)$(BINDIR)/

clean:
	rm -f soju-extract-icon

.PHONY: all install clean
