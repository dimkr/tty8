# this file is part of tty8.
#
# Copyright (c) 2015 Dima Krasner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

CC ?= cc
CFLAGS ?= -O2 -pipe
LDFLAGS ?= -Wl,-s
DESTDIR ?=
BIN_DIR ?= /bin
MAN_DIR ?= /usr/share/man
DOC_DIR ?= /usr/share/doc

CFLAGS += -Wall -pedantic -D_GNU_SOURCE
LIBS += -lutil

INSTALL = install -v

all: tty8

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

tty8: tty8.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

install: all
	$(INSTALL) -D -m 755 tty8 $(DESTDIR)/$(BIN_DIR)/tty8
	$(INSTALL) -D -m 644 tty8.1 $(DESTDIR)/$(MAN_DIR)/man1/tty8.1
	$(INSTALL) -D -m 644 README $(DESTDIR)/$(DOC_DIR)/tty8/README
	$(INSTALL) -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/tty8/AUTHORS
	$(INSTALL) -m 644 COPYING $(DESTDIR)/$(DOC_DIR)/tty8/COPYING

clean:
	rm -f tty8 tty8.o
