.PHONY: static test

LIB_PREFIX=libkhttp

OBJS=http_parser.o log.o khttp.o

CFLAGS=-fPIC -O2 -g -DCOLOR_LOG -DOPENSSL
LDFLAGS=-lssl -lcrypto

all: static test

static: $(OBJS)
	$(AR) rcs $(LIB_PREFIX).a $(OBJS)

shared:$(OBJS)
	@echo "Build shared library"
	$(CC) -shared -Wl,-soname,$(LIB_PREFIX).so.1 -o $(LIB_PREFIX).so $(OBJS)

test:
	$(MAKE) -C test

clean:
	rm -rf *.o *.a *.so *.exe
	$(MAKE) -C test clean
