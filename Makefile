.PHONY: static shared test

LIB_PREFIX=libkhttp

OBJS=http_parser.o log.o khttp.o

CFLAGS=-fPIC -O2 -g -Werror -DCOLOR_LOG -DOPENSSL
LDFLAGS=-lssl -lcrypto

all: shared static test

static: $(OBJS)
	$(AR) rcs $(LIB_PREFIX).a $(OBJS)

shared:$(OBJS)
	@echo "Build shared library"
	$(CC) -shared -Wl,-soname,$(LIB_PREFIX).so.1 -o $(LIB_PREFIX).so $(OBJS)

test:
	$(MAKE) -C test

clean:
	rm -rf *.o *.a *.so *.exe
