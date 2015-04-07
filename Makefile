.PHONY: static test

LIB_PREFIX = libkhttp
CFLAGS     = -fPIC -O2 -g -DOPENSSL
LDFLAGS    = -lssl -lcrypto
OBJS       = khttp.o http_parser.o

ifdef OSX
CFLAGS += -D__MAC__ -D__IOS__ -Wno-deprecated-declarations
endif

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
