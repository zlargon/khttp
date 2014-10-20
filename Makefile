.PHONY: static shared test test2

LIB_PREFIX=libkhttp

TEST_OBJS=test.o
OBJS=http_parser.o log.o khttp.o

CFLAGS=-fPIC -O2 -g -Werror -DCOLOR_LOG -DOPENSSL
LDFLAGS=-lssl -lcrypto

all: shared static test test2

static: $(OBJS)
	$(AR) rcs $(LIB_PREFIX).a $(OBJS)

shared:$(OBJS)
	@echo "Build shared library"
	$(CC) -shared -Wl,-soname,$(LIB_PREFIX).so.1 -o $(LIB_PREFIX).so $(OBJS)

test: $(TEST_OBJS)
	$(CC) -o test.exe $(TEST_OBJS) $(CFLAGS) libkhttp.a $(LDFLAGS)
test2: test2.o
	$(CC) -o test2.exe test2.o $(CFLAGS) libkhttp.a $(LDFLAGS)

clean:
	rm -rf *.o *.a *.so *.exe
