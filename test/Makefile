
CFLAGS= -I. -I../ -Werror
LDFLAGS= ../libkhttp.a -lssl -lcrypto

.PHONY: test1 test_get test_post test_ssl test_put test_del
all: test1 test_get test_post test_ssl test_put test_del

test_ssl: test_ssl.o
	$(CC) -o test_ssl.exe test_ssl.o $(CFLAGS) $(LDFLAGS)

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)

test_get: test_get.o
	$(CC) -o test_get.exe test_get.o $(CFLAGS) $(LDFLAGS)

test_post: test_post.o
	$(CC) -o test_post.exe test_post.o $(CFLAGS) $(LDFLAGS)

test_put: test_put.o
	$(CC) -o test_put.exe test_put.o $(CFLAGS) $(LDFLAGS)

test_del: test_del.o
	$(CC) -o test_del.exe test_del.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *.exe
