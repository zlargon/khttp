
CFLAGS= -I. -I../ -Werror
LDFLAGS= ../libkhttp.a -lssl -lcrypto

.PHONY: test1 test_get test_post test_ssl
all: test1 test_get test_post test_ssl

test_ssl: test_ssl.o
	$(CC) -o test_ssl.exe test_ssl.o $(CFLAGS) $(LDFLAGS)

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)

test_get: test_get.o
	$(CC) -o test_get.exe test_get.o $(CFLAGS) $(LDFLAGS)

test_post: test_post.o
	$(CC) -o test_post.exe test_post.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *.exe
