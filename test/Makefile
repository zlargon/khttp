
CFLAGS= -I. -I../ -Werror
LDFLAGS= ../libkhttp.a -lssl -lcrypto

.PHONY: test_get test_post test_ssl test_put test_del test_post_form
all: test_get test_post test_ssl test_put test_del test_post_form

test_ssl: test_ssl.o
	$(CC) -o test_ssl.exe test_ssl.o $(CFLAGS) $(LDFLAGS)

test_get: test_get.o
	$(CC) -o test_get.exe test_get.o $(CFLAGS) $(LDFLAGS)

test_post: test_post.o
	$(CC) -o test_post.exe test_post.o $(CFLAGS) $(LDFLAGS)

test_put: test_put.o
	$(CC) -o test_put.exe test_put.o $(CFLAGS) $(LDFLAGS)

test_del: test_del.o
	$(CC) -o test_del.exe test_del.o $(CFLAGS) $(LDFLAGS)

test_post_form: test_post_form.o
	$(CC) -o test_post_form.exe test_post_form.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *.exe
