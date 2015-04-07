CFLAGS  = -I../ -DCOLOR_LOG
LDFLAGS = ../libkhttp.a -lssl -lcrypto
OBJ     = log.o

.PHONY: test_get test_post test_ssl test_put test_del test_post_form test_thread
all: test_get test_post test_ssl test_put test_del test_post_form test_thread

test_ssl: $(OBJ) test_ssl.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS)

test_get: $(OBJ) test_get.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS)

test_post: $(OBJ) test_post.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS)

test_put: $(OBJ) test_put.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS)

test_del: $(OBJ) test_del.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS)

test_post_form: $(OBJ) test_post_form.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS)

test_thread: $(OBJ) test_thread.o
	$(CC) $(CFLAGS) -o $@.exe $@.o $(OBJ) $(LDFLAGS) -lpthread

clean:
	rm -rf *.o *.exe
