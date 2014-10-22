
CFLAGS= -I. -I../
LDFLAGS= ../libkhttp.a -lssl -lcrypto

.PHONY: test1 test2
all: test1 test2

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)
test2: test2.o
	$(CC) -o test2.exe test2.o $(CFLAGS) $(LDFLAGS)
clean:
	rm -rf *.o *.exe
