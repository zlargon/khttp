
CFLAGS= -I. -I../
LDFLAGS= -lkhttp -L../ -lssl -lcrypto

.PHONY: test1
all: test1

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)
test2: test2.o
	$(CC) -o test2.exe test2.o $(CFLAGS) $(LDFLAGS)
