CC = gcc
CFLAGS = -O2 -Wall
LIBS = -lpcap


all: myids

ids.o: ids.c ids.h
	$(CC) $(CFLAGS) -c ids.c

myids: myids.c ids.o
	$(CC) $(CFLAGS) -o myids myids.c ids.o $(LIBS)

clean:
	@rm myids ids.o
