all: myids

myids: myids.c
	gcc -Wall myids.c -o myids -lpcap

clean:
	@rm myids
