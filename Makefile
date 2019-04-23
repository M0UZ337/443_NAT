CC = gcc
LIB =

all: nat

nat: NAT.c checksum.c
	${CC} -o nat NAT.c checksum.c iptable.c -lpthread${LIB}

clean:
	rm nat