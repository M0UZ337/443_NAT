CC = gcc
LIB = -lnetfilter_queue

all: nat

nat: NAT.c checksum.c iptable.c
	${CC} -o nat NAT.c checksum.c iptable.c ${LIB}

clean:
	rm nat
