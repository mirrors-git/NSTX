CC = gcc
CFLAGS = -Wall -ggdb -DLINUX

NSTXD_SRCS = nstxd.c nstx_encode.c nstx_util.c nstx_pstack.c nstx_dns.c nstx_tuntap.c nstx_queue.c
NSTXD_OBJS = nstxd.o nstx_encode.o nstx_util.o nstx_pstack.o nstx_dns.o nstx_tuntap.o nstx_queue.o

NSTXCD_SRCS = nstxcd.c nstx_encode.c nstx_util.c nstx_pstack.c nstx_dns.c nstx_tuntap.o nstx_queue.c
NSTXCD_OBJS = nstxcd.o nstx_encode.o nstx_util.c nstx_pstack.o nstx_dns.o nstx_tuntap.o nstx_queue.c

PROGS = nstxd nstxcd

all: $(PROGS)

nstxd: $(NSTXD_OBJS)
	$(CC) $(CFLAGS) -o nstxd $(NSTXD_OBJS)

nstxcd: $(NSTXCD_OBJS)
	$(CC) $(CFLAGS) -o nstxcd $(NSTXCD_OBJS)

clean:
	rm -f *.o $(PROGS) Makefile.bak *~ core

