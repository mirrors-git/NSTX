/* ----------------------------------------------------------------------------
    NSTX -- tunneling network-packets over DNS

     (C) 2000 by Florian Heinz and Julien Oster

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

  -------------------------------------------------------------------------- */

#ifndef _NSTXHDR_H
#define _NSTXHDR_H

/* constants */

#define NSTX_TIMEOUT 30
#define NSTX_MAGIC 0xb4		/* Huh? [sky] */
				/* Well, that seems really like a */
				/* *magic* number ;-) [frodo] */

/* nstx header */

struct nstxhdr {
   unsigned char magic;
   unsigned char seq:4;
   unsigned char chan:4; /* Unused yet... */
   unsigned short id:12;
   unsigned short flags:4;
};

/* flags... more to come ?! */
#define NSTX_LF 0x1     /* last fragment of this packet */
#define NSTX_CTL 0x2     /* for control-messages, not yet implemented */

#define DEBUG(x) puts(x)

/* encoding */

char *nstx_encode(char *, int);
char *nstx_decode(char *, int*);

/* DNS */

char *lbl2str(char *);
char *str2lbl(char *);
unsigned char *lbl2data(unsigned char*);
unsigned char *data2lbl(unsigned char*);
char *decompress_label (char*, int, char*);

void open_tuntap (void);
void open_ns (char*);

void sendtun (char*, int);
void sendns (char*, int, struct sockaddr*);

#define MAXPKT 2000

#define FROMNS  0
#define FROMTUN 1

struct nstxmsg 
{
   char data[MAXPKT];
   int len;
   int src;
   struct sockaddr_in peer;
};

struct nstxmsg *nstx_select (int);


/* Queue-handling functions */

#define QUEUETIMEOUT 5

struct nstxqueue
{
   unsigned short id;
   time_t timeout;
   
   char name[257];
   struct sockaddr peer;
   
   struct nstxqueue *next;
};

struct nstxqueue *finditem (unsigned short);
void queueitem (unsigned short, char*, struct sockaddr_in*);
void queueid (unsigned short);
int queuelen (void);
void qsettimeout (int);
struct nstxqueue *dequeueitem (int);
void timeoutqueue (void (*)(struct nstxqueue *));

void pktdump (char *, unsigned short, char *, int, int);

#endif /* _NSTXHDR_H */
