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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#include "nstxfun.h"
#include "nstx_pstack.h"
#include "nstxdns.h"

#define DNSTIMEOUT 5

#define MAX(a,b) ((a>b)?a:b)

#define BUFLEN 2000

void nstx_getpacket (void);
static void split_and_queue_packet(char *buf, int len);
static void copy_and_queue_data(char *buf, int len, int seq, int frc, int id);
static struct nstx_senditem * alloc_senditem(void);
extern int nstx_server_send_packet(char *, int, struct sockaddr_in *);
struct nstx_senditem * nstx_sendlist = NULL;


int main (int argc, char *argv[]) {
   
   if (argc < 2) {
      fprintf (stderr, "usage: %s <domainname>\n"
	               "example: %s tun.yomama.com\n", argv[0], argv[0]);
      exit (EXIT_FAILURE);
   }
   
   dns_setsuffix(argv[1]);
   
   open_tuntap();
   open_ns(NULL);
   init_pstack(CHUNKLEN);
   
   while (1)
     nstx_getpacket();
   
   exit(0);
}

struct nstx_senditem * nstx_get_senditem(void) {
   struct nstx_senditem *ptr = nstx_sendlist;
   
   if (!nstx_sendlist)
     return NULL;
   
   ptr = nstx_sendlist;
   nstx_sendlist = nstx_sendlist->next;
   
   return ptr;
}

static void do_timeout (struct nstxqueue *q)
{
   struct dnspkt *pkt;
   int len;
   char *buf;
   
   pkt = dns_alloc();
   dns_setid(pkt, q->id);
   dns_settype(pkt, DNS_RESPONSE);
   dns_addanswer(pkt, "\xb4\x00\x00\x00", 4, dns_addquery(pkt, q->name));
   buf = dns_constructpacket (pkt, &len);
   sendns(buf, len, &q->peer);
}  

void nstx_getpacket (void) {
   int len;
   struct nstx_senditem *senditem;
   char *name, *buf;
   struct nstxmsg *msg;
   struct nstxqueue *qitem;
   struct dnspkt *pkt;

   msg = nstx_select(1);
   
   if (msg) {
     if (msg->src == FROMNS) {
	pkt = dns_extractpkt(msg->data, msg->len);
	if (pkt)
	  {
	     name = dns_getquerydata(pkt);
	     if (name)
	       {
		  queueitem(pkt->id, name, &msg->peer);
		  if ((buf = nstx_decode(dns_fqdn2data(name), &len)))
		    {
		       nstx_handlepacket(buf, len, &sendtun);
		    }
		  
	       }
	  }
     } else if (msg->src == FROMTUN)
	  split_and_queue_packet(msg->data, msg->len);
   }
   
   while (queuelen()) {
      senditem = nstx_get_senditem();
      if (!senditem)
	break;
      qitem = dequeueitem(-1);
      pkt = dns_alloc();
      dns_setid(pkt, qitem->id);
      dns_settype(pkt, DNS_RESPONSE);
      dns_addanswer(pkt, senditem->data+1, *senditem->data,
		    dns_addquery(pkt, qitem->name));
      buf = dns_constructpacket(pkt, &len);
      sendns(buf, len, &qitem->peer);
      free(senditem);
   }
   timeoutqueue(do_timeout);
}

static void split_and_queue_packet(char *buf, int len) {
   int i = 0, seq = 0, frc, last;
   static int id = 0;
   
   id++;
   
   frc = len / SENDLEN - 1;
   if (len % SENDLEN)
     frc++;
   
   while ((len - i) >= SENDLEN) {
      copy_and_queue_data(buf+i, SENDLEN, seq, frc, id);
      seq++;
      i += SENDLEN;
   }
   if (i != len) {
      last = (len % SENDLEN);
      copy_and_queue_data(buf+i, last, seq, frc, id);
   }
}

static void copy_and_queue_data(char *buf, int len, int seq, int frc, int id) {
   struct nstx_senditem *item;
   struct nstxhdr nstx;
   
   nstx.magic = NSTX_MAGIC;
   nstx.seq = seq;
   nstx.frc = frc;
   nstx.id = id;
   nstx.crop = 0;
   nstx.flags = 0;
   
   item = alloc_senditem();
   item->data[0] = len + sizeof(struct nstxhdr);
   memcpy(item->data + 1, &nstx, sizeof(struct nstxhdr));
   memcpy(item->data + 1 + sizeof(struct nstxhdr), buf, len);
}

static struct nstx_senditem * alloc_senditem(void) {
   struct nstx_senditem *ptr = nstx_sendlist;
   struct nstxhdr *hdr;
   struct nstxhdr tmphdr;

   if (!nstx_sendlist) {
      ptr = nstx_sendlist = malloc(sizeof(struct nstx_senditem));
   } else {
      while (ptr->next) {
	hdr = (struct nstxhdr *) ((char *)ptr->data+1);
	memcpy(&tmphdr, hdr, sizeof(struct nstxhdr));
	tmphdr.flags = NSTX_MF;
	memcpy(hdr, &tmphdr, sizeof(struct nstxhdr));
	ptr = ptr->next;
      }
      hdr = (struct nstxhdr *) ((char *)ptr->data+1);
      memcpy(&tmphdr, hdr, sizeof(struct nstxhdr));
      tmphdr.flags = NSTX_MF;
      memcpy(hdr, &tmphdr, sizeof(struct nstxhdr));
      ptr->next = malloc(sizeof(struct nstx_senditem));
      ptr = ptr->next;
   }

   memset(ptr, 0, sizeof(struct nstx_senditem));
   
   return ptr;
}

