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

#include "nstx.h"
#include "nstxpstack.h"
#include "nstxdns.h"

#define DNSTIMEOUT 5

#define MAX(a,b) ((a>b)?a:b)

#define BUFLEN 2000

void nstx_getpacket (void);
static struct nstx_senditem * alloc_senditem(void);
static void queue_senditem(char *buf, int len);
char *dequeue_senditem (int *len);
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
   free(buf);
}  

void nstx_getpacket (void) {
   int len, link;
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
	dns_free(pkt);
     } else if (msg->src == FROMTUN)
	  queue_senditem(msg->data, msg->len);
   }
   
   while (queuelen()) {
      if (!nstx_sendlist)
	break;
      qitem = dequeueitem(-1);
      pkt = dns_alloc();
      dns_setid(pkt, qitem->id);
      dns_settype(pkt, DNS_RESPONSE);
      link = dns_addquery(pkt, qitem->name);
      len = dns_getfreespace(pkt, DNS_RESPONSE);
      buf = dequeue_senditem(&len);
      dns_addanswer(pkt, buf, len, link);
      buf = dns_constructpacket(pkt, &len);
      sendns(buf, len, &qitem->peer);
   }
   timeoutqueue(do_timeout);
}



static struct nstx_senditem * alloc_senditem(void) {
   struct nstx_senditem *ptr = nstx_sendlist;

   if (!nstx_sendlist) {
      ptr = nstx_sendlist = malloc(sizeof(struct nstx_senditem));
   } else {
      while (ptr->next)
	ptr = ptr->next;
      ptr->next = malloc(sizeof(struct nstx_senditem));
      ptr = ptr->next;
   }

   memset(ptr, 0, sizeof(struct nstx_senditem));
   
   return ptr;
}

static void queue_senditem(char *buf, int len) {
   static int id = 0;
   struct nstx_senditem *item;
   
   item = alloc_senditem();
   item->data = malloc(len);
   memcpy(item->data, buf, len);
   item->len = len;
   item->id = ++id;
}

char *dequeue_senditem (int *len) {
   static char *buf = NULL;
   struct nstx_senditem *item = nstx_sendlist;
   struct nstxhdr *nh;
   int remain, dlen;
   
   remain = item->len - item->offset;
   dlen = *len - sizeof(struct nstxhdr);
   if (dlen > remain)
     dlen = remain;
   *len = dlen + sizeof(struct nstxhdr);
   buf = realloc(buf, *len);
   nh = (struct nstxhdr *)buf;
   memset(nh, 0, sizeof(struct nstxhdr));
   memcpy(buf+sizeof(struct nstxhdr), item->data + item->offset, dlen);
   nh->magic = NSTX_MAGIC;
   nh->seq = item->seq++;
   nh->id = item->id;
   item->offset += dlen;
   if (item->offset == item->len) {
      nh->flags = NSTX_LF;
      nstx_sendlist = item->next;
      free(item->data);
      free(item);
   }
   
   return buf;
}
