/* ----------------------------------------------------------------------------
    NSTX -- tunneling network-packets over DNS

     (C) 2000 by Julien Oster and Florian Heinz

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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <resolv.h>
#include <netdb.h>

#include <time.h>

#include "nstxfun.h"
#include "nstx_dns.h"
#include "nstxdns.h"
#include "nstx_pstack.h"

#define DRQLEN 1

static void nstxc_handle_reply(char *, int);
static int nstxc_send_packet(char *, int);

static int nsid;
int gotpacket = 0;

int main (int argc, char * argv[]) {
  struct nstxmsg *msg;

  nsid = time(NULL);

  if (argc < 3) {
    fprintf(stderr, "Usage: ./nstxcd <domainname> <dns-server>\n");
    fprintf(stderr, "Example: ./nstxcd tun.yomama.com 125.23.53.12\n");
    exit (3);
  }

  dns_setsuffix(argv[1]);

  init_pstack (SENDLEN);
  qsettimeout(10);
  open_tuntap();
  open_ns(argv[2]);

  for (;;) {
    msg = nstx_select(1);
    if (msg) {
       if (msg->src == FROMNS) {
	  nstxc_handle_reply (msg->data, msg->len);
       } else if (msg->src == FROMTUN) {
	  nstxc_send_packet (msg->data, msg->len);
       }
    }
    timeoutqueue(NULL);
    while (queuelen() < DRQLEN)
      nstxc_send_packet (NULL, 0);
  }

  return 0;
}

static void nstxc_handle_reply (char * reply, int len) {
   struct dnspkt *pkt;
   char *data;
   int datalen;
   
   pkt = dns_extractpkt (reply, len);
   if (!pkt)
     return;
   data = dns_getanswerdata(pkt, &datalen);
   data = txt2data(data, &datalen);
   nstx_handlepacket (data, datalen, &sendtun);
   dequeueitem(pkt->id);
   dns_free(pkt);
}
  
static int nstxc_send_packet (char * buf, int len) {
  char *p;
  int chunks, rest;
  char hbuf[HCHUNKLEN];
  char *fqdn;
  static int id = -1;
  struct nstxhdr nh;

  if (id < 0)
    id = time(NULL);

  nh.magic = NSTX_MAGIC;
  nh.seq = 0;
  nh.frc = 0;
  nh.id = id++;
  nh.crop = 0;
  nh.flags = 0;

  p = buf;
  chunks = len / CHUNKLEN;
  rest = len % CHUNKLEN;
  if (len)
    nh.frc = chunks - (rest ? 0 : 1);

  while (chunks) {
    memcpy (hbuf, (char*)&nh, sizeof(nh));
    memcpy (hbuf + sizeof(nh), p, CHUNKLEN);
    fqdn = dns_data2fqdn(nstx_encode(hbuf, sizeof(nh)+CHUNKLEN));
    send_dns_msg (nsid,0,fqdn,NULL,NULL);

    queueid(nsid);
    nsid++;

    p += CHUNKLEN;
    chunks--;
    nh.seq++;
  }

  if (rest | !chunks) {
    nh.crop = 2 - (rest % 3);
    memcpy (hbuf, (char*)&nh, sizeof(nh));
    memcpy (hbuf + sizeof(nh), p, rest);

    fqdn = dns_data2fqdn(nstx_encode(hbuf, sizeof(nh)+rest));
    send_dns_msg (nsid,0,fqdn,NULL,NULL);

    queueid(nsid);
    nsid++;
  }

  return 0;
}
