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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/time.h>

#include "nstx.h"
#include "nstx_pstack.h"

static struct nstx_item * get_item_by_id(unsigned int id);
static struct nstx_item * alloc_item(int frc, unsigned int id);
static char * dealloc_item(struct nstx_item *ptr);
static int add_data(struct nstx_item *item, struct nstxhdr *pkt, int datalen);
static void check_timeouts(void);

static struct nstx_item *nstx_list = NULL;

static int chunklen = -1;

void init_pstack (int len) {
   chunklen = len;
}

void nstx_handlepacket(char *ptr, int len,
			 void (*nstx_usepacket)(char*,int)) {
   struct nstxhdr *nstxpkt = (struct nstxhdr *) ptr;
   struct nstx_item *nstxitem;
   char *netpacket;
   int netpacketlen;
   int datalen;
   
   if ((!ptr) || len < sizeof(struct nstxhdr))
     return;

   if (((datalen = len - sizeof(struct nstxhdr)) < 1) ||
	(datalen > chunklen))
     return;
   
   nstxitem = get_item_by_id(nstxpkt->id);
   
   if (!nstxitem)
     nstxitem = alloc_item(nstxpkt->frc, nstxpkt->id);
   
   if (add_data(nstxitem, nstxpkt, datalen)) {
      netpacketlen = nstxitem->datalen;
      netpacket = dealloc_item(nstxitem);
      nstx_usepacket(netpacket, netpacketlen);
   }
   check_timeouts();
}

static struct nstx_item * get_item_by_id(unsigned int id) {
   struct nstx_item *ptr = nstx_list;
   
   if (!ptr)
     return NULL;
   
   while (ptr) {
      if (ptr->id == id)
	return ptr;
      ptr = ptr->next;
   }
   return NULL;
}

static struct nstx_item * alloc_item(int frc, unsigned int id) {
   struct nstx_item *ptr;
   
   fflush(stdout);
   ptr = malloc(sizeof(struct nstx_item));
   memset(ptr, 0, sizeof(struct nstx_item));
   ptr->next = nstx_list;
   if (ptr->next)
     ptr->next->prev = ptr;
   nstx_list = ptr;
   
   ptr->data = malloc((frc+1) * chunklen);
   ptr->frc = frc;
   ptr->id = id;
   return ptr;
}

static char * dealloc_item(struct nstx_item *ptr) {
   char *data;
   
   if (ptr->prev)
     ptr->prev->next = ptr->next;
   else
     nstx_list = ptr->next;
   if (ptr->next)
     ptr->next->prev = ptr->prev;
   
   data = ptr->data;
   free(ptr);

   return data;
}

static int add_data(struct nstx_item *item, struct nstxhdr *pkt, int datalen) {
   char *payload;
   
   if ((pkt->seq > item->frc) ||
       (pkt->frc != item->frc) ||
       (item->areamask & (1 << pkt->seq)) ||
       ((item->frc != pkt->seq) && (datalen != chunklen)))
     return -1;
   
   payload = ((char *) pkt) + sizeof(struct nstxhdr);
   item->timestamp = time(NULL);
   
   if (pkt->seq == item->frc)
     item->datalen = (item->frc) * chunklen + datalen;
   
   memcpy((item->data + (chunklen * pkt->seq)), payload, datalen);
   item->areamask |= (1 << pkt->seq);
   
   if (item->areamask == ((1 << (item->frc+1)) - 1)) {
      return 1;
   }
   
   return 0;
}

static void check_timeouts(void) {
   unsigned int now;
   struct nstx_item *ptr = nstx_list, *ptr2;
   
   now = time(NULL);

   while (ptr) {
      ptr2 = ptr;
      ptr = ptr->next;
      if (now > (ptr2->timestamp + NSTX_TIMEOUT)) {
	 free(ptr2->data);
	 dealloc_item(ptr2);
      }
   }
}
