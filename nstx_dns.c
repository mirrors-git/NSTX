#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include "nstxfun.h"

#include "nstxdns.h"

/* lbl2str: Decodes a domainname to a string
 * <len1><NAME1><len2><NAME2><len3><NAME3>'\0' ->
 * NAME1.NAME2.NAME3                                
 * A lenght-byte may not be larger than 63 bytes (the two most significant
 * bits are reserved/used for compression */

char *lbl2str(char *data) {
   char *ptr, *buf;
   unsigned int buflen, datalen, chunklen;
   
   buf = NULL;
   buflen = 0;
   datalen = strlen(data);

   ptr = data;
   while ((chunklen = *ptr)) {
      if (((ptr + chunklen) > (data + datalen)) || (chunklen > 63)) {
	 if (buf)
	   free(buf);
	 printf("lbl2str: Error decoding lblstr (invalid lbllen %d)", chunklen);
	 return NULL ;
      }
      buf = realloc(buf, buflen + chunklen + 2);
      memcpy(buf+buflen, ptr+1, chunklen);
      buf[buflen+chunklen] = '.';
      buflen += chunklen + 1;
      ptr = ptr + chunklen + 1;
   }
   buf[buflen-1] = '\0';
   return buf;
}

/* Reverses lbl2str */

char *str2lbl (char *data) {
   char *ptr, *ptr2, *buf;
   unsigned int buflen, chunklen;
   
   ptr = data;
   buf = NULL;
   buflen = 0;
   
   while ((ptr2 = strchr(ptr, '.'))) {
      chunklen = ptr2 - ptr;
      if ((chunklen > 63) || (chunklen <= 0)) {
	 DEBUG("Too long or zero-length label");
	 if (buf)
	   free(buf);
	 return NULL;
      }
      buf = realloc(buf, buflen + chunklen + 1);
      buf[buflen] = chunklen;
      memcpy(buf+buflen+1, ptr, chunklen);
      buflen += chunklen + 1;
      ptr = ptr2 + 1;
   }
   chunklen = strlen(ptr);
   buf = realloc(buf, buflen + chunklen + 2);
   buf[buflen] = chunklen;
   memcpy(buf+buflen+1, ptr, chunklen);
   buflen += chunklen+1;
   buf[buflen] = '\0';
   buflen++;
   
   return buf;
}

/* Simply removes all dots... Duplicates the string first*/

char *remove_dots (char *str) {
   char *p1, *p2;
   
   p2 = p1 = str = strdup(str);
   
   while (*p1) {
      if (*p1 != '.')
	*(p2++) = *(p1++);
      else
	p1++;
   }
   *p2 = '\0';
   return str;
}

#define LBLLEN 63

/* Inserts dots every LBLLEN'th char */

char *insert_dots (char *str) {
   char *ptr, *res;
   int len;
   
   len = strlen(str);
   res = ptr = malloc(len + len/LBLLEN + 1);
   
   while (len > LBLLEN) {
      memcpy(ptr, str, LBLLEN);
      ptr[LBLLEN] = '.';
      ptr += LBLLEN + 1;
      str += LBLLEN;
      len -= LBLLEN;
   }
   if (len) {
      memcpy(ptr, str, len);
      ptr += len;
   }
   *ptr = '\0';
   
   return res;
}

/* decompress_label decompresses the label pointed to by 'lbl' inside the
 * DNS-packet 'msg'. */

char *decompress_label (char *msg, int msglen, char *lbl) {
   char *ptr = lbl, *buf;
   unsigned int chunklen, offset, buflen, followed = 0;
   
   buf = NULL;
   buflen = 0;
   
   while ((chunklen = *ptr)) {
      if (chunklen > 63) {
	 if ((ptr-msg) >= (msglen-1)) {
	    DEBUG("Bad pointer at end of msg");
	    if (buf)
	      free(buf);
	    return NULL;
	 }	    
	 if (followed > 20) {
	    DEBUG("Too many pointer-loops");
	    if (buf)
	      free(buf);
	    return NULL;
	 }
	 offset = (chunklen % 64)*256 + *(ptr+1);
	 if (offset >= msglen) {
	    DEBUG("offset behind message");
	    if (buf)
	      free(buf);
	    return NULL;
	 }
	 ptr = msg + offset;
	 followed++;
      }
      else {
	 buf = realloc(buf, buflen + chunklen + 2);
	 if ((ptr + chunklen + 1) >= (msg + msglen)) {
	    DEBUG("Invalid chunklen");
	    if (buf)
	      free(buf);
	    return NULL;
	 }
	 memcpy(buf+buflen, ptr, chunklen + 1);
	 buflen += chunklen + 1;
	 ptr += chunklen + 1;
      }
   }
   buf[buflen] = 0;
   buflen++;
   return buf;
}

static unsigned char *_cstringify (unsigned char *data, int *dlen, int clen)
{
   static unsigned char *buf = NULL;
   
   unsigned char *s = data, *d;
   unsigned int llen, len;
   
   len = *dlen;
   *dlen = 0;
   
   d = buf = realloc(buf, len+len/clen+2);
   
   while (len > 0) {
      llen = (len > clen) ? clen : len;
      *(d++) = llen;
      memcpy(d, s, llen);
      d += llen;
      (*dlen) += llen + 1;
      s += llen;
      len -= llen;
   }
   *d = '\0';
   (*dlen)++;
   
   return buf;
}

unsigned char *data2lbl (unsigned char *data)
{
   int len;
   
   len = strlen(data);
   return _cstringify(data, &len, 63);
}

unsigned char *data2txt (unsigned char *data, int *len)
{
   return _cstringify(data, len, 255);
}

unsigned char *txt2data (unsigned char *data, int *dlen)
{
   static unsigned char *buf = NULL;
   
   unsigned char *s = data, *d;
   unsigned int len, llen;
   
   len = *dlen;
   
   d = buf = realloc(buf, len);
   do
     {
	llen = *s++;
	if (llen > len - (s - data))
	  return NULL;
	memcpy(d, s, llen);
	s += llen;
	d += llen;
     } while (llen);
   
   *d = '\0';
   *dlen = d - buf;
   return buf;
}

unsigned char *lbl2data (unsigned char *data)
{
   static unsigned char *buf = NULL;
   
   unsigned char *s = data, *d;
   unsigned int len, llen;
   
   len = strlen(data);
   d = buf = realloc(buf, len);
   do
     {
	llen = *s++;
	if ((llen > 63) || (llen > len - (s - data)))
	  return NULL;
	memcpy(d, s, llen);
	s += llen;
	d += llen;
     } while (llen);
   *d = '\0';
   return buf;
}

/* This routine sends a DNS-packet through fd to peer.
 * id is the id of the DNS-packet
 * type is 0 for request, 1 for answer
 * name is the hostname to be queried/answered
 * data is only used for answers and contains the data in the TXT-record.
 *      Format: <length-byte><data-bytes....>                             */

int send_dns_msg (int id, int type, 
		   char *name, unsigned char *data,
		   struct sockaddr *peer) {
#if 0
   unsigned char buf[512];
   unsigned short _id = id;
   int len, totlen;
   
   if (type && !data)
     data = "\x04\xb4\x00\x00\x00"; /* An nstx-NULL-packet */
   
   memset(buf, 0, sizeof(buf));
   
   /* DNS-Header */
   *((unsigned short*)buf) = _id;
   if (type)
     buf[2] = 0x84; /* Flags: Response, Authoritative Answer */
   else
     buf[2] = 0x01; /* Flags: Recursion desired */
   buf[5] = 0x01; /* QDCOUNT = 1 */
   if (type)
     buf[7] = 0x01; /* ANCOUNT = 1 */
   totlen = 12;
   
   /* Query-Section */
   len = strlen(name) + 1; /* +1 since we need to copy the '\0'-Byte */
      
   memcpy(buf + totlen, name, len); /* Our hostname */
   buf[totlen+len+1] = 16; /* Type is TXT-record */
   buf[totlen+len+3] = 1; /* Class is IN */
   totlen += len + 4;
   
   /* Answer-Section */
   if (type) {
      len = *data + 1;
      buf[totlen] = 192;           /* Pointer to name in the qd- */
      buf[totlen+1] = 12;          /* section (offset 12)        */
      buf[totlen+3] = 16; /* Type is TXT-Record */
      buf[totlen+5] = 1;  /* Class is IN */
      buf[totlen+11] = len; /* RDLENGTH */
      memcpy(buf+totlen+12, data, len); /* Our data */
      totlen += len + 13;
   }
#endif
   struct dnspkt *pkt;
   char *buf;
   int len;
   
   if (type && !data)
     data = "\x04\xb4\x00\x00\x00"; /* An nstx-NULL-packet */

   pkt = dns_alloc();
   dns_setid(pkt, id);
   dns_settype(pkt, type?DNS_RESPONSE:DNS_QUERY);
   if (data)
     dns_addanswer(pkt, data+1, *data, dns_addquery(pkt, name));
   else
     dns_addquery(pkt, name);
   buf = dns_constructpacket(pkt, &len);
//   write(open("/tmp/bla", O_RDWR|O_CREAT|O_TRUNC), buf, len);
   sendns(buf, len, peer);
   
   return len;
}

/* New DNS-Code */

static struct rr *_new_listitem (struct rr **list)
{
   struct rr *rrp, *tmp;

   rrp = malloc(sizeof(struct rr));
   memset(rrp, 0, sizeof(struct rr));
   
   if (!*list)
      *list = rrp;
   else {
      for (tmp = *list; tmp->next; tmp = tmp->next)
	;
      tmp->next = rrp;
   }
   
   return rrp;
}

static unsigned char *_skip_lbl (unsigned char *ptr, int *len)
{
   while (*ptr) {
      if (*len < 2)
	return NULL;
      if ((*ptr & 0xc0)) {
	 ptr++;
	 (*len)--;
	 break;
      }
      *len -= *ptr;
      if (*len < 1)
	return NULL;
      ptr += *ptr+1;
   }
   
   ptr++;
   (*len)--;
   return ptr;
}
	   

static __inline__ int _get_listlen (struct rr *list)
{
   int nr = 0;
   
   while (list) {
      list = list->next;
      nr++;
   }
   
   return nr;
}

static char *suffix = NULL;

void dns_setsuffix (char *suf)
{
   suffix = str2lbl(suf);
}

struct dnspkt *dns_alloc (void)
{
   void *ptr;
   
   ptr = malloc(sizeof(struct dnspkt));
   memset(ptr, 0, sizeof(struct dnspkt));
   
   return ptr;
}

void dns_free (struct dnspkt *pkt)
{
   struct rr *list, *next;
   
   list = pkt->query;
   while (list) {
      if (list->data)
	free(list->data);
      next = list->next;
      free(list);
      list = next;
   }

   list = pkt->answer;
   while (list) {
      if (list->data)
	free(list->data);
      next = list->next;
      free(list);
      list = next;
   }
   
  free(pkt);
}

void dns_setid (struct dnspkt *pkt, unsigned short id)
{
   pkt->id = id;
}

void dns_settype (struct dnspkt *pkt, int type)
{
   pkt->type = type;
}

char *dns_data2fqdn (char *data)
{
   char *ptr;
   static char *fqdn = NULL;
   
   if (fqdn)
     free(fqdn);
   
   ptr = data2lbl(data);
   fqdn = malloc(strlen(ptr)+strlen(suffix)+1);
   strcpy(fqdn, ptr);
   strcat(fqdn, suffix);
   
   return fqdn;
}

char *dns_fqdn2data (char *fqdn)
{
   static char *buf = NULL;
   int off;
   
   if (buf)
     free(buf);
   
   off = strlen(fqdn)-strlen(suffix);
   if (!memcmp(fqdn+off, suffix, strlen(suffix)))
     fqdn[off] = '\0';
   
   buf = strdup(lbl2data(fqdn));
   
   return buf;
}

int dns_addquery (struct dnspkt *pkt, char *data)
{
   struct rr *rrp;

   rrp = _new_listitem(&pkt->query);
   rrp->data = strdup(data);
   rrp->len = strlen(data)+1;
   
   return _get_listlen(pkt->query) - 1;
}

int dns_addanswer (struct dnspkt *pkt, char *data, int len, int link)
{
   struct rr *rrp;
   char *ptr, *buf;
   
   ptr = data2txt(data, &len);
   buf = malloc(len);
   memcpy(buf, ptr, len);
   
   rrp = _new_listitem(&pkt->answer);
   rrp->data = buf;
   rrp->len = len;
   rrp->link = link;
   
   return _get_listlen(pkt->query) - 1;
}

int dns_getpktsize (struct dnspkt *pkt)
{
   int size;
   struct rr *list;
   
   size = 12; /* DNS-header */
   
   for (list = pkt->query; list; list = list->next)
     size += list->len + 4;

   for (list = pkt->answer; list; list = list->next)
     size += list->len + 12;
   
   return size;
}

unsigned char *dns_constructpacket (struct dnspkt *pkt, int *l)
{
   static unsigned char *buf, *ptr;
   int len, *offsets, qdcount, ancount, i;
   struct rr *list;
   
   qdcount = _get_listlen(pkt->query);
   ancount = _get_listlen(pkt->answer);

   len = dns_getpktsize(pkt);
   ptr = buf = malloc(len);
   memset(buf, 0, len);
   
   if (len > 512)
     printf("WARNING: Constructed non-conform DNS-packet (size: %d)\n", len);
   
   offsets = malloc(qdcount * 4);
   
   /* Header */
   buf[0] = pkt->id / 256;
   buf[1] = pkt->id % 256;
   if (pkt->type == DNS_RESPONSE) {
      buf[2] = 0x84; /* Flags: Response, Authoritative Answer */
      buf[3] = 0x80; /* Flag: Recursion available */
   } else
     buf[2] = 0x01; /* Flags: Recursion desired */
   buf[5] = qdcount;
   buf[7] = _get_listlen(pkt->answer);
   ptr += 12;
   
   /* Query section */
   for (list = pkt->query, i=0; list; list = list->next, i++) {
      offsets[i] = ptr-buf;
      memcpy(ptr, list->data, list->len);
      ptr += list->len;
      ptr[1] = 16;
      ptr[3] = 1;
      ptr += 4;
   }
   
   /* Answer section */
   for (list = pkt->answer; list; list = list->next) {
      ptr[0] = 0xc0 | (offsets[list->link]/256);
      ptr[1] = offsets[list->link]%256;
      ptr[3] = 16;
      ptr[5] = 1;
      ptr[10] = list->len / 256;
      ptr[11] = list->len % 256;
      ptr += 12;
      memcpy(ptr, list->data, list->len);
      ptr += list->len;
   }
   *l = len;
   dns_free (pkt);
   return buf;
}

struct dnspkt *dns_extractpkt (unsigned char *buf, int len)
{
   int qdcount, ancount, remain, *offsets, i, j, off;
   unsigned char *ptr;
   struct dnspkt *pkt;
   struct rr *rrp;
   
   if (len < 17)
     return NULL;
   
   pkt = dns_alloc();
   pkt->id = buf[0]*256+buf[1];
   
   qdcount = buf[5];
   ancount = buf[7];
   
   offsets = malloc(qdcount * 4);
   
   ptr = buf + 12;
   remain = len - 12;
   
   i = 0;
   while (qdcount--)
     {
	offsets[i++] = ptr - buf;
	rrp = _new_listitem(&pkt->query);
	rrp->data = decompress_label(buf, len, ptr);
	if (!rrp->data)
	  {
	     printf("dns_extractpkt: decompress_label choked in qd\n");
	     dns_free(pkt);
	     return NULL;
	  }
	rrp->len = strlen(rrp->data)+1;
	ptr = _skip_lbl(ptr, &remain);
	if (!ptr)
	  {
	     printf("dns_extractpkt: _skip_lbl choked in qd\n");
	     dns_free(pkt);
	     return NULL;
	  }
	ptr += 4;
	remain -= 4;
     }
   while (ancount--)
     {
	if (remain < 12)
	  {
	     printf("dns_extractpkt: too less bytes in an\n");
	     dns_free(pkt);
	     return NULL;
	  }
	rrp = _new_listitem(&pkt->answer);
	rrp->link = -1;
	if ((ptr[0] & 0xc0) == 0xc0)
	  {
	     off = (ptr[0] & ~(0xc0)) * 256 + ptr[1];
	     for (j = 0; j < i; j++)
	       if (offsets[j] == off)
		 break;
	     if (j < i)
	       rrp->link = j;
	  }
	rrp->len = ptr[10]*256+ptr[11];
	ptr += 12;
	remain -= 12;
	if (remain < rrp->len)
	  {
	     printf("dns_extractpkt: record too long in an (%d->%d)\n",
		    remain, rrp->len);
	     dns_free(pkt);
	     return NULL;
	  }
	rrp->data = malloc(rrp->len);
	memcpy(rrp->data, ptr, rrp->len);
	ptr += rrp->len;
	remain -= rrp->len;
     }
   return pkt;
}

char *dns_getquerydata (struct dnspkt *pkt)
{
   struct rr *q;
   static char *ret = NULL;
   
   if (!pkt->query)
     return NULL;
   
   if (ret)
     {
	free(ret);
	ret = NULL;
     }
   
   q = pkt->query;
   pkt->query = pkt->query->next;

   ret = q->data;
   free(q);
   
   return ret;
}


char *dns_getanswerdata (struct dnspkt *pkt, int *len)
{
   struct rr *q;
   static char *ret = NULL;
   
   if (!pkt->answer)
     return NULL;
   
   q = pkt->answer;
   pkt->answer = pkt->answer->next;
   
   if (ret)
     free(ret);
   
   ret = q->data;
   *len = q->len;
   
   free(q);
   return ret;
}
