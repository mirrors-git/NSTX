#ifndef _NSTXDNS_H
#define _NSTXDNS_H

#define DNS_QUERY    0x01
#define DNS_RESPONSE 0x02

#define DNS_MAXPKT 512

struct rr
{
   char *data;
   int len;
   int link;
   
   struct rr *next;
};

struct dnspkt
{
   unsigned short id;
   int type;
   struct rr *query;
   struct rr *answer;
};

void dns_setsuffix (char *);

struct dnspkt *dns_alloc (void);
void dns_free (struct dnspkt *);

void dns_setid (struct dnspkt *, unsigned short);
void dns_settype (struct dnspkt *, int);
int dns_addquery (struct dnspkt *, char *);
int dns_addanswer (struct dnspkt *, char *, int, int);

int dns_getpktsize (struct dnspkt *);
struct dnspkt *dns_extractpkt (unsigned char *, int);
char *dns_getquerydata (struct dnspkt *);
char *dns_getanswerdata (struct dnspkt *, int *);

char *dns_fqdn2data (char *);
char *dns_data2fqdn (char *);

unsigned char *txt2data (unsigned char *, int *);
unsigned char *dns_constructpacket (struct dnspkt *, int *);

int dns_getfreespace (struct dnspkt *, int);

#endif /* _NSTXDNS_H */
