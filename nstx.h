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

#define nstx_clen(x) ((x * 4) / 3)
#define HCHUNKLEN 171
#define CHUNKLEN (HCHUNKLEN - sizeof(struct nstxhdr))

#define C_CHUNKLEN nstx_clen(CHUNKLEN)
#define C_HCHUNKLEN nstx_clean(HCHUNKLEN)

#define NSTX_MAXPACKET (CHUNKLEN * 16)

#define FQDN_MAXLEN 250
#define SENDLEN 227
#define NSTX_TIMEOUT 30
#define NSTX_MAGIC 0xb4		/* Huh? [sky] */
				/* Well, that seems really like a */
				/* *magic* number ;-) [frodo] */

/* nstx header */

struct nstxhdr {
   unsigned char magic;
   unsigned char seq:4;
   unsigned char frc:4;
   unsigned short id:12;
   unsigned short crop:2;
   unsigned short flags:2;
};

/* flags... more to come ?! */
#define NSTX_MF 0x1     /* more fragments queued */
#define NSTX_STICKY 0x2 /* actually found a use for flag FRODOSKYP ;)) */

#define DEBUG(a) fprintf(stderr, a "\n")

/* useful functions */

char * nstx_remove_dots(char *);
int nstx_build_fqdn(char *, char *, char *, int);

int nstx_string_to_name (char *, char *, int);
int nstx_name_to_string (char *, char *, int);

/* encoding */

int nstx_encode(char *, char *, int);
int nstx_decode(char *, char *, int);

/* DNS */

char *lbl2str(char *);
char *str2lbl(char *);
char *remove_dots (char *);
char *insert_dots (char *);
char *decompress_label (char*, int, char*);
int send_dns_msg (int, int, char*, char*, int, void *);

#endif /* _NSTXHDR_H */
