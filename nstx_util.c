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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>

#include "nstx.h"

int checksum (unsigned char *buf, int len)
{
   int x = 0;
   
   while (len--)
     x ^= buf[len];
   
   return x;
}

void dwrite (char *path, char *buf, int len) {
   int fd;
   
   fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0600);
   write(fd, buf, len);
   close(fd);
}

void pktdump (char *prefix, unsigned short id, char *data, int len, int s) {
   int fd;
   char buf[30];

   snprintf(buf, 30, "%s%hu%c", prefix, id, s ? 's' : 'r');
   if ((fd = open(buf, O_WRONLY|O_CREAT|O_TRUNC, 0600)) >= 0) {
      write(fd, data, len);
      close(fd);
   }
}
