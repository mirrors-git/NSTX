#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#ifdef LINUX
#include <linux/if_tun.h>
#define TUNDEV "/dev/net/tun"
#else
#include <net/if_tun.h>
#define TUNDEV "/dev/tun"
#endif

#include "nstx.h"

#define TAPDEV "/dev/tap0"

#define MAXPKT 2000

int tfd = -1, nfd = -1;
static char dev[IFNAMSIZ+1];

int tun_alloc (char *path);
int tap_alloc (char *path);

void open_tuntap (void)
{
   int tunerr, taperr;
   
   fprintf(stderr, "Opening tun/tap-device... ");
   if((tunerr = tun_alloc(TUNDEV)) && (taperr = tap_alloc(TAPDEV))) {
      fprintf(stderr, "failed!\n"
	              "Diagnostics:\nTun ("TUNDEV"): ");
      switch (tunerr) {
       case EPERM:
	 fprintf(stderr, "Permission denied. You usually have to "
		         "be root to use nstx.\n");
	 break;
       case ENOENT:
	 fprintf(stderr, TUNDEV " not found. Please create /dev/net/ and\n"
		 "     mknod /dev/net/tun c 10 200 to use the tun-device\n");
	 break;
       case ENODEV:
	 fprintf(stderr, "Device not available. Make sure you have "
		 "kernel-support\n     for the tun-device. Under linux, you "
		 "need tun.o (Universal tun/tap-device)\n");
	 break;
       default:
	 fprintf(stderr, "Unexpected error: %s\n", strerror(tunerr));
	 break;
      }
      fprintf(stderr, "Tap ("TAPDEV"): \n(only available under linux)\n");
      switch (taperr) {
       case EPERM:
	 fprintf(stderr, "Permission denied. You generally have to "
		 "be root to use nstx.\n");
	 break;
       case ENOENT:
	 fprintf(stderr, TAPDEV " not found. Please\n"
		 "     mknod /dev/tap0 c 36 16 to use the tap-device\n");
	 break;
       case ENODEV:
	 fprintf(stderr, "Device not available. Make sure you have kernel-support\n"
		 "     for the tap-device. Under linux, you need netlink_dev.o and ethertap.o\n");
	 break;
       default:
	 fprintf(stderr, "Unexpected error: %s\n", strerror(taperr));
	 break;
      }
      exit(EXIT_FAILURE);
   }
   
   fprintf(stderr, "using device %s\n"
	  "Please configure this device appropriately (IP, routes, etc.)\n", dev);
}

int tun_alloc (char *path) 
{
#ifdef LINUX
   struct ifreq ifr;
#else
   struct stat st;
#endif
 
   if ((tfd = open(path, O_RDWR)) < 0)
     return errno;

#ifdef LINUX
   memset(&ifr, 0, sizeof(ifr));
   
   ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
   
   if (ioctl(tfd, TUNSETIFF, (void *) &ifr) < 0)
     {
	close(tfd);
	tfd = -1;
	return errno;
     }
   strncpy(dev, ifr.ifr_name, IFNAMSIZ+1);
#else
   fstat(tfd, &st);
   strncpy(dev, devname(st.st_dev, S_IFCHR), IFNAMSIZ+1);
#endif
   
   return 0;
}


int tap_alloc (char *path)
{
   char *ptr;
   
   if ((tfd = open(path, O_RDWR)) < 0)
     return errno;
   
   if ((ptr = strrchr(path, '/')))
     strncpy(dev, ptr+1, IFNAMSIZ+1);
   else
     strncpy(dev, path, IFNAMSIZ+1);
   
   return 0;
}

void open_ns (char *ip)
{
   struct sockaddr_in sock;
   
   fprintf(stderr, "Opening nameserver-socket... ");
   if ((nfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      fprintf(stderr, "failed!\nUnexpected error creating socket: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
   }
   sock.sin_family = AF_INET;
   sock.sin_port = htons(53);
   if (!ip)
     {
	sock.sin_addr.s_addr = INADDR_ANY;
	if (bind (nfd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in))) {
	   fprintf(stderr, "failed!\n");
	   switch (errno) {
	    case EADDRINUSE:
	      fprintf(stderr, "Address is in use, please kill other processes "
		      "listening on UDP-Port 53\n");
	      break;
	    case EACCES:
	    case EPERM:
	      fprintf(stderr, "Permission denied binding port 53. You generally "
		      "have to be root to bind privileged ports.\n");
	      break;
	    default:
	      fprintf(stderr, "Unexpected error: bind: %s\n", strerror(errno));
	      break;
	   }
	   exit(EXIT_FAILURE);
	}
	fprintf(stderr, "listening on 53/UDP\n");
     }
   else
     {
	sock.sin_addr.s_addr = inet_addr(ip);
	connect(nfd, (struct sockaddr *)&sock, sizeof(struct sockaddr_in));
	fprintf(stderr, "Using nameserver %s\n", ip);
     }
}

struct nstxmsg *nstx_select (int timeout)
{
   int peerlen;
   fd_set set;
   struct timeval tv;
   static struct nstxmsg *ret = NULL;
   
   FD_ZERO(&set);
   if (nfd > 0)
     FD_SET(nfd, &set);
   if (tfd > 0)
     FD_SET(tfd, &set);
   
   tv.tv_sec = timeout;
   tv.tv_usec = 0;
   
   if (timeout < 0)
     select(((tfd>nfd)?tfd:nfd)+1, &set, NULL, NULL, NULL);
   else
     select(((tfd>nfd)?tfd:nfd)+1, &set, NULL, NULL, &tv);
   
   if (!ret)
     ret = malloc(sizeof(struct nstxmsg));
   if (FD_ISSET(tfd, &set)) {
      ret->len = read(tfd, ret->data, MAXPKT);
      if (ret->len > 0) {
	 ret->src = FROMTUN;
	 return ret;
      }
   }
   if (FD_ISSET(nfd, &set)) {
      peerlen = sizeof(struct sockaddr_in);
      ret->len = recvfrom(nfd, ret->data, MAXPKT, 0,
			  (struct sockaddr *) &ret->peer, &peerlen);
      if (ret->len > 0) {
	 ret->src = FROMNS;
	 return ret;
      }
   }

   return NULL;
}

void sendtun (char *data, int len)
{
   write(tfd, data, len);
}

void sendns (char *data, int len, struct sockaddr *peer)
{
   if (peer)
     sendto(nfd, data, len, 0, peer,
	    sizeof(struct sockaddr_in));
   else
     send(nfd, data, len, 0);
}
