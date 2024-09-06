/*
 *************************************************************************
 *
 *        Copyright 1997, Bay Networks, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Bay Networks, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *
 *	Get the version number and PID from an ERPCD
 *
 * Original Author: Gary Malkin          Created on: Feb 27, 1997
 *************************************************************************/

#ifdef SCO
#include <sys/types.h>
#endif
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>

#include "../inc/port/port.h"
#include "../inc/erpc/erpc.h"
#include "../inc/erpc/bfs.h"
#include "../inc/courier/courier.h"

int debug = 0;

extern int errno;
#ifndef LINUX
extern char *sys_errlist[];	/* errno strings */
#endif

static void timeout();

main(argc, argv)
  int argc;
  char *argv[];
{
  char name[64];
  struct hostent *hostp;
  struct in_addr hostip;
  struct sockaddr_in dest;
  struct sockaddr src, *destp = (struct sockaddr *)(&dest);
  char buffer[1024];
  CHDR *overlay = (CHDR *)buffer;
  int s, recvlen;

  if (argc == 1) {
#ifdef GETHOST
    if (gethostname(name, sizeof(name)) < 0) {
      fprintf(stderr, "Unable to get hostname - %s\n", sys_errlist[errno]);
      exit(errno);
    }
    if ((hostp = gethostbyname(name)) == NULL) {
      fprintf(stderr, "Unable to get host's IP address\n");
      exit(EADDRNOTAVAIL);
    }
    bcopy(*hostp->h_addr_list, (char *)(&hostip.s_addr), 4);
#else
    hostip.s_addr = inet_addr("127.0.0.1");
#endif
  }
  else {
    argc--;
    argv++;
    if ((hostip.s_addr = inet_addr(*argv)) == -1) {
      if ((hostp = gethostbyname(*argv)) == NULL) {
	fprintf(stderr, "Unable to get IP address for host %s\n", *argv);
	exit(EADDRNOTAVAIL);
      }
      bcopy(*hostp->h_addr_list, (char *)(&hostip.s_addr), 4);
    }
  }

  printf("Trying host %s ...\n", inet_ntoa(hostip));

  /*
   * set up the socket
   */
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    fprintf(stderr, "Unable to open socket - %s\n", sys_errlist[errno]);
    exit(errno);
  }
  bzero((char *)(&dest), sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(IPPORT_ERPCLISTEN);
  dest.sin_addr.s_addr = hostip.s_addr;
  bzero((char *)(&src), sizeof(src));
  recvlen = sizeof(src);

  /*
   * sent the request
   */
  overlay->ch_id[0] = 0xaaaa;
  overlay->ch_id[1] = 0xaaaa;
  overlay->ch_client = htons(PET_ERPC);
  overlay->ch_type = htons(C_CALL);
  overlay->ch_tid = 0;
  set_long(overlay->ch_rpnum, (UINT32)BFS_PROG);
  overlay->ch_rpver = htons(BFS_VER);
  overlay->ch_rproc = htons(BFS_GETVER);

  if (sendto(s, buffer, CHDRSIZE, 0, destp, sizeof(dest)) < 0) {
    fprintf(stderr, "Unable to send request - %s\n", sys_errlist[errno]);
    exit(errno);
  }

  /*
   * wait for the reply
   */
  signal(SIGALRM, timeout);
  alarm(2);
  if (recvfrom(s, buffer, sizeof(buffer), 0, &src, &recvlen) < 0) {
    fprintf(stderr, "Unable to receive reply - %s\n", sys_errlist[errno]);
    exit(errno);
  }

  /*
   * print the reply
   */
  if (overlay->ch_type == C_REJECT)
    printf("ERPCD version too old to support Spy request\n");
  else
    printf("%s\n", buffer+RHDRSIZE);
  exit(0);
}

/*
 * SIGALRM handler
 */
static void
timeout()
{
    printf("No reply from host\n");
    exit(0);
}
