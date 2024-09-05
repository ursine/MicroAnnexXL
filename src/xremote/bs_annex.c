/* Copyright 1988, 1989, 1990 Network Computing Devices, Inc.  All rights reserved. */
/* Modified and distributed by permission of NCD by Xylogics, Inc. */

/* Created from "@(#)bs_unix.c	14.8	90/12/14" */
#ident "@(#)bs_annex.c	1.1	93/01/25"

/*
 * Annex-Specific bytestream.c support code.
 */

#ifndef KERNEL
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#else KERNEL
#include "stdio.h"
#include "types.h"
#include "time.h"
#include "errno.h"
#endif KERNEL
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if defined(ultrix) || defined(alliant) || defined(BFLY2) || defined(ibm032)
#include <sys/file.h>
#endif /* defined(ultrix) || defined(alliant) || defined(BFLY2) || defined(ibm032) */
#if defined(sun) || defined(hpux) || defined(i386)
#include <sys/fcntl.h>
#endif /* defined(sun) || defined(hpux) || defined(i386) */
#include <sys/signal.h>
#include "ppp.h"
#include "misc.h"
#ifndef BYTESTREAM_DAEMON
#include "X.h"
#include "osdep.h"
#endif BYTESTREAM_DAEMON

#ifdef BYTESTREAM_DAEMON
#define NoDelayTime 10		/* kick no delay timer every n seconds */
#endif BYTESTREAM_DAEMON
#ifdef hpux
#define bcopy(from,to,len) memcpy(to,from,len)
#endif /* hpux */

extern int errno,h_errno;

static int isopen = 0;
static int ioFd = -1;
static struct sockaddr_in sin = { 0 };
static char system_name[64];

#ifdef BYTESTREAM_DAEMON
extern int             BSdebug;
extern int             debugCompression;
extern int             debugProto;
extern void            XremoteStatsClear();
extern int             displayNum;
#else BYTESTREAM_DAEMON
#define             BSdebug 1
#define             debugCompression 0
#define             debugProto 0
#define             displayNum 0
#endif BYTESTREAM_DAEMON

#ifdef BYTESTREAM_DAEMON
static void
#ifdef SYSV
ProdIO(sig)
    int sig;
#else /* SYSV */
ProdIO()
#endif /* SYSV */
{
    if (ioFd != -1) {
	if (fcntl(ioFd, F_SETFL, FNDELAY) == -1)
	    perror("io keepalive");
    }
#ifdef SYSV
    signal(sig, ProdIO);
#endif /* SYSV */
#ifdef hpux
    signal(SIGALRM, ProdIO);
#endif /* hpux */
    alarm(NoDelayTime);
}

/*
 * Supposed to convert an integer baud rate into an OS dependent baud
 * code -- now coopted to set up the TCP listen or connect port.
 *
 * Returns TRUE if the port is legitimate.
 */
Bool
OS_ConvertSpeed(speed, speedCode)
    int speed;
    int *speedCode;
{
    int sock;

    *speedCode = 1;
    gethostname(system_name,sizeof(system_name));
    if ((sock = socket(AF_INET,SOCK_STREAM,0)) < 0) {
	perror("socket");
	return FALSE;
    }
    sin.sin_family = AF_INET;
    sin.sin_port = htons(speed+7000);
    if (speed == 0) {
	int alen,newsock;

	sin.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock,&sin,sizeof(sin)) < 0) {
	    perror("bind");
	    return FALSE;
	}
	if (listen(sock,5) < 0) {
	    perror("listen");
	    return FALSE;
	}
	switch (alen = fork()) {
	case -1:
	    perror("fork");
	    return FALSE;
	case 0:
	    break;
	default:
	    printf("Xremote daemon started for port 7000 as PID %d.\n",alen);
	    exit(0);
	}
	if (fcntl(sock,F_SETFD,1) < 0) {
	    perror("fcntl");
	    return FALSE;
	}
	for (;;) {
	    alen = sizeof(sin);
	    if ((newsock = accept(sock,&sin,&alen)) < 0) {
		perror("accept");
		continue;
	    }
	    switch (fork()) {	/* Fork failure */
	    case 0:
		ioFd = newsock;
		isopen = 1;
		/* Temporarily redirect stdout for user messages. */
		(void)fflush(stdout);
		dup2(ioFd,1);
		return TRUE;
	    case -1:
		perror("fork");
	    default:
		(void)close(newsock);
		break;
	    }
	}
    } else {
	isopen = 0;
	ioFd = sock;
    }
    return TRUE;
}
#endif BYTESTREAM_DAEMON

#ifdef BYTESTREAM_DAEMON
#ifdef SYSV
static void
DumpStats(sig)
    int sig;
#else /* SYSV */
static void
DumpStats()
#endif /* SYSV */
{
#define MAXPBUFLEN 200
    static char pbuf[MAXPBUFLEN];
    int item=0;
    while (item = XremoteStatsDisplay(NULL, item, pbuf, MAXPBUFLEN)) {
	fprintf(stderr, "%s\n", pbuf);
    };
    XremoteStatsClear();
#ifdef SYSV
    signal(sig, DumpStats);
#endif /* SYSV */
}
#endif BYTESTREAM_DAEMON

/*
 * Start up the byte stream driver on a given line.
 */
Bool
OS_tty_open(lineName, speedSpecified, speedCode, inFd, outFd)
    char * lineName;
    Bool speedSpecified;
    int speedCode;
    int * inFd;
    int * outFd;
{
    if (isopen) {
	printf("Xremote started.  You have display %s:%d.\r\n",
	    system_name,displayNum);
	(void)fflush(stdout);
	(void)close(1);
    } else if (ioFd < 0) {
	FatalError("-speed <port> parameter must be given\n");
	return FALSE;
    } else {
	struct hostent *hp;
	char **app,*ap;
	int i;

	if (strncmp(lineName,"/dev/",5) == 0) {
	    FatalError("-line <annex> parameter must be given\n");
	    return FALSE;
	}
	hp = gethostbyname(lineName);
	if (hp == NULL) {
	    FatalError("%s is an unknown host.  (%d)\n",lineName,
		h_errno);
	    return FALSE;
	}
	for (app = hp->h_addr_list; (ap = *app) != NULL; app++) {
	    sin.sin_family = hp->h_addrtype;
	    bcopy(ap,&sin.sin_addr,hp->h_length);
	    if (connect(ioFd,&sin,sizeof(sin)) >= 0)
		break;
	}
	if (ap == NULL) {
	    sprintf(system_name,"%s/%d",lineName,ntohs(sin.sin_port));
	    perror(system_name);
	    exit(1);
	}
	switch (i = fork()) {
	case -1:
	    perror("fork");
	    exit(1);
	case 0:
	    break;
	default:
	    fprintf(stderr,
		"Xremote daemon PID %d connected to %s on port %d.\n",
		i,hp->h_name,ntohs(sin.sin_port));
	    exit(0);
	}
    }
    *inFd = *outFd = ioFd;
#ifdef BYTESTREAM_DAEMON
    signal(SIGALRM, ProdIO);
    signal(SIGUSR1, DumpStats);
    alarm(NoDelayTime);
#endif BYTESTREAM_DAEMON
    return TRUE;
}

OS_tty_close(inFd, outFd)
    int * inFd;
    int * outFd;
{
#ifdef BYTESTREAM_DAEMON
	sleep(2);		/* allow lingering input to come in */
#endif BYTESTREAM_DAEMON
	(void)close(ioFd);
	*inFd = *outFd = ioFd = -1;
}

int
OS_tty_read(fd, buf, bufsize)
    int fd;
    unsigned char *buf;
    int bufsize;
{
    int len;

    len = read(fd, buf, bufsize);
    if (len == 0) {
	errno = ECONNRESET;
        len = -1;
    }
    return(len);
}

int
OS_tty_write(fd, buf, bufsize)
    int fd;
    unsigned char *buf;
    int bufsize;
{
    return( write(fd, buf, bufsize) );
}
