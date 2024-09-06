/*
 ******************************************************************************
 *
 *        Copyright 1989,1990, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 *
 * Makefile description:
 *
 *	Trivial Internet time server daemon
 *
 * Original Author: Roger Parker		Created on: 04/21/88
 *
 ******************************************************************************
 */

/*
 *	Include files
 */

#include "../inc/config.h"
#include "../inc/vers.h"

#include "port/port.h"
#include <sys/types.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#ifndef SYS_V
#include <sys/ioctl.h>
#endif
#include "../libannex/api_if.h"
#include <netinet/in.h>

/*
 *	External Data Declarations
 */

extern int errno;
extern int t_errno;
extern INT32 time();

/*
 *	Defines and Macros
 */

#define STDIN	0
#define STDOUT	1
#define STDERR	2

/* avoid spurious XENIX compiler warning */
#define FUG	((unsigned)1104494400L * (unsigned)2L)

/*
 *	Structure Definitions
 */


/*
 *	Forward Routine Declarations
 */

/*
 *	Global Data Declarations
 */
int debug = 0;		/* 1 if called with -d; 0 otherwise */

/*
 *	Static Declarations
 */

int
main(argc, argv)
int  argc;
char **argv;
{
	struct sockaddr_in sin;
	struct servent *sp;
	int s;
	TLI_PTR(struct t_bind,tlibind,NULL)
	TLI_PTR(struct t_unitdata,tlireq,NULL)
	TLI_PTR(struct t_unitdata,tlireqsnd,NULL)
	static char *app_nam="timserver";

	if (argc == 2 && !strcmp(argv[1],"-v")) {
	  printf("timserver host tool version %s, released %s\n",
	     VERSION,RELDATE);
	  exit(0);
	}

	if(argc == 2 && !strcmp(argv[1],"-d"))
		debug = 1;

	if (getuid()) {
		fprintf(stderr, "timserver: not super user\n");
		exit(1);
	}

	sp = getservbyname("timserver", "udp");
	if (sp == 0) {
		fprintf(stderr, "timserver: udp/timserver: unknown service\n");
		exit(1);
	}
	sin.sin_port =  sp->s_port;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;

	if ((s = api_open(IPPROTO_UDP, &sin, app_nam, TRUE)) == -1)
		exit(1);
	if ((api_bind(s, &tlibind, &sin, app_nam, TRUE)) != 0)
		exit(1);

	if (!debug) {
		int f;

		if ((f = fork()) < 0)
			perror("fork");
		if (f != 0)
			exit(f > 0 ? 0 : 1);
		for (f = 0; f < 10; f++)
			if (f != s)
				(void) close(f);
#ifdef SYS_V
		f = open ("/dev/console", O_RDWR);
		if (f < 0)
			f = open ("/dev/tty", O_RDWR);
		if (f < 0)
			f = open ("/dev/null", O_RDWR);
		(void) dup2(STDIN, STDOUT);
		(void) dup2(STDIN, STDERR);
		(void) setpgrp();
#else
		(void) open("/", 0);
		(void) dup2(STDIN, STDOUT);
		(void) dup2(STDIN, STDERR);
		f = open("/dev/tty", 2);
		if (f >= 0) {
			ioctl(f, TIOCNOTTY, 0);
			(void) close(f);
		}
#endif
	}


       TLI_ALLOC(tlireq,t_unitdata,s,T_UNITDATA,T_ADDR,app_nam,exit(1))
       TLI_ALLOC(tlireqsnd,t_unitdata,s,T_UNITDATA,T_ADDR|T_UDATA,
		  app_nam,exit(1))

	for (;;) {
		struct sockaddr_in	from;
		int			cc, i, len = sizeof (from);
		UINT32			clock, resp;
		char			buf[1024];

		/* safety */
		from.sin_family = AF_INET;
		from.sin_addr.s_addr = INADDR_ANY; 

		/* Wait to be poked for time */

		cc = sizeof(buf);
	    
		switch(api_rcvud(&cc,&len,s,tlireq,buf,app_nam,TRUE,&from)) {
		    case 0:
			break;
		    case 1:
		        exit(-1);
		        break;
		    case 2:
		    case 3:
		        continue;
		    default:
			break;
	        }
		if (debug)
			fprintf(stderr,
			"timserver: received %d errno %d from %lx port %d\n",
				cc, errno,
				from.sin_addr.s_addr, ntohs(from.sin_port));
		/*
		 * normally this is "cc <= 0", but timserver requests are
		 * usually zero bytes
		 */
		if (cc < 0)
			continue;

#ifdef notdef
		if (from.sin_port != sin.sin_port) {
			fprintf(stderr,
			       "timserver: %d: bad from port, continuing...\n",
				ntohs(from.sin_port));
			/* continue; */
		}
#endif

		clock = time(0);
		clock += FUG;
		resp = htonl(clock);

		from.sin_family = AF_INET;		/* for EXOS bug */

		if ((api_sndud(s, sizeof(struct sockaddr_in), &from, tlireqsnd,
			       &resp, sizeof(resp), app_nam, TRUE)) == 1)
			exit(1);

		if (debug)
			fprintf(stderr,
				"timserver: sent %d errno %d to %lx port %d\n",
				cc, errno, from.sin_addr.s_addr,
				ntohs(from.sin_port));
	}
}
