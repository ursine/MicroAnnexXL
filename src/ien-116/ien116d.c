/*
 * Copyright, 1984 The Regents of the University of California.  This software
 * was produced under a U.S. Government contract, W-7405-ENG-36, by the 
 * Los Alamos National Laboratory, which is operated by the University of
 * California for the U.S. Department of Energy.   The U.S. Government is 
 * licensed to use, reproduce, and distribute this software.  Permission
 * is granted to the public to copy and use this software without charge, 
 * provided that this notice and any statement of authorship are reproduced
 * on all copies.  Neither the Government nor the University makes any warranty
 * expressed or implied, or assumes any liability or responsibility for
 * the use of this software.
 *
 */

/*
 *	Include Files
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

struct	sockaddr_in sin = { AF_INET };

struct	namerequest {
	char nr_nameoctet;
	char nr_namelen;
	char nr_namestr[1024];	/* 1024 is arbitrary */
};

unsigned char	*replybuf;
unsigned char	*malloc();

#define STDIN	0
#define STDOUT	1
#define STDERR	2

#define ERRORMESSAGE	"Unknown machine"

extern	errno;
extern	t_errno;

struct servent     *sp;

int	debug = 0;

int
main(argc, argv)
int  argc;
char **argv;
{
	int fd;
	char *app_nam="ien116d";
	TLI_PTR(struct t_bind,tlibind,NULL)
	TLI_PTR(struct t_unitdata,tlireq,NULL)
	TLI_PTR(struct t_unitdata,tlireqsnd,NULL)

	if (argc == 2 && !strcmp(argv[1],"-v")) {
	  printf("ien116d host tool version %s, released %s\n",
		 VERSION,RELDATE);
	  exit(0);
	}

	if(argc == 2 && !strcmp(argv[1],"-d"))
		debug = 1;

	if (getuid()) {
		fprintf(stderr, "ien116d: not super user\n");
		exit(1);
	}

	sp = getservbyname("name", "udp");
	if (sp == 0) {
		fprintf(stderr, "ien116d: udp/name: unknown service\n");
		exit(1);
	}
	sin.sin_port = sp->s_port;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;

	/*open to API I/F*/
	if((fd = api_open(IPPROTO_UDP, &sin, app_nam, TRUE)) < 0)
		exit(1);

	if(api_bind(fd, &tlibind, &sin, app_nam, TRUE) != 0)
		exit(1);

	if (!debug) {
		int f;

		if ((f = fork()) < 0)
			perror("fork");
		if (f != 0)
			exit(f > 0 ? 0 : 1);
		for (f = 0; f < 10; f++)
			if (f != fd)
				(void) close(f);
#ifdef SYS_V
		f = open ("/dev/console", O_RDWR);
		if (f < 0)
			f = open ("/dev/tty", O_RDWR);
		if (f < 0)
			f = open ("/dev/null", O_RDWR);
		(void)dup2 (STDIN, STDOUT);
		(void)dup2 (STDIN, STDERR);
		(void)setpgrp();
#else
		(void) open("/", 0);
		(void) dup2(0, 1);
		(void) dup2(0, 2);
		f = open("/dev/tty", 2);
		if (f >= 0) {
			ioctl(f, TIOCNOTTY, 0);
			(void) close(f);
		}
#endif
	}

	TLI_ALLOC(tlireq,t_unitdata,fd,T_UNITDATA,T_ADDR|T_UDATA,
		  app_nam,exit(1))
	TLI_ALLOC(tlireqsnd,t_unitdata,fd,T_UNITDATA,T_ADDR|T_UDATA,
		  app_nam,exit(1))

	for (;;) {
		struct sockaddr_in from;
		int			cc, outcome, i, len=sizeof(from);
		struct namerequest	request;
		struct hostent		*rh;


		/* safety */
		from.sin_family = AF_INET;
		from.sin_addr.s_addr = INADDR_ANY;

		cc = sizeof(struct namerequest);

		if (api_rcvud(&cc,&len,fd,tlireq,(char *)&request,app_nam,TRUE,
		    &from) != 0)
			continue;

#ifdef notdef
		if (from.sin_port != sin.sin_port) {
			fprintf(stderr,
				"ien116d: %d: bad from port, continuing...\n",
				ntohs(from.sin_port));
			/* continue; */
		}
#endif

		from.sin_family = AF_INET;
		request.nr_namestr[request.nr_namelen] = '\0';
		if (debug)
			fprintf(stderr, "Request for <%s> from %#lx\n",
				request.nr_namestr, from.sin_addr.s_addr);

		rh = gethostbyname(request.nr_namestr);
		if (rh == NULL) {
			if (debug)
				fprintf(stderr, "%s: unknown host\n",
					request.nr_namestr);

			/* 3 = error type + length + error code */
			replybuf=malloc(cc+3+sizeof (ERRORMESSAGE));
			bcopy((char *)&request, replybuf, cc);
			i=cc;
			replybuf[i++]=(unsigned char)3;	 /*3 denotes an error*/
			replybuf[i++]=(unsigned char)strlen(ERRORMESSAGE);
			bcopy((char *)ERRORMESSAGE,&replybuf[i],
				strlen(ERRORMESSAGE));
			i+=strlen(ERRORMESSAGE);
			outcome = api_sndud(fd,len,&from,tlireqsnd,replybuf,
					    i, app_nam, TRUE);
			free(replybuf);
			if (outcome == 1)
				exit(1);
			continue;
		}

		if (debug)
			fprintf(stderr, "got back address %#lx\n",
				*(UINT32 *)rh->h_addr);

		/* 6 = addr type + len + internet addr */
		replybuf=malloc(cc+6);
		bcopy((char *)&request, replybuf, cc);
		i=cc;
		replybuf[i++]=(unsigned char)2;	/* 2 denotes an addr */
		replybuf[i++]=(unsigned char)rh->h_length;
		bcopy(rh->h_addr, &replybuf[i], rh->h_length);
		i+=(rh->h_length);
		(void)api_sndud(fd, len, &from, tlireqsnd, replybuf,i,app_nam,
				TRUE);
		free(replybuf);
	}
}
