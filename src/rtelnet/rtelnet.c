/*
 *****************************************************************************
 *
 *        Copyright 1989, 1990, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 * 	Annex Reverse Telnet Daemon
 *	modified telnetd to provide host-pty/annex-port association
 *
 * Original Author: Paul Mattes		Created on: an impulse
 *
 * Module Reviewers:
 *	lint, loverso
 *
 * Revision Control Information:
 * $Id: rtelnet.c,v 3.17 1992/09/25 15:13:09 emond Rel $
 *
 * This file created by RCS from
 * $Source: /annex/common/src/./rtelnet/RCS/rtelnet.c,v $
 *
 * Revision History:
 * $Log: rtelnet.c,v $
 * Revision 3.17  1992/09/25  15:13:09  emond
 * Per Steve Kelley's testing, rename() should not be defined for
 * DPX200/300 machines.
 *
 * Revision 3.16  92/08/06  09:03:46  carlson
 * Fixed bug in -h switch -- must use erpc udp port for the message,
 * not just some random number.
 * 
 * Revision 3.15  92/04/08  12:27:29  carlson
 * Prevent FD_SET from using a bad index, and make searching easier.
 * 
 * Revision 3.14  92/04/01  09:06:51  emond
 * When putting in Alan's change for AIX forgot to change "slave" definition.
 * 
 * Revision 3.13  92/03/15  17:56:13  emond
 * Merged in some changes from Barnett for AIX.
 * 
 * Revision 3.12  92/03/13  08:58:36  carlson
 * Fixed some FIONBIO calls for SYS_V, and worked around systems without
 * LITOUT, S_IFSOCK and S_IFLNK.
 * 
 * Revision 3.11  92/01/24  15:26:20  carlson
 * SPR 513 -- fixed to work with ../inc/config.h (I hope!)
 * 
 * Revision 3.10  92/01/23  09:31:15  carlson
 * SPR 482 -- don't remove inappropriate files with -r option!
 * 
 * Revision 3.9  91/11/21  18:31:48  carlson
 * Added transparent mode.
 * 
 * Revision 3.8  91/09/16  19:26:00  emond
 * undef TCGETA for Siemens MX300 machine (per Alan Barnett)
 * 
 * Revision 3.7  91/09/07  15:29:38  russ
 * Added A. Barnett changes for FD_ZERO of ibits and xbits before use.
 * 
 * Revision 3.6  91/08/01  17:33:52  emond
 * Scott Griffiths' new rtelnet which runs on many more machines now!
 * 
 * Revision 3.5  91/03/01  13:49:52  pjc
 * Made DPTG mods conditional
 * 
 * Revision 3.4  91/03/01  13:37:15  pjc
 * Modified to optionally use DPTG port numbering
 * 
 * Revision 3.3  90/10/25  13:22:55  emond
 * ANSI-ized an #endif; removed argument following #endif.
 * This won't compile on an ANSI C compiler.
 * 
 * Revision 3.2  90/09/18  17:28:07  raison
 * removed "#define DEBUG" to remove printfs.
 * 
 * Revision 3.1  90/06/12  19:30:13  loverso
 * rtelnet with connect-on-the-fly
 * 
 * Revision 2.8  90/04/19  16:07:20  loverso
 * Allow BANKS and UNITS to be overridden by the compiler with
 * -DBANKS=\"abcdef\", etc.
 * 
 * Revision 2.7  90/04/18  13:16:08  loverso
 * Use exponential backoff on delay when connection fails.
 * Check for !net_errno when out of loop; this means net is ok.
 * 
 * Revision 2.6  90/04/18  13:07:12  loverso
 * Re-add lost fix for "-m"
 * 
 * Revision 2.5  90/04/09  15:35:09  loverso
 * All debugging to stderr
 * 
 * Revision 2.4  90/04/03  13:37:17  loverso
 * Be sure to initialize pcc & ncc for hosts which don't signal net failure
 * 
 * Revision 2.3  90/03/26  12:00:49  loverso
 * Added more extensive debugging code.
 * Added change to make sure all pty buffer data gets sent out network
 * (fixes SPR.83, "rtelnet drops chars").
 * 
 * Revision 2.2  90/01/19  17:56:12  loverso
 * Corrections and cleanup
 * 
 * Revision 2.1  89/12/01  14:03:45  loverso
 * Fix typo and missing netdb.h
 * 
 * Revision 2.0  89/10/16  17:46:00  loverso
 * `New' rtelnet with many portability changes for SysV-ish hosts
 * 
 * This file is currently under revision by: $Locker:  $
 *
 *****************************************************************************
 */
#ifndef lint
static char sccsid[] = "based upon @(#)telnetd.c 4.26 (Berkeley) 83/08/06";
static char rcsid[] =
    "$Id: rtelnet.c,v 3.17 1992/09/25 15:13:09 emond Rel $";
#endif


#define have_sockdefs	1
#define have_msghdr	1
#include "../inc/config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sgtty.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#define TELOPTS
#include <arpa/telnet.h>

#ifdef MIPS
#undef TIOCPKT
#endif
#ifdef SVR4
#include <sys/stropts.h>
#define SYS_V		/* SVR4 includes SYS_V changes */
#define LINGER		/* SVR4 requires Lachmann linger option */
#ifdef TIOCPKT
#undef TIOCPKT		/* We don't use packet mode for SVR4 */
#endif
#endif

#ifdef AIX
#ifndef SYS_V
#define SYS_V		/* AIX includes SYS_V changes */
#define LINGER		/* AIX requires Lachmann linger option */
#endif
#endif

#ifdef FD_ISSET
/* SUNOS 4.1 and SVR4 compatible - now have fd_set struct and FD_ macros
** used by select() system call.
** We just define a macro to extract bits for debug and testing.
*/
#define FD_BITVAL(x)	(x.fds_bits[0])
#else
/* Old-style systems - define local macros here for backwards
** compatibility.
*/
#define FD_SET(n, p)	(*(p) |= (1 << n))
#define FD_ISSET(n, p)	(*(p) & (1 << n))
#define FD_ZERO(p)	(*(p) = 0)
#define FD_BITVAL(x)	(x)
#define fd_set		int
#endif

#if defined (SYS_V) || defined (ULTRIX)
#include <sys/termio.h>
#endif

#ifdef MX300
#undef TCGETA
#endif

#include "../inc/erpc/netadmp.h"

#define	after(s) (sizeof(s) - 1)

#ifdef CONVERGENT

/*
 * Convergent uses "virtual terminals"
 * master="vtXX" slave="ttypXX" units=[0..31]
 * we avoid unit=00
 * never-the-less, this code is less than correct.
 */
#define BANKS	"3210"
#define UNITS	"0123456789"
#define MASTERBANK	after("/dev/vt")
#define MASTERUNIT	after("/dev/vt0")
#define SLAVEBANK	after("/dev/ttyp")
#define SLAVEUNIT	after("/dev/ttyp0")
char	master[] = "/dev/vt00";
char	slave[] = "/dev/ttyp00";
char	alias[] = "/dev/vt00.rtelnet";

#else /* !CONVERGENT */

#ifdef SEQUENT

/*
 * Sequent uses Berkeley-style ptys but with more units per bank
 * master="ptyBU" slave="ttyBU" banks=[p] units=[0-9A-Za-z]
 * we avoid unit=0
 */
#define BANKS   "p"
#define UNITS	"123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

#define MASTERBANK	after("/dev/pty")
#define MASTERUNIT	after("/dev/ptyp")
#define SLAVEBANK	after("/dev/tty")
#define SLAVEUNIT	after("/dev/ttyp")
char	master[] = "/dev/ptyp0";
char	slave[] = "/dev/ttyp0";
char	alias[] = "/dev/ptyp0.rtelnet";

#else /* !SEQUENT */

#ifdef AIX

/*
 * AIX uses a multiplexed master device. An open on this device allocates
 * a channel with an assigned slave device. 
 */
#define BANKS ""	/* We don't have banks of ptys or units. */
#define UNITS ""	/* These definitions included for completeness */
#define MASTERBANK ""
#define MASTERUNIT ""
#define SLAVEBANK ""
#define SLAVEUNIT ""

char	master[] = "/dev/ptc";
char 	slave[20] = "/dev/pts/999";
char	alias[]	= "/dev/ptc.rtelnet";
extern	char *ttyname();

#else /* !AIX */

#ifdef SVR4

/*
 * SVR4 uses a multiplexed master device. An open on this device allocates
 * an unused channel with an assigned slave device.
 */

#define BANKS ""	/* We don't have banks of ptys or units. */
#define UNITS ""	/* These definitions included for completeness */
#define MASTERBANK ""
#define MASTERUNIT ""
#define SLAVEBANK ""
#define SLAVEUNIT ""

char	master[] = "/dev/ptmx";
char 	*slave;
int	slave_pty = -1;
int	slave_opened = 0;
char	alias[]	= "/dev/ptmx.rtelnet";
extern	char *ptsname();

#else /* !SVR4 */ /* Fall through to Berkeley style ptys */

/*
 * Berkeley-style ptys, banks of 16 units
 * master="ptyBU" slave="ttyBU" banks=[pqrs] units=[0-9a-f]
 * we avoid unit=0
 */

#define BANKS	"srqp"
#define UNITS	"123456789abcdef"

#define MASTERBANK	after("/dev/pty")
#define MASTERUNIT	after("/dev/ptyp")
#define SLAVEBANK	after("/dev/tty")
#define SLAVEUNIT	after("/dev/ttyp")
char	master[] = "/dev/ptyp0";
char	slave[] = "/dev/ttyp0";
char	alias[] = "/dev/ptyp0.rtelnet";

#endif  /* SVR4 */
#endif  /* AIX */
#endif  /* SEQUENT */
#endif  /* CONVERGENT */

char	banks[] = BANKS;
char	units[] = UNITS;

#define SENT	0
#define RCVD	1

#define	BELL	'\007'

char	hisopts[256];
char	myopts[256];

char	doopt[] = { IAC, DO, '%', 'c', 0 };
char	dont[] = { IAC, DONT, '%', 'c', 0 };
char	will[] = { IAC, WILL, '%', 'c', 0 };
char	wont[] = { IAC, WONT, '%', 'c', 0 };

/*
 * I/O data buffers, pointers, and counters.
 */
char	ptyibuf[BUFSIZ], *ptyip = ptyibuf;
char	ptyobuf[BUFSIZ], *pfrontp = ptyobuf, *pbackp = ptyobuf;
char	netibuf[BUFSIZ], *netip = netibuf;
char	netobuf[BUFSIZ], *nfrontp = netobuf, *nbackp = netobuf;

char	*new_node;
int	so_debug, drop, rflag;
int	debug, binary;
int	onthefly, hangup;
int	transparent;

int	cleanup();

int	pcc, ncc;
int	options;
int	port_num;
int	dev_pty = -1, dev_net = -1;

int erpc_port;		/* erpc port for -h flag in network order */
int tcp_port;		/* TCP port on Annex in network order */

extern	char **environ;
extern	int errno;
int	saved_errno;
int	progress = 0;
char	*myname;

#define	LINKED_TTY	1
#define RENAMED_PTY	2

struct	sockaddr_in sin = { AF_INET };
struct	sockaddr_in sin2 = { AF_INET };

int control_c();

static void datadump();

#define PORT_MAP_BASE	5000
#define RAW_MAP_BASE	7000

#ifdef LITOUT
#define VERYRAW		(RAW | LITOUT)
#else
#define VERYRAW		RAW
#endif


usage()
{
	fprintf(stderr,
"usage: %s [-bdfhmrtD] <annex_id> <annex_port> /dev/<new_dev_name>\n",myname);
	exit(1);
}

main(argc, argv)
	char *argv[];
{
	struct stat sbuf;
	struct sgttyb b;
	int	on=1, i, backoff=1;
	char	*bank, *unit, *cp;
	register struct hostent *host;
	struct servent *servp;

	myname = *argv++;
	argc--;
  	while (argc > 0 && argv[0][0] == '-') {
		for (cp = &argv[0][1]; *cp; cp++)
			switch(*cp) {
			case 'b':
				binary++;	/* try binary mode */
				break;

			case 'd':
				so_debug++;	/* turn socket debugging */
				break;

			case 'f':
				onthefly++;	/* open connection on the fly */
				break;

			case 'h':
				hangup++;	/* reset annex port */
				break;

			case 'm':
				drop++;		/* drop socket on pty close */
				break;

			case 'r':
				rflag++;	/* remove file if it exists */
				break;

			case 't':
				transparent++;	/* transparent connection */
				break;

			case 'D':
				debug++;	/* verbose debug output */
				break;

			default:
				fprintf(stderr, "%s: unknown flag '%c'\n",
						myname,*cp);
				exit(1);

			}	/* switch(argv[0][1]) */

		argv++;
		argc--;
	}

	if (argc != 3)
		usage();

	sin.sin_addr.s_addr = inet_addr(argv[0]);
	if (sin.sin_addr.s_addr != -1) {
		sin.sin_family = AF_INET;
	} else {
		host = gethostbyname(argv[0]);
		if (host) {
			sin.sin_family = host->h_addrtype;
			bcopy(host->h_addr,
			      (caddr_t)&sin.sin_addr,
			      host->h_length);
		} else {
			fprintf(stderr, "%s: %s: unknown host\n",myname,argv[0]);
			exit(1);
		}
	}

	argc--,	argv++;

#if NDPTG > 0
	port_num = name_to_unit(*argv);
	if (port_num == -1)
		usage();
#else
	port_num = atoi(*argv);
	if (port_num <= 0)
		usage();
#endif

	if (debug)
		fprintf(stderr,"req port %d\n", port_num);

	if (transparent)
		tcp_port = htons((u_short)(RAW_MAP_BASE + port_num));
	else
		tcp_port = htons((u_short)(PORT_MAP_BASE + port_num));

	argc--, argv++;

	if (stat(argv[0], &sbuf) >= 0) {
		if (rflag)
			switch (sbuf.st_mode&S_IFMT) {
				case S_IFCHR:
#ifdef S_IFLNK
				case S_IFLNK:
#endif
#ifdef S_IFSOCK
				case S_IFSOCK:
#endif
					if (unlink(argv[0])) {
						perror(argv[0]);
						exit(1);
						}
					break;
				default:
					fprintf(stderr,"%s: File \"%s\" is not the right type.\n",myname,argv[0]);
					exit(1);
				}
		else {
			fprintf(stderr, "%s: File \"%s\" already exists\n",
					myname,argv[0]);
			exit(1);
		}
	}

	new_node = *argv;

	if (so_debug)
		options |= SO_DEBUG;

	if ((servp = getservbyname("erpc","udp")) == NULL) {
		fprintf(stderr,
			"%s: udp/erpc: unknown service, using 121.\n",
			myname);
		erpc_port = htons((u_short)121);
	} else
		erpc_port = servp->s_port;	/* in net order */

#ifndef SVR4		/* We don't have to do this for SVR4 */
#ifndef AIX		/* or AIX */

	/*
	 * Clean up after previous incarnations of rtelnet
	 */
	for (bank = banks; *bank; bank++) {
		struct stat stb;

		alias[MASTERBANK] = *bank;
		for (unit = units; *unit; unit++) {
			int pty;

			alias[MASTERUNIT] = *unit;
			if (stat(alias, &stb) < 0)
				continue;
			if ((pty = open(alias, 2)) < 0)
				continue;
			else {
				master[MASTERBANK] = *bank;
				master[MASTERUNIT] = *unit;
				(void)rename(alias, master);
				(void)close(pty);
			}
		}
	}
#endif /* AIX */
#endif /* SVR4 */

	/*
	 * Due to the differences in pty implementations, we call a routine to 
	 * open the master and allocate a slave device.
         */

	 if ((dev_pty = openmaster()) < 0) {
		fprintf(stderr, "%s: All network ports in use\n",myname);
		cleanup();
		/*NOTREACHED*/
	}
	if (debug)
		fprintf(stderr,"using master=%s slave=%s alias=%s\n",
			master, slave, alias);

	if (!debug) {
		int fd;

		if (fork())
			exit(0);
		(void) close(0);
		(void) close(1);
		(void) close(2);

#ifdef SYS_V
		fd = open ("/dev/console", O_RDWR);
		if (fd < 0)
			fd = open ("/dev/tty", O_RDWR);
		if (fd < 0)
			fd = open ("/dev/null", O_RDWR);
		(void)dup2 (0, 1);
		(void)dup2 (0, 2);
#else
		(void)open("/", 0);
		(void)dup2 (0, 1);
		(void)dup2 (0, 2);

		fd = open("/dev/tty", 2);
		if (fd > 0) {
			(void)ioctl(fd, TIOCNOTTY, 0);
			(void)close(fd);
		}
#endif
	}

#ifdef SYS_V
	(void)setpgrp();
#endif
	signal(SIGINT, control_c);
	signal(SIGTERM, control_c);
#ifdef SVR4
	signal(SIGHUP,SIG_IGN);
#endif

	while(1) {

		if (debug)
			fprintf(stderr,"\nTop of loop, backoff=%d\n", backoff);

		if (onthefly && backoff==1) {
			int n_found;
			fd_set ibits, xbits;

			FD_ZERO(&ibits);
			FD_ZERO(&xbits);
			FD_SET(dev_pty, &ibits);
			FD_SET(dev_pty, &xbits);

			n_found = select(16, &ibits, (fd_set *)0, &xbits,
							(struct timeval *)0);
			if (n_found < 0) {
				perror("select");
				exit(1);
			}
			if (debug > 2)
				fprintf(stderr,
					"onthefly: %d found: i=%#x, x=%#x\n",
					n_found,
					FD_BITVAL(ibits), FD_BITVAL(xbits));
		}
		if (telnet()) {
			sleep(backoff);
			backoff = backoff > 32 ? 64 : backoff << 1;
		} else
			backoff = 1;
	}
}

#ifdef SVR4
/*
 * SVR4 requires some streams modules to be placed on the slave to provide
 * the same functionality of Berkely style ptys. Unfortunately, since we
 * open the slave, we have no indication of when an application closes the
 * device. For the modem hangup procedure to work correctly, we have to
 * close the device the first time we see an application use it. Then 
 * when they close, we get a message and need to re-open. The I_LOOK nonsense
 * is to check for a bogus close situation, i.e. it wasn't really the last
 * close of the stream.
 */
void 
openslave()
{
char *ldmod = "ldterm";

	    if ((slave_pty = open(slave, O_RDWR)) < 0) {
		if (debug) fprintf(stderr, "openslave, slave open errno = %d\n",
				  errno);
	    } else {
		if (ioctl(slave_pty, I_FIND, ldmod)) {
			if (debug) 
				fprintf(stderr,"ldterm already on stream\n");
		} else {
				ioctl(slave_pty, I_PUSH, "ptem");
				ioctl(slave_pty, I_PUSH, "ldterm");
		}
		slave_opened++;
	    }
}
#endif /* SVR4 */

#ifdef SVR4
/*
 * Function to open to generic master device, then obtain name of
 * slave device if open successful. Call openslave to push appropriate streams
 * modules. Link the new node name to the slave device.
 */
int 
openmaster()
{
	int newpty;
        int i;

	/*
	 *  System V Release 4 has multiplexed special master
         *  and extra system calls as follows...
	 */
        if (( newpty = open( master, O_RDWR )) >= 0 ) {
            i = grantpt(newpty);
            i = unlockpt(newpty);
            slave = ptsname(newpty);
	    if (debug) 
		fprintf(stderr, "ptsname returns %s\n", slave);
	    openslave();
	    if (link(slave,new_node) < 0) {
		fprintf(stderr, "%s: link to slave device ",myname);
	 	perror(slave);
	    }
	    chmod(new_node, 0777);
	    progress |= LINKED_TTY;
	    fcntl(newpty, F_SETFL, O_NDELAY);
        }
        return(newpty);
}
#else  /* !SVR4 */

#ifdef AIX

/*
 * AIX also has a multi-channel master device. We open the master and use
 * ttyname() to find the allocated slave device. Link to the new_node (using
 * symlink) and set the pty to a useable state.
 */
int
openmaster()
{
	int newpty;
	struct sgttyb b;
	int on=1;

	if ((newpty = open(master, O_RDWR)) >= 0) {
 	    strcpy(slave, ttyname(newpty));
	    if (symlink(slave,new_node) < 0) {
		fprintf(stderr, "%s: link to slave device ",myname);
	 	perror(slave);
	    }
	    progress |= LINKED_TTY;
	    chmod(new_node, 0777);
	    ioctl(newpty, TIOCGETP, (caddr_t)&b);
	    if (transparent)
		b.sg_flags = VERYRAW;
	    else
		b.sg_flags = CRMOD | XTABS | ANYP;
	    ioctl(newpty, TIOCSETP, (caddr_t)&b);
	    fcntl(newpty, F_SETFL, O_NDELAY);
#ifdef TIOCPKT
	    ioctl(newpty, TIOCPKT, (caddr_t)&on);
#endif
	}

	return(newpty);
}
#else /* !AIX */

/*
 * Berkeley style ptys.
 * Open the master pty.  Search backwards, so that the pty we take
 * permanently doesn't slow down other pty users.  We may reserve
 * the pty by renaming it, so don't use /dev/pty?0, which can't
 * ever disappear.
 */
int
openmaster()
{
	int newpty;
	char	*bank, *unit, *cp;
	struct stat stb;
	struct sgttyb b;
	int on=1;

	for (bank = banks; *bank; bank++) {
		master[MASTERBANK] = *bank;
		slave[SLAVEBANK] = *bank;
		master[MASTERUNIT] = units[0];
		if (stat(master, &stb) < 0) {
			if (debug)
				fprintf(stderr,
					"%s: missing pty bank %c\n",
					myname,*bank);
			continue;
		}
		for (unit = units; *unit; unit++) {
			master[MASTERUNIT] = *unit;
			if ((newpty = open(master, O_RDWR)) < 0)
				continue;
			slave[SLAVEUNIT] = *unit;
			if (link(slave, new_node) < 0) {
				perror(slave);
				(void)close(newpty);
				continue;
			}
	    		progress |= LINKED_TTY;
			alias[MASTERBANK] = *bank;
			alias[MASTERUNIT] = *unit;
			goto gotpty;
		}
	}
	return(-1);

gotpty:

	chmod(new_node, 0777);

	ioctl(newpty, TIOCGETP, (caddr_t)&b);
	if (transparent)
		b.sg_flags = VERYRAW;
	else
		b.sg_flags = CRMOD | XTABS | ANYP;
	ioctl(newpty, TIOCSETP, (caddr_t)&b);
#ifdef SYS_V
	fcntl(newpty, F_SETFL, O_NDELAY);
#else
	ioctl(newpty, FIONBIO, (caddr_t)&on);
#endif
#ifdef TIOCPKT
	ioctl(newpty, TIOCPKT, (caddr_t)&on);
#endif
	return(newpty);
}
#endif /* AIX */
#endif /* SVR4 */

int
make_connection()
{
	int s;
	int on = 1;
#ifdef	LINGER
	struct linger linger;
#endif

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("rtelnet: socket");
		return -1;
	}

	if (options & SO_DEBUG)
		if (setsockopt(s, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) < 0)
			perror("rtelnet: setsockopt (SO_DEBUG)");

	if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
		perror("rtelnet: setsockopt (SO_KEEPALIVE)");

#ifdef LINGER
	/*
	 * Set up linger option to block on a close if unsent messages
	 * are still queued on the socket 
	 */
	linger.l_onoff = 1;
	linger.l_linger = 60;
	if (setsockopt(s, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0)
		perror("rtelnet: setsockopt (SO_LINGER)");
#endif

	if (bind(s, (struct sockaddr *)&sin2, sizeof (struct sockaddr)) < 0)
		perror("rtelnet: bind");

	sin.sin_port = tcp_port;
	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		perror("rtelnet: connect");
		(void)close(s);
		return -1;
	}

#ifdef SYS_V
	(void)fcntl(s, F_SETFL, O_NDELAY);
#else
	(void)ioctl(s, FIONBIO, (caddr_t)&on);
#endif

	ptyip = ptyibuf;
	pfrontp = ptyobuf;
	pbackp = ptyobuf;

	netip = netibuf;
	nfrontp = netobuf;
	nbackp = netobuf;

	return s;
}

/*
 * Main loop.  Select from pty and network, and
 * hand data to telnet receiver finite state machine.
 */
telnet(f)
{
	int on = 1;
	struct sgttyb b;
	int net_errno, pty_errno;

	if ((dev_net = make_connection()) < 0)
		return -1;

	telrcv(1);

#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif

	/*
	 * Negotiate binary mode, if requested
	 */
	if (!transparent && binary) {
		dooption(TELOPT_BINARY);
		myopts[TELOPT_BINARY] = 1;
		willoption(TELOPT_BINARY);
	}

restart:
	pcc = 0; ncc = 0;

	if (debug > 2)
		fprintf(stderr,"fd: net=%d, pty=%d\n", dev_net, dev_pty);

	while (dev_net >= 0 && dev_pty >= 0) {
		fd_set ibits, obits;
#ifdef MIPS
		fd_set ebits;
#endif
		register int c;
		int n_found;

		FD_ZERO(&ibits);
		FD_ZERO(&obits);
#ifdef MIPS
		FD_ZERO(&ebits);
#endif

		/*
		 * Never look for input if there's still
		 * stuff in the corresponding output buffer
		 */
		if (nfrontp - nbackp || pcc > 0)
			FD_SET(dev_net, &obits);
		else
			FD_SET(dev_pty, &ibits);

		if (pfrontp - pbackp) {
#ifndef CONVERGENT
			FD_SET(dev_pty, &obits);
			
#else
			/* always possible for write on VT */
			ptyflush();
#endif
		} else
			FD_SET(dev_net, &ibits);

		if (ncc < 0 && pcc < 0)
			break;
#ifdef MIPS
		FD_SET(dev_pty, &ebits);
		if (debug > 2)
			fprintf(stderr,"selecting: i %#x, o %#x, e %#x\n",
				ibits, obits, ebits);
#else
		if (debug > 2)
			fprintf(stderr,"selecting: i %#x, o %#x\n",
				ibits, obits);
#endif

#ifdef MIPS
		n_found = select(16, &ibits, &obits, &ebits,
#else
		n_found = select(16, &ibits, &obits, (fd_set *)0,
#endif
				 (struct timeval *)0);
		if (n_found < 0) {
			perror("rtelnet: select");
			exit(1);
		}
#ifdef MIPS
		if (debug > 2)
			fprintf(stderr,"%d found: i=%#x, o=%#x, e=%#x\n",
				n_found, FD_BITVAL(ibits), FD_BITVAL(obits),
				FD_BITVAL(ebits));
#else
		if (debug > 2)
			fprintf(stderr,"%d found: i=%#x, o=%#x\n",
				n_found, FD_BITVAL(ibits), FD_BITVAL(obits));
#endif
#ifdef MIPS
		if (FD_BITVAL(ibits) == 0 && FD_BITVAL(obits) == 0 &&
		    FD_BITVAL(ebits) == 0) {
			sleep(5);
			continue;
		}
#else
		if (FD_BITVAL(ibits) == 0 && FD_BITVAL(obits) == 0) {
			sleep(5);
			continue;
		}
#endif

		/*
		 * Something to read from the network...
		 */
		if (FD_ISSET(dev_net, &ibits)) {
			if (debug > 1)
				fprintf(stderr,"net: ");
			ncc = read(dev_net, netibuf, BUFSIZ);
			if (debug > 1) {
				saved_errno = errno;
				fprintf(stderr, "returns %d errno %d\n",
					ncc, errno);
				errno = saved_errno;
			}
			if (ncc < 0 && errno == EWOULDBLOCK)
				ncc = 0;
			else {
				if (ncc <= 0) {
					net_errno = ncc<0?errno:0;
					pty_errno = 0;
					break;
				}
				netip = netibuf;
			}
			if (debug > 4 && ncc > 0)
				datadump(netip, ncc);
		}

		/*
		 * Something to read from the pty...
		 */
		if (FD_ISSET(dev_pty, &ibits)) {
#ifdef SVR4
		/*
		 * We check for our open of the slave device. Since we are
		 * here, we think someone has opened the slave device. We
		 * close so we will be notified when the application closes.
		 */
			if (slave_opened) {
				close(slave_pty);
				slave_opened--;
			}
#endif

			if (transparent)
				mode(RAW,0);
			if (debug > 1)
				fprintf(stderr,"pty: pcc was %d ", pcc);
			pcc = read(dev_pty, ptyibuf, BUFSIZ);
			if (debug > 1) {
				saved_errno = errno;
				fprintf(stderr, "returns %d errno %d\n",
					pcc, errno);
				errno = saved_errno;
			}
			if (pcc < 0 && errno == EWOULDBLOCK)
				pcc = 0;
			else {
				if (pcc <= 0) {
					net_errno = 0;
#if defined(SVR4) || defined(AIX)

				/*
				 * SVR4 indicates last close on slave by
				 * sending 0 length message. We indicate same
				 * via EIO
				 */
					if (pcc < 0) 
						pty_errno = errno;
					else {
						pty_errno = EIO;
					}

#else
					pty_errno = pcc<0?errno:0;
#endif
					break;
				}
#ifdef TIOCPKT
				pcc--;
				ptyip = &ptyibuf[1];
#else
				ptyip = &ptyibuf[0];
#endif

			}
			if (debug > 4 && pcc > 0)
				datadump(ptyip, pcc);
		}
		
#ifdef MIPS
		/*
		 * MIPS OS reports a close on the slave pty by setting
		 * the exception bit. We check it here and set EIO if
		 * it is closed
		 */
		if (FD_ISSET(dev_pty, &ebits)) {
			pcc = 0;
			pty_errno = EIO;
			break;
		}
#endif

		while (pcc > 0) {
			if ((&netobuf[BUFSIZ] - nfrontp) < 2)
				break;
			c = *ptyip++ & 0377, pcc--;
			*nfrontp++ = c;
			if (transparent)
				continue;
			if (c == IAC)
				*nfrontp++ = c;
			else if (c == '\r' && !myopts[TELOPT_BINARY])
				*nfrontp++ = '\0';
		}

		if (FD_ISSET(dev_net, &obits) && (nfrontp - nbackp) > 0)
			netflush();
		if (ncc > 0)
			telrcv(0);
		if ((pfrontp - pbackp) > 0)
			ptyflush();
		if (FD_ISSET(dev_pty, &obits) && (pfrontp - pbackp) > 0)
			ptyflush();
	}

	if (debug) {
		fprintf(stderr,
			"out of loop pcc=%d pty_errno=%d ncc=%d net_errno=%d\n",
			pcc, pty_errno, ncc, net_errno);
	}

	/*
	 * I/O error from pty or it looks like somebody closed the slave device.
	 * Simply start over.
	 */
	if (pty_errno == EIO || net_errno != 0 ||
	    (pcc == 0 && pty_errno == 0 && ncc == 0 && net_errno == 0)) {
#ifdef SVR4
		/*
		 * In SVR4, closing the slave device does not sever the 
		 * connection between the allocated slave channel and the
		 * opened master. All we have to do is re-open the slave and
		 * set the stream up again.
		 */

		if (pty_errno == EIO) 
			openslave(); 

#else  /* !SVR4 */
#ifdef AIX
		/* For AIX, we close the master side and start over */
		(void)close(dev_pty);
		unlink(new_node);
		if ((dev_pty = openmaster()) < 0) {
		   fprintf(stderr, "%s: reopen of master device failed\n",myname);
		   cleanup();
		}
#else /* !AIX */
		/*
		 * Berkeley style ptys.
		 * While the master pty is closed, someone could open
		 * it and effectively steal the remote device from us.
		 * (Yecch) rename the master pty while it's closed.
		 */
		if (rename(master, alias) < 0) {
			perror("rename to alias");
			cleanup();
			/*NOTREACHED*/
		}
		progress |= RENAMED_PTY;
		(void)close(dev_pty);
		if ((dev_pty = open(alias, 2)) < 0) {
			perror("reopen of alias");
			cleanup();
			/*NOTREACHED*/
		}
		if (rename(alias, master) < 0) {
			perror("rename to normal");
			cleanup();
			/*NOTREACHED*/
		}
		progress &= ~RENAMED_PTY;
		ioctl(dev_pty, TIOCGETP, (caddr_t)&b);
		if (transparent)
			b.sg_flags = VERYRAW;
		else
			b.sg_flags = CRMOD | XTABS | ANYP;
		ioctl(dev_pty, TIOCSETP, (caddr_t)&b);
#ifdef SYS_V
		fcntl(dev_pty, F_SETFL, O_NDELAY);
#else
		ioctl(dev_pty, FIONBIO, (caddr_t)&on);
#endif
#ifdef TIOCPKT
		ioctl(dev_pty, TIOCPKT, (caddr_t)&on);
#endif
#endif /* AIX */
#endif /* SVR4 */

		if (pty_errno
#ifdef BROKEN_NET
/*
 * some systems don't correctly indicate close of the connection!
 */
		    || !net_errno
#endif
		) {
			if (drop) {
				send_tm(dev_net);
				if (hangup) {
					/*we also need to set_global_passwd*/
					sin.sin_port = erpc_port;
					(void)reset_line(
						(struct sockaddr_in *)&sin,
						(u_short)SERIAL_DEV,
						(u_short)port_num);
				}
			} else
				goto restart;
		}
		if (shutdown(dev_net, 2) == -1)	/* Telnet connection down */
			perror("shutdown");
		(void)close(dev_net);
		return 0;
	}

	if (debug)
		fprintf(stderr,"outahere\n");
	cleanup();
	/*NOTREACHED*/
}

cleanup()
{
	if (debug)
		fprintf(stderr,"cleanup()\n");

	if (progress & LINKED_TTY)
		unlink(new_node);

	if (progress & RENAMED_PTY)
		rename(alias, master);

#if (!(defined (SYS_V) || defined (FREEBSD) || defined (BSDI)))
	if (!debug)
		vhangup();	/* XXX */
#endif

	if (dev_net >= 0)
		(void)shutdown(dev_net, 2);

	exit(1);
}

int control_c()
{
	if (debug)
		fprintf(stderr,"control_c()\n");
	cleanup();
}

/*
 * State for recv fsm
 */
#define	TS_DATA		0	/* base state */
#define	TS_IAC		1	/* look for double IAC's */
#define	TS_CR		2	/* CR-LF ->'s CR */
#define	TS_BEGINNEG	3	/* throw away begin's... */
#define	TS_ENDNEG	4	/* ...end's (suboption negotiation) */
#define	TS_WILL		5	/* will option negotiation */
#define	TS_WONT		6	/* wont " */
#define	TS_DO		7	/* do " */
#define	TS_DONT		8	/* dont " */

telrcv(init_it)
int init_it;
{
	register int c;
	static int state = TS_DATA;
	struct sgttyb b;

	if (init_it) {
		state = TS_DATA;
		return;
	}

	while (ncc > 0) {
		if ((&ptyobuf[BUFSIZ] - pfrontp) < 2)
			return;
		c = *netip++ & 0377, ncc--;

		if (transparent) {
			*pfrontp++ = c;
			continue;
			}

		switch (state) {

		case TS_DATA:
			if (c == IAC) {
				state = TS_IAC;
				break;
			}
			*pfrontp++ = c;
			if (!hisopts[TELOPT_BINARY] && c == '\r')
				state = TS_CR;
			break;

		case TS_CR:
			if (c && c != 0)
				*pfrontp++ = c;
			state = TS_DATA;
			break;

		case TS_IAC:
			switch (c) {

			/*
			 * Send the process on the pty side an
			 * interrupt.  Do this with a NULL or
			 * interrupt char; depending on the tty mode.
			 */
			case BREAK:
			case IP:
				interrupt();
				break;

			/*
			 * Are You There?
			 */
			case AYT:
				*pfrontp++ = BELL;
				break;

			/*
			 * Erase Character and
			 * Erase Line
			 */
			case EC:
			case EL:
				ptyflush();	/* half-hearted */
				ioctl(dev_pty, TIOCGETP, (caddr_t)&b);
				*pfrontp++ = (c == EC) ?
					b.sg_erase : b.sg_kill;
				break;

			/*
			 * Check for urgent data...
			 */
			case DM:
				break;

			/*
			 * Begin option subnegotiation...
			 */
			case SB:
				state = TS_BEGINNEG;
				continue;

			case WILL:
			case WONT:
			case DO:
			case DONT:
				state = TS_WILL + (c - WILL);
				continue;

			case IAC:
				*pfrontp++ = c;
				break;
			}
			state = TS_DATA;
			break;

		case TS_BEGINNEG:
			if (c == IAC)
				state = TS_ENDNEG;
			break;

		case TS_ENDNEG:
			state = c == SE ? TS_DATA : TS_BEGINNEG;
			break;

		case TS_WILL:
			printoption(RCVD, "will", c, !hisopts[c]);
			if (!hisopts[c])
				willoption(c);
			state = TS_DATA;
			continue;

		case TS_WONT:
			printoption(RCVD, "wont", c, hisopts[c]);
			if (hisopts[c])
				wontoption(c);
			state = TS_DATA;
			continue;

		case TS_DO:
			printoption(RCVD, "do", c, !myopts[c]);
			if (!myopts[c])
				dooption(c);
			state = TS_DATA;
			continue;

		case TS_DONT:
			printoption(RCVD, "dont", c, myopts[c]);
			if (myopts[c]) {
				myopts[c] = 0;
				sprintf(nfrontp, wont, c);
				nfrontp += sizeof (wont) - 2;
			}
			state = TS_DATA;
			continue;

		default:
			fprintf(stderr,"%s: panic: state=%d\n",myname,state);
			exit(1);
		}
	}
}

send_tm(f)
	int f;
{
	register int c, cc;
	int off = 0;
	int state = TS_DATA;
	char buff[1024], *p;

	sprintf(buff, doopt, TELOPT_TM);
	cc = strlen(buff);
	if (debug)
		fprintf(stderr,"sending tm\n");
	while(cc)
		cc -= write(f, buff, cc);
	if (debug)
		fprintf(stderr,"sent tm\n");
#ifdef SYS_V
	fcntl(f, F_SETFL, O_NDELAY);
#else
	ioctl(f, FIONBIO, (caddr_t)&off);
#endif
	while ((cc = read(f, buff, sizeof(buff))) > 0) {
		p = buff;
		while (cc > 0) {
			c = *p++ & 0377, cc--;
			switch (state) {

			case TS_DATA:
				if (c == IAC) {
					state = TS_IAC;
					break;
				}
				break;

			case TS_IAC:
				switch (c) {
				case WILL:
				case WONT:
				case DO:
				case DONT:
					state = TS_WILL + (c - WILL);
					continue;
				}
				state = TS_DATA;
				break;

			case TS_WILL:
			case TS_WONT:
				if (c == TELOPT_TM)
				return;

			case TS_DO:
			case TS_DONT:
				state = TS_DATA;
				continue;

			default:
				fprintf(stderr, "send_tm: panic state=%d\n",
					state);
				exit(1);
			}
		}
	}
}

willoption(option)
	int option;
{
	char *fmt;

	switch (option) {

	case TELOPT_BINARY:
		mode(RAW, 0);
		goto common;

	case TELOPT_ECHO:
		mode(0, ECHO|CRMOD);
		/*FALL THRU*/

	case TELOPT_SGA:
	common:
		hisopts[option] = 1;
		fmt = doopt;
		break;

	case TELOPT_TM:
		fmt = dont;
		break;

	default:
		fmt = dont;
		break;
	}
	printoption(SENT, fmt == doopt ? "do" : "don't", option, 0);
	sprintf(nfrontp, fmt, option);
	nfrontp += sizeof (dont) - 2;
}

wontoption(option)
	int option;
{
	char *fmt;

	switch (option) {

	case TELOPT_ECHO:
		mode(ECHO|CRMOD, 0);
		goto common;

	case TELOPT_BINARY:
		mode(0, RAW);
		/*FALL THRU*/

	case TELOPT_SGA:
	common:
		hisopts[option] = 0;
		fmt = dont;
		break;

	default:
		fmt = dont;
	}
	printoption(SENT, fmt == doopt ? "do" : "don't", option, 0);
	sprintf(nfrontp, fmt, option);
	nfrontp += sizeof (doopt) - 2;
}

dooption(option)
	int option;
{
	char *fmt;

	switch (option) {

	case TELOPT_TM:
		fmt = wont;
		break;

	case TELOPT_ECHO:
		mode(ECHO|CRMOD, 0);
		goto common;

	case TELOPT_BINARY:
		mode(RAW, 0);
		/*FALL THRU*/

	case TELOPT_SGA:
	common:
		fmt = will;
		break;

	default:
		fmt = wont;
		break;
	}
	printoption(SENT, fmt == will ? "will" : "won't", option, 0);
	sprintf(nfrontp, fmt, option);
	nfrontp += sizeof (doopt) - 2;
}

mode(on, off)
	int on, off;
{
	struct sgttyb b;

	ptyflush();
	ioctl(dev_pty, TIOCGETP, (caddr_t)&b);
	if ((b.sg_flags&on)!=on || (b.sg_flags&off)!=0) {
		b.sg_flags |= on;
		b.sg_flags &= ~off;
		ioctl(dev_pty, TIOCSETP, (caddr_t)&b);
		}
}

/*
 * Send interrupt to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write intr char.
 */
interrupt()
{
#ifdef TCGETA
	struct termio tv;
#else
	struct sgttyb b;
	struct tchars tchars;
#endif

	ptyflush();	/* half-hearted */
	if (transparent)
		return;
#ifdef TCGETA
	ioctl(dev_pty, TCGETA, &tv);
	if (!(tv.c_lflag & ISIG) )
#else
	ioctl(dev_pty, TIOCGETP, (caddr_t)&b);
	if (b.sg_flags & RAW)
#endif
	{
		*pfrontp++ = '\0';
		return;
	}
#ifdef TCGETA
	*pfrontp++ = tv.c_cc[VQUIT];
#else
	*pfrontp++ = ioctl(dev_pty, TIOCGETC, (caddr_t)&tchars) >= 0
			? tchars.t_intrc
			: '\177';
#endif
}

ptyflush()
{
	int n;

	if ((n = pfrontp - pbackp) > 0)
		n = write(dev_pty, pbackp, n);

	if (n < 0)
		return;
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}

netflush()
{
	int n;

	if ((n = nfrontp - nbackp) > 0) {
		n = write(dev_net, nbackp, n);
	}
	if (n < 0) {
		if (errno == EWOULDBLOCK)
			return;
		/* should blow this guy away... */
		return;
	}
	nbackp += n;
	if (nbackp == nfrontp)
		nbackp = nfrontp = netobuf;
}

printoption(dir, what, which, reply)
int dir;
char *what;
char which;
int reply;
{
	char *s_witch, ssb[32];

	if (debug<2)
		return;

	sprintf(ssb, "%d", which);

	if (which < 0 || which >= sizeof(telopts) / sizeof(telopts[0]))
		s_witch = ssb;
	else
		s_witch = telopts[which];

	if (dir == SENT)
		fprintf(stderr,"SENT %s %s\n", what, s_witch);
	else
		fprintf(stderr,"RCVD %s %s (%sreply)\n",
			what, s_witch, reply ? "" : "don't ");
}


#if defined(SYS_V) && !defined(DPX200) && !defined(DPX300)
rename(old,new)
char *old, *new;
{
	if(unlink(new) < 0) {
		if (errno != ENOENT)
			return(-1);
	}
	if(link(old,new) < 0)
		return(-1);
	if(unlink(old) < 0)
		return(-1);
}
#endif

static void
datadump(p, len)
u_char *p;
int len;
{
	int i;
	u_char *s = (u_char *)(~0xf & (u_long)p);

	len += p-s;
	while (len > 0) {
		u_char *s1 = s;
		fprintf(stderr,s<=p ? "%6x:%-3x" : "%6x:   ",
			s<=p ? p : s,
			len - (p-s));
		for (i = 0; i < 16; i++, s++)
			fprintf(stderr,s<p||i>=len ? "%s   " : "%s%.2x ",
				i % 8 ? "" : " ",
				*s);
		s = s1;
		fprintf(stderr," |");
		for (i = 0; i < 16; i++, s++)
			fprintf(stderr,"%c", s<p||i>=len ? ' '
					: *s<' '||*s>'~' ? '.' : *s);
		len -= 16;
		fprintf(stderr,"|\n");
	}
}
