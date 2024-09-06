/*
 *****************************************************************************
 *
 *        Copyright 1992, by Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description:
 *
 * 	Annex Reverse Telnet Daemon -- modified version of telnetd that
 *	provides host pseudo terminal and Annex serial port association.
 *
 * 	Originally based upon @(#)telnetd.c 4.26 (Berkeley) 83/08/06,
 *	by Paul Mattes.
 *
 *	Rewritten from version 3.15 by James Carlson
 *
 * Original Author: James Carlson		Created on: 30JUL92
 *
 * Module Reviewers:
 *	lint, loverso, carlson
 *
 *****************************************************************************
 */


/*
 * Turn this switch on to enable TELNET SENDLOC queries.  (Not currently
 * implemented in the Annex telnetd.)
 */
/* #define GET_LOCATION */

/* Maximum suboption size */
#define SUBSIZE	256

/* Milliseconds between network activity tests for -k option */
#define KEEPALIVE_CHECK 20*1000

#include "../inc/config.h"
#include "../inc/vers.h"

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>

#ifndef NO_DEBUG
#define TELCMDS	1
#define TELOPTS	1
#endif
#include "rtelnet.h"

#ifndef Dim
#define Dim(x)	(sizeof(x)/sizeof(*x))
#endif

#define SENT	0
#define RCVD	1

/*
 * I/O data buffers, pointers, and counters.
 *
 * The input buffer contains data only when the other side's output
 * buffer is completely full.  Therefore, it is only a one-way (not a
 * circular) buffer.
 */

struct buffer_set {
	char *front,*back;		/* for output buffer */
	char *next; int cc;		/* for input buffer */
	int filenum,error,flags;
	int backoff;
	int (*read)(),(*write)();
	void (*close)();
#ifndef NO_DEBUG
	int output_sent,output_discard,output_canceled;
	int input_received,input_canceled;
	char *name;
#endif
	char obuffer[BUFSIZ];
	char ibuffer[BUFSIZ];
};

/* These are bit flags in buffer_set.flags */
#define BFLAG_CLOSED	0x01	/* file descriptor closed */
#define BFLAG_SUSPEND	0x02	/* output suspended */
#define BFLAG_DISCARD	0x04	/* discarding output */
#define BFLAG_UNSELECT	0x08	/* don't select for output */
#define BFLAG_NODATA	0x10	/* no data yet received */

static struct buffer_set ptybuf,netbuf;

/* Add another byte to the output queue */
#define add_to_front(b,v) {			\
	*(b)->front++ = (v);			\
	if ((b)->front >= (b)->obuffer+BUFSIZ)	\
		(b)->front = (b)->obuffer;	\
	}

/* Get corrected count of bytes in the output queue */
#define queue_count(b)					\
	((b)->front >= (b)->back			\
		? (b)->front - (b)->back		\
		: BUFSIZ - ((b)->back - (b)->front))

#define clear_obuffer(b)	(b)->front = (b)->back = (b)->obuffer
#define clear_ibuffer(b)	(b)->next = (b)->ibuffer, (b)->cc = 0

#define add_to_network(v)	add_to_front(&netbuf,v)
#define add_to_pty(v)		add_to_front(&ptybuf,v)
#define net_output_queue()	queue_count(&netbuf)
#define pty_output_queue()	queue_count(&ptybuf)

#ifndef NO_DEBUG
int so_debug = 0, debug = 0, force_fork = 0;
static int protocol_sent=0,protocol_received=0;
#define ProtoReceive(x)	protocol_received += x
#define ProtoSent(x)	protocol_sent += x
static char text_buffer[1024];
#else
#define ProtoReceive(x)
#define ProtoSent(x)
#endif

int
	alternate_ptys = 0,	/* -a */
	binary = 0,		/* -b */
	cbreakmode = 0,		/* -c */
	onthefly = 0,		/* -f */
	hangup = 0,		/* -h */
	noioctls = 0,		/* -i */
	keepalive = 0,		/* -k */
	drop = 0,		/* -m */
	never_open = 0,		/* -n */
	hold_open = 0,		/* -o */
	show_pid = 0,		/* -p */
	removetarget = 0,	/* -r */
	symbolic = 0,		/* -s */
	transparent = 0,	/* -t */
	noinsertion = 0,	/* -C */
	nooob = 0,		/* -O */
	tcp_port_specified = 0,	/* -P */
	renametarget = 0,	/* -R */
	truncatelines = 0;	/* -T */

int port_num = 0;		/* Annex serial port number */
int tcp_port = 0;		/* Annex TCP port */

char
 	*myname,		/* Contents of argv[0] */
	*ptylink;		/* Pointer to user's device name */

/* Forward declarations */

int
	do_timing_mark();

static int
	telnet(),
	telrcv(),
	willoption(),
	wontoption(),
	dooption(),
	dontoption(),
	change_mode(),
	interrupt(),
	flush_buffer(),
	buffer_read(),
	telnet_ship_option(),
	telnet_ship_iac(),
	telnet_ship_crnull();

static void
	telsnd(),
	close_buffer();

#ifndef NO_DEBUG
static void
	datadump(),
	printoption();
#endif

/* Public declarations */
void
	cleanup();

/* External declarations */
extern void
	use_log_file(),
	start_using_log(),
#ifndef NO_DEBUG
	initialize_debugging(),
#endif
	i_perror(),
	startup_cleaning(),
	become_daemon(),
	set_socket_linger(),
	machdep_cleanup(),
	resolve_annex(),
	reset_serial_line(),
	network_close(),
	pty_close(),
	first_pty_data(),
	unlink_pty(),
	set_file_mode(),
	set_user_name();

extern int
	flag_check(),
	set_io_block(),
	get_pty_output_space(),
	fix_cooked_mode_bug(),
	make_connection(),
	force_send(),
	network_read(),
	network_write(),
	pty_read(),
	pty_write();

extern int errno;
extern char *malloc();



/*
 * Display revision information for rtelnet.c, machdep.c and debugging.c
 * modules.  Also display compilation date, if compiled with an ANSI-
 * compliant compiler.
 */

static void
show_version(fp)
FILE *fp;
{
  fprintf(fp,"rtelnet host tool version %s, released %s\n",
	  VERSION,RELDATE);
#ifdef __DATE__
  (void)fprintf(fp,"Compiled on %s at %s.\n",__DATE__,__TIME__);
#endif
  exit(0);
}

/*
 * Check for user's specified device name and remove it if necessary.
 */

static void
check_existing_node(name)
char *name;
{
	struct stat sbuf;

	if (stat(name, &sbuf) >= 0) {
		if (removetarget)
			switch (sbuf.st_mode&S_IFMT) {
			case S_IFCHR:
#ifdef S_IFLNK
			case S_IFLNK:
#endif
#ifdef S_IFSOCK
			case S_IFSOCK:
#endif
				if (unlink(name)) {
					perror(name);
					exit(1);
				}
				break;
			default:
				(void)fprintf(stderr,
		"%s: File \"%s\" is not the right type.\n",myname,name);
				exit(1);
			}
		else {
			(void)fprintf(stderr,
		"%s: File \"%s\" already exists.\n",myname,name);
			exit(1);
		}
	}
}

/*
 * Display usage information.
 */

static void
usage()
{
	(void)fprintf(stderr,
"Usage:\n\
\t%s [-%s] [-lfile] [-uuser] [-Mmode]\n\
\t\t<annex_id> <annex_port> /dev/<new_dev_name>\n",
		myname,
#ifdef NO_DEBUG
		"abcfhkmnoprstvCOPRTV"
#else
		"abcdfhkmnoprstvCDFOPRTV"
#endif
	);
	(void)fprintf(stderr,"\n\
Where:\n\
\t-a\tUse alternate pty banks -- switch between BSD and SysV ptys.\n\
\t-b\tUse telnet binary mode -- useful for terminal connections.\n\
\t-c\tDefault to CBREAK mode on the pty -- avoid cooked line breaks.\n"
	);
#ifndef NO_DEBUG
	(void)fprintf(stderr,"\t-d\tTurn on socket-level debugging.\n");
#endif
	(void)fprintf(stderr,
"\t-f\tOpen network connection when slave pty is opened.\n\
\t-h\tUse 'na reset' to hang up port when slave pty is closed.\n\
\t-i\tDo not send ioctl set-ups to ptys.\n\
\t-k\tPeriodically retry network connection.  ('keepalive')\n\
\t-lfile\tAppend log output to given file name.\n\
\t-m\tClose network connection when pty is closed.\n\
\t-n\tNever open slave side of pty.\n\
\t-o\tHold slave side of pty open at all times.\n\
\t-p\tGive process ID of child on standard output.\n\
\t-r\tOverwrite <new_dev_name> if it exists, rather than aborting.\n\
\t-s\tUse a symbolic link instead of a hard link for the slave.\n\
\t-t\tUse a transparent TCP connection, rather than telnet protocol.\n\
\t-uuser\tChange UID to <user> before creating pty.\n\
\t-C\tDon't try to fix cooked-mode pty problems with LF insertion.\n"
	);
#ifndef NO_DEBUG
	(void)fprintf(stderr,
"\t-D\tEnable debugging mode (more D's for higher levels).\n\
\t-F\tForce rtelnet to fork into background, even in debug mode.\n");
#endif
	(void)fprintf(stderr,"\
\t-Mmode\tSet default pty file mode to <mode>, given in octal.\n\
\t-O\tDisable out-of-band telnet data (for pre-R7.0 Annexes).\n\
\t-P\tInterpret the port number as a TCP port (1-65535 or name).\n\
\t-R\tRename slave pty to given name rather than linking.\n\
\t-T\tTruncate (rather than break) lines that would choke pty.\n\
\t-v\tDisplay version information on standard output and exit (-V).\n");
	exit(1);
}

/*
 * Main entry point -- parse command line arguments and start the show.
 */

int
main(argc, argv)
int argc;
char **argv;
{
	int backoff=1,daemonseed=1;
	char *cp,**oargv;
	int found;

	oargv = argv;
	myname = *argv++;
	argc--;

/* If no arguments specified, then show usage information */
	if (argc <= 0)
		usage();

/* While we are looking at a switch (flag) argument ... */
  	while (argc > 0 && **argv == '-') {
		cp = *argv++ + 1;
		argc--;
	/* Must have something after the '-' character */
		if (*cp == '\0') {
			(void)fprintf(stderr,
				"%s:  Illegal flag -- \"-\".\n",myname);
			exit(1);
		}
	/* Handle all of the switches here */
		while (found = (int)*cp++)
			switch ((char)found) {
			case 'a':	/* use alternate ptys */
				alternate_ptys++;
				break;
			case 'b':	/* try binary mode */
				binary++;
				break;
			case 'c':	/* use CBREAK mode */
				cbreakmode++;
				break;
#ifndef NO_DEBUG
			case 'd':	/* turn socket debugging */
				so_debug++;
				break;
#endif
			case 'f':	/* open connection on the fly */
				onthefly++;
				break;
			case 'h':	/* reset annex port */
				hangup++;
				break;
			case 'i':	/* Do not send ioctl controls */
				noioctls++;
				break;
			case 'k':	/* retry network connection */
				keepalive++;
				break;
			case 'l':	/* Log messages to file */
				if (*cp == '\0') {
					cp = *argv++;
					argc--;
					if (argc <= 0 || cp == NULL) {
						(void)fprintf(stderr,
					"%s:  Missing log file name.\n",
							myname);
						exit(1);
					}
				}
				use_log_file(cp);
				cp += strlen(cp);
				break;
			case 'm':	/* drop socket on pty close */
				drop++;
				break;
			case 'n':	/* Never open slave pty (SV) */
				never_open++;
				break;
			case 'o':	/* Hold open slave pty */
				hold_open++;
				break;
			case 'p':	/* Print child PID on stdout */
				show_pid++;
				break;
			case 'r':	/* remove file if it exists */
				removetarget++;
				break;
			case 's':	/* Use symbolic link */
				symbolic++;
				break;
			case 't':	/* use transparent connection */
				transparent++;
				break;
			case 'u':	/* set user-id */
				if (*cp == '\0') {
					cp = *argv++;
					argc--;
					if (argc <= 0 || cp == NULL) {
						(void)fprintf(stderr,
					"%s:  Missing user name.\n",
							myname);
						exit(1);
					}
				}
				set_user_name(cp);
				cp += strlen(cp);
				break;
			case 'C':
				noinsertion++;
				break;
#ifndef NO_DEBUG
			case 'D':	/* verbose debug output */
				debug++;
				break;
			case 'F':	/* Always fork child process */
				force_fork++;
				break;
#endif
			case 'O':	/* Don't use out-of-band data */
				nooob++;
				break;
			case 'M':	/* Set file mode */
				if (*cp == '\0') {
					cp = *argv++;
					argc--;
					if (argc <= 0 || cp == NULL) {
						(void)fprintf(stderr,
					"%s:  Missing default file mode.\n",
							myname);
						exit(1);
					}
				}
				set_file_mode(cp);
				cp += strlen(cp);
				break;
			case 'P':	/* Use TCP port number */
				tcp_port++;
				tcp_port_specified++;
				break;
			case 'R':	/* Rename slave to target, not link */
				renametarget++;
				break;
			case 'T':	/* truncate rather than break */
				truncatelines++;
				break;
			case 'v':
			case 'V':	/* Display software version */
				show_version(stdout);
				exit(0);
			default:
				(void)fprintf(stderr,
					"%s:  unknown flag '%c'.\n",
					myname,*cp);
				exit(1);
			}	/* switch */
	}

/* Test compatibility of flags specified by the user */
	if (hold_open && (drop || onthefly || hangup || never_open)) {
		(void)fprintf(stderr,
		     "%s:  -o flag is incompatible with -fhmn flags.\n",
			myname);
		exit(1);
	}
	if (tcp_port && hangup) {
		(void)fprintf(stderr,
			"%s:  -P flag is incompatible with -h flag.\n",
			myname);
		exit(1);
	}
	if (transparent && (binary || nooob)) {
		(void)fprintf(stderr,
		       "%s:  -bO flags are superfluous with -t flag.\n",
			myname);
		exit(1);
	}
	if (symbolic && renametarget) {
		(void)fprintf(stderr,
			"%s:  -s flag is incompatible with -R flag.\n",
			myname);
		exit(1);
	}
	if (flag_check())	/* allow machdep to do some checking */
		exit(1);

/* Need Annex name, port number and device name here -- three args */
	if (argc != 3) {
		(void)fprintf(stderr,
"%s:  invalid argument count -- invoke without arguments for help.\n",
			myname);
		exit(1);
	}

/* Attempt to find Annex in network databases */
	resolve_annex(*argv++);

/* Decode requested port number */
	if ((tcp_port = name_to_unit(*argv++)) <= 0)
		exit(1);
	if (tcp_port > PORT_MAP_BASE &&
	    tcp_port <= PORT_MAP_BASE+MAX_PORT)
		port_num = tcp_port - PORT_MAP_BASE;
	else
		port_num = 0;	/* not a serial port */
/* Transparent mode uses alternate TCP port range */
	if (transparent && !tcp_port_specified)
		tcp_port += RAW_MAP_BASE - PORT_MAP_BASE;

	ptylink = argv[0];	/* Save user's name for device */
	check_existing_node(ptylink);	/* Make sure we can use it */

/* Clean up after any abended rtelnet sessions */
	startup_cleaning();

/* Redirect all output to specified log file -- DBG macro now in use */
	start_using_log();

#ifndef NO_DEBUG
/* Do any debug-log initialization needed -- mostly for using syslog */
	initialize_debugging();
	if (debug) {
	/* Recreate and print a copy of the user's command line */
		(void)strcpy(text_buffer,"Command line:  \"");
		(void)strcat(text_buffer,*oargv++);
		for (;*oargv;oargv++) {
			(void)strcat(text_buffer," ");
			(void)strcat(text_buffer,*oargv);
		}
		DBG((1,D_INIT,"%s\"",text_buffer));
	}
#endif

	if (tcp_port)
		DBG((1,D_INFO,"requested TCP port %d",tcp_port));
	else
		DBG((1,D_INFO,"requested serial port %d on TCP port %d",port_num,tcp_port));

	bzero((caddr_t)&ptybuf,sizeof(ptybuf));
	bzero((caddr_t)&netbuf,sizeof(netbuf));
	ptybuf.error = EIO;	/* force it to open up */
	ptybuf.read = pty_read;
	ptybuf.write = pty_write;
	ptybuf.close = pty_close;
	netbuf.read = network_read;
	netbuf.write = network_write;
	netbuf.close = network_close;
#ifndef NO_DEBUG
	ptybuf.name = "pty";
	netbuf.name = "network";
#endif

/*
 * Main loop -- wait for pty open (if necessary) then start telnet
 * session.
 */
	for (;;) {
		if (ptybuf.error != 0) {
			ptybuf.filenum = openmaster(ptylink);
			if (ptybuf.filenum < 0) {
		     DBG((0,D_ERR,"Unable to allocate a master pty."));
				cleanup();
				/*NOTREACHED*/
			}
			ptybuf.error = 0;
			ptybuf.flags = BFLAG_NODATA;
			ptybuf.backoff = 1;
		}

	/* If we haven't forked out yet, do it now */
		if (daemonseed) {
			daemonseed = 0;
			become_daemon();
		}

		DBG((1,D_INFO,"Top of loop, backoff = %d.",backoff));

		if (onthefly && backoff==1) {
	/* Wait for user to open slave pty */
			DBG((1,D_INFO,"Waiting for slave pty open."));
			found=wait_for_io(FROM_PTY,ptybuf.filenum,-1,0);
			DBG((3,D_INFO,"onthefly: io flag %02X",found));
		}
		if (telnet()) {
			sleep((unsigned)backoff);
			backoff = backoff > 16 ? 16 : backoff << 1;
		} else
			backoff = 1;
	}
	/*NOTREACHED*/
}

#define enough_room(needed)	(net_output_queue()+needed < BUFSIZ)
#define enough_pty_room(needed)	(pty_output_queue()+needed < BUFSIZ)

/*
 * Main loop.  Select from pty and network, and hand data to telnet
 * encoding and decoding finite state machines.
 *
 * Returns -1 if network connection fails, 0 if done.
 */

static int
telnet()
{
	int keepleft;

	if ((netbuf.filenum = make_connection()) < 0)
		return -1;

	clear_obuffer(&ptybuf);
	clear_ibuffer(&ptybuf);

/*
 * This loop point is used by the keepalive code -- if a new network
 * connection is created, then act as if nothing happened.
 */

network_restart:
	netbuf.error = netbuf.flags = 0;
	netbuf.backoff = 1000;
	keepleft = KEEPALIVE_CHECK;

	clear_obuffer(&netbuf);
	clear_ibuffer(&netbuf);

/* Initialize the TELNET protocol decoder and encoder */
	(void)telrcv(1);
	telsnd(1);

	/*
	 * Negotiate binary mode, if requested
	 */
	if (!transparent) {
		if (binary) {
			(void)telnet_ship_option(WILL,TELOPT_BINARY);
			(void)telnet_ship_option(DO,TELOPT_BINARY);
		}
		(void)telnet_ship_option(DO,TELOPT_LFLOW);
#ifdef GET_LOCATION
		(void)telnet_ship_option(DO,TELOPT_SNDLOC);
#endif
	}

/*
 * Main TELNET loop -- stay here as long as the network connection
 * holds -- we come back here when the master pty is reopened, or if it
 * never closed.
 */

restart:
DBG((3,D_INFO,"fds - net %d, pty %d.",netbuf.filenum,ptybuf.filenum));

/*
 * TELNET I/O loop -- copy data back and forth between pty and net until
 * something stops us.
 */
	for (;;) {
		register int c;
		int lookfor,writeok,timet;

		lookfor = writeok = timet = 0;

/* Set up selection flags for pty -> network direction.  (Encoder) */
		if (ptybuf.cc == 0) {
			lookfor = FROM_PTY;
	DBG((4,D_INFO,"No data in pty input queue -- selecting it."));
		}
		if (!(netbuf.flags & BFLAG_SUSPEND)) {
			if (netbuf.flags&BFLAG_UNSELECT) {
				timet = netbuf.backoff;
				writeok = TO_NET;
				DBG((4,D_INFO,"Unselected network output."));
			} else if (netbuf.front != netbuf.back) {
				lookfor |= TO_NET;
				DBG((4,D_INFO,"Selected data for net output."));
			} else {
				writeok = TO_NET;
				DBG((4,D_INFO,"No data for network output."));
			}
		} else
			DBG((4,D_INFO,"Network output suspended."));

/* Set up selection flags for network -> pty direction.  (Decoder) */
		if (netbuf.cc == 0) {
			lookfor |= FROM_NET;
			DBG((4,D_INFO,"No data in net input queue -- selecting it."));
		}
		if (!(ptybuf.flags & BFLAG_SUSPEND)) {
			if (ptybuf.flags&BFLAG_UNSELECT) {
				timet += ptybuf.backoff;
				writeok |= TO_PTY;
				DBG((4,D_INFO,"Unselected pty output."));
			} else if (ptybuf.front != ptybuf.back) {
				lookfor |= TO_PTY;
				DBG((4,D_INFO,"Selected data for pty output."));
			} else {
				writeok |= TO_PTY;
				DBG((4,D_INFO,"No data for pty output."));
			}
		} else
			DBG((4,D_INFO,"Pty output suspended."));

/*
 * If we're waiting on input from the net, then make sure the keep-alive
 * timer is set to the right value.
 */
		if (keepalive && (lookfor&FROM_NET) && timet < keepleft)
			timet = keepleft;
		c = wait_for_io(lookfor,ptybuf.filenum,netbuf.filenum,
			timet);
/* If we timed out waiting on network data, then count down */
		if ((c & WFIO_TIMEOUT) && (lookfor & FROM_NET))
			keepleft -= timet;
		lookfor = c | writeok;

	/* Something to read from the network, and we've got room. */
		if ((lookfor & FROM_NET) && netbuf.cc == 0) {
			c = buffer_read(&netbuf);
			if (c >= 2) {
DBG((3,D_ERR,"Leaving loop on network read error %d.",netbuf.error));
				break;
			}
/* If we successfully read something from the network, then we're ok */
			if (c == 0)
				keepleft = KEEPALIVE_CHECK;
		}

	/* Something to read from the pty, and we've got room */
		if ((lookfor & FROM_PTY) && ptybuf.cc == 0) {
			if (!transparent || !change_mode(1,MODEF_RAW))
				if ((c = buffer_read(&ptybuf)) > 1) {
DBG((3,D_ERR,"Leaving loop on pty read error %d.",ptybuf.error));
					break;
				}
		}

		do {

/* Copy from input to output buffers and handle protocols. */
			if (ptybuf.cc > 0)
				telsnd(0);		/* Encoder */
			if (netbuf.cc > 0)
				(void)telrcv(0);	/* Decoder */

/* Attempt to flush output buffers if at all possible */
			if ((lookfor & TO_NET) &&
			    (c = flush_buffer(&netbuf))) {
				lookfor &= ~TO_NET;
				if (c > 1)
					lookfor |= ERR_NET;
			}
			if ((lookfor & TO_PTY) &&
			    (c = flush_buffer(&ptybuf))) {
				lookfor &= ~TO_PTY;
				if (c > 1)
					lookfor |= ERR_PTY;
			}

/* Repeat while translation still possible */
		} while (ptybuf.cc > 0 && (lookfor & TO_NET) ||
			 netbuf.cc > 0 && (lookfor & TO_PTY));

/* Check for errors */
		if (lookfor & ERR_PTY) {
			ptybuf.cc = 0;
			if (ptybuf.error == 0)
				ptybuf.error = EIO;
			DBG((3,D_ERR,"Leaving loop on pty select error"));
			break;
		}
		if (lookfor & ERR_NET) {
			netbuf.cc = 0;
			if (netbuf.error == 0)
				netbuf.error = EIO;
			DBG((3,D_ERR,"Leaving loop on network select error"));
			break;
		}

/*
 * If the keepalive timer is out of time, then check the network
 * connection by reattempting to connect.  If it succeeds, then the
 * Annex must have been rebooted, and we lost our old connection.  We
 * keep this new connection and set the session back up.  If it fails,
 * then we assume (!) that the old connection to the Annex still holds,
 * so we reset the timer and continue.
 */
		if (keepleft <= 0) {
			if ((c = make_connection()) < 0) {
				keepleft = KEEPALIVE_CHECK;
				continue;
			}
			(*netbuf.close)(netbuf.filenum);
			netbuf.filenum = c;
			goto network_restart;
		}
	}

	 DBG((1,D_INFO,"Out of main loop -- remaining data:"));
	 DBG((1,D_INFO,"\tpty:  %d chars, errno %d",ptybuf.cc,ptybuf.error));
	 DBG((1,D_INFO,"\tnet:  %d chars, errno %d",netbuf.cc,netbuf.error));

/* One last try -- try to push the data through */
	if (ptybuf.error == 0)
		(void)flush_buffer(&ptybuf);
	if (netbuf.error == 0)
		(void)flush_buffer(&netbuf);

/*
 * I/O error from pty or it looks like somebody closed the slave device.
 * Simply start over.
 */
	if ((ptybuf.filenum = reopen_pty(ptybuf.filenum)) < 0) {
#if 0
/* ... this is a mistaken piece of code -- it thinks that a missing -r */
/* option means that we can't remove the link that we put there ourselves. */
/* Of course, this isn't so! */
		/* Make sure we can reuse pty */
		if (!removetarget) {
	 DBG((0,D_ERR,"Cannot reopen master and cannot reassign pty."));
			cleanup();
		}
#endif
		for (;;) {
			ptybuf.filenum = openmaster(ptylink);
			if (ptybuf.filenum >= 0)
				break;
	       DBG((1,D_WARN,"Cannot open pty -- pausing 10 seconds."));
			(void)sleep(10);
		}
	}
	ptybuf.error = 0;
	ptybuf.flags = BFLAG_NODATA;
	ptybuf.backoff = 1;

/* If no network errors, then do end-of-connection handling */
	if (netbuf.error == 0 && !(netbuf.flags & BFLAG_CLOSED)) {
		if (!drop)
			goto restart;
		if (do_timing_mark())
			netbuf.error = errno;
	}

/* Network error occurred, or drop requested -- take connection down */
	DBG((1,D_INFO,"Shutting down telnet."));
	close_buffer(&netbuf);
	if (hangup)
		reset_serial_line();
	return 0;
}

#ifndef NO_DEBUG

/*
 * Show some statistics from the internal buffer structure.
 */

static void
show_inout(level,buf)
int level;
struct buffer_set *buf;
{
DBG((level,D_INFO,"%s statistics:",buf->name));
DBG((level,D_INFO,"\tOutput sent %d, input received %d.",buf->output_sent,buf->input_received));
DBG((level,D_INFO,"\tOutput discard %d, output canceled %d, input canceled %d.",buf->output_discard,buf->output_canceled,buf->input_canceled));
DBG((level,D_INFO,"\tInternal rtelnet data:"));
DBG((level,D_INFO,"\t\tinput buffer %d, output buffer %d.",buf->cc,queue_count(buf)));
DBG((level,D_INFO,"\t\tlast error %d, flags %02X, backoff %d.",buf->error,buf->flags,buf->backoff));
}

/*
 * Show global rtelnet statistics.
 */

void
show_rtelnet_statistics(level)
int level;
{
	if (debug >= level) {
		show_inout(level,&ptybuf);
		show_inout(level,&netbuf);
DBG((level,D_INFO,"Telnet protocol statistics:"));
DBG((level,D_INFO,"\t%d bytes sent, %d bytes received.",protocol_sent,protocol_received));
	}
}
#endif

/*
 * Clean-up routine -- take down any connections and clean up any
 * modified system structures, then exit.
 */
void
cleanup()
{
	DBG((1,D_INIT,"cleanup entry"));

	machdep_cleanup();

	if (netbuf.filenum >= 0)
		close_buffer(&netbuf);

#ifndef NO_DEBUG
	show_rtelnet_statistics(2);
#endif

	DBG((1,D_INIT,"Exiting"));
	exit(0);
}


/*
 * Telnet protocol finite state machines.
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

static char hisopts[256],myopts[256];
static int flow_mode;		/* Current state of LFLOW */

/*
 * TELNET protocol encoder -- reads from pty and writes to net.
 */
static void
telsnd(cmnd)
int cmnd;
{
	int c;

	if (cmnd == 1) {
		flow_mode = 1;		/* Defaults to local flow */
		return;
	}

	if (ptybuf.cc <= 0)
		return;

/*
 * This is used by SysV machines to close the slave port when necessary.
 */
	if (ptybuf.flags & BFLAG_NODATA) {
		ptybuf.flags &= ~BFLAG_NODATA;
		first_pty_data();
	}

	/* Handle outbound (encoding) telnet protocol */
	for (;ptybuf.cc > 0;ptybuf.next++,ptybuf.cc--) {
		c = *ptybuf.next & 0xFF;
		if (!transparent) {
			if (c == IAC) {
				if (!telnet_ship_iac())
					break;
				continue;
			} else if (c == '\r' &&
				!myopts[TELOPT_BINARY]) {
				if (!telnet_ship_crnull())
					break;
				continue;
			}
		}
		if (!enough_room(1))
			break;
		add_to_network(c);
	}
}

/*ARGSUSED*/
static void
process_sub_option(text)
char *text;
{
#ifdef GET_LOCATION
	if (*text == TELOPT_SNDLOC)
		DBG((1,D_INFO,"Terminal location:  \"%s\".",text+1));
#endif
}

/*
 * TELNET protocol decoder -- reads from net and writes to pty.
 *
 * Parameter cmnd tells what to do -
 *	0 - run state machine through as much of network input buffer as
 *	    possible.
 *	1 - initialize internal state.
 *	2 - run state machine, halt on timing mark.
 *
 * Return value is 0 for normal commands, 1 if timing mark received.
 */

static int
telrcv(cmnd)
int cmnd;
{
	register int c;
	static int state,skipshow,columncount,truncating;
	static char savesubopt[SUBSIZE],*sp;

    DBG((4,D_INFO,"telrcv:Number of chars in netbuf %d\n",netbuf.cc));
    DBG((4,D_INFO,"telrcv:Current State %d",state));

	if (cmnd == 1) {
		bzero((caddr_t)myopts,sizeof(myopts));
		bzero((caddr_t)hisopts,sizeof(hisopts));
		state = TS_DATA;
		truncating = columncount = skipshow = 0;
		return 0;
	}

	for (;netbuf.cc > 0; netbuf.cc--, netbuf.next++,skipshow = 0) {
		c = *netbuf.next & 0xFF;

        DBG((4,D_INFO,"telrcv:c %d\n",c));

		if (transparent) {
			if (!enough_pty_room(1))
				return 0;
			add_to_pty(c);
			continue;
		}
#ifndef NO_DEBUG
		if (state != TS_DATA)
			protocol_received++;
#endif

		switch (state) {

		case TS_DATA:
			if (c == IAC) {
				ProtoReceive(1);
				state = TS_IAC;
				break;
			}
add_pty_character:
			if (c == '\n')
				truncating = 0;
			else if (!noinsertion &&
				fix_cooked_mode_bug(columncount,
				ptybuf.filenum)) {
				if (truncatelines) {
					truncating = 1;
				} else {
					if (!enough_pty_room(1))
						return 0;
					add_to_pty('\n');
					columncount = 0;
				}
			}
			if (!truncating) {
				if (!enough_pty_room(1))
					return 0;
				add_to_pty(c);
			}
			if (c == '\n')
				columncount = 0;
			else
				columncount++;
			if (!hisopts[TELOPT_BINARY] && c == '\r')
				state = TS_CR;
			else	/* For entry from other states */
				state = TS_DATA;
			break;

		case TS_CR:
			if (c != 0) {
				ProtoReceive(-1);
				if (c != '\n' &&
				    fix_cooked_mode_bug(columncount,
					ptybuf.filenum)) {
					if (!enough_pty_room(1))
						return 0;
					add_to_pty('\n');
					columncount = 1;
				}
				if (!enough_pty_room(1))
					return 0;
				add_to_pty(c);
			}
			state = TS_DATA;
			break;

		case TS_IAC:
			switch (c) {

			case BREAK:
			case IP:
/*
 * Send the process on the pty side an interrupt.  Do this with a NULL
 * or interrupt char; depending on the tty mode.
 */
				if (!interrupt())
					return 0;
				break;

			/*
			 * Are You There?
			 */
			case AYT:
				c = '\7';
				goto add_pty_character;

			/*
			 * Erase Character and
			 * Erase Line
			 */
			case EC:
			case EL:
				if (flush_buffer(&ptybuf) > 1)
					return 0;
				c = get_erase_char(ptybuf.filenum,
					c == EL);
			/* Fall through */
			case IAC:
				ProtoReceive(-1);
				goto add_pty_character;

			/*
			 * Begin option subnegotiation...
			 */
			case SB:
				sp = savesubopt;
				state = TS_BEGINNEG;
				continue;

			case WILL:
			case WONT:
			case DO:
			case DONT:
				state = TS_WILL + (c - WILL);
				continue;
			}
			state = TS_DATA;
			break;

		case TS_BEGINNEG:
			if (c == IAC)
				state = TS_ENDNEG;
			else if (sp < savesubopt+SUBSIZE-1)
				*sp++ = c;
			break;

		case TS_ENDNEG:
			if (c == SE) {
				state = TS_DATA;
				*sp = '\0';
				process_sub_option(savesubopt);
			} else if (c == IAC) {
				state = TS_BEGINNEG;
				if (sp < savesubopt+SUBSIZE-1)
					*sp++ = IAC;
			} else	/* Error -- this shouldn't happen! */
				state = TS_DATA;
			break;

		case TS_WILL:
            DBG((4,D_INFO,"The Will Parameter is %d",c));
#ifndef NO_DEBUG
			if (!skipshow)
				printoption(RCVD,WILL,c,!hisopts[c]);
#endif
			if (cmnd == 2 && c == TELOPT_TM) {
				netbuf.cc--;
				netbuf.next++;
                DBG((1,D_INFO,"telrcv:Hit the Time Marker\n"));
                state = TS_DATA;
				return 1;
			}
			if (!hisopts[c] && !willoption(c)) {
				skipshow = 1;
				return 0;
			}
			state = TS_DATA;
			continue;

		case TS_WONT:
#ifndef NO_DEBUG
			if (!skipshow)
				printoption(RCVD,WONT,c,hisopts[c]);
#endif
			if (cmnd == 2 && c == TELOPT_TM) {
				netbuf.cc--;
				netbuf.next++;
				return 1;
			}
			if (hisopts[c] && !wontoption(c)) {
				skipshow = 1;
				return 0;
			}
			state = TS_DATA;
			continue;

		case TS_DO:
#ifndef NO_DEBUG
			if (!skipshow)
				printoption(RCVD,DO,c,!myopts[c]);
#endif
			if (!myopts[c] && !dooption(c)) {
				skipshow = 1;
				return 0;
			}
			state = TS_DATA;
			continue;

		case TS_DONT:
#ifndef NO_DEBUG
			if (!skipshow)
				printoption(RCVD,DONT,c,myopts[c]);
#endif
			if (myopts[c] && !dontoption(c)) {
				skipshow = 1;
				return 0;
			}
			state = TS_DATA;
			continue;

		default:
			DBG((0,D_FATL,"telrcv state %d - aborting",state));
			exit(1);
		}
	}
	return 0;
}

/*
 **********************************************************************
 * telnet protocol generation routines
 **********************************************************************
 */

static int
telnet_ship_iac()
{
	if (!enough_room(2))
		return 0;
	add_to_network(IAC);
	add_to_network(IAC);
	ProtoSent(1);		/* One byte of overhead */
	return 1;
}

static int
telnet_ship_crnull()
{
	if (!enough_room(2))
		return 0;
	add_to_network('\r');
	add_to_network('\0');
	ProtoSent(1);		/* One byte of overhead */
	return 1;
}

int
tn_send_break()
{
	if (!enough_room(2))
		return 0;
	add_to_network(IAC);
	add_to_network(BREAK);
	ProtoSent(2);		/* Two bytes of overhead */
	DBG((2,D_INFO,"telnet protocol sent:  IAC BREAK"));
	return 1;
}

/* Send a standard TELNET request -- DO/DONT/WILL/WONT some-option */
static int
telnet_ship_option(verb,option)
int verb,option;
{
	char tbuf[3];

	if (netbuf.flags & BFLAG_SUSPEND) {
		tbuf[0] = IAC;
		tbuf[1] = verb;
		tbuf[2] = option;
		if (force_send(netbuf.filenum,tbuf,3,0) < 0)
			return 0;
	} else {
		if (!enough_room(3))
			return 0;
		add_to_network(IAC);
		add_to_network(verb);
		add_to_network(option);
		ProtoSent(3);
	}
	if (verb == WILL)
		myopts[option] = 1;
	else if (verb == WONT)
		myopts[option] = 0;
#ifndef NO_DEBUG
	printoption(SENT, verb, option, 0);
#endif
	return 1;
}

/* Send a standard suboption string -- IAC SB <data> IAC SE */
static int
telnet_ship_suboption(buffer,len,dbgnames)
char *buffer,**dbgnames;
int len;
{
	int rlen = len;

	if (netbuf.flags & BFLAG_SUSPEND) {
		char *tbuf;
		int rval;

		if ((tbuf = (char *)malloc((unsigned)len+4)) == NULL)
			return 0;
		bcopy(buffer,tbuf+2,len);
		tbuf[0] = IAC;
		tbuf[1] = SB;
		tbuf[len+2] = IAC;
		tbuf[len+3] = SE;
		rval = force_send(netbuf.filenum,tbuf,len+4,0);
		free(tbuf);
		if (rval < 0)
			return 0;
	} else {
		if (!enough_room(len+4))
			return 0;
		ProtoSent(len + 4);
		add_to_network(IAC);
		add_to_network(SB);
		for (;len > 0;len--,buffer++)
			add_to_network(*buffer);
		add_to_network(IAC);
		add_to_network(SE);
	}
#ifndef NO_DEBUG
	if (debug >= 2) {
		(void)strcpy(text_buffer,
			"telnet protocol sent:  IAC SB");
		while (rlen-- > 0) {
			(void)strcat(text_buffer," ");
			(void)strcat(text_buffer,*dbgnames++);
		}
		DBG((3,D_INFO,"%s IAC SE",text_buffer));
	}
#endif
	return 1;
}

/*
 * This routine is called from the machine-dependent code when the user
 * requests the enabling or disabling of local (Annex) flow control.
 */

int
telnet_ship_lflow(flag)
int flag;
{
	char buffer[2],*dbgnames[2];

/* If we can't send this or it's not needed, pretend it succeeded */
	if (transparent || !hisopts[TELOPT_LFLOW] || flow_mode == flag)
		return 1;
	DBG((3,D_INFO,"%ssetting flow control.",flag?"":"re"));
	buffer[0] = TELOPT_LFLOW;
	buffer[1] = flag;
	dbgnames[0] = "LFLOW";
	dbgnames[1] = flag ? "ENABLE" : "DISABLE";
	if (telnet_ship_suboption(buffer,2,dbgnames)) {
		flow_mode = flag;
		return 1;
	}
	return 0;
}

/*
 * Send an out-of-band timing mark indicator and wait for it to come
 * back.  This is used for flushing the output pipe.
 */

int
do_timing_mark()
{
	register int c;

/* Make network I/O blocking */
	(void)set_io_block(netbuf.filenum,1);
	c = flush_buffer(&netbuf);
	if (c == 2 || transparent) {
		(void)set_io_block(netbuf.filenum,0);
		return c;
	}
	if (!telnet_ship_option(DO,TELOPT_TM))
		return 1;
	DBG((1,D_INFO,"sending timing mark"));
	if (c = flush_buffer(&netbuf))
		return c;
	DBG((1,D_INFO,"sent timing mark"));
    DBG((1,D_INFO,"timemark-- netbuf character count %d\n",netbuf.cc));
	for (;;) {
		if (netbuf.cc <= 0 && (c = buffer_read(&netbuf)) != 0)
			return c;
		if (netbuf.cc > 0 && telrcv(2))
			break;
		if ((c = flush_buffer(&ptybuf)) == 0)
			return 3;
	}
	return 0;
}


/* Called when other side says "IAC WILL option" */
static int
willoption(option)
int option;
{
	int verb = DONT;

	switch (option) {
	case TELOPT_TM:
		ptybuf.flags &= ~BFLAG_DISCARD;
		DBG((3,D_INFO,"done cancelling read-ahead."));
		return 1;
	case TELOPT_BINARY:
	case TELOPT_ECHO:
	case TELOPT_LFLOW:
	case TELOPT_SGA:
#ifdef GET_LOCATION
	case TELOPT_SNDLOC:
#endif
		verb = DO;
	}

	if (!telnet_ship_option(verb,option))
		return 0;

	hisopts[option] = 1;

	switch (option) {
	case TELOPT_BINARY:
		if (change_mode(1,MODEF_RAW))
			return 0;
		break;

	case TELOPT_ECHO:
		if (change_mode(0,MODEF_ECHO))
			return 0;
		break;
	}
	return 1;
}

/* Called when other side says "IAC WONT option" */
static int
wontoption(option)
int option;
{
	if (option == TELOPT_TM) {
		ptybuf.flags &= ~BFLAG_DISCARD;
		DBG((3,D_WARN,"abend of cancel read-ahead."));
		return 1;
	}

	if (!telnet_ship_option(DONT,option))
		return 0;

	hisopts[option] = 0;

	switch (option) {

	case TELOPT_ECHO:
		if (change_mode(1,MODEF_ECHO))
			return 0;
		break;

	case TELOPT_BINARY:
		if (change_mode(0,MODEF_RAW))
			return 0;
		break;
	}
	return 1;
}

/* Called when other side says "IAC DO option" */
static int
dooption(option)
int option;
{
	int verb = WONT;

	switch (option) {
	case TELOPT_ECHO:
	case TELOPT_BINARY:
	case TELOPT_SGA:
		verb = WILL;
	}

	if (!telnet_ship_option(verb,option))
		return 0;

	switch (option) {
	case TELOPT_ECHO:
		if (change_mode(1,MODEF_ECHO))
			return 0;
		break;

	case TELOPT_BINARY:
		if (change_mode(1,MODEF_RAW))
			return 0;
		break;
	}
	return 1;
}

/* Called when other side says "IAC DONT option" */
static int
dontoption(option)
int option;
{
	return telnet_ship_option(WONT,option);
}

static int
change_mode(flag,option)
int flag,option;
{
	int c;

	if ((c = flush_buffer(&ptybuf)) > 1) {
		DBG((1,D_ERR,"change_mode: flush_buffer returns %d.",c));
		return c;
	}
	return mode(ptybuf.filenum,flag,option);
}

/*
 * Send interrupt to process on other side of pty.  If the pty is in raw
 * mode, just write NULL; otherwise, write interrupt char.
 */

static int
interrupt()
{
	/* half-hearted attempt */
	if (flush_buffer(&ptybuf) > 1)
		return 0;
	if (transparent)
		return 1;
	if (!enough_pty_room(1))
		return 0;
	add_to_pty(get_interrupt_char(ptybuf.filenum));
	return 1;
}

/*
 * Attempt to write pending data from output buffer to device.
 *
 * Returns:
 *	0 - all data sent
 *	1 - some data sent, rest blocked
 *	2 - error condition
 */

static int
flush_buffer(buf)
struct buffer_set *buf;
{
	int n,redo = 1;

	if (buf->flags & (BFLAG_SUSPEND|BFLAG_CLOSED)) {
		DBG((4,D_INFO,"Flags are %02X -- not writing.",buf->flags));
		return 0;
	}

	if (buf->flags & BFLAG_DISCARD) {
		DBG((4,D_INFO,"Flags are %02X -- discarding.",buf->flags));
#ifndef NO_DEBUG
		buf->output_discard += queue_count(buf);
#endif
		clear_obuffer(buf);
		return 0;
	}

	if (buf->error == 0) while (redo) {
		if (buf->front >= buf->back)
			n = buf->front - buf->back, redo = 0;
		else
			n = (buf->obuffer + BUFSIZ) - buf->back;
		DBG((4,D_INFO,"%d bytes for %s.",n,buf->name));
		if (n <= 0)
			break;
		n = (*buf->write)(buf->filenum,buf->back,n);
		switch (n) {
		case MDIO_ERROR:
			buf->error = errno;
	      DBG((1,D_ERR,"error %d flushing to %s.",errno,buf->name));
			close_buffer(buf);
			break;
		case MDIO_CLOSED:
		DBG((2,D_INFO,"%s closed while writing.",buf->name));
			buf->flags |= BFLAG_CLOSED;
			break;
		case MDIO_DEFER:
			n = 0;
			break;
		case MDIO_UNSELECT:
			buf->flags |= BFLAG_UNSELECT;
	     DBG((4,D_INFO,"%s would block -- unselecting.",buf->name));
			break;
		}
		if (n <= 0)
			break;
		buf->flags &= ~BFLAG_UNSELECT;
		buf->back += n;
#ifndef NO_DEBUG
		buf->output_sent += n;
#endif
		if (buf->back >= buf->obuffer+BUFSIZ)
			buf->back = buf->obuffer;
		DBG((2,D_INFO,"flushed %d bytes to %s.",n,buf->name));
	}

/*
 * If we're going unselected, then bump the backoff time, otherwise
 * reset it to a nominal value.
 */
	if (buf->flags & BFLAG_UNSELECT) {
		if (buf->backoff < 5000)
			buf->backoff *= 5;
	} else if (buf == &ptybuf)
		buf->backoff = 1;
	else
		buf->backoff = 1000;

/* an efficiency hack -- reduce probability of wrap-around */
	if (buf->error != 0 || buf->back == buf->front)
		clear_obuffer(buf);

	if (buf->error != 0)
		return 2;
	return buf->back == buf->front ? 0 : 1;
}

/*
 * Attempt to read pending data from device into input buffer.
 *
 * Returns:
 *	0 - data successfully read
 *	1 - no data read -- none ready
 *	2 - error condition
 */

static int
buffer_read(buf)
struct buffer_set *buf;
{
	int cc;

	buf->next = buf->ibuffer;
	cc = buf->cc = 0;
	if (buf->flags & BFLAG_CLOSED) {
	    DBG((4,D_INFO,"Flags are %02X -- not reading.",buf->flags));
		return 2;
	}
	if (buf->error == 0) {
		cc = (*buf->read)(buf->filenum,&buf->next,BUFSIZ);
		switch (cc) {
		case MDIO_ERROR:
			buf->error = errno;
	     DBG((1,D_ERR,"error %d reading from %s.",errno,buf->name));
			close_buffer(buf);
			break;
		case MDIO_CLOSED:
		DBG((2,D_INFO,"%s closed while reading.",buf->name));
			buf->flags |= BFLAG_CLOSED;
			break;
		case MDIO_DEFER:
			break;
		case MDIO_UNSELECT:
		       DBG((4,D_FATL,"%s unselect on read?",buf->name));
			exit(1);
		default:
			buf->cc = cc;
		}
	}

#ifndef NO_DEBUG
	buf->input_received += buf->cc;
	if (buf->error != 0)
DBG((1,D_ERR,"read from %s:  returns %d, errno %d.",buf->name,cc,buf->error));
	else if (cc < 0)
	DBG((2,D_INFO,"read from %s:  returns code %d.",buf->name,cc));
	else
	DBG((2,D_INFO,"read from %s:  returns %d bytes.",buf->name,cc));
#endif

	if (buf->error != 0)
		return 2;
#ifndef NO_DEBUG
	if (debug > 4)
		datadump(buf);
#endif
	return buf->cc == 0 ? 1 : 0;
}

static void
close_buffer(buf)
struct buffer_set *buf;
{
	if (buf->filenum >= 0) {
		(*buf->close)(buf->filenum);
		buf->filenum = -1;
		buf->flags |= BFLAG_CLOSED;
	}
}

/*
 * This routine is called from the machine-dependent code when the user
 * requests the suspension of output.
 */

int
telnet_halt_network(flag)
int flag;
{
	if (flag) {
		netbuf.flags |= BFLAG_SUSPEND;
		DBG((3,D_INFO,"suspending output."));
	} else {
		netbuf.flags &= ~BFLAG_SUSPEND;
		DBG((3,D_INFO,"resuming output."));
	}
	
	return 1;
}

/*
 * This routine is called from the machine-dependent code when the user
 * requests the flushing of input.
 */

int
cancel_network_input()
{
	int c;

#ifndef NO_DEBUG
	ptybuf.output_canceled += queue_count(&ptybuf);
#endif
	DBG((3,D_INFO,"cancelling read-ahead."));
	clear_obuffer(&ptybuf);
	if (transparent) {
#ifndef NO_DEBUG
		netbuf.input_canceled += netbuf.cc;
#endif
		clear_ibuffer(&netbuf);
		return 1;
	}
/* Make sure the flush gets there before setting the discard flag! */
	if (c = telnet_ship_option(DO,TELOPT_TM)) {
		(void)set_io_block(netbuf.filenum,1);
		if (flush_buffer(&netbuf))
			c = 0;
		else
			ptybuf.flags |= BFLAG_DISCARD;
		(void)set_io_block(netbuf.filenum,0);
	}
#ifndef NO_DEBUG
	netbuf.input_canceled += netbuf.cc;
#endif
	clear_ibuffer(&netbuf);
	return c;
}

/*
 * This routine is called from the machine-dependent code when the user
 * requests the flushing of output.
 */

int
cancel_network_output()
{
	char msg[2];

#ifndef NO_DEBUG
	netbuf.output_canceled += queue_count(&netbuf);
#endif
	clear_obuffer(&netbuf);

	if (!transparent && !nooob) {
		msg[0] = IAC;
		msg[1] = DM;
		(void)force_send(netbuf.filenum,msg,2,1);
	}
	DBG((3,D_INFO,"cancelling output data."));
	return 1;
}

#ifndef NO_DEBUG

/*
 * Decode TELNET protocol toggle switches -- IAC DO/DONT/WILL/WONT opt.
 *
 * Send human-readable form to debug output.
 */
static void
printoption(dir, verb, which, reply)
int dir,verb,which,reply;
{
	char *s_witch, ssb[32];
	char *s_verb, svb[32];

	if (debug < 2)
		return;

/* Decode verb and option */
	if (verb > 255 || verb < 256-Dim(telcmds)) {
		(void)sprintf(svb, "%d", verb);
		s_verb = svb;
	} else
		s_verb = telcmds[verb-(256-Dim(telcmds))];
	if (which < 0 || which >= Dim(telopts)) {
		(void)sprintf(ssb, "%d", which);
		s_witch = ssb;
	} else
		s_witch = telopts[which];

	DBG((2,D_INFO,"telnet protocol %s:  IAC %s %s %s",(dir==SENT ? "sent" : "received"),s_verb,s_witch,(dir==SENT ? "" : reply ? "(do reply)":"(don't reply)")));
}

/*
 * Dump an input data buffer from the pty or network to debug output.
 */

static void
datadump(buf)
struct buffer_set *buf;
{
	int i,len;
	char *s,*s2;

	if (debug < 5)
		return;
/* figure count to back up to line start */
	i = (buf->next - buf->ibuffer) % 16;
	s = buf->next - i;
	len = buf->cc + i;
	while (len > 0) {
		if (s <= buf->next)	/* if first line */
			(void)sprintf(text_buffer,"%03X:%-3X",
				buf->next - buf->ibuffer,buf->cc);
		else
			(void)sprintf(text_buffer,"%03X:   ",
				s - buf->ibuffer);
		for (i = 0; i < 16; i++, s++) {
			if (i % 8 == 0)
				(void)strcat(text_buffer," ");
			if (s < buf->next || i >= len)
				(void)strcat(text_buffer,"   ");
			else
				(void)sprintf(
					text_buffer+strlen(text_buffer),
					"%02X ",*s&0xFF);
		}
		s -= 16;
		(void)strcat(text_buffer," |");
		s2 = text_buffer + strlen(text_buffer);
		for (i = 0; i < 16; i++,s++,s2++)
			if (s < buf->next || i >= len)
				*s2 = ' ';
			else if (isprint(*s))
				*s2 = *s;
			else
				*s2 = '.';
		len -= 16;
		*s2++ = '|';
		*s2 = '\0';
		DBG((5,D_INFO,"%s",text_buffer));
	}
}
#endif /* NO_DEBUG */
