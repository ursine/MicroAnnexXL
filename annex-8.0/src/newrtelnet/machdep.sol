/*
 *****************************************************************************
 *
 *        Copyright 1992 by Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description:
 *
 * 	Annex reverse-telnet daemon machine-dependent code for SunOS
 *	version 5.1 (a/k/a Solaris 2.0).  Based upon @(#)telnetd.c 4.26
 *	(Berkeley) 83/08/06
 *
 * Original Author: James Carlson		Created on: 17DEC92
 *
 * Module Reviewers:
 *	lint, carlson
 *
 * Revision Control Information:
 * $Id:  $
 *
 * This file created by RCS from
 * $Source: $
 *
 * Revision History:
 * $Log: machdep.sol,v $
 * Revision 1.7  1995/07/26  11:17:05  carlson
 * Fixed a flush problem.
 *
 * Revision 1.6  1994/09/28  14:48:54  carlson
 * SPR 3573 -- only open streams administrative driver when needed.
 * SPR 3569 -- incorrect kind of flush implemented.
 *
 * Revision 1.5  1994/01/11  14:12:01  carlson
 * Added ability to detect break ioctl and send across network.
 *
 * Revision 1.4  93/07/29  11:28:46  carlson
 * Added "config.h" to work around configuration problems, moved chmod
 * to set_slave_flags to fix "cu" problems, forced close with -nf flags
 * and fixed t_snd argument usage.
 * 
 * Revision 1.3  93/02/11  08:44:23  carlson
 * Removed separate process hack, added autopush clearing on master
 * start-up and cleaned up a little.
 * 
 * Revision 1.2  93/02/04  16:59:03  carlson
 * Added support for -auM flags, added autopush set-up, fixed controlling
 * tty bug, added work-arounds for NDELAY and poll problems, and decoded
 * more "normal" error codes.
 * 
 * Revision 1.1  92/12/17  17:51:43  carlson
 * Initial revision
 * 
 * 
 * This file is currently under revision by: $Locker: $
 *
 *****************************************************************************
 */


#include "../inc/config.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/sad.h>
#include <sys/socket.h>
#include <sys/tiuser.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/mkdev.h>
#include <poll.h>
#include <netdb.h>
#include <stropts.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termio.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>

#include "rtelnet.h"
#include "../inc/erpc/netadmp.h"

char machrev[] = "$Revision: 1.7 $";
char machsrc[] = "$Source: $";

/*
 * Uncomment this macro to enable ioctl debug messages.  (These will
 * be used to implement full ioctl control of the Annex slave port
 * some day.)
 */
/* #define TEST_IOCTL */

static char slave[64];	/* saved device name */

int process_id;		/* Main rtelnet process number */

extern int
	onthefly, hangup, symbolic, tcp_port, never_open,
	hold_open, transparent, show_pid, cbreakmode, port_num,
	renametarget, binary, alternate_ptys;

#ifndef NO_DEBUG
extern int so_debug,debug,force_fork;
#endif

extern int errno,t_errno;
extern char *ptsname();

extern char *myname;

static char *new_node;		/* User's name for pty */
static int progress = 0;	/* Internal flags (for cleanup) */
static int erpc_port = 121;	/* Port for na communication */
static int using_log_file = 0;	/* Flag and file descriptor */
static int slave_pty = -1,	/* File descriptor for holding slave */
	   master_pty = -1;
static int net_was_selected = 0,pty_was_selected = 0;
static int pty_is_closed = 0;	/* Close message has arrived in master */
static int first_dummy = 0;	/* Ignore first zero-length message */
static int pipe_break = 0;	/* Set if a SIGPIPE arrives */
static int file_mode = 0666;	/* Default file mode (set by -M) */
static int user_id = -1;

static struct termio slaveconf;

static struct sockaddr_in sin = { AF_INET };	/* Annex address */

#define	LINKED_TTY	1
#define RENAMED_PTY	2

static char master[64],alias[64];

#define BANKS   "srqp"
#define UNITS   "0123456789abcdef"
#define MASTER(b,u)     (void)sprintf(master,"/dev/pty%c%c",b,u)
#define SLAVE(b,u)      (void)sprintf(slave,"/dev/tty%c%c",b,u)
#define ALIAS(b,u)      (void)sprintf(alias,"/dev/tty%c%c.rtelnet",b,u)

extern void
	cleanup(),
	show_rtelnet_statistics();

extern int
	telnet_halt_network();

void
	pty_close(),
	i_perror();

static int
	set_slave_flags();

#define BADPOLL		(POLLERR | POLLHUP | POLLNVAL)



/*
 * Examine command-line option flags and reject combinations that won't
 * work (or just don't make sense) on this system.
 */

int
flag_check()
{
	if (cbreakmode && (never_open || onthefly)) {
		(void)fprintf(stderr,
		       "%s:  -c flag is incompatible with -fn flags.\n",
			myname);
		return 1;
	}
	return 0;
}

/*
 * Open debugging log file as named by command line argument.
 */

void
use_log_file(name)
char *name;
{
	int fd;

	if (using_log_file) {
		(void)fprintf(stderr,
			"Duplicate log file name \"%s\" ignored.\n",
			name);
		return;
	}
	if ((fd = open(name,O_RDWR|O_APPEND|O_CREAT|O_NOCTTY,0666)) < 0) {
		perror(name);
		return;
	}
	using_log_file = fd;
}

/*
 * Change standard output to point to log file and prepare for
 * debugging.
 */

void
start_using_log()
{
	process_id = (int)getpid();
	if (using_log_file == 0)
		return;
	if (dup2(using_log_file,2) < 0) {
		using_log_file = 0;
		perror("dup2 log file");
		return;
	}
	(void)close(using_log_file);
	using_log_file = -1;
	if (user_id < 0)
		return;
	if (fchown(2,user_id,-1) < 0) {
		i_perror("fchown");
		exit(1);
	}
}

/*
 * Convert port number string to TCP port number.
 */

int
name_to_unit(port)
char *port;
{
	int num;
	struct servent *servp;

	if (tcp_port) {
/* User requested interpretation of port number as TCP port */
		if (isdigit(*port))
			num = atoi(port);
		else if (servp = getservbyname(port,"tcp"))
			num = ntohs((u_short)servp->s_port);
		else {
			(void)fprintf(stderr,
				"%s:  tcp/%s:  unknown service.\n",
				myname,port);
			return -1;
		}
		if (num <= 0 || num >= 65536) {
			(void)fprintf(stderr,
				"%s:  Illegal TCP port number -- %d.\n",
				myname,num);
			return -1;
		}
	} else {
/* Interpret port number as Annex serial port number */
		num = atoi(port);
		if (num <= 0 || num > MAX_PORT) {
			(void)fprintf(stderr,
		      "%s:  Illegal serial port specifier -- \"%s\".\n",
				myname,port);
			return -1;
		}
		num += PORT_MAP_BASE;
	}
	return num;
}

/*
 * Attempt to locate Annex named by given string, and initialize
 * erpc port information if necessary.
 */

void
resolve_annex(name)
char *name;
{
	register struct hostent *host;
	struct servent *servp;

	sin.sin_addr.s_addr = inet_addr(name);
	if (sin.sin_addr.s_addr != (ulong)-1)
		sin.sin_family = AF_INET;
	else {
		host = gethostbyname(name);
		if (host) {
			sin.sin_family = host->h_addrtype;
			memcpy((caddr_t)&sin.sin_addr,
				host->h_addr,
				host->h_length);
		} else {
			(void)fprintf(stderr, "%s: %s: unknown host\n",
				myname,name);
			exit(1);
		}
	}
	if (hangup) {
		servp = getservbyname("erpc", "udp");
		if (servp == 0)
			(void)fprintf(stderr,
			   "%s: udp/erpc: unknown service, using %d.\n",
				myname,erpc_port);
		else
			erpc_port = ntohs((u_short)servp->s_port);
	}
}

void
set_file_mode(fmode)
char *fmode;
{
	int i;

	i = (int)strtol(fmode,&fmode,8);
	if (*fmode == '\0')
		file_mode = i;
	else {
		(void)fprintf(stderr,"%s:  Illegal data in file mode: %s\n",
			myname,fmode);
		exit(1);
	}
}

void
set_user_name(uname)
char *uname;
{
	struct passwd *pd;

	if ((pd = getpwnam(uname)) == NULL) {
		perror(uname);
		exit(1);
	}
	if (getuid() == pd->pw_uid)
		return;
	user_id = pd->pw_uid;
}

/*
 * Clean up anything left behind from crashed rtelnets.
 */

void
startup_cleaning()
{
	struct stat stb;
	char *bank,*unit;
	int pty;

	if (!alternate_ptys)
		return;

	/*
	 * Clean up after previous incarnations of rtelnet
	 */
	for (bank = BANKS; *bank; bank++)
		for (unit = UNITS; *unit; unit++) {
			ALIAS(*bank,*unit);
			MASTER(*bank,*unit);
			if (stat(alias, &stb) < 0 ||
			    stat(master,&stb) == 0)
				continue;
			if ((pty = open(alias, O_RDWR|O_NOCTTY)) < 0)
				continue;
			else {
				(void)rename(alias, master);
				(void)close(pty);
			}
		}
}

/*
 * Internal version of perror -- send string through debugging
 * interface so that it gets formatted as expected.
 */

void
i_perror(str)
char *str;
{
#ifdef NO_DEBUG
	perror(str);
#else
	extern int sys_nerr;
	extern char *sys_errlist[];

	if (errno < 0 || errno >= sys_nerr)
		DBG((0,D_ERR,"%s: error %d",str,errno));
	else
		DBG((0,D_ERR,"%s: %s",str,sys_errlist[errno]));
#endif
}

/*
 * Internal version of t_error -- send string through debugging
 * interface so that it gets formatted as expected.
 */

int
i_t_error(str)
char *str;
{
	extern int t_nerr;
	extern char *t_errlist[];

	if (t_errno == TSYSERR) {
		int myerrno = errno;
		i_perror(str);
		return myerrno;
	}
#ifdef NO_DEBUG
	t_error(str);
#else
	if (t_errno < 0 || t_errno >= t_nerr)
		DBG((0,D_ERR,"%s: TLI error %d",str,t_errno));
	else
		DBG((0,D_ERR,"%s: %s",str,t_errlist[t_errno]));
#endif
	return EIO;
}

/*ARGSUSED*/
static void
control_c(dummy)
int dummy;
{
	DBG((1,D_INFO,"control_c interrupt"));
	cleanup();
}

/*ARGSUSED*/
static void
increase_debugging(dummy)
int dummy;
{
#ifndef NO_DEBUG
	if (debug < 5)
		debug++;
	DBG((debug,D_INFO,"Setting debug to level %d.",debug));
	show_rtelnet_statistics(debug);
#endif
}

/*ARGSUSED*/
static void
stop_debugging(dummy)
int dummy;
{
#ifndef NO_DEBUG
	DBG((0,D_INFO,"Turning off debugging."));
	debug = 0;
#endif
}

/*ARGSUSED*/
static void
bad_connection(dummy)
int dummy;
{
	pipe_break = 1;
}

/*
 * Fork off daemon task and make appropriate system calls so that
 * we appear as a normal daemon -- removing control tty, et cetera.
 */

void
become_daemon()
{
	int fd;

#ifndef NO_DEBUG
	if (!debug || force_fork)
#endif
	{
		if (fd = fork()) {
			if (fd < 0) {
				perror("fork");
				exit(1);
			}
			if (show_pid)
				(void)printf("%d\n",fd);
			exit(0);
		}
		fd = getpid();
		DBG((1,D_INIT,"Forked off child process %d",fd));
		process_id = fd;

/*
 * Don't keep the current file system busy.  If we're debugging, then
 * we should stay put so that any core files aren't dropped in the root
 * directory.
 */
#ifndef NO_DEBUG
		if (!debug)
#endif
			if (chdir("/") < 0)
				DBG((1,D_WARN,"chdir / failed -- %d",errno));
		(void)close(0);
		(void)close(1);
		if (!using_log_file)
			(void)close(2);
		(void)setsid();
	}

	(void)sigset(SIGINT,control_c);
	(void)sigset(SIGTERM,control_c);
	(void)sigset(SIGPWR,control_c);
	(void)sigset(SIGUSR1,increase_debugging);
	(void)sigset(SIGUSR2,stop_debugging);
	(void)sigset(SIGHUP,SIG_IGN);
	(void)sigset(SIGTSTP,SIG_IGN);
	(void)sigset(SIGPIPE,bad_connection);
}

/*
 * Set given file descriptor to blocking or non-blocking I/O.
 */

int
set_io_block(s,flag)
int s,flag;
{
	return fcntl(s,F_SETFL,flag ? 0 : O_NONBLOCK);
}

static int
set_tli_option(s,opt)
int s,opt;
{
	struct t_optmgmt request,reply;
	u_long reqopts[10],repopts[10];
	struct opthdr *iop;

	iop = (struct opthdr *)reqopts;
	iop->level = IPPROTO_TCP;
	iop->name = opt;
	iop->len = sizeof(u_long);
	*(u_long *)(iop+1) = 1;
	request.flags = T_NEGOTIATE;
	request.opt.len = sizeof(*iop)+sizeof(u_long);
	request.opt.buf = (char *)iop;

	reply.flags = 0;
	reply.opt.len = 0;
	reply.opt.maxlen = sizeof(repopts);
	reply.opt.buf = (char *)repopts;

	return t_optmgmt(s,&request,&reply);
}

static int
set_tli_linger(s)
int s;
{
	struct t_optmgmt request,reply;
	u_long reqopts[10],repopts[10];
	struct opthdr *iop;
	struct linger *lp;

	iop = (struct opthdr *)reqopts;
	iop->level = IPPROTO_TCP;
	iop->name = SO_LINGER;
	iop->len = sizeof(struct linger);
	lp = (struct linger *)(iop+1);
	lp->l_onoff = 1;
	lp->l_linger = 120;
	request.flags = T_NEGOTIATE;
	request.opt.len = sizeof(*iop)+sizeof(struct linger);
	request.opt.buf = (char *)iop;

	reply.flags = 0;
	reply.opt.len = 0;
	reply.opt.maxlen = sizeof(repopts);
	reply.opt.buf = (char *)repopts;

	return t_optmgmt(s,&request,&reply);
}

/*
 * Open a TLI connection to the previously determined Annex address.
 */

int
make_connection()
{
	int s,myerrno = 0;
	struct t_call tcall;

	s = t_open("/dev/tcp",O_RDWR,(struct t_info *)NULL);
	if (s < 0) {
		errno = i_t_error("t_open");
		return -1;
	}

	if (t_bind(s,(struct t_bind *)NULL,(struct t_bind *)NULL) < 0) {
		myerrno = i_t_error("t_bind");
		goto general_error;
	}

#if 0
	if (set_tli_option(s,SO_NEWPORT) < 0) {
		myerrno = i_t_error("t_optmgmt SO_NEWPORT");
		goto general_error;
	}
	if (set_tli_option(s,SO_REUSEADDR) < 0) {
		myerrno = i_t_error("t_optmgmt SO_REUSEADDR");
		goto general_error;
	}
	if (set_tli_linger(s) < 0) {
		myerrno = i_t_error("t_optmgmt SO_LINGER");
		goto general_error;
	}
	if (set_tli_option(s,SO_KEEPALIVE) < 0) {
		myerrno = i_t_error("t_optmgmt SO_KEEPALIVE");
		goto general_error;
	}
#endif
	if (set_tli_option(s,TCP_NODELAY) < 0) {
		myerrno = i_t_error("t_optmgmt TCP_NODELAY");
		goto general_error;
	}
#if 0
	if (set_tli_option(s,SO_OOBINLINE) < 0) {
		myerrno = i_t_error("t_optmgmt SO_OOBINLINE");
		goto general_error;
	}
#ifndef NO_DEBUG
	if (so_debug && set_tli_option(s,SO_DEBUG) < 0) {
		myerrno = i_t_error("t_optmgmt SO_DEBUG");
		goto general_error;
	}
#endif
#endif

	sin.sin_port = htons((u_short)tcp_port);
	tcall.addr.len = sizeof(sin);
	tcall.addr.buf = (char *)&sin;
	tcall.opt.len = tcall.udata.len = 0;
	tcall.opt.buf = tcall.udata.buf = NULL;
	tcall.sequence = 0;

	pipe_break = 0;
	if (t_connect(s,&tcall,(struct t_call *)NULL) < 0) {
		int i;

		if (pipe_break)
			myerrno = ECONNREFUSED;
		else if (t_errno == TLOOK) {
			i = t_look(s);
			if (i < 0)
				myerrno = i_t_error("t_connect/t_look");
/*
 * Connect returns asynchronous "DISCONNECT" if another connection is
 * in use.
 */
			else if (i == T_DISCONNECT)
				myerrno = ECONNREFUSED;
			else {
				DBG((0,D_ERR,"Unexpected t_look %d.",i));
				myerrno = EIO;
			}
		} else
			myerrno = i_t_error("t_connect");
		goto general_error;
	}

/* Make I/O non-blocking */
	if (set_io_block(s,0) < 0)
		i_perror("set_io_block");

/*
 * New host connection now established -- set up default slave configuration
 * data.
 */
	memset((caddr_t)&slaveconf,0,sizeof(slaveconf));
	if (transparent) {
		slaveconf.c_iflag = IMAXBEL;
		slaveconf.c_oflag = 0;
		slaveconf.c_cflag = B9600 | CS8 | CREAD;
		slaveconf.c_lflag = 0;
	} else if (cbreakmode) {
		slaveconf.c_iflag = ICRNL | IXON | IXOFF | IGNPAR | IMAXBEL;
		slaveconf.c_oflag = OPOST | ONLCR | TAB3;
		slaveconf.c_cflag = B9600 | CS8 | CREAD;
		slaveconf.c_lflag = 0;
	} else {
		slaveconf.c_iflag = ICRNL | IXON | IXOFF | IGNPAR | IMAXBEL;
		slaveconf.c_oflag = OPOST | ONLCR | TAB3;
		slaveconf.c_cflag = B9600 | CS8 | CREAD;
		slaveconf.c_lflag = ISIG | ICANON;
	}
	if (binary) {
		slaveconf.c_iflag = IGNPAR | IMAXBEL;
		slaveconf.c_oflag &= ~ONLCR & ~TAB3;
	}
	slaveconf.c_cc[VINTR] = 0x7F;
	slaveconf.c_cc[VQUIT] = 0x1C;
	slaveconf.c_cc[VERASE] = '#';
	slaveconf.c_cc[VKILL] = '@';
	slaveconf.c_cc[VEOF] = 0x04;
	if (slave_pty >= 0 &&
	    ioctl(slave_pty,(int)TCSETA,(char *)&slaveconf) < 0 &&
	    errno != ETIME)
		i_perror("TCSETA");

	return s;

general_error:
	(void)t_close(s);
	errno = myerrno;
	return -1;
}

/*
 * Wait until something interesting happens.
 * timet is in milliseconds.
 */

int
wait_for_io(from,dev_pty,dev_net,timet)
int from,dev_pty,dev_net,timet;
{
	int n_found;
	struct pollfd pollfds[2];
	unsigned long towait;
#ifndef NO_DEBUG
	char temp[64];	/* 58 bytes used */
#endif

#if 0
	/* This is a fix for a poll() bug in Solaris BSD ptys. */
	if (alternate_ptys && timet <= 0 && dev_net >= 0)
		timet = 500;
#endif

/* Zero time means wait forever */
	if (timet == 0)
		timet = -1;

	net_was_selected = pty_was_selected = 0;
	for (;;) {
		towait = 0;
		if (dev_pty >= 0) {
			if (pty_is_closed)
				return ERR_PTY;
			pollfds[towait].fd = dev_pty;
			pollfds[towait].events = 0;
			if (from & FROM_PTY) {
				pollfds[towait].events |= POLLIN |
					POLLPRI | POLLRDNORM;
				if (alternate_ptys)
					pollfds[towait].events |=
						POLLRDBAND;
			}
			if (from & TO_PTY) {
				pollfds[towait].events |= POLLOUT;
				pty_was_selected = 1;
			}
			towait++;
		} else
			pty_is_closed = 0;
		if (dev_net >= 0) {
			pollfds[towait].fd = dev_net;
			pollfds[towait].events = 0;
			if (from & FROM_NET)
				pollfds[towait].events |= POLLIN | POLLPRI;
			if (from & TO_NET) {
				pollfds[towait].events |= POLLOUT;
				net_was_selected = 1;
			}
			towait++;
		}

#ifndef NO_DEBUG
#define FDB(x,e)	pollfds[x].fd,pollfds[x].e
#define IOB(e)		FDB(0,e),FDB(1,e)
		if (towait == 1)
			DBG((3,D_INFO,"polling: %d - %X,%X (%d).",towait,FDB(0,events),timet));
		else
			DBG((3,D_INFO,"polling: %d - %X,%X %X,%X (%d).",towait,IOB(events),timet));
#endif
		n_found = poll(pollfds,towait,timet);
		if (n_found < 0) {
			if (errno == EINTR) {
				DBG((3,D_INFO,"interrupted -- trying again."));
				continue;
			}
			i_perror("poll");
			cleanup();
		} else
			break;
	}
#ifndef NO_DEBUG
	if (towait == 1)
		DBG((3,D_INFO,"polled: %d - %X,%X.",towait,FDB(0,revents)));
	else
		DBG((3,D_INFO,"polled: %d - %X,%X %X,%X.",towait,IOB(revents)));
#endif
	if (n_found == 0)
		from = WFIO_TIMEOUT;
	else
		from = 0;
#ifndef NO_DEBUG
	(void)strcpy(temp,"\t");
#define ADDS(s)	(void)strcat(temp,s)
#else
#define ADDS(s)
#endif
	if (dev_pty >= 0) {
		ADDS("(pty");
		if (pollfds[0].revents & (POLLIN | POLLPRI)) {
			from = FROM_PTY;
			ADDS(" input");
		}
		if (pollfds[0].revents & POLLOUT) {
			from |= TO_PTY;
			ADDS(" output");
		}
		if (pollfds[0].revents & BADPOLL) {
			from |= ERR_PTY;
			ADDS(" exception");
		}
		ADDS((from&ALL_PTY) ? ")" : " none)");
	}
	if (dev_net >= 0) {
		ADDS("(net");
		if (pollfds[towait-1].revents & (POLLIN | POLLPRI)) {
			from |= FROM_NET;
			ADDS(" input");
		}
		if (pollfds[towait-1].revents & POLLOUT) {
			from |= TO_NET;
			ADDS(" output");
		}
		if (pollfds[towait-1].revents & BADPOLL) {
			from |= ERR_NET;
			ADDS(" exception");
		}
		ADDS((from&ALL_NET) ? ")" : " none)");
	}
	DBG((3,D_INFO,temp));
	return from;
}

/*
 * Set flags for slave pty.
 */

static int
set_slave_flags()
{
	int retval = 0;
	struct termio b;
	char *name;

	name = renametarget?new_node:slave;
	if (chmod(name,file_mode) < 0)
		i_perror("chmod");
	if (!onthefly && slave_pty < 0 &&
	    (hold_open || cbreakmode || transparent)) {
		if (never_open) {
			DBG((1,D_WARN,"-n flag set -- cannot set modes."));
			return 0;
		}
		retval = 1;
		DBG((3,D_INFO,"Opening slave end of pseudo terminal."));
		slave_pty = open(name,O_RDONLY|O_NDELAY|O_NOCTTY);
		if (slave_pty < 0)
			i_perror(name);
		else if (ioctl(slave_pty,(int)TCSETA,(char *)&slaveconf) < 0) {
			if (errno == ETIME)
				retval = 2;
			i_perror("TCSETA");
		} else {
			DBG((3,D_INFO,"Successfully set modes on slave."));
			retval = 0;
		}
	}
	return retval;
}

void
unlink_pty()
{
	if (progress & LINKED_TTY) {
		if (renametarget)
			(void)rename(new_node,slave);
		else
			(void)unlink(new_node);
		progress &= ~LINKED_TTY;
		DBG((2,D_INFO,"Removed link between %s and pty %s.",new_node,slave));
	}
}

/*
 * Clean up before exiting -- remove user's pty node.
 */

void
machdep_cleanup()
{
	pty_close(master_pty);
	unlink_pty();
	if (progress & RENAMED_PTY) {
		(void)rename(alias, master);
		progress &= ~RENAMED_PTY;
	}
}

/*
 * Turn autopush on or off for the current slave device.
 * Flag is zero to clear autopush, non-zero to set it, negative to
 * silently clear it.
 */

static void
call_autopush(flag)
int flag;
{
	struct strapush sadpush;
	struct stat sbuf;
	int sad_fd;

	if (alternate_ptys)
		return;

	/* Grab the device number for configuration. */
	if (stat(slave,&sbuf) < 0) {
		i_perror("stat slave");
		return;
	}

	while (errno = 0, (sad_fd=open(ADMINDEV,O_RDWR)) < 0) {
		if (errno != ENXIO) {
			i_perror("sad admin");
			DBG((1,D_ERR,"Cannot open sad device."));
			return;
		}
		sleep(1);
		DBG((3,D_INFO,"Sad device was busy; trying again."));
	}

	/* Set up autopush modules, if possible. */
	bzero(&sadpush,sizeof(sadpush));
	sadpush.sap_major = major(sbuf.st_rdev);
	sadpush.sap_minor = minor(sbuf.st_rdev);
	if (flag > 0) {
		sadpush.sap_cmd = SAP_ONE;
		sadpush.sap_npush = 3;
		strcpy(sadpush.sap_list[0],"ptem");
		strcpy(sadpush.sap_list[1],"ldterm");
		strcpy(sadpush.sap_list[2],"ttcompat");
	} else
		sadpush.sap_cmd = SAP_CLEAR;

	if (ioctl(sad_fd,SAD_SAP,(char *)&sadpush) < 0 && flag >= 0)
		i_perror("ioctl SAD_SAP");
	else
		DBG((3,D_INFO,"Configured autopush sucessfully."));

	(void)close(sad_fd);
}

/*
 * Open the multiplexed master device and get a pty pair. Then, link up
 * the user's name for this device.
 */

int
openmaster(name)
char *name;
{
	int newpty,i;
	struct stat stb;
	char *bank,*unit;
	static int first_time=1;

	if (first_time) {
		if (user_id > 0 && setuid(user_id) < 0) {
			i_perror("setuid");
			exit(1);
		}
		first_time = 0;
	}

	pty_is_closed = 0;
	machdep_cleanup();
	DBG((2,D_INFO,"Attempting to find pty for \"%s\".",name));

	if (alternate_ptys) {
		for (bank = BANKS; *bank; bank++) {
			unit = UNITS;
			MASTER(*bank,*unit);
			if (stat(master, &stb) < 0) {
			DBG((1,D_WARN,"%s: missing pty bank %c.",myname,*bank));
				continue;
			}
	/*
	 * Skip unit 0 -- this master is the key for the bank, and other
	 * programs will think the entire bank is missing if we rename it.
	 */
			unit++;
			for (; *unit; unit++) {
				MASTER(*bank,*unit);
				if ((newpty = open(master, O_RDWR|O_NOCTTY))< 0)
					continue;
				SLAVE(*bank,*unit);
				if (symbolic)
					i = symlink(slave,name);
				else if (renametarget)
					i = rename(slave,name);
				else
					i = link(slave,name);
				if (i < 0) {
					i_perror(name);
					(void)close(newpty);
					continue;
				}
				goto got_the_master;
			}
		}
		return -1;
	}
	if ((newpty = open("/dev/ptmx",O_RDWR|O_NOCTTY)) < 0) {
		DBG((0,D_ERR,"No pseudo terminals left."));
		return -1;
	}
	if (grantpt(newpty) < 0)
		i_perror("grantpt");
	else if (unlockpt(newpty) < 0)
		i_perror("unlockpt");
	else if ((unit = ptsname(newpty)) == NULL)
		i_perror("ptsname");
	else if (ioctl(newpty,I_PUSH,"pckt") < 0)
		i_perror("I_PUSH pckt");
	else {
		(void)strcpy(slave,unit);
		call_autopush(-1);	/* remove any trash quietly */
		call_autopush(1);
		if (symbolic)
			i = symlink(slave,name);
		else if (renametarget)
			i = rename(slave,name);
		else
			i = link(slave,name);
		if (i < 0)
			i_perror(name);
		goto got_the_master;
	}
	(void)close(newpty);
	return -1;

got_the_master:
	master_pty = newpty;
	new_node = name;
	progress |= LINKED_TTY;

	if (set_slave_flags()) {
		(void)close(newpty);
		return -1;
	}
	if (alternate_ptys) {
		DBG((1,D_INFO,"Using master %s, slave %s.",master,slave));
		ALIAS(*bank,*unit);
		DBG((1,D_INFO,"\talias for master is %s.",alias));
	}
	DBG((1,D_INFO,"Slave %s linked to %s.",slave,name));
	first_dummy = 1;
	if (set_io_block(newpty,0))
		i_perror("pty nbio");
	return newpty;
}

/*
 * Reopening the master pty isn't necessary on System V.4 -- it stays
 * open.  All that happens is that we get a zero-length message.  We can
 * just reopen the slave, push everything back on and start over.
 */

int
reopen_pty(dev_pty)
int dev_pty;
{
	int saved_errno,try;

	if (onthefly) {
		pty_close(dev_pty);
	DBG((3,D_WARN,"Using -f switch -- forced to close master."));
		return -1;
	}
	if (alternate_ptys) {
/*
 * Berkeley style ptys.  While the master pty is closed, someone could
 * open it and effectively steal the remote device from us.
 * (Yecch) rename the master pty while it's closed.
 */
		if (rename(master, alias) < 0) {
			i_perror("rename to alias");
			unlink_pty();
			return -1;
		}
		progress |= RENAMED_PTY;
		pty_close(dev_pty);
	/* Try a few times to reopen the alias */
		try = 0;
		while ((dev_pty = open(alias,O_RDWR|O_NOCTTY)) < 0) {
			saved_errno = errno;
			if (++try > 2)
				break;
			(void)sleep(1);
		}
		master_pty = dev_pty;
		if (rename(alias, master) < 0 || dev_pty < 0) {
			if (dev_pty < 0) {
				errno = saved_errno;
				i_perror("reopen of alias");
			} else {
				i_perror("rename to normal");
				(void)close(dev_pty);
			}
			progress &= ~RENAMED_PTY;
			unlink_pty();
			return -1;
		}
		progress &= ~RENAMED_PTY;
		set_slave_flags();
		if (set_io_block(dev_pty,0))
			i_perror("pty nbio");
		return dev_pty;
	}
	pty_is_closed = 0;
	if (ioctl(dev_pty,I_NREAD,&try) < 0) {
		pty_close(dev_pty);
	DBG((3,D_WARN,"Unable to reuse master pty on multiplexed device."));
		return -1;
	}
	if (!never_open) {
		pty_close(dev_pty);
		if (!onthefly)
	DBG((3,D_WARN,"Not using -n switch -- forced to close master."));
		return -1;
	}
	DBG((3,D_INFO,"Reusing master pty fd %d in reopen_pty.",dev_pty));
	if (hold_open)
		return dev_pty;
	pty_close(-1);		/* Close the slave if it's still open */
	if (set_slave_flags()) {	/* Reopen the slave */
		pty_close(dev_pty);	/* Darn -- someone grabbed the slave */
		return -1;		/* while we were fooling around */
	}
	return dev_pty;
}

/*
 * This routine is called when the first real data packet is read from
 * the pty.  We can now close our slave pty so that we'll see the
 * application's last close as a zero length message on the master.
 */

void
first_pty_data()
{
	first_dummy = 0;
	if (!hold_open && slave_pty >= 0) {
		DBG((3,D_INFO,"Closing slave pty."));
		(void)close(slave_pty);
		slave_pty = -1;
	}
}

/*
 * If we're in canonical input mode, then we can experience trouble
 * with the pty if we give it more than 255 bytes between line feeds.
 * (I have no idea why this is!)  In any event, we have to compensate
 * for this bit of weirdness.
 */

/*ARGSUSED*/
int
fix_cooked_mode_bug(columns,pty)
int columns,pty;
{
	if (columns == 255) {
		if (slaveconf.c_lflag & ICANON)
			return 1;
	}
	return 0;
}

/*
 * Get the proper representation of an interrupt character for the
 * current pty mode.
 */

/*ARGSUSED*/
int
get_interrupt_char(s)
int s;
{
	if (!(slaveconf.c_oflag & OPOST))
		return (int)'\0';
	return (int)slaveconf.c_cc[VQUIT];
}

/*
 * If flag is zero, return character-erase, if non-zero return line-
 * erase.
 */

/*ARGSUSED*/
int
get_erase_char(s,flag)
int s,flag;
{
	return (int)slaveconf.c_cc[flag ? VKILL : VERASE];
}

/*
 * flag is 0 to clear, 1 to set, and option is 0 for raw mode, 1 for
 * echo/crmod.
 */

/*ARGSUSED*/
int
mode(s,flag,option)
int s,flag,option;
{
	struct termio b;
	int oopt,iopt,lopt;

	b = slaveconf;
	if (option == MODEF_RAW) {
		oopt = OPOST | TAB3;
		iopt = 0;
		lopt = 0;
		flag = !flag;
	} else {
		oopt = ECHO | ONLCR;
		iopt = ICRNL;
		lopt = ICANON;
	}
	if (flag) {
		if ((b.c_oflag&oopt) != oopt || (b.c_iflag&iopt) != iopt ||
		    (b.c_lflag&lopt) != lopt) {
			b.c_oflag |= oopt;
			b.c_iflag |= iopt;
			b.c_lflag |= lopt;
			if (slave_pty < 0)
				slaveconf = b;
			else if (ioctl(slave_pty,(int)TCSETA,(char *)&b) < 0) {
				i_perror("TCSETA");
				return 1;
			}
		}
	} else {
		if ((b.c_oflag&oopt) != 0 || (b.c_iflag&iopt) != 0 ||
		    (b.c_lflag&lopt) != 0) {
			b.c_oflag &= ~oopt;
			b.c_iflag &= ~iopt;
			b.c_lflag &= ~lopt;
			if (slave_pty < 0)
				slaveconf = b;
			else if (ioctl(slave_pty,(int)TCSETA,(char *)&b) < 0) {
				i_perror("TCSETA");
				return 1;
			}
		}
	}
	return 0;
}

/*
 * Call netadm (na) routine to forcibly reset the Annex's serial line.
 */

void
reset_serial_line()
{
	sin.sin_port = htons((u_short)erpc_port);
	(void)reset_line((struct sockaddr_in *)&sin,(u_short)SERIAL_DEV,
		(u_short)port_num);
}

/*
 * Convert the TLI error code into one of rtelnet's internal error codes,
 * and handle any special processing along the way.
 */

static int
convert_error(fd,module)
int fd;
char *module;
{
	int i,myerrno = errno;

	switch (t_errno) {
	case TSYSERR:
		if (errno != EWOULDBLOCK && errno != EAGAIN) {
			i_perror(module);
			break;
		}
	case TNODATA:
	case TFLOW:
		myerrno = EAGAIN;
		return MDIO_DEFER;
	case TLOOK:
		i = t_look(fd);
		if (i < 0) {
			myerrno = i_t_error("t_look");
			break;
		}
		switch (i) {
		case T_CONNECT:
			DBG((3,D_INFO,"t_look returns T_CONNECT"));
			break;
		case T_DATA:
			DBG((3,D_INFO,"t_look returns T_DATA"));
			break;
		case T_LISTEN:
			DBG((3,D_INFO,"t_look returns T_LISTEN"));
			break;
		case T_UDERR:
			DBG((3,D_INFO,"t_look returns T_UDERR"));
			break;
		case T_EXDATA:
			DBG((3,D_INFO,"t_look returns T_EXDATA"));
			break;
		case T_DISCONNECT:
			DBG((3,D_INFO,"t_look returns T_DISCONNECT"));
			errno = ECONNABORTED;
			return MDIO_ERROR;
		case T_ORDREL:
			DBG((3,D_INFO,"t_look returns T_ORDREL"));
			errno = ECONNRESET;
			return MDIO_ERROR;
		case T_ERROR:
			DBG((3,D_INFO,"t_look returns T_ERROR"));
			errno = EIO;
			return MDIO_ERROR;
		default:
			DBG((3,D_INFO,"Unknown t_look value -- %d.",i));
			break;
		}
		errno = EINTR;
		return MDIO_DEFER;
	default:
		myerrno = i_t_error(module);
	}
	errno = myerrno;
	return MDIO_ERROR;
}

/*
 * Bypass normal I/O to send a message to the Annex.
 */

int
force_send(fd,buff,len,flag)
int fd,flag,len;
char *buff;
{
	int cc;

	t_errno = errno = 0;
	cc = t_snd(fd,buff,len,flag ? T_EXPEDITED : 0);
	if (cc > 0 || t_errno == 0)
		return cc;
	return convert_error(fd,"force_send");
}

/*
 * Read from network interface.
 */

int
network_read(fd,buffp,siz)
int fd,siz;
char **buffp;
{
	int cc,flags = 0;

	t_errno = errno = 0;
	cc = t_rcv(fd,*buffp,siz,&flags);
	if (cc > 0 || t_errno == 0)
		return cc;
	return convert_error(fd,"network_read");
}

/*
 * Write to network interface.
 */

int
network_write(fd,buff,siz)
int fd,siz;
char *buff;
{
	int cc,nws = net_was_selected;

	net_was_selected = 0;
	t_errno = errno = 0;
	cc = t_snd(fd,buff,siz,0);
	if (cc > 0 || t_errno == 0)
		return cc;
	cc = convert_error(fd,"network_write");
	if (cc == MDIO_DEFER && nws)
		cc = MDIO_UNSELECT;
	return cc;
}

/*
 * Shut down network connection and close interface.
 */

void
network_close(fd)
int fd;
{
	(void)t_sndrel(fd);
	(void)sleep(1);
	(void)t_close(fd);
}

#ifdef TEST_IOCTL

static void
dump_strbuf(name,buf)
char *name;
struct strbuf *buf;
{
	int i;

	fprintf(stderr,"%s length %d:\n",name,buf->len);
	for (i = 0;i < buf->len;i++)
		fprintf(stderr,"%02X ",((unsigned char *)buf->buf)[i]);
	fprintf(stderr,"\n");
}

struct flag_table {
	char *name;
	int flag;
};

static void
show_flags(flags,tp)
int flags;
struct flag_table *tp;
{
	while (tp->name) {
		if (tp->flag & flags) {
			fprintf(stderr,"%s ",tp->name);
			flags &= ~tp->flag;
		}
		tp++;
	}
	if (flags)
		fprintf(stderr,"%06o",flags);
	fprintf(stderr,"\n");
}

static void
display_terminal_flags(iflag,oflag,cflag,lflag)
int iflag,oflag,cflag,lflag;
{
	static struct flag_table input[] = {
		{ "IMAXBEL", IMAXBEL },
		{ "IXOFF", IXOFF },
		{ "IXANY", IXANY },
		{ "IXON", IXON },
		{ "IUCLC", IUCLC },
		{ "ICRNL", ICRNL },
		{ "IGNCR", IGNCR },
		{ "INLCR", INLCR },
		{ "ISTRIP", ISTRIP },
		{ "INPCK", INPCK },
		{ "PARMRK", PARMRK },
		{ "IGNPAR", IGNPAR },
		{ "BRKINT", BRKINT },
		{ "IGNBRK", IGNBRK },
		{ NULL, 0 }
	};
	static struct flag_table output[] = {
		{ "WRAP", WRAP },
		{ "PAGEOUT", PAGEOUT },
		{ "FFDLY", FFDLY },
		{ "VTDLY", VTDLY },
		{ "BSDLY", BSDLY },
		{ "NLDLY", NLDLY },
		{ "OFDEL", OFDEL },
		{ "OFILL", OFILL },
		{ "ONLRET", ONLRET },
		{ "ONOCR", ONOCR },
		{ "OCRNL", OCRNL },
		{ "ONLCR", ONLCR },
		{ "OPOST", OPOST },
		{ NULL, 0 }
	};
	static struct flag_table control[] = {
		{ "PAREXT", PAREXT },
		{ "XCLUDE", XCLUDE },
		{ "LOBLK", LOBLK },
		{ "XMT1EN", XMT1EN },
		{ "RCV1EN", RCV1EN },
		{ "CLOCAL", CLOCAL },
		{ "HUPCL", HUPCL },
		{ "PARODD", PARODD },
		{ "PARENB", PARENB },
		{ "CREAD", CREAD },
		{ "CSTOPB", CSTOPB },
		{ NULL, 0 }
	};
	static struct flag_table line[] = {
		{ "IEXTEN", IEXTEN },
		{ "PENDIN", PENDIN },
		{ "FLUSHO", FLUSHO },
		{ "DEFECHO", DEFECHO },
		{ "ECHOKE", ECHOKE },
		{ "ECHOPRT", ECHOPRT },
		{ "ECHOCTL", ECHOCTL },
		{ "TOSTOP", TOSTOP },
		{ "NOFLSH", NOFLSH },
		{ "ECHONL", ECHONL },
		{ "ECHOK", ECHOK },
		{ "ECHOE", ECHOE },
		{ "ECHO", ECHO },
		{ "XCASE", XCASE },
		{ "ICANON", ICANON },
		{ "ISIG", ISIG },
		{ NULL, 0 }
	};
	static int baud_table[16] = {
		0, 50, 75, 110, 134, 150, 200, 300, 600, 1200,
		1800, 2400, 4800, 9600, 19200, 38400
	};

	fprintf(stderr,"Input flags:  ");
	show_flags(iflag,input);
	fprintf(stderr,"Output flags:  ");
	if ((oflag & TABDLY) != 0)
		fprintf(stderr,"TAB%d ",(oflag&TABDLY)>>11);
	if ((oflag & CRDLY) != 0)
		fprintf(stderr,"CR%d ",(oflag&CRDLY)>>9);
	oflag &= ~TABDLY & ~CRDLY;
	show_flags(oflag,output);
	fprintf(stderr,"Control flags:  CS%d ",((cflag&CSIZE)>>4)+5);
	fprintf(stderr,"B%d ",baud_table[cflag&CBAUD]);
	fprintf(stderr,"IB%d ",baud_table[(cflag&CIBAUD)>>16]);
	cflag &= ~CSIZE & ~CBAUD & ~CIBAUD;
	show_flags(cflag,control);
	fprintf(stderr,"Line flags:  ");
	show_flags(lflag,line);
}

static void
termio_dump(tp)
struct termio *tp;
{
	display_terminal_flags(tp->c_iflag,tp->c_oflag,tp->c_cflag,tp->c_lflag);
	fprintf(stderr,"Line discipline %d.\n",tp->c_line);
	fprintf(stderr,"INTR %02X, QUIT %02X, ERASE %02X, KILL %02X,\n",
		tp->c_cc[VINTR],tp->c_cc[VQUIT],tp->c_cc[VERASE],
		tp->c_cc[VKILL]);
	fprintf(stderr,"EOF %02X, EOL %02X, EOL2 %02X, SWTCH %02X,\n",
		tp->c_cc[VEOF],tp->c_cc[VEOL],tp->c_cc[VEOL2],
		tp->c_cc[VSWTCH]);
}

static void
termios_dump(tp)
struct termios *tp;
{
	display_terminal_flags(tp->c_iflag,tp->c_oflag,tp->c_cflag,tp->c_lflag);
	fprintf(stderr,"INTR %02X, QUIT %02X, ERASE %02X, KILL %02X,\n",
		tp->c_cc[VINTR],tp->c_cc[VQUIT],tp->c_cc[VERASE],
		tp->c_cc[VKILL]);
	fprintf(stderr,"EOF %02X, EOL %02X, EOL2 %02X, SWTCH %02X,\n",
		tp->c_cc[VEOF],tp->c_cc[VEOL],tp->c_cc[VEOL2],
		tp->c_cc[VSWTCH]);
	fprintf(stderr,"START %02X, STOP %02X, SUSP %02X, DSUSP %02X,\n",
		tp->c_cc[VSTART],tp->c_cc[VSTOP],tp->c_cc[VSUSP],
		tp->c_cc[VDSUSP]);
	fprintf(stderr,"REPRINT %02X, DISCARD %02X, WERASE %02X, LNEXT %02X,\n",
		tp->c_cc[VREPRINT],tp->c_cc[VDISCARD],tp->c_cc[VWERASE],
		tp->c_cc[VLNEXT]);
}

#endif /* TEST_IOCTL */

static void
termios_configure(tp)
struct termios *tp;
{
	int i;

	slaveconf.c_iflag = tp->c_iflag;
	slaveconf.c_oflag = tp->c_oflag;
	slaveconf.c_cflag = tp->c_cflag;
	slaveconf.c_lflag = tp->c_lflag;
	slaveconf.c_line = 0;
	for (i=0;i<sizeof(slaveconf.c_cc) && i<sizeof(tp->c_cc);i++)
		slaveconf.c_cc[i] = tp->c_cc[i];
}

static void
termio_configure(tp)
struct termio *tp;
{
	slaveconf = *tp;
}

static void
handle_tioc(cmd,data)
int cmd;
char *data;
{
	switch (cmd) {
#ifdef TEST_IOCTL
	case TCGETA:
		fprintf(stderr,"ioctl TCGETA\n");
		termio_dump((struct termio *)data);
		break;
#endif /* TEST_IOCTL */
	case TCSETA:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSETA\n");
		termio_dump((struct termio *)data);
#endif /* TEST_IOCTL */
		termio_configure((struct termio *)data);
		break;
	case TCSETAW:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSETAW\n");
		termio_dump((struct termio *)data);
#endif /* TEST_IOCTL */
		termio_configure((struct termio *)data);
		break;
	case TCSETAF:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSETAF\n");
		termio_dump((struct termio *)data);
#endif /* TEST_IOCTL */
		termio_configure((struct termio *)data);
		break;
	case TCSBRK:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSBRK\n");
#endif /* TEST_IOCTL */
                DBG((4,D_INFO,"handle_tioc:About to do timemark.\n"));
		do_timing_mark();
                DBG((4,D_INFO,"handle_tioc: data after timeing mark %d\n",*data));
		if (!*(unsigned long *)data)
		    tn_send_break();
		break;
#ifdef TEST_IOCTL
	case TCXONC:
		fprintf(stderr,"ioctl TCXONC\n");
		break;
	case TCFLSH:
		fprintf(stderr,"ioctl TCFLSH\n");
		break;
	case TCGETS:
		fprintf(stderr,"ioctl TCGETS\n");
		termios_dump((struct termios *)data);
		break;
#endif /* TEST_IOCTL */
	case TCSETS:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSETS\n");
		termios_dump((struct termios *)data);
#endif /* TEST_IOCTL */
		termios_configure((struct termios *)data);
		break;
	case TCSETSW:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSETSW\n");
		termios_dump((struct termios *)data);
#endif /* TEST_IOCTL */
		termios_configure((struct termios *)data);
		break;
	case TCSETSF:
#ifdef TEST_IOCTL
		fprintf(stderr,"ioctl TCSETSF\n");
		termios_dump((struct termios *)data);
#endif /* TEST_IOCTL */
		termios_configure((struct termios *)data);
		break;
#ifdef TEST_IOCTL
	default:
		fprintf(stderr,"Unknown ioctl TIOC %d.\n",cmd&0xFF);
#endif /* TEST_IOCTL */
	}
}

static void
handle_ioctl(buf,dlen)
char *buf;
int dlen;
{
	struct iocblk *ioc;
	char *data;

	ioc = (struct iocblk *)buf;
	data = (char *)(ioc+1);
#ifdef TEST_IOCTL
	{
	int i;
	fprintf(stderr,"ioctl data length %d:\n",ioc->ioc_count);
	for (i = 0; i < ioc->ioc_count; i++)
		fprintf(stderr,"%02X ",data[i]&0xFF);
	fprintf(stderr,"\n");
	}
#endif /* TEST_IOCTL */
	if (dlen != ioc->ioc_count + sizeof(struct iocblk)) {
		DBG((1,D_WARN,"Strange IOCTL data -- length %d/%d",dlen,ioc->ioc_count+sizeof(struct iocblk)));
#ifdef TEST_IOCTL
		{
		int i;
		fprintf(stderr,"ioctl header:\n");
		for (i = 0 ; i < sizeof(struct iocblk); i++)
			fprintf(stderr,"%02X ",buf[i]&0xFF);
		fprintf(stderr,"\n");
		cleanup();
		}
#else
		return;
#endif
	}
	switch (ioc->ioc_cmd & 0xFF00) {
	case TIOC:
		handle_tioc(ioc->ioc_cmd&0xFFFF,data);
		break;
#ifdef TEST_IOCTL
	case tIOC:
		fprintf(stderr,"Old BSD ioctl %d.\n",ioc->ioc_cmd&0xFF);
		break;
	case LDIOC:
		fprintf(stderr,"LDIOC %d.\n",ioc->ioc_cmd&0xFF);
		break;
	case DIOC:
		fprintf(stderr,"DIOC %d.\n",ioc->ioc_cmd&0xFF);
		break;
	default:
		fprintf(stderr,"Unknown ioctl type %02X '%c'.\n",
			(ioc->ioc_cmd>>8)&0xFF,(ioc->ioc_cmd>>8)&0xFF);
#endif /* TEST_IOCTL */
	}
}

static int
handle_telnet_changes(flagp)
int *flagp;
{
	if (*flagp & 4) {
		if (telnet_halt_network(1))
			*flagp &= ~4;
		else
			return 1;
	}
	if (*flagp & 8) {
		if (telnet_halt_network(0))
			*flagp &= ~8;
		else
			return 1;
	}
	if (*flagp & 2) {
		if (cancel_network_output())
			*flagp &= ~2;
		else
			return 1;
		telnet_halt_network(0);
	}
	if (*flagp & 1) {
		if (cancel_network_input())
			*flagp &= ~1;
		else
			return 1;
	}
	return 0;
}

/*
 * Read from master pty interface.
 */

int
pty_read(fd,buffp,siz)
int fd,siz;
char **buffp;
{
	int cc,flags;
	struct strbuf ctl,data;
	char ctlbuf[256];
	static int savedtelnet = 0;

	if (alternate_ptys) {
		errno = 0;
		cc = read(fd,*buffp,siz);
		if (cc == 0)
			return MDIO_CLOSED;
		if (cc < 0)
			if (errno == EWOULDBLOCK || errno == EINTR ||
			    errno == EAGAIN)
				return MDIO_DEFER;
			else if (errno == EIO)
				return MDIO_CLOSED;
			else
				return MDIO_ERROR;
		return cc;
	}

	if (savedtelnet && handle_telnet_changes(&savedtelnet)) {
		DBG((3,D_INFO,"Pending telnet protocol flags %X",savedtelnet));
		return MDIO_UNSELECT;
	}
	flags = errno = 0;
	ctl.maxlen = sizeof(ctlbuf);
	ctl.len = 0;
	ctl.buf = ctlbuf;
	data.maxlen = siz;
	data.len = 0;
	data.buf = *buffp;
	cc = getmsg(fd,&ctl,&data,&flags);
	if (cc < 0)
		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			return MDIO_DEFER;
		else
			return MDIO_ERROR;
	if (ctl.len == -1) {
		ctl.len = 1;
		ctlbuf[0] = M_DATA;
	}
	if (ctl.len != 1) {
		DBG((1,D_WARN,"Strange control message -- length %d?",ctl.len));
#ifdef TEST_IOCTL
		dump_strbuf("Control",&ctl);
		dump_strbuf("Data",&data);
		cleanup();
#else
		return MDIO_DEFER;
#endif /* TEST_IOCTL */
	}
	switch (ctlbuf[0]&0xFF) {
	case M_DATA:
		cc = data.len;
		if (cc == 0)
			if (first_dummy) {
				DBG((3,D_INFO,"First dummy zero-length message."));
				first_dummy = 0;
				cc = MDIO_DEFER;
			} else {
				DBG((3,D_INFO,"Received close message."));
				pty_is_closed = 1;
				cc = MDIO_CLOSED;
			}
		else
			DBG((3,D_INFO,"Received %d bytes in M_DATA.",cc));
		break;
	case M_IOCTL:
		if (data.len < sizeof(struct iocblk)) {
			DBG((1,D_WARN,"Strange IOCTL message -- length %d?",data.len));
#ifdef TEST_IOCTL
			dump_strbuf("Data",&data);
			cleanup();
#else
			return MDIO_DEFER;
#endif /* TEST_IOCTL */
		}
		DBG((3,D_INFO,"Received M_IOCTL."));
		handle_ioctl(data.buf,data.len);
		cc = MDIO_DEFER;
		break;
	case M_FLUSH:
		DBG((3,D_INFO,"Received M_FLUSH."));
		savedtelnet |= data.buf[0] & 3;
		handle_telnet_changes(&savedtelnet);
		cc = MDIO_DEFER;
		break;
	case M_STOP:
		DBG((3,D_INFO,"Received M_STOP."));
		savedtelnet = (savedtelnet & ~8) | 4;
		handle_telnet_changes(&savedtelnet);
		cc = MDIO_DEFER;
		break;
	case M_START:
		DBG((3,D_INFO,"Received M_START."));
		savedtelnet = (savedtelnet & ~4) | 8;
		handle_telnet_changes(&savedtelnet);
		cc = MDIO_DEFER;
		break;
	default:
		DBG((1,D_WARN,"Strange control message -- type %02X?",ctlbuf[0]&0xFF));
#ifdef TEST_IOCTL
		dump_strbuf("Control",&ctl);
		dump_strbuf("Data",&data);
		cleanup();
#else
		cc = MDIO_DEFER;
#endif /* TEST_IOCTL */
	}
	return cc;
}

/*
 * Write to master pty interface.
 */

int
pty_write(fd,buff,siz)
int fd,siz;
char *buff;
{
	int cc,pws = pty_was_selected;
	struct strbuf ctl,data;

	pty_was_selected = errno = 0;
	if (alternate_ptys) {
		cc = write(fd,buff,siz);
		if (cc >= 0)
			return cc;
		if (errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
			if (pws)
				return MDIO_UNSELECT;
			else
				return MDIO_DEFER;
		else if (errno == EIO)
			return MDIO_CLOSED;
		return MDIO_ERROR;
	}
	ctl.len = -1;
	ctl.buf = NULL;
	data.len = siz;
	data.buf = buff;
	cc = putmsg(fd,&ctl,&data,0);
	if (cc >= 0)
		return siz;
	if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
		if (pws)
			return MDIO_UNSELECT;
		else
			return MDIO_DEFER;
	return MDIO_ERROR;
}

/*
 * Close master and slave ptys.
 */

void
pty_close(fd)
int fd;
{
	if (slave_pty >= 0) {
		DBG((3,D_INFO,"Closing held slave pty fd %d in pty_close.",slave_pty));
		(void)close(slave_pty);
		slave_pty = -1;
	}
	if (fd >= 0) {
		call_autopush(0);
		DBG((3,D_INFO,"Closing master pty fd %d in pty_close.",fd));
		(void)close(fd);
		master_pty = -1;
	}
}
