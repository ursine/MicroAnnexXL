/*****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *
 *	Xenix UDP SL/IP Daemon
 *
 * Original Author:  Paul Mattes		Created on: 01/04/88
 *
 *****************************************************************************/


/*****************************************************************************
 *									     *
 * Include files							     *
 *									     *
 *****************************************************************************/

#include "../inc/config.h"
#include "../inc/vers.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include "../inc/slip/slip_user.h"
#include "../inc/slip/slip_system.h"
#include "../inc/slip/BSDslip.h"


/*****************************************************************************
 *									     *
 * Local defines and macros						     *
 *									     *
 *****************************************************************************/

#undef perror
#undef exit
#undef read
#undef write
#undef close

#define CMD_SIZE	256
#define READ_SIZE	256

#define TRUE		1
#define FALSE		0

#define ESCAPED		0x0001
#define ENDED		0x0002
#define DEAF		0x0004
#define PARMRK0		0x0008
#define PARMRK1		0x0010

#define PARMRK_ESCAPE	0377
#define PARMRK_ERROR	0

#define TICK		2
#define TICKS_MAX	8 /* 3 */


/*****************************************************************************
 *									     *
 * Structure and union definitions					     *
 *									     *
 *****************************************************************************/

struct bufferq {
    u_short bq_port;
    u_short bq_ticks;
    struct packet *bq_data;
    int bq_seq;
    struct bufferq *bq_next;
    };

struct packet {
    u_short p_length;
    char p_data[SLMTU];
    };


/*****************************************************************************
 *									     *
 * External data							     *
 *									     *
 *****************************************************************************/

extern int errno;
extern char *malloc();

#ifndef SYS_V
#ifndef AIX
char		*sprintf();
#endif
#endif

/*****************************************************************************
 *									     *
 * Global data								     *
 *									     *
 *****************************************************************************/

int debug;
int state;
int byte_count;
struct packet frame_buffer;
int ttyf;
int n_buffered = 0;
struct bufferq *BQ_head = (struct bufferq *)0;
struct bufferq *BQ_tail = (struct bufferq *)0;
int bq_seq = 0;


/*****************************************************************************
 *									     *
 * Static data								     *
 *									     *
 *****************************************************************************/

static int parmrk;


/*****************************************************************************
 *									     *
 * Forward definitions							     *
 *									     *
 *****************************************************************************/

int alarm_handler();
int report_status();
int die_gracefully();


main(argc, argv)
int argc;
char *argv[];
{
    FILE *f;
    char inet_addr[32], ttyname[256], command[CMD_SIZE], tty_buf[READ_SIZE];
    char other[3][10];
    int n_scanned, n_bytes;

    /* parse arguments */

    if (argc == 2 && strcmp("-v") == 0) {
      printf("slipd host tool version %s, released %s\n",
	     VERSION,RELDATE);
      exit(0);
    }

    if((argc > 2) || (argc == 2 && !(debug = !strcmp("-D", argv[1])))) {
	fprintf(stderr, "usage: %s [-v] [-D]\n", argv[0]);
	exit(1);
	}

    /* leave dad behind and become a daemon */

    if(!debug) {
	int i, fd;

	if(fork())
	    exit(0);

	for(i = 0; i < 10; ++i)
	    close(i);

	fd = open("/dev/console", O_RDWR);
	if(fd < 0)
	    fd = open("/dev/tty", O_RDWR);
	if(fd < 0)
	    fd = open("/dev/null", O_RDWR);
	dup(fd);
	dup(fd);
	setpgrp();
	}

    /* look for the configuration file and pick it apart */

    f = fopen(CFGFILE, "r");
    if(!f) {
	perror(CFGFILE);
	exit(1);
	}

    /* we want "inet_addr ttyname [baud] [parity] [stopb] */

    n_scanned = fscanf(f, "%s %s %s %s %s",
		       inet_addr, ttyname, other[0], other[1], other[2]);
    if(n_scanned == EOF || n_scanned < 2) {
	fprintf(stderr, "%s: illegal configuration file: %s\n",
		argv[0], CFGFILE);
	exit(1);
	}

    if(!(ttyf = open(ttyname, O_RDWR))) {
	perror(ttyname);
	exit(1);
	}

    /* set up the tty */

    if(sV_stty(ttyname, ttyf, other, n_scanned - 2, &parmrk) == -1) {
	perror(ttyname);
	exit(1);
	}

    /* keep the roof from caving in (we're a daemon, after all) */

    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    /* fork off the writer daemon */

    if(!fork())
	slip_writer(&frame_buffer); /* won't return */

    /* prepare for alarms */

    signal(SIGALRM, alarm_handler);
    if(debug)
	signal(SIGINT, report_status);
    signal(SIGTERM, die_gracefully);

    /* set up the port lock file */

    {
	int fd;

	fd = creat(PORTLOCK, 0666);
	if(fd != -1)
	    close(fd);
	chmod(PORTLOCK, 0666);	/* in case of umask problems */
	}

    /* now satisfy read requests forever */

    while(1) {
	n_bytes = read(ttyf, tty_buf, READ_SIZE);
	switch(n_bytes) {
	case 0:
	    if(debug)
		fprintf(stderr, "slipd reader: EOF on tty\n");
	    continue;
	case -1:
	    if(errno == EINTR) {
		if(debug)
		    fprintf(stderr, "slipd reader: interrupted tty read\n");
		retry_buffers(-1);
		continue;
		}
	    else {
		perror("slipd reader");
		exit(1);
		}
	    break;
	default:
	    whittle(tty_buf, n_bytes);
	    break;
	    }

	}
    }


whittle(ttybuf, count)
char *ttybuf;
int count;
{
    unsigned char c;
    int add_it;

    while(count--) {

	c = (unsigned char)*ttybuf++;
	if(debug)
	    fprintf(stderr, "%02x ", c);
	add_it = TRUE;

	if(state & PARMRK0) {
	    state &= ~PARMRK0;
	    switch(c) {
	    case PARMRK_ESCAPE:		/* 0377 0377 ==> 0377 */
		goto as_usual;
	    case PARMRK_ERROR:		/* 0377 0 x ==> error */
		state |= PARMRK1;
		goto next;
	    default:			/* 0377 x ==> Sys V screwup */
		state |= DEAF;
		goto next;
		}
	    }
	else if(state & PARMRK1) {	/* 0377 0 x ==> error */
	    state &= ~PARMRK1;
	    state |= DEAF;
	    goto next;
	    }
	else if(parmrk && (c == PARMRK_ESCAPE)) {
	    state |= PARMRK0;
	    goto next;
	    }

    as_usual:
	if(state & ESCAPED) {
	    switch(c) {
	    case TRANS_FRAME_ESCAPE:
		c = FRAME_ESCAPE;
		break;
	    case TRANS_FRAME_END:
		c = FRAME_END;
		break;
	    default:
		if(debug)
		    fprintf(stderr, "Escape error ", c);
		state |= DEAF;
		add_it = FALSE;
		break;
		}
	    state &= ~ESCAPED;
	    }
	else switch(c) {
	    case FRAME_ESCAPE:
		state |= ESCAPED;
		add_it = FALSE;
		break;
	    case FRAME_END:
		add_it = FALSE;
		if(!(state & DEAF) && byte_count) {
		    frame_buffer.p_length = byte_count;
		    receive_pkt(&frame_buffer);
		    }
		state = 0;
		byte_count = 0;
		break;
		}

	if(add_it & !(state & DEAF)) {
	    if(byte_count >= SLMTU) {
		if(debug)
		    fprintf(stderr, "Packet too long\n");
		state |= DEAF;
		}
	    else
		frame_buffer.p_data[byte_count++] = c;
	    }
    next:
	;
	}
    }


receive_pkt(buf)
struct packet *buf;
{
    FILE *f;
    char rn[256];
    struct udpiphdr *u;
    u_short port;

    /* I only understand UDP */

    u = (struct udpiphdr *)buf->p_data;
    if(buf->p_length < sizeof(*u)) {
	if(debug)
	    fprintf(stderr, "slipd reader: packet too small\n");
	return;
	}
    else if(u->ui_pr != IPPROTO_UDP) {
	if(debug)
	    fprintf(stderr, "slipd reader: unknown protocol: %02x\n", u->ui_pr);
	return;
	}

    port = u->ui_dport;

    if(debug)
	fprintf(stderr, "slipd reader: pkt Rx'd for port %d, len %d...\n",
		ntohs(port), buf->p_length);

    /* retry the buffer list, so we preserve packet order */

    if(BQ_head)
	retry_buffers(ntohs(port));

    /* send or buffer the current packet */

    (void)try_to_send(ntohs(port), buf, TRUE);
    }


int try_to_send(port, buf, first_time)
u_short port;
struct packet *buf;
int first_time;
{
    char dn[256];
    int fd;

    sprintf(dn, SLIPDATA, port);
    fd = open(dn, O_WRONLY | O_NDELAY);
    if(fd == -1) {
	if(errno == ENXIO) {	/* No reader, at present */
	    if(debug)
		fprintf(stderr, "slipd reader: pipe, but no user\n");
	    if(first_time)
		insert_bufferq(port, buf);
	    }
	else if(errno == ENOENT) {	/* No reader ever */
	    if(debug)
		fprintf(stderr, "slipd reader: no pipe, dropping\n");
	    return(0);
	    }
	else if(debug)
	    perror(dn);
	return(0);
	}

    write(fd, buf, buf->p_length + sizeof(buf->p_length));
    close(fd);

    if(debug)
	fprintf(stderr, "slipd reader: to user\n");
    return(1);
    }


/* Add a buffer to the end of the queue */

insert_bufferq(port, buf)
u_short port;
struct packet *buf;
{
    struct bufferq *b;

    if(debug)
	fprintf(stderr, "slipd reader: enqueueing\n");

    b = (struct bufferq *)malloc(sizeof(*b));
    if(!b) {
	if(debug)
	    fprintf(stderr, "slipd reader: out of buffer space\n");
	return;
	}
    b->bq_port = port;
    b->bq_ticks = 0;
    b->bq_data = (struct packet *)malloc(buf->p_length + sizeof(buf->p_length));
    if(!(b->bq_data)) {
	if(debug)
	    fprintf(stderr, "slipd reader: out of buffer space\n");
	free((char *)b);
	return;
	}
    memcpy(b->bq_data, (char *)buf, buf->p_length + sizeof(buf->p_length));
    b->bq_seq = ++bq_seq;
    b->bq_next = (struct bufferq *)0;
    if(BQ_tail)
	BQ_tail->bq_next = b;
    else
	BQ_head = b;
    BQ_tail = b;
    alarm(TICK);
    }


/* Walk the list of buffers, trying to send each.  Remove old ones. */

/* There is an important policy decision to be made here:
 *
 * The existing buffering scheme will preserve the integrity and order of
 * an arbitrary number of buffers for an arbitrary period of time (once the
 * input pipe exists).  This makes the data itself more important than when
 * it arrives, which may not be a good thing, considering that UDP data
 * going to an "unlistened-to" port is probably going to be retried.
 *
 * If we end up forever supplying out-of-date packets while queueing the
 * ones we should be delivering, it is a simple enough matter to change
 * retry_buffers(n), where n != -1, to _throw_away_ packets for port n.
 */

retry_buffers(port)
int port;	/* Specific port or -1 for all ports */
{
    struct bufferq *b = BQ_head;
    struct bufferq *prev = (struct bufferq *)0;

    while(b) {
	if(debug)
	    fprintf(stderr, "retrying pkt #%d... ", b->bq_seq);
	if((port != -1) && (b->bq_port != port)) {
	    b = b->bq_next;
	    continue;
	    }
	if(try_to_send(b->bq_port, b->bq_data, FALSE) ||
	   b->bq_ticks >= TICKS_MAX) {
	    if(debug)
		fprintf(stderr, "slipd reader: Rx'd or expired\n");
	    free(b->bq_data);
	    if(prev) {
		prev->bq_next = b->bq_next;
		if(b == BQ_tail)
		    BQ_tail = prev;
		free((char *)b);
		b = prev->bq_next;
		continue;
		}
	    else {	/* last one */
		BQ_head = BQ_tail = (struct bufferq *)0;
		free((char *)b);
		return;
		}
	    }
	else
	    ++b->bq_ticks;

	prev = b;
	b = b->bq_next;
	}

    if(BQ_head)
	alarm(TICK);
    }


/* SIGALRM handler: re-enable yourself, and assume that
   any pending TTY read will complete with EINTR */

int alarm_handler(s)
int s;
{
    signal(SIGALRM, alarm_handler);
    }


/* SIGINT handler for debug mode: report what is going on */

int report_status(s)
int s;
{
    signal(SIGINT, report_status);
    fprintf(stderr, "slipd reader status:\n");
    fprintf(stderr, "BQ_head = %lx, BQ_tail = %lx\n", (u_long)BQ_head, (u_long)BQ_tail);
    }


/* SIGTERM handler: wipe out the outpipe, leave the port lock */

int die_gracefully(s)
int s;
{
    (void)unlink(OUTPIPE);
    exit(0);
    }


/* SL/IP writer */

slip_writer(buffer)
struct packet *buffer;
{
    u_char pending_char, c;
    char *pktbuf;
    int fd, pktlen, readlen;
    FILE *ttyout;
    struct packet *pkt;

    /* Manufacture the input pipe, open a channel to it */

    if(mknod(OUTPIPE, S_IFIFO | 0666, 0) == -1) {
	if(errno != EEXIST) {
	    perror(OUTPIPE);
	    exit(1);
	    }
	}

    chmod(OUTPIPE, 0666);

    fd = open(OUTPIPE, O_RDONLY);
    if(fd < 0) {
	perror(OUTPIPE);
	exit(1);
	}

    /* Get a buffered descriptor for the tty */

    ttyout = fdopen(ttyf, "w");
    if(!ttyout) {
	perror("slipd writer: ttyout");
	exit(1);
	}

#define xmit(ch) { \
    if(debug) \
	fprintf(stderr, "%02x.", (ch)); \
    fputc((ch), ttyout); \
    }

    while(1) {

	/* Read a group of whole packets */

	readlen = read(fd, (char *)buffer, sizeof(*buffer));
	switch(readlen) {
	case -1:	/* misc errors */
	    if(errno == EINTR)
		continue;
	    perror(OUTPIPE);
	    exit(1);
	    break;
	case 0:		/* eof */
	    close(fd);
	    fd = open(OUTPIPE, O_RDONLY);
	    if(fd < 0) {
		perror(OUTPIPE);
		exit(1);
		}
	    continue;
	default:	/* success */
	    if(debug)
		fprintf(stderr, "slipd writer: got %d bytes\n",
			readlen);
	    break;
	    }

	
	/* Issue them to the outside world */

	pkt = buffer;

	do {

	    /* Make sure the buffer is big enough */

	    if(pkt->p_length > (readlen - sizeof(pkt->p_length))) {
		if(debug)
		    fprintf(stderr, "slipd writer: length mismatch\n");
		break;
		}

	    pktlen = pkt->p_length;
	    pktbuf = pkt->p_data;

	    if(debug)
		fprintf(stderr, "slipd writer: pkt len %d\n", pktlen);

	    pending_char = FRAME_END;

	    while(1) {

		if(pending_char) {
		    xmit(pending_char);
		    pending_char = 0;
		    }
		else if(pktlen) {
		    switch(c = *(u_char *)pktbuf) {
		    case FRAME_ESCAPE:
			xmit(FRAME_ESCAPE);
			pending_char = TRANS_FRAME_ESCAPE;
			break;
		    case FRAME_END:
			xmit(FRAME_ESCAPE);
			pending_char = TRANS_FRAME_END;
			break;
		    default:
			xmit(c);
			break; /* switch */
			}
		    --pktlen;
		    ++pktbuf;
		    }
		else {
		    xmit(FRAME_END);
		    break;
		    }
		}

	    fflush(ttyout);

	    readlen -= (pkt->p_length + sizeof(pkt->p_length));
	    pkt = (struct packet *)(pkt->p_data + pkt->p_length);

	    } while(readlen);
	}
    }
