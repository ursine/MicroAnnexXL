/*
 *****************************************************************************
 *
 *		Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 * Command to spool to an Annex, serial or parallel port.
 *
 * Original Author: Jack Oneil		Created on: June 3, 1986
 *
 * Module Reviewers: harris oneil lint
 *
 *****************************************************************************
 */


/*
 * Annex remote printer program
 *
 * usage: aprint [-Aannex] [-Lline] [-pprinter_port] [-Fstring] [-fD] [files]...
 *
 * -A specifies the hostname or Internet address of the Annex to print on.
 *
 * -L specifies the port on the Annex to print on.  0, or no value,
 *	indicates the parallel printer port.  Otherwise, valid values
 *	go from 1 to the maximum number of serial ports.
 *
 * -F specifies a string to be used for formfeeds instead of CTRL-L.
 *	No special escape sequences are recognized.
 *
 * -p specifies the printer port on the Annex to print on.
 *
 * -f specifies that formfeeds are NOT to be sent to the Annex at the
 *	start/end of every job.
 *
 * -D specifies that debug output should be sent to standard output.
 *	This option may be repeated (a la rtelnet) for more detailed
 *	information.
 *		Level	Description
 *		  1	Connection acknowledge and per-file messages
 *		  2	Connection setup details
 *
 * OBSOLETE USAGE: aprint [-Pprinter] [-Fstring] [-f] [files]...
 *
 * -P specifies printer name to be looked up in /etc/printcap.  Aprint
 *	uses the ra (remote Annex), al (Annex line), and ff (form feed)
 *	printcap capabilities.  ra & al are Annex `extensions'.  If you can,
 *	apply the BSD `lpd' mods supplied with the Annex software release
 *	to your BSD `lpd' sources; these provide direct support of the
 *	ra & al capabilities in `lpd', allowing you to use that without aprint.
 *	If you didn't/can't apply the mods, you can still add ra & al
 *	entries to printcap entries with no side effects.
 */

/*
 *	Include Files
 */

#include "../inc/config.h"
#include "../inc/vers.h"

#include <sys/types.h>
#include "port/port.h"
#include "../libannex/api_if.h"
#include <netinet/in.h>
#include <strings.h>
#include <netdb.h>
#include <fcntl.h>

#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "aprint.h"

/*
 *	External Definitions
 */

extern int errno;
extern char *getenv();

#ifndef BSDI
#ifndef FREEBSD
#ifndef SYS_V
#ifndef AIX
#ifndef LINUX
extern char *sprintf();
#endif
#endif
#endif
#endif
#endif

extern void printcap_lookup();

/*
 *	Global Data Declarations
 */

int debug = 0;		/* debugging level */
int so;				/* token for socket number */

int formfeedflag = 0;		/* if set, then output no formfeeds */
char *formfeed;			/* form feed string */

char *prog;			/* name of this program */

char *file_printing;

INT32 bytes;			/* total bytes to send to printer */

/* Last message read from or sent to the Annex */
char buffer[BUFSIZ];
int buffer_count;

int block_send = 0;		/* if set, send in 1-255 byte blocks */
int do_oob_ack = 0;		/* if set, use old out-of-band ack */

char *sock_errors[] = {
#define SEND_FF 0
	"file \"%s\" aborted while sending formfeed to Annex",
#define SEND_DATA 1
	"file \"%s\" aborted while sending data to Annex",
#define SEND_FINAL_FF 2
	"error sending final formfeed to Annex",
#define SEND_PORTSET 3
	"error during Annex port select",
#define ACK_PORTSET 4
	"error during wait for ACK after port select",
#define ACK_FINAL 5
	"error during wait for final ACK"
};

/*
 *	Macro Definitions
 */

#ifndef BADSIG
#ifndef SIG_ERR
#define BADSIG (int (*)())-1
#else
#define BADSIG SIG_ERR
#endif
#endif

#define	ARGVAL (*++(*argv) || (--argc && *++argv))
#define ARGSTR(s)	*argv += strlen((s) = *argv);

#define FORMFEED "\f"

#define SEND(buf,len,msg) \
	if (api_send(so,(buf),(len),API_NOFLAGS,app_nam,TRUE) != (len)) { \
    		fatal(CNULL, sock_errors[(msg)], file_printing); \
	}

#define SENDOOB(buf,len,msg) \
	if (api_send(so, (buf), (len), API_OOB, app_nam, TRUE) != (len)) { \
    		fatal(CNULL, sock_errors[(msg)], file_printing); \
	}

#define	RECV(buf,len,msg,ret) \
	if((ret = api_recv(so,(buf),(len),API_NOFLAGS,TRUE,app_nam)) < 0) { \
		if (debug > 1) \
			printf("Error:  api_recv returned %d.\n",ret); \
    		fatal(CNULL, sock_errors[(msg)], file_printing); \
	} else if (debug > 1) \
		printf("Received %d bytes.  %02X %02X ...\n",ret,(buf)[0],(buf)[1]);

/*
 * Annex LPD protocol definitions
 */
#define ANNEX_SPOOL_CMD '\011'
#define ACK '\0'
#define NACK '\001'
#define FRAME '\002'

#define OFF		0	/* timer off */
#define ACK_WAIT	10	/* seconds to wait for initial ACK */
#define ACK_TIMEOUT	30	/* seconds to timeout final ACK */

/*
 * usage: display usage info and exit
 */
usage()
{
	fprintf(stderr,
		"Usage:\n\t%s [-Dv] [-Pprinter] [-Aannex] [-L#] [-pprinter_port] [-Fstring]\n\t\t[-f] [file]...\n",
		prog);
	fprintf(stderr,"\n\
\t-D\tEnable debug mode (use more Ds for more detail)\n\
\t-v\tPrint software version number and exit.\n\
\t-P\tSpecify printer name (obsolescent).\n\
\t-A\tSpecify IP name or address of Annex.\n\
\t-L\tSpecify serial port number.\n\
\t-p\tSpecify parallel port number.\n\
\t-F\tSpecify form-feed string.\n\
\t-f\tDisable automatic form-feeds.\n");
	exit(1);
}

/* 
 * fatal: print error message and give up
 */
void
fatal(perr,str,arg1)
char *perr,*str,*arg1;
{
	fprintf(stderr, "%s: ", prog);
	if (str != NULL)
		fprintf(stderr,str,arg1);
	if (perr != NULL) {
		if (str != NULL)
			fprintf(stderr, ": ");
		perror(perr);
	} else
		fprintf(stderr, "\n");
	exit(1);
}

/*
 * gotpipe: catch SIGPIPE and die
 */
void
gotpipe(dummy)
int dummy;
{
	fatal(CNULL,
		file_printing == NULL
		? "Annex connection was lost unexpectedly"
		: "Annex connection was lost during attempt to spool \"%s\"" ,
		file_printing);
}

main(argc,argv)
int argc;
char *argv[];
{
        char *printer = NULL, *annex = NULL, *ff = NULL, *port = NULL;
        int pport = 0;
        int gotl = 0;
        int gotp = 0;
        int type = PARALLEL;	/* default, if nothing specified */
	int line = 1;
	char opt; 
	FILE *userfile;
	int i;

	prog = (prog = (char *)rindex(argv[0],'/')) ? ++prog : *argv;
	/*
	 * Crack arguments
	 */
	if (argc <= 1)
	   usage(); 
	while (--argc > 0) {			/* for each argument */
		if (**(++argv) == '-')	/* found a flag, deal with it */
			while (**argv && (opt = *++*argv) != '\0')
			switch (opt) {
			case 'f':		/* don't produce formfeeds */
				formfeedflag++;
				break;
			case 'D':
				debug++;
				break;
			case 'F':		/* specify formfeed string */
				if (!ARGVAL)
					usage();
				ARGSTR(ff);
				break;
			case 'P':		/* specify printer */
				if (!ARGVAL)
					usage();
				ARGSTR(printer);
				break;
			case 'A':		/* specify annex */
				if (!ARGVAL)
					usage();
				ARGSTR(annex);
				break;
            		case 'p':    /* specify annex parallel port */
                		if (gotl)
				    fatal(CNULL,"Can't mix -L and -p flags",CNULL);

                		if (!ARGVAL)
				    usage();

				line = atoi(*argv);
				if (line == -1)
				    usage();
				if (line <= 0 || line > MAX_PRINTER_PORTS)
				    fatal(CNULL,"invalid parallel port number %s",*argv);
				type = PARALLEL;
				gotp = 1;
                		break;
			case 'L':        /* specify annex serial line */
				if (gotp)
				    fatal(CNULL,"Can't mix -L and -p flags",CNULL);

				if (!ARGVAL)
				    usage();
				ARGSTR(port);
#if NDPTG > 0
				line = name_to_unit(port);
				if(line == -1)
				    usage();
#else
				line = atoi(port);
#endif
				if (line < 0 || line > MAX_SERIAL_PORTS)
				    fatal(CNULL,
					"invalid serial/parallel unit number %s",port);
				if (line) {
				    type = SERIAL;
				} else {
				    type = PARALLEL;
				    line = 1;
				}
				break;
			case 'v':
				printf("aprint host tool version %s, released %s\n",
				       VERSION,RELDATE);
				exit(0);
				break;
			default:		/* unknown argument */
				usage();
				break;
			}
		else
			break;
   	}

	/*
	 * check consistancy of, and process, -P & -A flags
	 */
	if (annex) {					/* -A specified */
		if (printer)
			fatal(CNULL,"Can't mix -A and -P flags",CNULL);
	} else {
		if (line != 0)
			fatal(CNULL,"Can't mix -L and -P flags",CNULL);

		/* if -P not specified */
		if (printer == NULL) {
			printer = getenv("PRINTER");
			if (printer == NULL)
				printer = DEFAULT_PRINTER;
		}
		printcap_lookup(printer,&annex,&line,&formfeed);
	}
	/*
	 * formfeed from command line overrides that from printcap
	 */
	if (ff)
		formfeed = ff;
	else
		if (formfeed == NULL)
			formfeed = FORMFEED;

/*
 * Note that we might have problems here if the file extends itself
 * after we've counted up the bytes and the socket to the Annex doesn't
 * linger and the Annex requests non-blocked data -- the Annex will ACK
 * this program N bytes early, and it might exit before its time.
 * This is just too bad.
 */
	bytes = 0L;
	for (i=0; i < argc; i++) {
		userfile = fopen(argv[i],"r");
		if (userfile == NULL) {
			perror(argv[i]);
			argv[i] = NULL;
			}
		else if (fseek(userfile,0L,2) < 0) {
	/* Darn.  Looks like we can't count the number of bytes. */
			perror(argv[i]);
			bytes = 0;
			fclose(userfile);
			break;
			}
		else {
			bytes += ftell(userfile);
			fclose(userfile);
			}
		}

	if (debug > 0)
		printf("Connecting to Annex %s port %d\n",annex,line);
	make_connection(annex);
	set_annex_line(line, type);

	if (debug > 1)
		printf("Connection set-up is complete.  Handling %d files.\n",argc);
	if (argc > 0)
		while (argc-- > 0) {
			if (*argv) {
				userfile = fopen(*argv, "r");
				if (userfile == NULL)
					perror(*argv);
				else {
					(void)print_file(*argv,userfile);
					(void)fclose(userfile);
				}
			}
			++argv;
		}
	else {
		(void)print_file("standard input",stdin);
	}	
	file_printing = NULL;

	if (formfeedflag == 0) 
		send_block(formfeed,strlen(formfeed),SEND_FINAL_FF);
	
	/*
	 * End-of-job handshake; wait for final ACK
	 */
	if (ack_ack())
		fatal(CNULL,"Annex didn't acknowledge final data",CNULL);

	exit (0);
}

/*
 * print_file: spool file over TCP connection
 */
print_file(name,file)
char *name;
FILE *file;
{
	file_printing = name;

	if (debug > 0)
		printf("Printing file \"%s\".\n",name);

	if (formfeedflag == 0) 
		send_block(formfeed, strlen(formfeed), SEND_FF);

	for (;;) {
		buffer_count = fread(buffer, sizeof(*buffer), BUFSIZ, file);
#ifdef DEBUG
fprintf(stderr,"object size=%d, buffer size=%d, length=%d\nbuffer=>>%.*s<<\n",
sizeof(*buffer),BUFSIZ,len,len,buffer);
#endif
		/* fread should never return <0, but... */
		if (buffer_count <= 0)
			break;
		send_block(buffer, buffer_count, SEND_DATA);
	}

	return(0);
}

/*
 * make_connection: establish TCP connection with designated Annex
 */
make_connection (hostname)
char *hostname;
{
	struct hostent *host;
	struct servent *serv;
	struct sockaddr_in sname;
	static char app_nam[]="aprint:make_connection";

	if (signal(SIGPIPE, gotpipe) == BADSIG)
		fatal("signal",CNULL,CNULL);

	bzero ((char *)&sname, sizeof(sname));

	if (debug > 1)
		printf("Attempting to resolve host name \"%s\".\n",hostname);
	sname.sin_addr.s_addr = inet_addr(hostname);
	if (sname.sin_addr.s_addr != -1) {
		sname.sin_family = AF_INET;
	} else {
		host = gethostbyname(hostname);
		if (host) {
			sname.sin_family = host->h_addrtype;
			bcopy(host->h_addr,
				(caddr_t)&sname.sin_addr,
				host->h_length);
		} else
			fatal(CNULL,
				"can't find host address for Annex \"%s\"",
				hostname);
	}

#ifdef DEBUG
	sname.sin_port = htons(5555);
#else
	if (debug > 1)
		printf("Attempting to resolve service \"printer/tcp\".\n");
	serv = getservbyname("printer","tcp");
	if (serv == NULL)
		fatal(CNULL,"can't get service to printer",CNULL);
	sname.sin_port = serv->s_port;
	if (debug > 1)
		printf("\t-> resolved to port %d.\n",
			ntohs(sname.sin_port));
#endif

#ifdef EXOS
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = INADDR_ANY;
	sin->sin_port = 0;
#endif

	if (debug > 1)
		printf("Opening connection to API layer.\n");
	if((so = api_open(IPPROTO_TCP, &sname, app_nam, TRUE)) < 0)
	    exit(1);

#ifdef TLI			/* only bind for TLI, Sockets don't need bind*/
	if (debug > 1)
		printf("Binding API address.\n");
	switch (api_bind(so, (struct t_bind **)0, (struct sockaddr_in *)0, app_nam, TRUE)) {
	    case 0:
		break;
	    case 1:
		exit(-1);
	    case 2:
		exit(1);
	    default:
		break;
	}
#endif

	if (debug > 1)
		printf("Connecting to host through API.\n");
	switch (api_connect(so, &sname, IPPROTO_TCP, app_nam, TRUE)) {
	    case 0:
		break;
	    case 1:
		exit(-1);
	    case 2:
		exit(1);
	    default:
		break;
	}
}

/*
 * Tell the Annex which port to print on by creating a escape sequence
 * to select which port to print on:
 *
 *	  CMD TYPE ; UNIT ; BYTES \n
 *
 * CMD is \011 is for the new-style lpd, where you select, get an ack,
 * and then shovel data.
 *
 *					serial			parallel
 * TYPE is the port type:		1			2
 * UNIT is the unit number:		[1-MAX_SERIAL_PORTS]	1
 * (TYPE & UNIT are ASCII strings)
 */

set_annex_line(line, type)
int line;
int type;
{
	static char app_nam[]="aprint:set_annex_line";

	(void)sprintf(buffer,"%c%d;%d;%ld\n",
			ANNEX_SPOOL_CMD,	/* command byte */
			type,			/* parallel or serial */
			line,			/* unit */
			bytes);

	if (debug > 1)
		printf("Sending port designator --\n\t%s",buffer);
	SEND(buffer, strlen(buffer), SEND_PORTSET);

	/* check if Annex supports ACKing */
	if (ack_wait(ACK_PORTSET))
		fatal(CNULL, "Annex can't access requested printer",CNULL);

	/* Check if count/buffers needed and supported */
	if (buffer_count > 1) {
		if (buffer[1] == 1) {
			block_send = 1;
			if (debug > 0)
				printf("Block send mode.\n");
		} else if (debug > 0)
			printf("Stream mode.\n");
	} else {
		do_oob_ack = 1;		/* backwards compatibility */
		if (debug > 0)
			printf("Backward compatibility mode.\n");
	}
}

/*
 * Send a block of data to the Annex.
 *
 * In block_send mode, this is a pair of bytes that encode an integer
 * in big-endian format in the range 0x0001 through 0xFFFF, followed by
 * 1 to 65536 bytes.  A count of 0x0000 is reserved for end-of-all-files
 * indication.
 *
 * When not in block_send mode, data are just streamed over.
 */
send_block(ptr,len,msg)
char *ptr;
int len,msg;
{
	char blockbuf[2];
	unsigned int piece;
	static char app_nam[]="aprint:send_block";

	if (block_send) {
		while (len > 0) {
			piece = len;
			if (piece > 65535)
				piece = 65535;
			blockbuf[0] = piece / 256;
			blockbuf[1] = piece % 256;
			SEND(blockbuf,2,msg);
			SEND(ptr,piece,msg);
			len -= piece;
			ptr += piece;
			}
		}
	else
		SEND(ptr,len,msg);
}

/************** Annex LPD protocol handshaking routines **************/

/*
 * ack_alrm: catch SIGALRM and longjmp back
 */
void
ack_alrm(dummy)
int dummy;
{
	static char app_nam[]="aprint:ack_alrm";

#ifdef SYS_V
	signal(SIGALRM,ack_alrm);
#endif
	(void)alarm(ACK_TIMEOUT);
	if (debug > 0)
		printf("ACK timeout -- going to re-try.\n");
	SEND("",1,ACK_FINAL);	/* detect lost connections! */
}

/*
 * Wait for an inline acknowledgement from the Annex
 *
 * return 0 if we get the ACK, 1 o/w.
 */
int
ack_wait(msg)
int msg;
{
	static char app_nam[]="aprint:ack_wait";

	if (debug > 1)
		printf("Waiting for acknowledge.\n");
	RECV(buffer,BUFSIZ,msg,buffer_count);
	return (buffer_count <= 0 || buffer[0] != ACK);
}

/*
 * Send an OOB ACK and wait for an inline ACK back.
 * Use timeout to prevent waiting forever.
 *
 * return 0 if exit handshake went ok, 1 o/w.
 *
 * If in block_send mode, then send the magic end-of-all-blocks message
 * and wait for ACK (no OOB).  If old (pre R6.2) Annex detected in
 * set-up, then send an OOB message to terminate the data.  This part is
 * a little unclean.
 */

ack_ack()
{
	int gotack;
	static char app_nam[]="aprint:ack_ack";

	if (block_send) {
		char endblock[2];

		if (debug > 0)
			printf("Sending End-Of-Blocks message.\n");
	/* send end-of-all-blocks message */
		endblock[0] = endblock[1] = '\0';
		SEND(endblock,2,ACK_FINAL);
		}
	else if (do_oob_ack) {
#ifdef MSG_OOB
		if (debug > 0)
			printf("Sending OOB message.\n");
	/* try to get the OOB past the end of the data for SysV */
		sleep(7);
	/* send OOB ACK to indicate EOF */
		SENDOOB("",1,ACK_FINAL);
	/* clear for recv's on broken 4.2 systems */
		SEND("",1,ACK_FINAL);
#else
		if (debug > 0)
			printf("No OOB possible -- just closing.\n");
	/* if no OOB available, then just trust that it got there. */
		return 0;
#endif
		}
	if (debug > 0)
		printf("Waiting for final ACK.\n");
	if (signal(SIGALRM, ack_alrm) == BADSIG)
		fatal("signal",CNULL,CNULL);
	(void)alarm(ACK_TIMEOUT);
	gotack = ack_wait(ACK_FINAL);
	(void)alarm(OFF);
	return gotack;
}
