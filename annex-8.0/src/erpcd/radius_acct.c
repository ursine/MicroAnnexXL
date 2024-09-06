/*
 *****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 *     RADIUS_ACCT: Host Security Server - RADIUS Support for Accounting
 *
 * Original Author: Dave Mitton        Created on: April 3, 1996
 *
 * Module Reviewers:
 *
 *    lint dfox
 *
 * Revision Control Information:
 *
 * $Header: /annex_src/erpcd/radius_acct.c
 *
 *
 * Revision History:
 *
 * $Log: acp.c,v $
 * Revision 0.1  1996/4/3  15:48:00 mitton
 * Initial draft
 *
 */

/* includes */
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <stdio.h>
#include "../inc/config.h"
#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <syslog.h>
#include <sys/ioctl.h>
#endif

#ifdef LINUX   /* This is needed as else the defines in stdlib.h get
		  into conflicts*/
#undef __OPTIMIZE__
#endif
#include <stdlib.h>
#ifdef LINUX
#define __OPTIMIZE__
#endif
#include <string.h>
#include <time.h>
#include "acp.h"
#include "../libannex/api_if.h"
#include "../inc/erpc/nerpcd.h"

#include "../inc/port/port.h"
#include "radius.h"
#include "acp_regime.h"
#include "acp_policy.h"
#include "environment.h"
#include "session_db.h"


/* Code conditionals */
#define ACCT_START	1			/* Send Accounting-On and -Off messages */
/*#define DEBUG_PROTOS 1			* define debug prototype code */
/*#define SYSDEBUG 1				* define system prototypes */

/* code for setting up debugging prototypes *!* ANSI C only */
#undef _						/* also defined in nerpcd.h */
#if (__STDC__ && DEBUG_PROTOS )
#define _(x)	x
#else
#define _(x)	()
#endif

/* for debugging on systems without system calls prototyped */
#if (__STDC__ && SYSDEBUG)
time_t time(time_t *tloc);
char *inet_ntoa(struct in_addr in);
void bzero(void *b, size_t len);
void bcopy(void *s1, void *s2, size_t len);
int syslog(int prio, char *format, ...);
int printf(char *format, ...);
#endif

/* macros for field building routines */
#define RADIUS_BUILD_INT(bpp, type, lvalue) radius_add_attribute(bpp, type, 4, NULL, lvalue);
#define RADIUS_BUILD_STR(bpp, type, ptr) radius_add_attribute(bpp, type, strlen(ptr), ptr, 0);

/* Integer time subtraction */
#define TIMEDIFF(time2, time1) ((time2) - (time1))

/* structure shortcuts (from acp_regime.c) */
#define ACCT_SERVER_ADDR regime_supplement.radius_servers.acct_server.s_addr
#define AUTH_SERVER_ADDR regime_supplement.radius_servers.auth_server.s_addr

#ifndef UDEBUG					/* Unit debugging */

/* external erpcd variables */
extern int debug;
extern int raddb_up;
extern char *service_name[];	/* acp_lib.c */
extern char *event_name[];		/* acp_lib.c */
extern Radius_server *default_servers;	/* radius_config.c */
#define NCODETYPES 13     /*This is the number of elemnets in array below*/
extern char *codetype[];  /*This array is defined in radius_parser.c*/

/* external routines */
extern int api_open _((int pd, struct sockaddr_in *sin, char *app_nam, int sho_err));		/* api_if.c */
extern int api_bind _((int fd, int **tbp, struct sockaddr_in *sin, char *app_nam, int sho_err));
extern int api_connect _((int fd, struct sockaddr_in *sin, int pd, char *app_nam, int sho_err));
extern int api_send _((int fd, char *buf, int len, int flags, char *app_nam, int sho_err));
extern int api_recvwait _((int fd, char *buf, int len, int tmo, int flags, int sho_err, char *app_nam));
extern int api_close _((int fd));

extern int get_security_regime _((struct environment_spec *env_p));		/* acp_regime.c */
extern void release_security_regime _((struct security_regime *regimep));
extern int get_time_stamp _((struct tm *intime));                       /* acp_lib.c */
extern char *port_to_name _((SECPORT *portd, char *name));

#else
#include "radebug.c"			/* unit debug code */
#endif


/* constants	*/
char	appname[] = "RADIUS Acct";		/* component name for error logging	*/
#define MAX_RAD_MSG 4096+16		/* max msg length *!* move to RADIUS.H */
								/* should be max msg length + secret length */
#define VPORT_MULT  1000        /* multiplier for virtual and unknown port types */

/* local data declarations */
int			actinit;		/* accounting initialized */
int			actfd;			/* accounting socket descriptor */
struct servent	*svp;		/* server descriptor struct */
struct sockaddr_in	actlsa;	/* local socket address structure*/
struct sockaddr_in	actrsa; /* remote socket address structure */
static char portname[8];    /* port name buffer */


/* current server information */
int			actdelay;		/* delay time */
int			actretry;		/* retry limit  */
int			acttmos;		/* timeout counter */
int			actbackup;		/* using backup server?	*/
int			actfailed;		/* accounting service failed */
struct in_addr	actbackaddr; /* backup server address */
struct in_addr	actwasaddr;  /* primary server addr before failover */
char	actsecret[16];		/* server secret */

/* message vars	*/
u_char	actseq;			/* current accounting sequence number */
u_char	*startp;		/* start of request buffer */
u_char	*bufp;			/* working request buffer pointer */
u_char  *delayp;		/* delay time pointer */
time_t	sndtime;		/* time built to send */
u_char	reqauth[16];	/* saved request authenticator */

#ifdef _WIN32
/* session records */
typedef struct	sesrec {
	struct sesrec *next;	/* next in list */
	UINT32		sesid;		/* session id assigned */
	UINT32		nasaddr;	/* NAS IP address */
	SECPORT		nasport;	/* NAS Port descriptor */
	u_char		username[AUTH_STRING_LEN];	/* Username	*/
	time_t		starttime;		/* starting time stamp */
	struct in_addr 	srvaddr;	/* RADIUS server IP addr */
	struct in_addr	ataddr;		/* negoiated address */
	int			iservice;		/* initial service type */
	int			actses;		/* active session count */
	int			totses;		/* total session count */
} SESREC;

SESREC	*seslist;		/* session structure list  */
#endif  /* defined _WIN32 */

UINT32	nextses;		/* next session id number counter */

/* Annex service type translation */
/* NOTE: not all of these services will be logged, but the table entries don't hurt */
/* this should probably be moved to somewhere visable to the services definitions */

char xa2_service_type[NSERVICES] =
{
	-1,							/* security bootup */
	PW_NAS_PROMPT_USER,			/* cli */
	-1,							/* call */
	PW_LOGIN_USER,				/* rlogin */
	PW_LOGIN_USER,				/* telnet */
	PW_OUTBOUND_USER,			/* ports */
	-1,							/* dialup address */
	PW_FRAMED_USER,				/* slip */
	PW_FRAMED_USER,				/* ppp */
	PW_LOGIN_USER,				/* connect */
	-1,							/* slip dyn-dial */
	-1,							/* ppp dyn-dial */
	PW_CALLBACK_PROMPT_USER,	/* dialback */
	PW_FRAMED_USER,				/* arap */
	PW_ADMINISTRATIVE_USER,		/* FTP */
	PW_NAS_PROMPT_USER,			/* cli hook */
	PW_FRAMED_USER,				/* ipx */
	PW_DIALBACK_FRAMED_USER,	/* ipx dialback */
	PW_NAS_PROMPT_USER,			/* rcf */
	-1,							/* ppp timeout */
	-1,							/* ppp dyn-dial timeout */
	-1,							/* slip timeout */
	-1,							/* slip dyn-dial timeout */
	PW_NAS_PROMPT_USER,			/* vms */
	PW_FRAMED_USER,				/* sync ppp */
	-1,							/* sync dialup */
	-1,							/* dyndialpass or user index */
	-1,							/* CHAP secret */
	-1,							/* CHAP good */
	-1,							/* CHAP bad */
	-1,							/* CHAP option */
	-1,							/* IPX dialup address */
	-1,							/* Output string */
	-1,							/* Prompt */
	-1,							/* Appletalk profile */
	-1,							/* none */
	-1,							/* Audit log */
	-1,							/* shell */
	-1,							/* filters */
	-1,							/* PRImate mgr */
	-1,							/* CHAP */
	-1,							/* MLPPP */
	-1,							/* modem */
	-1,							/* max logon */
	-1,							/* UDAS */
    PW_FRAMED_USER              /* vpn ppp */
};
/* the above table should include an entry for all defined service types */


/* local forward prototypes */
#ifdef _WIN32
int syslog( int pri, const char *format, ...);
extern StructErpcdOption *ErpcdOpt;
#endif
int radius_send_acct_stat _((int fd, UINT32 type, UINT32 nasaddr, int cause));
int radius_send_log _((u_char *msg, int len, SESREC *sptr));

/* utility function */

char *nullchk(s)
char *s;
{
return ((s == NULL) ? "(NULL)" : s);
}

/* radius_init_acnt() - Initialize RADIUS Accounting service
 *
 *	one time startup init -
 *	Init's session data block pool
 *	Looks up RADIUS protocol port numb
 *  Opens UDP socket using actfd
 *
 *  Inputs: none
 *  Outputs: session vars re-inited
 *			 actlsa = socket address struct filled in
 *			 fd = socket opened
 *
 *  Returns: 0=success, -1 if error
 */
int radius_init_acnt()
{
	/* re-init session vars */
	actretry = 0;
	actbackup = 0;
	actfailed = 0;
	actseq = 0;

	actrsa.sin_family = AF_INET;

	/* get accounting udp port num */
	svp = getservbyname("radacct", "udp");
	if (svp != NULL) {
      actrsa.sin_port = svp->s_port;
	}
    else {
      actrsa.sin_port = htons(PW_ACCT_UDP_PORT);
		/* default rather than error out */
		/* fprint (stderr, "%s: Service not defined: %s/%s\n", appname, "radacct", "udp");
		exit (-1);
		*/
	}

	/* allocate and bind the local UDP socket */
	actlsa.sin_family = AF_INET;
	actlsa.sin_addr.s_addr = htonl(INADDR_ANY);
	actlsa.sin_port = 0;

	if ((actfd = api_open(IPPROTO_UDP, &actlsa, appname, 1)) == -1) {
		syslog(LOG_ERR, "%s: Failed to open UDP socket, error %i", appname, actfd);
		return -1;
	}

	if (api_bind(actfd, NULL, &actlsa, appname, 1) != 0) {
		syslog(LOG_ERR, "%s: Failed to bind UDP socket, error %i", appname, actfd);
		return -1;
	}
	actinit = 1;
	return 0;
}

/* radius_open_acct() - Open socket to RADIUS Accounting Server
 *
 * Called for any possible server change or if failover to backup server
 *
 * Because the accounting server may be different for any user profile
 * this code only assumes that the server socket is availible but may
 * not be pointing at the desired server.
 * Since this is the case, we will not send the Open Accounting message
 *
 * Inputs: Server = address of server
 *		   bflag = 0 if new request, 1=backup failover
 * Output: acctfd = opened UDP socket
 *			Start Accounting message sent to server
 * Returns:  0 if Success, !0 if error
 */
int radius_open_acct(server, nasaddr, bflag)
struct in_addr server;
UINT32 nasaddr;
int bflag;
{
	Radius_serverinfo *actsrvptr;
	int rc = 0;

	/* Optimization: check if current server is what we want, if so skip */
	/*  if we have switched to a backup server, do not got back to primary just because we started a new session */
	if ((server.s_addr != actrsa.sin_addr.s_addr)
		 && (!(actbackup && (actrsa.sin_addr.s_addr == actbackaddr.s_addr)))) {

		if (debug) printf("%s: Open_server [%s]\n", appname, inet_ntoa(server));

		if (bflag) actwasaddr.s_addr = actrsa.sin_addr.s_addr;	 /* if backup, remember primary address */
		actrsa.sin_addr.s_addr = server.s_addr;			/* init the sockaddr structure with server addr */

		/* get server info for this server address */
		if ((actsrvptr = get_serverinfo(server)) == NULL) {
			/* failed to find, now what? */
			if (debug) printf("%s: Failed to find server info for [%s]\n", appname, inet_ntoa(server));
			syslog(LOG_CRIT, "%s: Failed to find server information for [%s]", appname, inet_ntoa(server));
			return 1;
		}

		/* init server vars (timeout, retries, secret, backup) */
		actdelay = actsrvptr->resp_timeout;
		actretry = actsrvptr->retries;
		acttmos = 0;
		memcpy(actsecret, actsrvptr->shared_secret, 16);

		if (!bflag && !actbackup) {
			actbackaddr.s_addr = actsrvptr->backup_address.s_addr;
			actbackup = 0;
		}

		if (debug) {
			printf("%s: ServerInfo: Timeout=%i, Retries=%i, BackupSrvr=[%s]\n",
				appname, actdelay, actretry, inet_ntoa(actbackaddr));
			printf("%s: Secret= ", appname);
			display_mem(actsecret, sizeof(actsecret));
		}

		/* do udp connect */
		rc = api_connect(actfd, &actrsa, IPPROTO_UDP, appname, 1);

		if (rc == 0) {
			/* set socket non-blocking for receives */
			/* ioctl(actfd, FIONBIO, (char *)&on);	negated by new recv loop*/

#ifdef ACCT_START
			if (!bflag)			   /* possible recursion - not reentrable */
				rc = radius_send_acct_stat(actfd, PW_ACCT_ON, nasaddr, 0);
#endif
		}
	}

	return rc;
}

/*  radius_close_acct() - Close socket to RADIUS Server
 *
 *	Called for subsystem re-initialization
 *		Sends Accounting-Off Status message
 *		Frees dynamically allocated memory
 *		Closes socket
 *
 * Inputs: 	actfd socket
 * Outputs: actfd socket is closed
 * Returns: void
 */
void radius_close_acct(nasaddr)
UINT32 nasaddr;
{
#ifdef _WIN32
	 SESREC *wpnt, *npnt;
#endif  /* _WIN32 */

#ifdef ACCT_START
	 radius_send_acct_stat(actfd, PW_ACCT_OFF, nasaddr, PW_CAUSE_ADMIN_RESET);
#endif

#ifdef _WIN32
	/* free dynamic memory for session blocks */
	wpnt = seslist;
	while (wpnt != NULL) {
		npnt = wpnt->next;
		free(wpnt);
		wpnt = npnt;
	}
#endif  /* _WIN32 */

	api_close(actfd);		/* close socket */
	return;
}


/*  radius_close_actserver() - Close logical session to RADIUS Server
 *
 *	Called for program shutdown
 *		Sends Accounting-Off Status message
 *		only if we were ever initialized and connected
 *
 * Inputs: 	actfd socket
 * Outputs: Accounting-Off sent, remote socket address cleared
 * Returns: void
 */
void radius_close_actserver(nasaddr, cuz)
UINT32 nasaddr;
int cuz;
{
	 if ((actinit == 1) && (actrsa.sin_addr.s_addr != 0)) {
#ifdef ACCT_START
		radius_send_acct_stat(actfd, PW_ACCT_OFF, nasaddr, cuz);
#endif
		actrsa.sin_addr.s_addr = 0;
	 }
	 return;
}



/* radius_fix_act_auth() - Do the authenticator for an Accounting request message
 *
 *	Calculate and insert authenticator for message
 *	Assumes message is otherwise complete; id and length have been set
 *
 * Inputs: startp = start of message
 *			endp = end of message
 *			newauth = pointer to buffer to store new authenticator
 * Outputs: Authenticator is written into buffer
 */

void radius_fix_act_auth(startp, endp, newauth)
u_char *startp, *endp, *newauth;
{
	int slen;

	bzero(startp+4, 16);							/* zero auth slot */
	for(slen=0; (slen<16) && (actsecret[slen] != '\0'); slen++);   /* variable length secret */
	memcpy(endp, actsecret, slen);					/* append secret to outgoing message */
	MDString(startp, (endp-startp)+slen, newauth); 	/* run through MD5 routine */
	memcpy(startp+4, newauth, 16);					/* put digest in authenticator slot */
	bzero(endp, slen);								/* zero secret copy in msg buffer */
	return;
}

#ifdef _WIN32

/* radius_find_acntg_session - Lookup Accounting session context
 *
 * Inputs: Annex IP address, Port, Username
 *		cflag = 1: Start session: overwrite stale or create new
 *		cflag = 0: End session: return found w/no changes, or create new
 *		cflag = -1: Non session: return if found, but don't create new
 *
 * The session id assigned is derived from the current logid upper two bytes;
 *  and an incrementing counter in the lower two bytes
 *
 * Returns: pointer to context block
 *			or NULL if allocation failure or cflag = -1	and not found
 */
SESREC *radius_find_acntg_session(ipaddr, port, user, logid, service, cflag)
UINT32 ipaddr;
SECPORT *port;
u_char *user;
UINT32 logid;
int service, cflag;
{
	SESREC *sespnt = seslist;
	u_char nlstr[1];

	nlstr[0] = 0;
	if (user == NULL) user = nlstr;	 /* avoid problems with strcmp and strcpy */

	/* 	look for matching record on addr & port */
	while (sespnt != NULL) {
		if ((sespnt->nasport.unit == port->unit) &&
            (sespnt->nasport.type == port->type) &&
			(sespnt->nasaddr == ipaddr) ) break;

		sespnt = sespnt->next;
	}

	/* not found at all, create a new one or return NULL */
	if (sespnt == NULL) {
		if (cflag == -1) return sespnt;

		/* allocate memory block */
		if ((sespnt = (SESREC *)malloc(sizeof(SESREC))) != NULL) {

			/* init contents */
			sespnt->sesid = (logid & 0xFFFF0000) | (++nextses & 0x0000FFFF);
			sespnt->nasaddr = ipaddr;
			sespnt->nasport.type = port->type;
	        sespnt->nasport.unit = port->unit;
			strncpy(sespnt->username, user, AUTH_STRING_LEN);
			sespnt->starttime = ((cflag) ? time(NULL) : (time_t)0);
			sespnt->srvaddr.s_addr = 0;
			sespnt->ataddr.s_addr = 0;
			sespnt->iservice = service;
			sespnt->actses = 1;
			sespnt->totses = 1;

			sespnt->next = seslist;		 /* link to front */
			seslist = sespnt;

			if (debug && (cflag == 0)) printf("%s: UNMATCHED Logout!\n", appname);

			if (debug) printf("%s: Sesrec created block=%p User=%s, NASaddr=[%s], Port=%s, Sesid=%08lX\n",
							appname, sespnt, user, inet_ntoa(*(struct in_addr *)&ipaddr), port_to_name(port, portname), sespnt->sesid);
		}
		else if (debug) printf("%s: Sesrec create failed: User=%s, NASaddr=[%s], Port=%s\n",
					appname, user, inet_ntoa(*(struct in_addr *)&ipaddr), port_to_name(port,portname));
	}

	/* check if this record matches on username */
	else if (strcmp(sespnt->username, user) == 0) {

		if (cflag != 1) return sespnt;	  /* if lookup or logout, just return */

		/* look for nesting this login */
		if ((sespnt->iservice == SERVICE_CLI_HOOK)) {
			sespnt->actses++;
			sespnt->totses++;
		}
		else {
			/* write over prior record */
			sespnt->sesid = (logid & 0xFFFF0000) | (++nextses & 0x0000FFFF);
			sespnt->starttime = time(NULL);
			sespnt->srvaddr.s_addr = 0;
			sespnt->ataddr.s_addr = 0;
			sespnt->iservice = service;
			sespnt->actses = 1;
			sespnt->totses = 1;

			if (debug) printf("%s: Sesrec update block=%p User=%s, NASaddr=[%s], Port=%s, Sesid=%08lX\n",
							appname, sespnt, user, inet_ntoa(*(struct in_addr *)&ipaddr), port_to_name(port, portname), sespnt->sesid);
		}
	}
	else {
		if (cflag == -1) return NULL;

		/* write over old record */
		{
			strncpy(sespnt->username, user, AUTH_STRING_LEN);
			sespnt->sesid = (logid & 0xFFFF0000) | (++nextses & 0x0000FFFF);
			sespnt->starttime = time(NULL);
			sespnt->srvaddr.s_addr = 0;
			sespnt->iservice = service;
			sespnt->actses = 1;
			sespnt->totses = 1;

			if (debug) printf("%s: Sesrec overwrite block=%p User=%s, NASaddr=[%s], Port=%s, Sesid=%08lX\n",
							appname, sespnt, user, inet_ntoa(*(struct in_addr *)&ipaddr), port_to_name(port,portname), sespnt->sesid);
		}
	}

	return sespnt;
}

/* radius_free_session() - Deallocate Accounting session context
 *
 * Inputs: pointer to context block
 */
void radius_free_session(sptr)
SESREC *sptr;
{
	SESREC *wptr = seslist;

	if (sptr == NULL) return;

	if (seslist == sptr) {
		seslist = sptr->next;
	}
	else while (wptr != NULL) {
		if (wptr->next == sptr) {
			wptr->next = sptr->next;
			break;
		}
		wptr = wptr->next;
	}
	/* freed - found or not */
	if (debug) printf ("%s: Sesrec free block=%p, Sesid=%08lX\n", appname, sptr, sptr->sesid);

	free((u_char *)sptr);
	return;
}

#endif  /* defined _WIN32 */


#ifdef ACCT_START
/* radius_send_acct_stat() - Send RADIUS Accounting status message
 *
 * This routine builds & sends Accounting Start and Stop messages
 *
 * Inputs: fd = socket number
 *			type = status type code
 * Returns: 0 = sent
 *			-1 = not sent
 * Side effects: uses startp, bufp
 */

int radius_send_acct_stat(fd, type, nasaddr, cause)
int fd, cause;
UINT32 type, nasaddr;
{
#ifndef _WIN32
	struct hostent *hentp;
#endif  /* defined _WIN32 */

    /* allocate buffer */
	if ((startp = bufp = (u_char *)malloc(MAX_RAD_MSG)) != NULL) {

		radius_build_header(&bufp, PW_ACCOUNTING_REQUEST, ++actseq, NULL);
		RADIUS_BUILD_INT(&bufp, PW_ACCT_STATUS_TYPE, type);
		if (nasaddr != 0) {
			RADIUS_BUILD_INT(&bufp, PW_NAS_IP_ADDRESS, nasaddr);		/* for this NAS */
#ifndef _WIN32

		    if ((hentp = gethostbyaddr((char *)&nasaddr, sizeof(nasaddr), AF_INET)) != NULL) {
			radius_add_attribute(&bufp, PW_NAS_IDENTIFIER, strlen(hentp->h_name), hentp->h_name, 0);
		    }
#endif  /* defined _WIN32 */
        }

        if (cause != 0)
			RADIUS_BUILD_INT(&bufp, PW_ACCT_TERMINATE_CAUSE, cause);

		radius_fix_length(startp, bufp);		/* put in length */
		radius_fix_act_auth(startp, bufp, reqauth);			/* build authenticator */
		delayp = NULL;

		radius_send_log(startp, (bufp-startp), NULL);	/* send msg and wait for ack */

		free(startp);		/* dealloc send buffer	*/
	}
	else {
		  syslog(LOG_ERR, "%s: malloc failure sending status msg", appname);
		  return -1;
	}
	return 0;
}
#endif

/* radius_send_log() - Send RADIUS Accounting message
 *
 *	Sends message and waits for ack.
 *	If timeout, try again until counter expire,
 *	Then try backup server
 *
 * Global: actfd - accounting socket, connected to server
 * Inputs: smsg - pointer to message body to send
 * Returns: 0 = success, <0 error
 */
int radius_send_log(smsg, slen, sesptr)
u_char *smsg;
int slen;
#ifdef _WIN32
SESREC *sesptr;
#else  /* not defined _WIN32 */
SESPROFILE *sesptr;
#endif  /* not defined _WIN32 */
{
	int rc = 0;
	int rlen = MAX_RAD_MSG;
	u_char *rcvp, *tptr;
	u_long ntime;
	int dcnt;
	int code_val = 0;

	/* setup receive buffer, don't send if cannot receive */
	if ((rcvp = (u_char *)malloc(rlen))) {

		/* try current first, if failure then backup */
		do {
			/* Do this until count or break */
			for (acttmos=0; acttmos<actretry; acttmos++) {

				if (debug) printf("%s: sending request to [%s]\n", appname, inet_ntoa(actrsa.sin_addr));

				/* send message */
				if (api_send(actfd, smsg, slen, 0, appname, 1) > 0) {
					code_val = (int)*smsg;
					syslog(LOG_DEBUG, "Sent RADIUS %s to %s",
                     			(code_val < NCODETYPES && code_val > 0)? codetype[code_val - 1]: "\0",
                     			inet_ntoa(actrsa.sin_addr));
					if (debug) printf("%s: message #%i sent okay\n", appname, actseq);

					/* read messages until we get the sequence id we want or timeout/error or discard max reached */
					dcnt = 0;
					do {
						rc = api_recvwait(actfd, rcvp, rlen, actdelay, 0, 1, appname);
						dcnt++;
					}  while ((rc > 0) && (rcvp[1] != actseq) && (dcnt < DISCARD_COUNT));

					if (rc <= 0) {
						syslog(LOG_DEBUG, "No response from RADIUS server %s", inet_ntoa(actrsa.sin_addr));
						/* timeout or error */
						if (debug) {
							printf("%s: request timeout/err: error code=%i, retry count=%i, #%i, server=[%s]\n",
								appname, rc, acttmos, actseq, inet_ntoa(actrsa.sin_addr));
						}
						/* if timeout, modify message to attempt to send again */
						if ((rc == -2) && (delayp != NULL))  {
							/* increment sequence id and delay time attribute */
							smsg[1] =  ++actseq;
							/* NOTE: this will change the message and authenticator, but not the length */
							tptr = delayp;		/* retrieve pointer to delay time, but don't let it get changed */
							bcopy((char *)(tptr+2), (char *)&ntime, 4);
							RADIUS_BUILD_INT(&tptr, PW_ACCT_DELAY_TIME, (UINT32)TIMEDIFF(time(NULL), sndtime));
							radius_fix_act_auth(smsg, smsg+slen, reqauth);
						}
					}
					else {
						if (debug) {
							printf("%s: response recvd buf=%p len=%i id=%u\n", appname, rcvp, rc, rcvp[1]);
							/* display_mem(rcvp, rc); */
						}
						/* check if response message is authentic and valid */
#ifdef _WIN32
                        if ((rc = radius_parse_server_response(rcvp, rc, actseq, reqauth, actrsa.sin_addr, NULL)) == PW_ACCOUNTING_RESPONSE) {
#else   /* not defined _WIN32 */
						if ((rc = radius_parse_server_response(rcvp, rc, actseq, reqauth, actrsa.sin_addr)) == PW_ACCOUNTING_RESPONSE) {
#endif  /* not defined _WIN32 */
							code_val = (int)*rcvp;
#ifdef USE_SYSLOG
    							syslog(LOG_DEBUG, "Received RADIUS %s from %s",
            						         (code_val < NCODETYPES && code_val > 0)? codetype[code_val - 1]: "\0",
            						         inet_ntoa(actrsa.sin_addr));
#endif

							if (debug) printf("%s: ack on #%i received okay\n", appname, actseq);
							rc = 0;
							break;
						}
						/* else bad response; try again next time around the loop*/
						if (debug) printf("%s: response failed authentication; code=%i on #%i\n", appname, rc, actseq);
					}
				}
				else {
					/* send failure */
					if (debug) printf("%s: send failure	 rc=%i errno=%i\n", appname, rc, errno);
					syslog(LOG_ERR, "%s: send datagram failed ", appname);
				}
			}
			/* if current server failed, failover or quit */
			if (acttmos >= actretry) {

				syslog(LOG_ERR, "%s: Transmit retries exceeded for server [%s]", appname, inet_ntoa(actrsa.sin_addr));
				if (debug) printf( "%s: Transmit retries exceeded for server [%s]\n", appname, inet_ntoa(actrsa.sin_addr));

				/* if not the backup server, open the backup */
				if (!actbackup) {

					if (actbackaddr.s_addr != 0) {
						actwasaddr.s_addr = actrsa.sin_addr.s_addr;
						actbackup = 1;

						/* try to open backup server */
						if (radius_open_acct(actbackaddr, (UINT32)0, 1) == 0) {
							if (sesptr) sesptr->srvaddr.s_addr = actrsa.sin_addr.s_addr;	/* remember to prevent future switch */
							radius_fix_act_auth(smsg, smsg+slen, reqauth);	 /* redo authenticator on new secret */
							continue;
						}
						syslog(LOG_ERR, "%s: Failed to open Backup server", appname);
					}
					else {
						/* no backup server defined */
						syslog(LOG_CRIT, "%s: No Backup server defined for failover", appname);
					}
				}
				/* backup server has failed too! log event */
				else {
					if (debug) printf("%s: Backup server retries exceeded for [%s]\n", appname, inet_ntoa(actrsa.sin_addr));

					syslog(LOG_ERR, "%s: Backup server retries exceeded for [%s]", appname, inet_ntoa(actrsa.sin_addr));
				}

#ifdef USE_SYSLOG
				syslog(LOG_CRIT, "%s: RADIUS Accounting shutting down", appname);
#endif
				actfailed = 1;			 /* set flag to indicate logging disabled */
				rc = -1;
				break;
			}
			else {
				/* sent okay */
				break;
			}

		} while (actfailed == 0);

		/*deallocate recv buffer  */
		free(rcvp);
	}

	else {
		/* allocation error */
		syslog(LOG_ERR, "%s: malloc failure for response recv bfr", appname);
		return -1;
	}

	return rc;
}


/* radius_build_log() - Build and send RADIUS accounting message
 *
 *  General call to log information to a RADIUS accounting server
 *
 * Called from write_audit_log() in acp_lib.c
 *
 * Inputs: arguments of info to log
 *		event = type of log
 *		nasaddr = IP address of NAS
 *		port = NAS Port descriptor
 *		user = username
 *		service = service type
 *		usraddr	= user's address
 *		stats = statistics block
 *		msg = message text
 *
 * Side effects: global variables are used for the message build and server status
 *		A session context block is started for Login type sessions
 *
 * Outputs: accounting request message is sent to RADIUS server
 *
 * Returns: 0= if log message generated
 *			1= if non-logged event on RADIUS
 *			2= User not in RADIUS regime
 *			    -or-
 *			   radius not enabled (win32 only)
 *		   	-1= failure
 */
#ifndef _WIN32
int radius_build_log(event,logid,nasaddr,port,user,service,usraddr,stats,msg )
int event, service;
UINT32 logid, nasaddr;
SECPORT *port;
char *user, *msg;
NetAddr *usraddr;
LOG_PORT_STATS *stats;
{
        int rlogtype = PW_STATUS_START;         /* default */
        struct environment_spec envblk;
        struct profileses sesblk;
        char sesidbuf[9];
        int cflag, rc=0;
        UINT32 tval,stype;
        struct attrib_handle ahndl;
        struct radius_attribute atrblk;
        struct hostent *hentp;
	struct in_addr negoaddr;

	if (!raddb_up)
		 return (-1);	/* db must be up */
	if (actinit == 0) {
		if ((rc = radius_init_acnt()) != 0 )
			return rc;
	}

	if (debug) {
		printf("Acplog: Event=%s, Service=%s, NASip=[%s], Port=%s, User=%s, Msg=%s\n",
			event_name[event], service_name[service], inet_ntoa(*(struct in_addr *)&nasaddr), port_to_name(port, portname), nullchk(user), nullchk(msg));
		if (stats) printf("%s:\tStats: In: %li, %li\tOut: %li, %li\n", appname, stats->pkts_rx, stats->bytes_rx, stats->pkts_tx, stats->bytes_tx);
	}

	/* Check type of log message event
	 * Only interested the following events: LOGIN, LOGOUT, ACCT
	 * Others ignored by RADIUS for now
	 *
	 * Defined in: acp_policy.h  Strings in: acp_lib.c
	 */
	switch (event) {
	case EVENT_LOGIN:
		cflag = 1;					/* create or update block for this session */
		rlogtype = PW_STATUS_START;	/* session start msg */
		break;
	case EVENT_NEGO_ADDR:
		cflag = -1;
		rlogtype = PW_IPCP_START;
		break;

	case EVENT_LOGOUT:
	case EVENT_ACCT:
		cflag = 0;					/* use existing block, or create temp */
		rlogtype = PW_STATUS_STOP;	/* end of session message and free context */
		break;
	case EVENT_BOOT:				/* Annex just rebooted */
		ses_nas_reboot(nasaddr);	/* clear sessions on this NAS */
		return 2;					/* leave it in acp_logfile */
	default:
		/* ignore all other events */
		if (debug>1) printf("%s: not a loggable event type\n", appname);
		return 2;
	}

	/* Check service type, and reject if not a RADIUS supported Annex service type */
	stype = xa2_service_type[service];
	if (stype == -1)
		return 2;

	if (port->type == DEV_MP) return 2;			/* ignore events on multi-link port */

	if ((user == NULL) || (strlen(user) == 0)) return 2;	/* if no user, Consider not RADIUS */

	/* Now, we like this event;
	 * fill in environment block with the information
     * Find or Create a session context
     */

	bzero((char *)&envblk, sizeof(envblk));
	envblk.annex = nasaddr;
	envblk.port = port->unit;
    envblk.ptype = port->type;
	envblk.protocol = service;
    envblk.group_list = (struct group_entry *)NULL;
    get_time_stamp(&envblk.time);          /* use system local time, ignore failures */
    strncpy(envblk.username, user, sizeof(envblk.username)-1);


	/* find our session context, if not: then not radius user */
	switch (cflag) {
	case -1:
		if ((rc = ses_lookup(&envblk, &sesblk, SDB_FINDACTIVEUSER)) <= 0) {
			if (debug) printf("%s: Lookup search status %i for %s\n",
                              appname, rc, user);
			return 2;
		}
		if (debug > 1) printf("%s: Processing log\n", appname);
		break;

	case 1:
		if ((rc = ses_login(&envblk, &sesblk, logid)) != 0) {
			if (debug) printf("%s: Login search status %i for %s\n", appname, rc, user);
			return rc;
		}
		if (debug > 1) printf("%s: Processing login\n", appname);
		break;

	case 0:
		if ((rc = ses_logout(&envblk, &sesblk, event, logid)) != 0) {
			if (debug) printf("%s: Logout search status %i for %s\n", appname, rc, user);
			return rc;
		}
		if (debug > 1) printf("%s: Processing logout\n", appname);
		break;

	default:
		return 2;  /* shouldn't happen but sesptr would be invalid */
	}


	/* If server unassigned for some underlying reason, we cannot send anything */
	if ((sesblk.srvaddr.s_addr == -1L) || (sesblk.srvaddr.s_addr == 0)) {
		if (rlogtype == PW_STATUS_STOP)
				ses_delete(&envblk, &sesblk);
		if (debug) printf("%s: Not a RADIUS regime (srvaddr=%s)\n", appname, inet_ntoa(sesblk.srvaddr));
		return 2;
	}


	/* test if we have shut down accounting, if so don't touch the network */
	if (actfailed != 0) {
			/* if all done, free-up session record */
			if (rlogtype == PW_STATUS_STOP) ses_delete(&envblk, &sesblk);
			return (-1);
	}

	/* Make socket point to our server */
	/* NOTE!: if we are on the backup server, this value will be the primary server
	 * and not agree with the current socketaddr contents.
	 *  Use the sockaddr value for all real server address needs
	 */
	rc = radius_open_acct(sesblk.srvaddr, nasaddr, 0);
	if (rc != 0) {
		if (rc == 1) actfailed = 1;  /* no recovery if we cannot get it up at all */
		return -1;		/* just fail up */
	}

	/* for Nego Address, parse the address out of the msg string 
	 * and insert into local session context   
	 */
	if (event == EVENT_NEGO_ADDR) {
		if (strncmp(msg, "ip ", 3) == 0) {
			if ((negoaddr.s_addr = inet_addr(msg+3)) != -1) {
				if (sesblk.aservice == 0) sesblk.aservice = PW_FRAMED_USER;
				sesblk.aprotocol = PW_PPP;
				sesblk.ataddr = negoaddr;
				msg = NULL;
				ses_update(&envblk, &sesblk, SDB_FINDACTIVEUSER, EVENT_NEGO_ADDR);
			}
		}
	}
			

	/* Build and send the message to the current server*/
	/* if we can allocate a buffer */
	if ((startp = bufp = (u_char *)malloc(MAX_RAD_MSG)) != NULL) {

		if (debug) printf("%s: Building accounting message\n", appname);

		/* build accounting message  */
		radius_build_header(&bufp, PW_ACCOUNTING_REQUEST, ++actseq, NULL);
		RADIUS_BUILD_INT(&bufp, PW_ACCT_STATUS_TYPE, rlogtype);

		/* session info from saved data */
		RADIUS_BUILD_STR(&bufp, PW_USER_NAME, sesblk.username);
		RADIUS_BUILD_INT(&bufp, PW_NAS_IP_ADDRESS, nasaddr);

		if ((hentp = gethostbyaddr((char *)&nasaddr, sizeof(nasaddr), AF_INET)) != NULL) {
			radius_add_attribute(&bufp, PW_NAS_IDENTIFIER, strlen(hentp->h_name), hentp->h_name, 0);
		}

        /* for non-serial port types that cannot be encoded into a RADIUS port type,
         * put port type into high order part of port number
         */
        tval = radius_convert_type(port->type);
        if ((tval != PW_PORT_VIRTUAL) && (tval != -1)) {
            RADIUS_BUILD_INT(&bufp, PW_NAS_PORT, port->unit);
        }
        else {
            RADIUS_BUILD_INT(&bufp, PW_NAS_PORT, ((port->type * VPORT_MULT) + port->unit));
        }

		if (tval != -1)
			RADIUS_BUILD_INT(&bufp, PW_NAS_PORT_TYPE, tval);

	/* do calling information */
        if (strlen(sesblk.caller) > 0 )
    	    RADIUS_BUILD_STR(&bufp, PW_CALLING_STATION_ID, sesblk.caller);
    	if (strlen(sesblk.called) > 0 )
    	    RADIUS_BUILD_STR(&bufp, PW_CALLED_STATION_ID, sesblk.called);
	
	if (sesblk.aservice) {
            RADIUS_BUILD_INT(&bufp, PW_USER_SERVICE_TYPE, (u_long)sesblk.aservice);
        }
        else if (stype != -1) {
            RADIUS_BUILD_INT(&bufp, PW_USER_SERVICE_TYPE, stype);
        }


        /* service attributes based on authorization */
        /* NOTE: not all the following services are currently supported,
         *      but the case is simply paired with the nearest equivalent
         */

        switch (sesblk.aservice) {
        case PW_FRAMED_USER:
        case PW_DIALBACK_FRAMED_USER:
            if (!sesblk.aprotocol) goto report_protocol;
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, (u_long)sesblk.aprotocol);

            switch (sesblk.aprotocol) {
            case PW_PPP:
            case PW_SLIP:
			    if (!sesblk.ataddr.s_addr) goto report_address;
                RADIUS_BUILD_INT(&bufp, PW_FRAMED_ADDRESS, sesblk.ataddr.s_addr);
                break;

            case PW_ARAP:
            case PW_IPXSLIP:
                goto report_address;
			    break;
            }
            break;

        case PW_LOGIN_USER:
        case PW_DIALBACK_LOGIN_USER:
            if (sesblk.aprotocol == 255) goto report_protocol;
 	    	RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, (u_long)sesblk.aprotocol);
            if ((sesblk.aprotocol == PW_TELNET) && (sesblk.aport))
                RADIUS_BUILD_INT(&bufp, PW_LOGIN_TCP_PORT, (u_long)sesblk.aport);
			if (sesblk.ataddr.s_addr)
                RADIUS_BUILD_INT(&bufp, PW_LOGIN_HOST, sesblk.ataddr.s_addr);
			break;

        case PW_NAS_PROMPT_USER:
        case PW_ADMINISTRATIVE_USER:
        case PW_CALLBACK_PROMPT_USER:
            break;

        case PW_OUTBOUND_USER:
            if (sesblk.aport) RADIUS_BUILD_INT(&bufp, PW_LOGIN_TCP_PORT, (u_long)sesblk.aport);
            break;

        case PW_AUTHENTICATE_USER:
        default:
                /* fall through */

report_protocol:
		/* service attributes based on delivery */
		switch (service) {
		case SERVICE_RLOGIN:
			RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, PW_RLOGIN);
			break;
		case SERVICE_TELNET:
 			RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, PW_TELNET);
			break;
		case SERVICE_CONNECT:
 			RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, PW_LAT);
			break;
		case SERVICE_SLIP:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_SLIP);
			break;
		case SERVICE_PPP:
		case SERVICE_SYNC_PPP:
        case SERVICE_VPN_PPP:
		case SERVICE_MP:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_PPP);
			break;
		case SERVICE_ARAP:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_ARAP);
			break;
		case SERVICE_IPX:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_IPXSLIP);
			break;
		}

report_address:
        /* remote or host address in event record */
		if (usraddr) {
			switch (usraddr->type) {
			case IP_ADDRT:
				/* if login service then this is the Host address */
				if (stype == PW_LOGIN_USER) {
					RADIUS_BUILD_INT(&bufp, PW_LOGIN_HOST, usraddr->n.ip_addr.inet);
				}
				else {
					RADIUS_BUILD_INT(&bufp, PW_FRAMED_ADDRESS, usraddr->n.ip_addr.inet);
				}
				break;

			case IPX_ADDRT:
				RADIUS_BUILD_INT(&bufp, PW_FRAMED_IPXNET, usraddr->n.ipx_addr.network);
				break;

			case LAT_ADDRT:
				RADIUS_BUILD_STR(&bufp, PW_LOGIN_LAT_SERVICE, usraddr->n.lat_addr.service);
				RADIUS_BUILD_STR(&bufp, PW_LOGIN_LAT_NODE, usraddr->n.lat_addr.node);
				break;
			}
        }
        } /* end switch (aservice) */

		/* accounting specific fields */
#ifndef USE_64
                sprintf(sesidbuf, "%08.8lX", sesblk.sesid);
#else
		sprintf(sesidbuf, "%08.8X", sesblk.sesid);
#endif
		RADIUS_BUILD_STR(&bufp, PW_ACCT_SESSION_ID, sesidbuf);
		RADIUS_BUILD_INT(&bufp, PW_ACCT_AUTHENTIC, PW_AUTH_RADIUS );

		if (sesblk.class[0]) {
            radius_add_attribute(&bufp, PW_CLASS, sesblk.class[0],
                                 sesblk.class + 1, 0);
		}

		delayp = bufp;	/* save for later retry update */
		RADIUS_BUILD_INT(&bufp, PW_ACCT_DELAY_TIME, 0);
		sndtime = time(NULL);

		if (event != EVENT_LOGIN) 	 /* calc elapsed session time */
			if (sesblk.starttime)	 /* but don't send if start is zero*/
				RADIUS_BUILD_INT(&bufp, PW_ACCT_SESSION_TIME,
                                 (UINT32)TIMEDIFF(time(NULL),
                                                  sesblk.starttime) );

		if (stats) {
			RADIUS_BUILD_INT(&bufp, PW_ACCT_INPUT_PACKETS, stats->pkts_rx);
			RADIUS_BUILD_INT(&bufp, PW_ACCT_OUTPUT_PACKETS, stats->pkts_tx);
			RADIUS_BUILD_INT(&bufp, PW_ACCT_INPUT_OCTETS, stats->bytes_rx);
			RADIUS_BUILD_INT(&bufp, PW_ACCT_OUTPUT_OCTETS, stats->bytes_tx);
		}
		/* RADIUS_BUILD_INT(&bufp, PW_ACCT_TERMINATE_CAUSE, ?? );	* reason code */

		if (msg)
			RADIUS_BUILD_STR(&bufp, PW_PORT_MESSAGE, msg);				/* to see whats here */

		radius_fix_length(startp, bufp);		/* put in length  */
		radius_fix_act_auth(startp, bufp, reqauth);		/* build authenticator */

		if (debug) {
			printf("%s: Built Accounting message #%u\n", appname, actseq);
			display_mem(startp, (bufp-startp));
		}

		rc = radius_send_log(startp, (bufp-startp), &sesblk);	/* send msg and wait for ack */

		free(startp);		/* dealloc send buffer  */
	}
	else {
		/* allocation error */
		syslog(LOG_ERR, "%s: malloc failure in send log, send bfr", appname);
		return -1;
	}
	/* if all done, free-up session record */
	if (rlogtype == PW_STATUS_STOP) {
		ses_delete(&envblk, &sesblk);
	}
	return rc;
}

#else   /* defined _WIN32 */

int radius_build_log(event,logid,nasaddr,port,user,service,usraddr,stats,msg )
int event, service;
UINT32 logid, nasaddr;
SECPORT *port;
char *user, *msg;
NetAddr *usraddr;
LOG_PORT_STATS *stats;
{
	int rlogtype = PW_STATUS_START;		/* default */
	SESREC *sesptr;
	char sesidbuf[9];
	int cflag, rc=0;
	UINT32 tval,stype;
	struct in_addr negoaddr;

	if ( !ErpcdOpt->RadiusAuthentication )
	{
		return 2;	/* Radius not enabled, try other logging */
	}
	if ( !ErpcdOpt->UseRadiusLogging )
	{
		return 2;	/* Not a Radius logged event */
	}

	if (actfailed != 0) return (-1);
	if (actinit == 0) {
		if ((rc = radius_init_acnt()) != 0 )
			return rc;
	}

	if (debug) {
		printf("%s: Event=%s, Service=%s, NASip=[%s], Port=%s, User=%s, Msg=%s\n",
			appname, event_name[event], service_name[service], inet_ntoa(*(struct in_addr *)&nasaddr), port_to_name(port, portname), nullchk(user), nullchk(msg));
		if (stats) printf("%s:\tStats: In: %li, %li\tOut: %li, %li\n", appname, stats->pkts_rx, stats->bytes_rx, stats->pkts_tx, stats->bytes_tx);
	}

	/* Check type of log message event
	 * Only interested the following events: LOGIN, LOGOUT, ACCT
	 * Others ignored by RADIUS for now
	 *
	 * Defined in: acp_policy.h  Strings in: acp_lib.c
	 */
	switch (event) {
	case EVENT_LOGIN:
		cflag = 1;					/* create or update block for this session */
		rlogtype = PW_STATUS_START;	/* session start msg */
		break;
	case EVENT_NEGO_ADDR:
		cflag = -1;
		rlogtype = PW_IPCP_START;
		break;


	case EVENT_LOGOUT:
	case EVENT_ACCT:
		cflag = 0;					/* use existing block, or create temp */
		rlogtype = PW_STATUS_STOP;	/* end of session message and free context */
		break;

	default:
		/* ignore all other events */
		if (debug) printf("%s: not a loggable event type\n", appname);
		return 2;
	}

	/* Check service type, and reject if not a RADIUS supported Annex service type */
	stype = xa2_service_type[service];
	if (stype == -1)
		return 2;

	if (port->type == DEV_MP) return 2; /* Ignore MP requests */

	if ((user == NULL) || (strlen(user) == 0)) return 2;	/* if no user, Consider not RADIUS */

        if (stype == PW_LOGIN_USER) cflag = -1;		/* if terminal service, do not update session block */

	/* Now, Find or Create a session context	 */
	if ((sesptr = radius_find_acntg_session(nasaddr, port, user, logid, service, cflag)) == NULL) {
             if (cflag != -1) {
		/* allocation error */
		syslog(LOG_ERR, "%s: malloc failure creating session block", appname);
		return -1;
             }
             else {
		return 2;  /* not radius */
             }
	}

	/* If we don't have a server address yet (Login), figure out where this should go
	 * taking into account that we may have failed over to the backup server
	 */
	if (sesptr->srvaddr.s_addr == 0) {

		/* Get the accounting server, the address has been
		   resolved and saved as the default accounting server
		 */
        sesptr->srvaddr = default_servers->acct_server;

	}

	/* If not in RADIUS regime or otherwise unassigned, Bail out now */
	if ((sesptr->srvaddr.s_addr == -1L) || (sesptr->srvaddr.s_addr == 0)) {
		if (rlogtype == PW_STATUS_STOP)
				radius_free_session(sesptr);
		if (debug) printf("%s: Not a RADIUS regime (srvaddr=%08lX)\n", appname, sesptr->srvaddr.s_addr);
		return 2;
	}

	/* If Login type service, this is nested inside of CLI session for start/stop purposes */
	/* NOTE: This could be fixed by some sort of nested or multisession logging */
	if (stype == PW_LOGIN_USER)
		return 1;

	/* For RADIUS session stops, In the following cases we use the ACCT event instead of LOGOUT:
	 * not if service_from == SERVICE_PORTS
	 *	yes if port_from_type == DEV_VIRTUAL
	 *		or service_from == {TELNET, RLOGIN, CONNECT}
	 * Indicate to standard logging that this is an ignored but RADIUS event
	 */
	if (event == EVENT_LOGOUT) {
		if (service == SERVICE_PORTS) return 1;
		if (!((port->type == DEV_VIRTUAL) ||
			  ((service == SERVICE_TELNET) ||
			   (service == SERVICE_RLOGIN) ||
			   (service == SERVICE_CONNECT)))) return 1;
	}

	/* if a nested login/logout, ignore this event */
	if (sesptr->actses > 1) {
		if (rlogtype == PW_STATUS_STOP) sesptr->actses--;
		return 1;
	}

	/* Make socket point to our server */
	/* NOTE!: if we are on the backup server, this value will be the primary server
	 * and not agree with the current socketaddr contents.
	 *  Use the sockaddr value for all real server address needs
	 */
	rc = radius_open_acct(sesptr->srvaddr, nasaddr, 0);
	if (rc != 0) {
		if (rc == 1) actfailed = 1;  /* no recovery if we cannot get it up at all */
		return -1;		/* just fail up */
	}

	/* Build and send the message to the current server*/
	/* if we can allocate a buffer */
	if ((startp = bufp = (u_char *)malloc(MAX_RAD_MSG)) != NULL) {

		if (debug) printf("%s: Building accounting message\n", appname);

		/* build accounting message  */
		radius_build_header(&bufp, PW_ACCOUNTING_REQUEST, ++actseq, NULL);
		RADIUS_BUILD_INT(&bufp, PW_ACCT_STATUS_TYPE, rlogtype);

		/* session info from saved data */
		RADIUS_BUILD_STR(&bufp, PW_USER_NAME, sesptr->username);
		RADIUS_BUILD_INT(&bufp, PW_NAS_IP_ADDRESS, sesptr->nasaddr);

        /* for non-serial port types that cannot be encoded into a RADIUS port type,
         * put port type into high order part of port number
         */
        tval = radius_convert_type(port->type);
        if ((tval != PW_PORT_VIRTUAL) && (tval != -1)) {
            RADIUS_BUILD_INT(&bufp, PW_NAS_PORT, port->unit);
        }
        else {
            RADIUS_BUILD_INT(&bufp, PW_NAS_PORT, ((port->type * VPORT_MULT) + port->unit));
        }

		if (tval != -1)
			RADIUS_BUILD_INT(&bufp, PW_NAS_PORT_TYPE, tval);

		if (stype != -1)
			RADIUS_BUILD_INT(&bufp, PW_USER_SERVICE_TYPE, stype);

		/* service attributes */
		switch (service) {
		case SERVICE_RLOGIN:
			RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, PW_RLOGIN);
			break;
		case SERVICE_TELNET:
 			RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, PW_TELNET);
			break;
		case SERVICE_CONNECT:
 			RADIUS_BUILD_INT(&bufp, PW_LOGIN_SERVICE, PW_LAT);
			break;
		case SERVICE_SLIP:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_SLIP);
			break;
		case SERVICE_PPP:
		case SERVICE_SYNC_PPP:
        case SERVICE_VPN_PPP:
		case SERVICE_MP:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_PPP);
			break;
		case SERVICE_ARAP:
            RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_ARAP);
			break;
		case SERVICE_IPX:
 			RADIUS_BUILD_INT(&bufp, PW_FRAMED_PROTOCOL, PW_IPXSLIP);
			break;
		}

		/* for Nego Address, parse the address out of the msg string 
	 	 * and insert into local session context */
		if (event == EVENT_NEGO_ADDR) {
			if (strncmp(msg, "ip ", 3) == 0) {
				if ((negoaddr.s_addr = inet_addr(msg+3)) != -1) {
					RADIUS_BUILD_INT(&bufp, PW_FRAMED_ADDRESS,
					negoaddr.s_addr);
					msg = NULL;
					sesptr->ataddr = negoaddr;
				}
			}
		}


		/* remote or host address */
		else if (usraddr) {
			switch (usraddr->type) {
			case IP_ADDRT:
				/* if login service then this is the Host address */
				if (stype == PW_LOGIN_USER) {
					RADIUS_BUILD_INT(&bufp, PW_LOGIN_HOST, usraddr->n.ip_addr.inet);
				}
				else {
					RADIUS_BUILD_INT(&bufp, PW_FRAMED_ADDRESS, usraddr->n.ip_addr.inet);
				}
				break;

			case IPX_ADDRT:
				RADIUS_BUILD_INT(&bufp, PW_FRAMED_IPXNET, usraddr->n.ipx_addr.network);
				break;

			case LAT_ADDRT:
				RADIUS_BUILD_STR(&bufp, PW_LOGIN_LAT_SERVICE, usraddr->n.lat_addr.service);
				RADIUS_BUILD_STR(&bufp, PW_LOGIN_LAT_NODE, usraddr->n.lat_addr.node);
				break;
			}
		}

		/* do we have a saved nego address? */
		else if (sesptr->ataddr.s_addr) {
			switch (stype) {
			case PW_FRAMED_USER:
				RADIUS_BUILD_INT(&bufp, PW_FRAMED_ADDRESS, sesptr->ataddr.s_addr);
				break;
			}
		}
		
		/* accounting specific fields */
		sprintf(sesidbuf, "%08lX", sesptr->sesid);
		RADIUS_BUILD_STR(&bufp, PW_ACCT_SESSION_ID, sesidbuf);
		RADIUS_BUILD_INT(&bufp, PW_ACCT_AUTHENTIC, PW_AUTH_RADIUS );

		delayp = bufp;	/* save for later retry update */
		RADIUS_BUILD_INT(&bufp, PW_ACCT_DELAY_TIME, 0);
		sndtime = time(NULL);

		if (event != EVENT_LOGIN) 	 /* calc elapsed session time */
			if (sesptr->starttime)	 /* but don't send if start is zero*/
				RADIUS_BUILD_INT(&bufp, PW_ACCT_SESSION_TIME, (UINT32)TIMEDIFF(time(NULL), sesptr->starttime) );

		if (stats) {
			RADIUS_BUILD_INT(&bufp, PW_ACCT_INPUT_PACKETS, stats->pkts_rx);
			RADIUS_BUILD_INT(&bufp, PW_ACCT_OUTPUT_PACKETS, stats->pkts_tx);
			RADIUS_BUILD_INT(&bufp, PW_ACCT_INPUT_OCTETS, stats->bytes_rx);
			RADIUS_BUILD_INT(&bufp, PW_ACCT_OUTPUT_OCTETS, stats->bytes_tx);
		}
		/* RADIUS_BUILD_INT(&bufp, PW_ACCT_TERMINATE_CAUSE, ?? );	* reason code */

		if (msg)
			RADIUS_BUILD_STR(&bufp, PW_PORT_MESSAGE, msg);				/* to see whats here */

		radius_fix_length(startp, bufp);		/* put in length  */
		radius_fix_act_auth(startp, bufp, reqauth);		/* build authenticator */

		if (debug) {
			printf("%s: Built Accounting message #%u\n", appname, actseq);
			display_mem(startp, (bufp-startp));
		}

		rc = radius_send_log(startp, (bufp-startp), sesptr);	/* send msg and wait for ack */

		free(startp);		/* dealloc send buffer  */
	}
	else {
		/* allocation error */
		syslog(LOG_ERR, "%s: malloc failure in send log, send bfr", appname);
		return -1;
	}
	/* if all done, free-up session record */
	if (rlogtype == PW_STATUS_STOP) {
		radius_free_session(sesptr);
	}
	return rc;
}

#endif  /* defined _WIN32 */
