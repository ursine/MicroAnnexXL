/*
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 * 	%$(Description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 * Module Reviewers:
 *
 *	%$(reviewers)$%
 *
 *****************************************************************************
 */


/*
 *    Include Files
 */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>

#ifndef _WIN32
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/time.h>
#endif
#include <signal.h>

#include "../libannex/api_if.h"
#include "../inc/erpc/netadmp.h"
#include "acp_lib.h"
#include "../inc/port/install_dir.h"
#include "../inc/courier/courier.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "acp_policy.h"
#include "errno.h"
#include "../libannex/asn1.h"
#include "getacpuser.h"
#include "environment.h"

#if TLIPOLL
#include <poll.h>
#endif


#ifdef USE_SYSLOG
#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#endif /* _WIN32 */
#endif /* USE_SYSLOG */

extern int alarm_flag;
extern int debug;
extern StructErpcdOption *ErpcdOpt;
extern void dial_timer();

/* External Routine Declarations */
#define DEF_LINGER_TIME 120

void inet_number();
void set_long();
void erpc_reject();
int dialout_srpc_open();
int srpc_return();
int srpc_callresp();
int return_dialup_address_tcp();
int return_max_logon_tcp();
int serial_validate_authorize_tcp();
int return_user_index_tcp();
int return_ppp_security_tcp();
int return_port_to_annex_tcp();
int return_annex_to_net_tcp();
int net_to_port_authorize_tcp();
int promptstring_wt();
int promptstring_tcp();
int outputstring_tcp();
int return_appletalk_profile_tcp();
int return_hook_callback_tcp();
int return_serial_validate_tcp();
int inet_name();
void log_timer();
void log_acknowledge();

#ifdef _WIN32
void LogACPToEventLog();
int gettimeofday();
void alarm();
int getpid();
#endif

extern KEYDATA *make_table();
extern void generate_table();
extern int cipher();
extern void racp_timer();
extern int radius_build_log();

#ifdef FASTRETRY
#define TURNAROUND(t)    INPUT_POLL_TIMEOUT
#else
#define TURNAROUND(t)    t
#endif

char    *service_name[NSERVICES] =
    {
        "security",
        "cli",
        "call",
        "rlogin",
        "telnet",
        "pserv" ,
        "dialup address",
        "slip",
        "ppp",
        "connect",
        "slip dyn-dial",
        "ppp dyn-dial",
        "dialback",
        "arap",
        "ftp daemon",
        "cli hook",
        "ipx",
        "ipx dialback",
	"rcf",
	"ppp timeout",
	"ppp dyn-dial timeout",
	"slip timeout",
	"slip dyn-dial timeout",
        "vms",
	"sync ppp",
	"sync dialup",
        "user index",
        "chap secret",
        "chap",
        "chap",
        "chap",
        "ipx dialup address",
        "output",
        "prompt",
        "appletalk profile",
        "none",
        "audit log",
        "shell",
        "filters/routes",
	"WAN manager",
        "chap",
	"Multi-Link PPP",
	"modem",
        "max logon",
        "VPN tunnel",
        "vpn ppp"
    };
#define MAX_SERVICE_NAME  30  /* length of the service name string */

char    *event_name[NEVENTS] =
    {
        "boot",
        "login",
        "reject",
        "logout",
        "timeout",
        "provide",
        "no provide",
        "dial",
        "bad response",
        "option refused",
        "acct",
        "parse error",
        "BLACKLISTED",
        "call accept",
        "call reject",
        "call disconnect",
        "nego addr",
        "call connect",
        "mp attach",
        "mp detach",
        "line seizure",
    };
#define MAX_EVENT_NAME  20 	 /* length of the event name string */

#ifdef USE_SYSLOG
int    event_priority[NEVENTS] =
    {
        LOG_INFO,	/* boot */
        LOG_INFO,	/* login */
        LOG_WARNING,	/* reject */
        LOG_INFO,	/* logout */
        LOG_NOTICE,	/* timeout */
        LOG_NOTICE,	/* provide */
        LOG_WARNING,	/* no provide */
        LOG_INFO,	/* dial */
	LOG_ERR,	/* bad resp */
	LOG_ERR,	/* option refused */
        LOG_INFO,	/* acct */
        LOG_ERR,	/* parse error */
        LOG_WARNING,	/* BLACKLISTED */
        LOG_INFO,	/* call accept */
        LOG_INFO,	/* call reject */
        LOG_INFO,	/* call disconnect */
        LOG_INFO,	/* login addresses */
        LOG_INFO,	/* call connect */
        LOG_INFO,   /* mp attach */
        LOG_INFO,   /* mp detach */
    };
#endif /* USE_SYSLOG */

extern ACP *globalacp;


/*****************************************************************************
 *
 * NAME: acp_auth_resp()
 *
 * DESCRIPTION: Performs and RACP authorization-response
 *
 * ARGUMENTS:
 * ACP *acp; - INPUT connected acp
 * UINT32 grant - INPUT status of authorization grant
 * any of the following can be NULL, in which case no segment is built
 * UINT32 *cli_mask - INPUT pointer to returned CLI command mask
 * UINT32 *hooks_mask - INPUT pointer to HOOKS mask
 * char *user_name - INPUT username of user
 *
 * RETURN VALUE: next free space after PDU
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int acp_auth_resp(acp, grant, cli_mask, hooks_mask, user_name)
ACP *acp;
UINT32 grant;
UINT32 *cli_mask;
UINT32 *hooks_mask;
char *user_name;
{
    u_char cbuff[MAXPDUSIZE];
    int datalength = MAXPDUSIZE;

    if ((errno = racp_send_auth_resp(acp, cbuff, datalength, grant, cli_mask,
                                     hooks_mask, user_name, NULL, NULL))
        != ESUCCESS)
        return(ACP_ERROR);
}
int acp_exec_reply(acp, grant, port, flags, text, codep)
ACP *acp;
int grant;
SECPORT *port;
int *flags;
char *text;
int *codep;
{
    char cbuff[MAXPDUSIZE];
    int size = MAXPDUSIZE;

    if ((errno = racp_send_exec_reply(acp, cbuff, size, grant, port, flags,
                                      text, codep)) != ESUCCESS)
        return(ACP_ERROR);

    return(ESUCCESS);
}


/*****************************************************************************
 *
 * NAME: acp_lib_exec_req()
 *
 * DESCRIPTION: Performs ACP execution request
 *
 * ARGUMENTS:
 * ACP *acp - INPUT connected acp
 * int service_from - INPUT service user is on
 * int service_req - INPUT service user requests
 * any of the following can be NULL, in which case the relevant data is
 * neither sent nor received
 * char *rtext - OUTPUT other relevant text
 * char *username - INPUT username
 * char *phone - INPUT phone number to dial out
 * char *access - INPUT user access code
 * char *text - INPUT other relevant text
 * char *job - INPUT job to execute
 * char *portmask - INPUT bit array of ports allowed for execution
 * int *flagsp - INPUT flags for execution
 * int *timeoutp - INPUT timeout for executed task
 * int *echop - INPUT should user-entered text be echoed
 * NetAddr *destaddr - INPUT network address of where to preform action
 * int *codep - INPUT/OUTPUT code
 * int *grantp - OUTPUT status of execution
 * SECPORT *port_from - INPUT port user is on
 * SECPORT *port_dest - OUTPUT port execution preformed on
 * void (*timecall)() - INPUT timeout function 
 *
 * RETURN VALUE: errno_t
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

/* return -1 normal error */
/* return -2 timeout */
/* for now, execution request can only get response */
static int acp_lib_exec_req(acp, service_from, service_req, rtext, username,
                 phone, access, text, job, portmask, flagsp,
                 timeoutp, echop, destaddr, codep, grantp,
                 port_from, port_dest, timecall)
ACP *acp;
int service_from, service_req;
char *rtext, *username, *phone, *access, *text, *job;
unsigned char *portmask;
int *flagsp, *timeoutp, *echop;
NetAddr *destaddr;
int *codep, *grantp;
SECPORT *port_from, *port_dest;
void (*timecall)();
{
    ERQ_PROFILE opt_info;
    u_char cbuff[MAXPDUSIZE];
    u_char *packet = cbuff;
    u_char *data = cbuff;
    u_char *pdu;
    u_char type;
    int datalength = MAXPDUSIZE;
    int pdulen; /*, rcode;*/
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);

    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
#if defined(need_select)
    INT32    readfds;
    INT32    sdelay;
#else
#ifndef SLIP
#ifdef    FD_ZERO
    fd_set    readfds;
#else
    int    readfds;
#endif
    struct timeval timeval;
#endif
#endif
#if TLIPOLL
#define NPOLL 1
	struct pollfd pollfds[NPOLL];
#endif	

    if (debug)
      printf("acp_lib_exec_req\n");

    bzero ((char*)&opt_info, sizeof(ERQ_PROFILE));

    opt_info.username = username;
    opt_info.phone = phone;
    opt_info.access = access;
    opt_info.text = text;
    opt_info.job = job;
    opt_info.portmask = (char *)portmask;
    opt_info.flags = flagsp;
    opt_info.timeout = timeoutp;
    opt_info.echo = echop;
    opt_info.destaddr = destaddr;
    opt_info.code = codep;
    opt_info.port_from = port_from;
    if ((errno = racp_send_exec_req(acp, cbuff, datalength, service_from,
                                    service_req, &opt_info)) != ESUCCESS) {
        return(ACP_ERROR);
    }
    
    if (timeoutp && *timeoutp) {
        int nfound;
        
#ifdef SLIP
        /* post a read timeout */
        if(so_schedule_timeout(acp->s, delay)) {
            perror("erpc_callresp: so_schedule_timeout");
            return(ACP_ERROR);
        }
#else
#ifdef need_select
        /* use alarm for timeout on recv */
#ifdef _WIN32
		RegistAlarmHandler(timecall);
#else
        signal(SIGALRM, timecall);
#endif
        alarm(*timeoutp);
        alarm_flag = 0; /* clear alarm signal flag */
#else
            /* use select to wait for data */
#if TLIPOLL
        pollfds[0].fd = acp->s;
        pollfds[0].events = POLLIN;
        /* *timeoutp is in sec and poll wants it in msec */
        if(poll(pollfds, NPOLL, (*timeoutp*1000)) < 0) {
            if(errno != EINTR) { /* is this wrong ?? */
                perror("erpc_sendresp: poll");
                return(ACP_ERROR);
            }
            if(debug)
                printf("erpc_subr: poll returned -1\n");
        }
        if ((pollfds[0].revents ==  0) ||
            ((pollfds[0].revents !=  POLLIN) && 
             (errno == EINTR))) {
            return(ACP_ERROR);
        }
#else
#ifdef FD_ZERO
        FD_ZERO(&readfds);
        FD_SET(acp->s, &readfds);
#else
        readfds = (1 << acp->s);
#endif

            /* use real select */
        timeval.tv_sec = *timeoutp;
        timeval.tv_usec = 0;
        nfound = select(acp->s + 1, &readfds, NULL, NULL, &timeval);

        /* error? */
        
        if (nfound < 0 && errno != EINTR) {
            perror("erpc_sendresp: select");
            return(ACP_ERROR);
        }
        
        /* timeout? */
        if (nfound == 0 || (nfound <0 && errno == EINTR)) {
            return(ACP_ERROR);
        }
        
#endif /*TLIPOLL*/
#endif /*need_select*/
#endif /*SLIP*/
    }
    
    if ((errno = racp_recv_pdu(acp, cbuff, MAXPDUSIZE, &pdulen, &pdu))
        != ESUCCESS) {
	if (debug)
	    printf("racp_recv_pdu = %d\n",errno);
        return(ACP_ERROR);
    }

    if ((pdu = asn_parse_header(pdu, &pdulen, &type)) == NULL) {
        return(ACP_ERROR);
    }
    /* only allow exec-reply */
    if (type != RACP_EXEC_REPLY)
        return(ACP_ERROR);

    if (racp_parse_exec_reply(pdu, &pdulen, grantp, port_dest, flagsp, rtext,
                              codep) == NULL) {
        errno = EINVAL;
        return(ACP_ERROR);
    }
    return(ESUCCESS);
}

int acp_info_resp(acp, grant, opt_info)

ACP *acp;
int grant;
IRQ_PROFILE *opt_info;
{
    char cbuff[MAXPDUSIZE];
    int pdulen = MAXPDUSIZE;

    if ((errno = racp_send_info_resp(acp, cbuff, pdulen, grant, opt_info))
	!= ESUCCESS)
        return(ACP_ERROR);

    return(ESUCCESS);
}

void terminate_session()
{
/*	Sleep(3000);
fprintf(stderr, "--------------------------------------terminate-session\n");
*/
	ErpcdExit(0);
}

dialup_address_authorize(Acp, grant, net_type, loc, rem, node, filters, routes)

ACP        *Acp;            /*  points to ACP state  */
UINT32        grant;            /*  grant, deny, error   */
int net_type;
UINT32        loc, rem;        /*  local and remote addrs   */
u_char *node;
STR_LIST *filters, *routes;

{
    int        rlength;
    AUTH_RDA    cdata;
    ACK        rdata;

    if(debug)
        puts("dialup_address_authorize");

    if (ISTCP(Acp->state))
      return(return_dialup_address_tcp(Acp, grant, net_type, loc, rem, node,
				       filters, routes));

    set_long(cdata.auth_handle, Acp->handle);
    set_long(cdata.auth_grant, grant);
    cdata.auth_loc = loc;
    cdata.auth_rem = rem;
    bcopy(node, cdata.auth_node, 6);
    return srpc_callresp(
        Acp->Srpc, Acp->s, (struct sockaddr_in *)NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_DIALUP_ADDRESS_AUTHORIZE),
        (char *)(&cdata), SIZE_AUTH_RDA, 1, AUTH_TIMEOUT,
        (char *)(&rdata), SIZE_ACK, &rlength);
}

serial_validate_authorize(Acp, grant)

ACP             *Acp;                   /*  points to ACP state  */
UINT32		grant;                  /*  grant, deny, error   */

{
        int             rlength;
        AUTH_SERVAL     cdata;
        ACK             rdata;

        if(debug)
                puts("serial_validate_authorize");

        if (ISTCP(Acp->state))
          return(serial_validate_authorize_tcp(Acp, grant));
	else if(ISREJECT(grant))
	       grant= REQ_DENIED;

        set_long(cdata.auth_handle, Acp->handle);
        set_long(cdata.auth_grant, grant);
        return srpc_callresp(
                Acp->Srpc, Acp->s, NULL, Acp->pid,
                (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
                (unsigned short)(ACP_SERIAL_VALIDATE_AUTHORIZE),
                (char *)(&cdata), SIZE_AUTH_SERVAL, 1, AUTH_TIMEOUT,
                (char *)(&rdata), SIZE_ACK, &rlength);
}

serial_validate_authorize_tcp(acp, grant)
     ACP *acp; /*  points to ACP state */
     UINT32 grant; /*  grant, deny, error */
{
  return(acp_auth_resp(acp, grant, NULL, NULL, NULL));
}

user_index_authorize(Acp, grant, index)

ACP             *Acp;                   /*  points to ACP state  */
UINT32   grant;                  /*  grant, deny, error   */
char		*index;			/*  index (password or secret) */

{
        int             rlength;
        AUTH_RUI        cdata;
        ACK             rdata;

        if(debug)
                puts("user_index_authorize");

        if (ISTCP(Acp->state))
          return(return_user_index_tcp(Acp, grant, index));
	else if(ISREJECT(grant))
		grant = REQ_DENIED;
        
        set_long(cdata.auth_handle, Acp->handle);
        set_long(cdata.auth_grant, grant);
        strcpy(cdata.auth_index, index);
        return srpc_callresp(
                Acp->Srpc, Acp->s, NULL, Acp->pid,
                (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
                (unsigned short)(ACP_USER_INDEX_AUTHORIZE),
                (char *)(&cdata), SIZE_AUTH_RUI, 1, AUTH_TIMEOUT,
                (char *)(&rdata), SIZE_ACK, &rlength);
}

log_authorize(Acp, grant)

ACP             *Acp;                   /*  points to ACP state  */
UINT32  grant;                  /*  grant, deny, error   */

{
        int             rlength;
        AUTH_RL        cdata;
        ACK             rdata;

        if(debug)
               puts("log_authorize");

        if (ISTCP(Acp->state))
          return(ACPU_ESUCCESS);

        set_long(cdata.auth_handle, Acp->handle);
        set_long(cdata.auth_grant, grant);
        return srpc_callresp(
                Acp->Srpc, Acp->s, NULL, Acp->pid,
                (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
                (unsigned short)(ACP_LOG_AUTHORIZE),
                (char *)(&cdata), SIZE_AUTH_RL, 1, AUTH_TIMEOUT,
                (char *)(&rdata), SIZE_ACK, &rlength);
}

ppp_security_authorize(Acp, grant)

ACP		*Acp;			/*  points to ACP state  */
UINT32		grant;			/*  grant, deny, error   */

{
	int		rlength;
	AUTH_PPP	cdata;
	ACK		rdata;
	char buf[80];

    if(debug)
    {
		sprintf(buf, "ppp_security_authorize %x", grant);
        puts(buf);
	}

    if (ISTCP(Acp->state))
      return(return_ppp_security_tcp(Acp, grant));
    else if(ISREJECT(grant))
            grant = REQ_DENIED;

    set_long(cdata.auth_handle, Acp->handle);
    set_long(cdata.auth_grant, grant);
    return srpc_callresp(
        Acp->Srpc, Acp->s, NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_PPP_SECURITY_AUTHORIZE),
        (char *)(&cdata), SIZE_AUTH_PPP, 1, AUTH_TIMEOUT,
        (char *)(&rdata), SIZE_ACK, &rlength);
}

int
port_to_annex_authorize(Acp,grant,cli_cmd_mask,Username,hmask)
ACP        *Acp;            /*  points to ACP state  */
UINT32        grant;            /*  grant, deny, error   */
UINT32        cli_cmd_mask;        /*  CLI command disable  */
char        *Username;        /*  username or token    */
UINT32        hmask;
{
    int        dlength, rlength;
    AUTH_CLI    cdata;
    ACK        rdata;

    if(debug)
        puts("port_to_annex_authorize");

    if (ISTCP(Acp->state))
        return(return_port_to_annex_tcp(Acp, grant, cli_cmd_mask, Username,
                                        hmask));
    else if(ISREJECT(grant))
            grant = REQ_DENIED;

    /* Not TCP: still using 16 character usernames */
    set_long(cdata.auth_handle, Acp->handle);
    set_long(cdata.auth_grant, grant);
    set_long(cdata.auth_mask, cli_cmd_mask);
    set_long(cdata.auth_hooks,hmask);
    if((int)strlen(Username) >= ACP_MAXSTRING)
      Username[ACP_MAXSTRING - 1] = '\0';
    (void)strncpy(cdata.auth_username, Username, ACP_MAXSTRING - 1);

    if (grant == REQ_GRANT_HOOK)
        dlength = SIZE_AUTH_CLI;
    else {
        dlength = SIZE_AUTH_CLI - ACP_MAXSTRING;
        dlength += strlen(cdata.auth_username) + 1;
    }

    return srpc_callresp(
        Acp->Srpc, Acp->s, (struct sockaddr_in *)NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_PORT_TO_ANNEX_AUTHORIZE),
        (char *)(&cdata), dlength, 1, AUTH_TIMEOUT,
        (char *)(&rdata), SIZE_ACK, &rlength);

}

annex_to_net_authorize(Acp, grant)

ACP		*Acp;			/*  points to ACP state  */
UINT32		grant;			/*  grant, deny, error   */
{
    AUTH        cdata;
    ACK        rdata;
    int        rlength;

    if (ISTCP(Acp->state))
      return(return_annex_to_net_tcp(Acp, grant));

    set_long(cdata.auth_handle, Acp->handle);
    set_long(cdata.auth_grant, grant);

    return srpc_callresp(
        Acp->Srpc, Acp->s, NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_ANNEX_TO_NET_AUTHORIZE),
        (char *)(&cdata), SIZE_AUTH, 1, AUTH_TIMEOUT,
        (char *)(&rdata), SIZE_ACK, &rlength);
}

net_to_port_authorize(Acp, grant, Username)

ACP        *Acp;            /*  points to ACP state  */
UINT32        grant;            /*  grant, deny, error   */
char        *Username;        /*  username  */

{
	int		dlength, rlength;
	AUTH_CLI	cdata;
	ACK		rdata;

    if (ISTCP(Acp->state))
      return(net_to_port_authorize_tcp(Acp, grant, Username));
    else if(ISREJECT(grant))
	    grant=REQ_DENIED;

    /* Not TCP: still using 16 character usernames */
    set_long(cdata.auth_handle, Acp->handle);
    set_long(cdata.auth_grant, grant);
    if((int)strlen(Username) >= ACP_MAXSTRING)
      Username[ACP_MAXSTRING - 1] = '\0';
    (void)strncpy(cdata.auth_username, Username, ACP_MAXSTRING - 1);

    dlength = SIZE_AUTH_CLI - ACP_MAXSTRING;
    dlength += strlen(cdata.auth_username) + 1;

    return srpc_callresp(
        Acp->Srpc, Acp->s, NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_NET_TO_PORT_AUTHORIZE),
        (char *)(&cdata), dlength, 1, AUTH_TIMEOUT,
        (char *)(&rdata), SIZE_ACK, &rlength);
}

int net_to_port_authorize_tcp(acp, grant, Username)
     ACP *acp; /*  points to ACP state  */
     UINT32 grant; /*  grant, deny, error   */
     char *Username; /*  username  */
{
    if (grant == REQ_PENDING)
        return(0);
    return(acp_auth_resp(acp, grant, NULL, NULL, Username));
}

outputstring(Acp, String)

ACP		*Acp;		/*  Acp session state structure  */
char		*String;	/*  String to be put out  */
{
    int        dlength, rlength, rval;
    OUTPUT_STRING    cdata;
    ACK        rdata;

    if (ISTCP(Acp->state))
      return(outputstring_tcp(Acp, String));

    while (*String != '\0') {
        set_long(cdata.out_handle, Acp->handle);

        (void)strncpy(cdata.out_string,String,ACP_MAXSTRING-1);
        cdata.out_string[ACP_MAXSTRING -1] = '\0';
        dlength = strlen(cdata.out_string);
        String += dlength;

        dlength += SIZE_OUTPUT - ACP_MAXSTRING + 1;

        rval = srpc_callresp(
            Acp->Srpc, Acp->s, NULL,
            Acp->pid, (UINT32)(ACP_PROG),
            (unsigned short)(ACP_VER),
            (unsigned short)(ACP_OUTPUTSTRING),
            (char *)(&cdata), dlength, 
            TURNAROUND(AUTH_TIMEOUT), AUTH_TIMEOUT,
            (char *)(&rdata), SIZE_ACK, &rlength);
        if (rval != 0)
            return rval;
    }
    return 0;
}

outputstring_tcp(acp, string)
     ACP *acp; /*  Acp session state structure  */
     char *string; /*  String to be put out  */
{
  int grant;

  return(acp_lib_exec_req(acp, SERVICE_CLI_HOOK, SERVICE_OUTPUTSTRING, NULL, NULL,
                      NULL, NULL, string, NULL, NULL, NULL, NULL, NULL, NULL,
                      NULL, &grant, NULL, NULL, racp_timer));
}

/*
 * promptstring(), promptstring_wt():
 *      Calls promptstring_wt() to do the work. 
 *      promptstring() is used to shield
 *      system to parameter changes in promptstring_wt().
 *      When calls to promptstring_wt() have "flag" set to
 *      GET_TERMINATOR, the terminator (usually <return>)
 *      is included in the input string.
 */
int
promptstring(Acp, Inpstr, Outstr, echo, timeout)

ACP             *Acp;           /*  Acp session state structure  */
char            *Inpstr,        /*  Place to put return string  */
                *Outstr;        /*  String to be put out  */
int             echo,           /*  Boolean - echo input?  */
                timeout;        /*  How long should I wait?  */
{
        return promptstring_wt(Acp,Inpstr,Outstr,echo,timeout,0);
}

int
promptstring_wt(Acp, Inpstr, Outstr, echo, timeout, securID_info)

ACP        *Acp;        /*  Acp session state structure  */
char        *Inpstr,    /*  Place to put return string  */
        *Outstr;    /*  String to be put out  */
int        echo,        /*  Boolean - echo input?  */
        timeout;    /*  How long should I wait?  */
u_short        *securID_info;    /* on input: get terminator in string
                   on output: length of RETURN_STRING recvd */
{
    int        dlength, rlength, ret;
    PROMPT_STRING    cdata;
    RETURN_STRING    rdata;

    if(debug)
        puts("promptstring");

    if (ISTCP(Acp->state))
      return(promptstring_tcp(Acp, Inpstr, Outstr, echo, timeout,
                              securID_info));

    bzero((char*)&cdata, sizeof(PROMPT_STRING));
    set_long(cdata.pmt_handle, Acp->handle);
    cdata.pmt_timeout = htons((u_short)timeout);
    cdata.pmt_echo = htons((u_short)echo);
    if(securID_info)
        {
        cdata.pmt_flags = htons(*securID_info);
        *securID_info = 0;
        }

    (void)strncpy(cdata.pmt_string, Outstr, ACP_MAXSTRING);
    cdata.pmt_string[ACP_MAXSTRING -1] = '\0';

    dlength = SIZE_PROMPT;

    timeout += AUTH_TIMEOUT;    /*  add a few seconds to timeout  */

    Inpstr[0] = '\0';
#ifdef FASTRETRY
    Acp->pid++;
#endif

    bzero((char*)&rdata,sizeof(rdata));
    ret = srpc_callresp(
        Acp->Srpc, Acp->s, NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_PROMPTSTRING),
        (char *)(&cdata), dlength, TURNAROUND(timeout), timeout,
        (char *)(&rdata), SIZE_STRING, &rlength);

    if(ret)
        return ret;

    /* if talking to pre 8.1 or pre 8.0.6 annex */
    /* this flag doesn't get set                */
    if ((securID_info) && (rlength == SIZE_STRING))
        *securID_info = ntohs(rdata.ret_flags);

    (void)strncpy(Inpstr, rdata.ret_string, LEN_USERNAME);
    Inpstr[LEN_USERNAME -1] = '\0';

    return strlen(Inpstr);
}

int promptstring_tcp(acp, inpstr, outstr, echo, timeout, securID_info)
ACP *acp; /*  Acp session state structure  */
char *inpstr, /*  Place to put return string  */
    *outstr;    /*  String to be put out  */
int echo, /*  Boolean - echo input?  */
    timeout;    /*  How long should I wait?  */
u_short *securID_info;    /* on input: get terminator in string
                           on output: length of RETURN_STRING recvd */
{
    int rcode;
    int flags;
    int *flagsp = NULL;
    int grant;

    *inpstr = 0;

    if (securID_info) {
        flags = *securID_info;
        flagsp = &flags;
    }
    
    if (debug)
      printf("promptstring_tcp\n");
    
    if ((rcode = acp_lib_exec_req(acp, SERVICE_CLI_HOOK, SERVICE_PROMPTSTRING,
                  inpstr, NULL, NULL, NULL, outstr, NULL, NULL,
                  flagsp, &timeout, &echo, NULL, NULL, &grant,
                  NULL, NULL, racp_timer))  < 0) {
        return(rcode);
    }
    
    return(strlen(inpstr));
}

return_appletalk_profile(Acp, return_code, zones_len, zone_count,
             zone_list, passwd, connect_time, nve_exclude, 
             nve_list, nves_len, nve_count)
ACP        *Acp;
UINT32        return_code;        /*  grant or deny  */
int zones_len;
int zone_count;
char *zone_list;
char *passwd;
int connect_time;
int nve_exclude;
char *nve_list;
int nves_len;
int nve_count;
{
    APPLETALK_RETURN rap;
    int len;

    if (debug)
        puts ("return appletalk profile");

    if (ISTCP(Acp->state))
        return(return_appletalk_profile_tcp(Acp, return_code, zones_len,
            zone_count, zone_list, passwd,
            connect_time, nve_exclude,
            nve_list, nves_len, nve_count));
		
    else if(ISREJECT(return_code))
           return_code = REQ_DENIED;
    bzero ((char*)&rap, SIZE_RAP);

    set_long(rap.rap_handle, Acp->handle);
    set_long(rap.rap_grant, return_code);
    set_long(rap.rap_connect_time, connect_time);
    if (zone_list && zones_len)
        strncpy((char *)rap.rap_zones_list, zone_list, zones_len);
    set_long(rap.rap_zones, zones_len);
    set_long(rap.rap_zone_count, zone_count);
    if (passwd)
        strcpy((char *)rap.rap_passwd, passwd);

    /*
     * if we are not sending an nve_list then only send up to the zone list,
     * otherwise 8.0 appletalk annex will choke on the big RAP.
     */
    if (nve_list) {
        strcpy((char *)rap.rap_nve, nve_list);
        set_long(rap.rap_nve_exclude, nve_exclude); 
        len = SIZE_RAP;
    } else
        len = SIZE_RAP_OLD;
    
    return srpc_return( Acp->Srpc, Acp->s, NULL,
                        Acp->pid, (char *)(&rap), len);
}

int return_appletalk_profile_tcp(acp, return_code, zones_len, zone_count,
                 zone_list, passwd, connect_time, nve_exclude,
                 nve_list, nves_len, nve_count)
ACP *acp;
UINT32    return_code; /*  grant or deny  */
int zones_len;
int zone_count;
char *zone_list;
char *passwd;
int connect_time;
int nve_exclude;
char *nve_list;
int nves_len;
int nve_count;
{
    AT_PROFILE_RETURN profile;
    IRQ_PROFILE opt_info;

    switch(return_code) {
      case REQ_GRANTED:
    
        bzero((char*)&profile, sizeof(AT_PROFILE_RETURN));
    
        if (zones_len >= ATZONELIST)
            zones_len = ATZONELIST - 1;
    
        profile.connect_time = connect_time;
        if (zone_list && zones_len)
            strncpy((char *)profile.zones_list, zone_list, zones_len);
        profile.zones_len = zones_len;
        profile.zone_count = zone_count;
        if (passwd)
            strncpy((char *)profile.passwd, passwd, ATPASSWD);
    
        if (nve_list) {
            strncpy((char *)profile.nve, nve_list, ATFILTERLEN);
            profile.nve_exclude = nve_exclude;
            profile.nves_len = nves_len;
            profile.nve_count = nve_count;
        }

        bzero ((char*)&opt_info, sizeof (IRQ_PROFILE));
        opt_info.at_profile = &profile;
        return(acp_info_resp(acp, return_code, &opt_info));
        break;

      case REQ_PENDING:
        return(0);

      default:
        return(acp_info_resp(acp, return_code, NULL));
    }
}

int
return_hook_callback(Acp,code,str)
ACP *Acp;
int code;
char *str;
{
    HOOK_CALLBACK callback;
    int slen = 0;

    if (debug)
        puts("return_hook_callback");

    if (ISTCP(Acp->state))
      return(0);

    set_long(callback.hcb_handle,Acp->handle);
    callback.hcb_code = htons((unsigned short)code);
    callback.hcb_reserved = htons(0);
    if (str == NULL)
        str = "";
    else if ((slen = strlen(str)) > HCB_TEXT_MAX)
        str[HCB_TEXT_MAX] = '\0';
    (void)strcpy(callback.hcb_text,str);
    slen += SIZE_HOOK_CALLBACK - HCB_TEXT_MAX;
    return srpc_return(Acp->Srpc,Acp->s,(struct sockaddr_in *)NULL,
        Acp->pid,(char *)&callback,slen);
}

int return_hook_callback_tcp(acp, code, str)
ACP *acp;
int code;
char *str;
{
    return(acp_exec_reply(acp, REQ_GRANTED, NULL, NULL, (str ? str : ""), 
                          &code));
}

int
hook_callback_string(Acp,code,str)
ACP *Acp;
int code;
char *str;
{
	int dlength = 0, rlength;
	HOOK_CALLBACK callback;
	ACK		rdata;

    if (debug)
        puts("hook_callback_string");

    if (ISTCP(Acp->state))
      return(return_hook_callback_tcp(Acp, code, str));

    set_long(callback.hcb_handle,Acp->handle);
    callback.hcb_code = htons((unsigned short)code);
    callback.hcb_reserved = htons(0);
    (void)strncpy(callback.hcb_text,str, HCB_TEXT_MAX);
    dlength += SIZE_HOOK_CALLBACK - HCB_TEXT_MAX;
    rlength = SIZE_ACK;

    return srpc_callresp(
        Acp->Srpc,Acp->s,(struct sockaddr_in *)NULL, Acp->pid,
        (UINT32)(ACP_PROG), (unsigned short)(ACP_VER),
        (unsigned short)(ACP_HOOK_RETURN),
        (char *)&callback, dlength, 1, AUTH_TIMEOUT,
        (char *)&rdata, SIZE_ACK, &rlength);
}

return_dialup_address(Acp, return_code, net_type, loc, rem, node, filters,
                      routes)

ACP        *Acp;
UINT32        return_code;        /*  grant or deny  */
int net_type;
UINT32        loc,rem;        /*  local and remote slip addresses */
u_char *node;
STR_LIST *filters, *routes;
{
    AUTH_RDA    sdata;

    if(debug)
      puts("return_dialup_address");

    if (ISTCP(Acp->state))
      return(0);
    
    set_long(sdata.auth_handle, Acp->handle);
    set_long(sdata.auth_grant, return_code);
    set_long(&sdata.auth_loc, loc);
    set_long(&sdata.auth_rem, rem);
    bcopy(node, sdata.auth_node, 6);
    return srpc_return(
        Acp->Srpc, Acp->s, (struct sockaddr_in *)NULL,
        Acp->pid, (char *)(&sdata), SIZE_AUTH_RDA);
}

int return_dialup_address_tcp(acp, return_code, net_type, loc, rem, node,
			      filters, routes)
     ACP *acp;
     UINT32 return_code; /*  grant or deny  */
     int net_type;
     UINT32    loc, rem; /*  local and remote slip addresses */
STR_LIST *filters, *routes;
     u_char *node;
{
    NetAddr locaddr;
    NetAddr remaddr;
    IRQ_PROFILE opt_info;

    switch(return_code) {
      case REQ_PENDING:
        return(0);

      case REQ_GRANTED:
        bzero((char*)&locaddr, sizeof(NetAddr));
        bzero((char*)&remaddr, sizeof(NetAddr));
        locaddr.type = remaddr.type = net_type;
	switch (net_type) {
	case IP_ADDRT:
	  locaddr.n.ip_addr.inet = loc;
	  remaddr.n.ip_addr.inet = rem;
	  break;
	case IPX_ADDRT:
	  remaddr.n.ipx_addr.network = rem;
	  bcopy(node,remaddr.n.ipx_addr.node,6);
	  break;
	default:
	case LAT_ADDRT:
	  return(acp_info_resp(acp, return_code, NULL));
	}
	bzero ((char*)&opt_info, sizeof(IRQ_PROFILE));
	opt_info.local_Address = &locaddr;
	opt_info.remote_Address = &remaddr;
	opt_info.filters = filters;
	opt_info.routes = routes;
        return(acp_info_resp(acp, return_code, &opt_info));

      default:
        return(acp_info_resp(acp, return_code, NULL));
    }
}

int return_max_logon_tcp(acp, return_code, max_logon)
     ACP *acp;
     UINT32 return_code; /*  grant or deny  */
     int    max_logon;
 
{
    IRQ_PROFILE opt_info;
 
  if(debug)
    puts("return_max_logon_tcp");
 
  if (!ISTCP(acp->state)) {
    if (debug)
      puts("error");
    return(0);
  }
 
        switch(return_code) {
        case REQ_PENDING:
          if (debug)
            puts("REQ_PENDING");
          return(0);
 
        case REQ_GRANTED:
          bzero (&opt_info, sizeof(IRQ_PROFILE));
          opt_info.max_logon = &max_logon;
          return(acp_info_resp(acp, return_code, &opt_info));
 
        default:
          return(acp_info_resp(acp, return_code, NULL));
        }
  }

return_serial_validate(Acp, return_code)

ACP                *Acp;
UINT32		return_code;  /*  grant or deny */
{
        AUTH_PPP        rdata;

        if(debug)
          puts("return_serial_validate");

        if (ISTCP(Acp->state)) {
            return(return_serial_validate_tcp(Acp, return_code));
        }
        else if(ISREJECT(return_code))
                return_code = REQ_DENIED;

        set_long(rdata.auth_handle, Acp->handle);
        set_long(rdata.auth_grant, return_code);
        return srpc_return(
                Acp->Srpc, Acp->s, NULL,
                Acp->pid, (char *)(&rdata), SIZE_AUTH_PPP);
}

int return_serial_validate_tcp(acp, return_code)
     ACP *acp;
     UINT32 return_code;  /*  grant or deny */
{
    if (return_code == REQ_PENDING)
        return(0);
    return(acp_auth_resp(acp, return_code, NULL, NULL, NULL));
}

return_ppp_security(Acp, return_code)

ACP		   *Acp;
UINT32	   return_code;  /*  grant or deny */
{
    AUTH_PPP    rdata;

    if(debug)
      puts("return_ppp_security");

    if (ISTCP(Acp->state))
      return(return_ppp_security_tcp(Acp, return_code));
    else if(ISREJECT(return_code))
	   return_code = REQ_DENIED;

    set_long(rdata.auth_handle, Acp->handle);
    set_long(rdata.auth_grant, return_code);
    return srpc_return(
        Acp->Srpc, Acp->s, NULL,
        Acp->pid, (char *)(&rdata), SIZE_AUTH_PPP);
}

return_ppp_security_tcp(acp, return_code)
     ACP *acp;
     UINT32 return_code;  /*  grant or deny */
{
    if (return_code == REQ_PENDING)
        return(0);
    return(acp_auth_resp(acp, return_code, NULL, NULL, NULL));
}

return_user_index(Acp, return_code, index)

ACP             *Acp;
UINT32   return_code;    /*  grant or deny  */
char        *index;        /* password */
{
        AUTH_RUI        sdata;

        if(debug)
          puts("return_user_index");

        if (ISTCP(Acp->state))
          return(return_user_index_tcp(Acp, return_code, index));
	else if(ISREJECT(return_code))
	       return_code = REQ_DENIED;

        set_long(sdata.auth_handle, Acp->handle);
        set_long(sdata.auth_grant, return_code);
        strcpy(&sdata.auth_index[0], index);
        return srpc_return(
                Acp->Srpc, Acp->s, NULL,
                Acp->pid, (char *)(&sdata), SIZE_AUTH_RUI);
}

int return_user_index_tcp(acp, return_code, index)
     ACP *acp;
     UINT32 return_code;    /*  grant or deny  */
     char *index; /* password */
{
    IRQ_PROFILE opt_info;
    
    switch(return_code) {
      case REQ_PENDING:
        return(0);

      case REQ_GRANTED:
          bzero ((char*)&opt_info, sizeof(IRQ_PROFILE));
          opt_info.text = index;
          return(acp_info_resp(acp, return_code, &opt_info));

      default:
        return(acp_info_resp(acp, return_code, NULL));
    }
    
}

return_max_links(acp, return_code, mp_max_links)
ACP		*acp;
UINT32	         return_code;	/*  grant or deny  */
int		mp_max_links;	/* max links for this authorization */
{
    IRQ_PROFILE opt_info;

    if(debug)
        puts("return_max_links");

    if (!ISTCP(acp->state)) {		/* unsupported for non-TCP connections */
        return(0);
    }

    if(ISREJECT(return_code))
	return_code = REQ_DENIED;

    switch(return_code) {
      case REQ_PENDING:
        return(0);

      case REQ_GRANTED:
          bzero ((char*)&opt_info, sizeof(IRQ_PROFILE));
          opt_info.mp_max_links = &mp_max_links;
          return(acp_info_resp(acp, return_code, &opt_info));

      default:
        return(acp_info_resp(acp, return_code, NULL));
    }
}
    
return_log(Acp, return_code)

ACP             *Acp;
UINT32   return_code;    /*  grant or deny  */
{
        AUTH_RL        sdata;

        if(debug)
          puts("return_log");

        if (ISTCP(Acp->state))
            return(0);

        set_long(sdata.auth_handle, Acp->handle);
        set_long(sdata.auth_grant, return_code);
        return srpc_return(
                Acp->Srpc, Acp->s, NULL,
                Acp->pid, (char *)(&sdata), SIZE_AUTH_RL);
}

return_port_to_annex(Acp, return_code, cli_cmd_mask, Username)

ACP        *Acp;
UINT32        return_code;        /*  grant, deny, delay, or reject  */
UINT32        cli_cmd_mask;        /*  bits set to disable cli cmds   */
char        *Username;        /*  username or token          */
{
    int        rlength;
    AUTH_CLI    rdata;

    if(debug)
        puts("rtn_port_to_annex");

    if (ISTCP(Acp->state))
      return(return_port_to_annex_tcp(Acp, return_code, cli_cmd_mask,
                                      Username, 0));
    else if(ISREJECT(return_code))
	     return_code = REQ_DENIED;

    /* Not TCP: still using 16 character usernames */
    set_long(rdata.auth_handle, Acp->handle);
    set_long(rdata.auth_grant, return_code);
    set_long(rdata.auth_mask, cli_cmd_mask);
    if((int)strlen(Username) >= ACP_MAXSTRING)
      Username[ACP_MAXSTRING - 1] = '\0';
    (void)strncpy(rdata.auth_username, Username, ACP_MAXSTRING - 1);

    rlength = SIZE_AUTH_CLI - ACP_MAXSTRING;
    rlength += strlen(rdata.auth_username) + 1;

    return srpc_return(
        Acp->Srpc, Acp->s, NULL,
        Acp->pid, (char *)(&rdata), rlength);
}

int return_port_to_annex_tcp(acp, return_code, cli_cmd_mask, Username, hmask)
ACP *acp;
UINT32 return_code; /*  grant, deny, delay, or reject  */
UINT32 cli_cmd_mask; /*  bits set to disable cli cmds   */
char *Username; /*  username or token          */
UINT32 hmask;
{
    switch(return_code) {
      case REQ_PENDING:
        return(0);

      case REQ_GRANTED:
        return(acp_auth_resp(acp, return_code, &cli_cmd_mask, NULL, Username));

      case REQ_GRANT_HOOK:
        return(acp_auth_resp(acp, return_code, &cli_cmd_mask, &hmask,
                             Username));

      default:
        return(acp_auth_resp(acp, return_code, NULL, NULL, Username));
    }
}

return_annex_to_net(Acp, return_code)

ACP		*Acp;
UINT32		return_code;		/*  grant, deny, delay, or reject  */
{
    AUTH    rdata;

    if (ISTCP(Acp->state))
      return(return_annex_to_net_tcp(Acp, return_code));

    set_long(rdata.auth_handle, Acp->handle);
    set_long(rdata.auth_grant, return_code);

    return srpc_return(
        Acp->Srpc, Acp->s, NULL,
        Acp->pid, (char *)(&rdata), SIZE_AUTH);
}

int return_annex_to_net_tcp(acp, grant)
     ACP *acp; /*  points to ACP state  */
     UINT32 grant; /*  grant, deny, error   */
{
    if (grant == REQ_PENDING)
        return(0);
    return(acp_auth_resp(acp, grant, NULL, NULL, NULL));
}

return_net_to_port(Acp, return_code)

ACP		*Acp;
UINT32		return_code;		/*  grant, deny, delay, or reject  */
{
    AUTH    rdata;

    if (ISTCP(Acp->state))
      return(net_to_port_authorize_tcp(Acp, return_code, NULL));
    else if(ISREJECT(return_code))
	   return_code = REQ_DENIED;

    set_long(rdata.auth_handle, Acp->handle);
    set_long(rdata.auth_grant, return_code);

    return srpc_return(
        Acp->Srpc, Acp->s, NULL,
        Acp->pid, (char *)(&rdata), SIZE_AUTH);
}

acp_acknowledge(Acp)

ACP		*Acp;
{
	ACK	rdata;

    if (ISTCP(Acp->state))
        return(0);

    set_long(rdata.ack_handle, Acp->handle);
    set_long(rdata.ack_ack, ACP_ACK);

    return srpc_return(Acp->Srpc, Acp->s, NULL,
                       Acp->pid, (char *)(&rdata), SIZE_ACK);
}

void
shift_array(begin, length, shift_amount)
u_char        *begin;
register int    length;
int            shift_amount;
{
    register u_char    *old, *new;

    if (shift_amount >= 0){
    old = begin + length - 1;
    new = old + shift_amount;

    while(length--)
        *new-- = *old--;
    } else {
    old = begin;
    new = begin + shift_amount;

    while(length--)
        *new++ = *old++;
    }
}

void get_host_name(name, inet)
char *name;
UINT32 inet;
{
#ifdef USE_ANAME
    struct hostent *host;
#endif

    bzero(name, 32);
#ifdef USE_ANAME
    if (ErpcdOpt->UseHostName)
    {
   		if (host = gethostbyaddr((char *)&inet, sizeof(long), AF_INET))
		{
			if (host->h_name != NULL && host->h_name[0])
			{
        		strncpy(name, host->h_name, 31);
			}
		}
	}
    else
#endif
        inet_name(name, inet);
}

char *
port_to_name(port, name)
SECPORT *port;
char *name;
{
    static char idents[] = PORT_DEV_IDENTS;

    if (port->type >= DEV_MAX)
        port->type = 0;

    (void)sprintf(name, /*NOSTR*/"%c%3.3d", idents[port->type], port->unit);
    return(name);
}

 
int write_audit_log(inet, logid, port, service, type, clock, stats, remaddr,
                    user, text)
UINT32 inet, logid;
SECPORT *port;
int service, type;
time_t clock; /* current time in seconds, only used for tcp connection */
LOG_PORT_STATS *stats;
NetAddr *remaddr;
char *user, *text;
{
    FILE            *Log;    
    char            logfile[PATHSZ];
    struct    tm        *Time;
#ifdef USE_FLOCK
    int  lf_retv;
#endif /* USE_FLOCK */
    int rc, retv, lf_retry_count;
    int rcode = ACP_ERROR;
    char locname[32];
    char hostname[33];
    char portstats[60];
    char portname[8];
    char *strp = NULL;
    int tcp_port = 0;
    char tcpportname[8];
    char empty[1];
    char colon[2];
    char *userdelim, *textdelim;
    char *username, *textstring;
    char delimeter[2];
    int udp_protocol = FALSE;
    char *servicestr, *eventstr;
#ifdef _WIN32
	char Message[256];
#endif

    bzero(locname, 32);
    bzero(hostname, 33);
    bzero(portstats, 60);
    bzero(portname, 8);
    bzero(tcpportname, 8);

    if (service >= 0 && service < NSERVICES)
        servicestr = service_name[service];
    else
        servicestr = "unknown";

    if (type >= 0 && type < NEVENTS)
        eventstr = event_name[type];
    else
        eventstr = "unknown";

    if (debug > 9) {
        /* first make sure we are in sequence */
        if (globalacp->logseq && logid != (globalacp->logseq + 1)) {
            return(ACP_ERROR);
        }
    }

    if (stats || remaddr || user || text)
      strcpy(delimeter, "");
    else
      strcpy(delimeter, ":");
    
    empty[0] = '\0';
    strcpy(colon, ":");

    if (user) {
      username = user;
      userdelim = colon;
    }
    else {
      username = empty;
      userdelim = empty;
    }

    if (text) {
      textstring = text;
      textdelim = colon;
    }
    else {
      textstring = empty;
      textdelim = empty;
    }

    if (debug)
        puts("log_message");

    get_host_name(locname, inet);

    if (remaddr) {
        switch(remaddr->type) {
          case LAT_ADDRT:
            strcpy(hostname, ":");
            strncpy(hostname+1, remaddr->n.lat_addr.service, 31);
            break;

          case IP_ADDRT:
            tcp_port = remaddr->n.ip_addr.port;
            if (tcp_port) {
                sprintf(tcpportname, ":%u", tcp_port);
            }
            bzero(hostname, 32);
            strcpy(hostname, ":");
            strp = hostname + strlen(hostname);
            get_host_name(strp, remaddr->n.ip_addr.inet);
            break;

          case IPX_ADDRT: /* for now do not display ipx addr */
            break;
        }
    }

    port_to_name(port, portname);

    portstats[0]= '\0';
    if (stats)
        sprintf(portstats, ":%u:%u:%u:%u:%u", stats->pkts_rx, stats->pkts_tx,
                stats->bytes_rx, stats->bytes_tx, stats->elapsed_time);
    
    if (ErpcdOpt->UseSyslog)
	{
#ifndef _WIN32
#ifdef USE_SYSLOG
    syslog(event_priority[type], "%s:%s:%s:%s%s%s%s%s%s%s%s%s", locname,
           portname, servicestr, eventstr, delimeter,
           portstats, hostname, tcpportname, userdelim, username, textdelim,
           textstring);
#endif

#else
	/* for NT, this option logs ACP events to the NT Event log */
    sprintf(Message, "%s:%s:%s:%s%s%s%s%s%s%s%s%s", locname, 
           portname, servicestr, eventstr, delimeter, 
           portstats, hostname, tcpportname, userdelim, username, textdelim, 
           textstring); 
    LogACPToEventLog(type, service, locname, port->unit, Message); 
/*   	syslog(event_priority[type], "Annex_ACP %s:%s:[%s/%d]: %s:%s%s%s%s%s%s%s%s%s",
	  			event_name[type],
				service_name[service],
				locname,
				port->unit,
				servicestr,
				eventstr,
				delimeter,
				portstats,
				hostname,
				tcpportname,
				userdelim,
				username,
				textdelim,
				textstring);*/
#endif /* _WIN32 */
	}

     /* call RADIUS Accounting;
      * Do NOT log event to file if RADIUS accepts it or explicitly ignores it
      */
#ifdef RADIUS_ACCT    
     rc = radius_build_log(type, logid, inet, port, user, service, remaddr, stats, text);
     if ((rc == 0) || (rc == 1)) 
     {
        rcode = ACPU_ESUCCESS;
     }
     else
	{		/* Matching brace is down <> 200 lines	vvvvvvvvvvvvvvvvvvvvvvvvvvv */

#endif	/* defined(RADIUS_ACCT) */

#ifdef USE_LOGFILE
#ifdef _WIN32
	/* Open the log file if not using RADIUS Authentication */
    if (ErpcdOpt->UseLogfile && !ErpcdOpt->RadiusAuthentication)
#else
    if (ErpcdOpt->UseLogfile)
#endif	/* WIN32 */
    {
    lf_retry_count = 0;

#if defined USE_FLOCK || defined USE_F_LOCK
retry_file_lock:
#endif

    ACP_LOGFILE(logfile);
#ifdef SEPARATE_LOGS
    /* add the IP addr of annex as extension for separate logs */
    strcat(logfile, ".");
    strcat(logfile, locname);
#endif
    
    retv = umask(ACP_LOG_MASK^0666);
    Log = fopen(logfile,"a");
    if (Log == NULL) {
        perror(logfile);
        umask(retv);
        return(ACP_ERROR);
    }
    umask(retv);

#ifdef USE_FLOCK
    /* Originally added to support Linux Slackware 1.2. */
    lf_retv = flock(fileno(Log),LOCK_EX);
        if(lf_retv < 0) {
          (void)fclose(Log);
          if(lf_retry_count > 5) {
            if(debug)
                    printf("ACP log_message: lockf error/retrys exceeded\n");
            perror("ACP log message failure: lockf error");
            return(ACP_ERROR);
          }
          else {
            lf_retry_count++;
            sleep(1);     /* Wait before retrying lockf */
            goto retry_file_lock;
          }
        }
#elif USE_F_LOCK
         /* Lockf is used to block other processes from file access
           while this process updates the log. SEE USE_F_LOCK DEFINE */

        /* When calling lockf and the F_LOCK argument is passed, and no other
	   process has the file LOCKED, the  call locks the file and returns 
	   instantly. If the when making the call and the file is LOCKED via
	   another process, this process shall sleep until the resource is
           available. The process awakes with the file LOCKED. */

        /* Retry count required, lockf may fail because of temporary
           system related deficiencies */
        lf_retv = lockf(fileno(Log),F_LOCK, 0);
        if(lf_retv < 0) {
          (void)fclose(Log);
          if(lf_retry_count > 5) {
            if(debug)
                    printf("ACP log_message: lockf error/retrys exceeded\n");
            perror("ACP log message failure: lockf error");
            return(ACP_ERROR);
          }
          else {
            lf_retry_count++;
            sleep(1);     /* Wait before retrying lockf */
            goto retry_file_lock;
          }
        }

#else /* USE_T_LOCK */	   
	/*
	   When Lockf is called with the T_LOCK argument and no other process
	   has the file locked, the resource is acquired and the call returns
	   SUCCESS. If when making the call and the file is LOCKED via 
	   another process, the call returns instantly with an error(non-zero).
	   In this latter case the resource is not obtained and the call 
	   must be repeated until SUCCESS. Pretty silly huuuh. */

          for(lf_retry_count=100000; lf_retry_count; lf_retry_count-- ) {
#ifdef _WIN32
			  rewind(Log);
			  if((lockf(fileno(Log),F_TLOCK, 1)) == 0)
#else
			  if((lockf(fileno(Log),F_TLOCK, 0)) == 0)
#endif
					break;

	/*  If retry count exhausted, flag the lockf/T_LOCK failure and still
	    make attempt to log the record. */
            if(lf_retry_count == 1) {
              if(debug)
	              perror("ACP log_message: lockf/T_LOCK error, retrys exceeded");
	    }
	  }

#endif /* USE_FLOCK */

	/* Set file pointer up to append, file pointer could have been blown
	   away by another process if we were put to sleep on the lockf call */
        if((fseek(Log, 0L, 2) != 0)) {
      if(debug)
          printf("ACP log_message: lockf error/retrys exceeded\n");
      perror("ACP log_message failure: fseek error");
      (void)fclose(Log);
      return(ACP_ERROR);
    }

    } /* use_logfile */
#endif /* USE_LOGFILE */

    if(!clock){
       udp_protocol = 1;
       clock = time(NULL);
    }
    Time = localtime(&clock);        /*  break down into fields  */


#ifdef DEBUG
    printf(LOG_FORMAT, locname, logid, portname,
           Time->tm_year % 100, Time->tm_mon + 1, Time->tm_mday,
           Time->tm_hour, Time->tm_min, Time->tm_sec,
           servicestr, eventstr, delimeter, portstats,
           hostname, tcpportname, userdelim, username, textdelim, textstring);
#endif
    rcode = ACPU_ESUCCESS;

#ifdef USE_SYSLOG
	if (ErpcdOpt->UseSyslog) {
	    if (ErpcdOpt->UseSeconds) {
		 syslog (LOG_CRIT, LOG_FORMAT_S, locname, logid, portname, (long)clock,
                   servicestr, eventstr, delimeter, portstats,
                   hostname, tcpportname, userdelim, username, textdelim,
                   textstring);
	    } else {
		 syslog (LOG_CRIT, LOG_FORMAT, locname, logid, portname,
        	   Time->tm_year % 100, Time->tm_mon + 1, Time->tm_mday,
        	   Time->tm_hour, Time->tm_min, Time->tm_sec, 
        	   servicestr, eventstr, delimeter, portstats,
        	   hostname, tcpportname, userdelim, username, textdelim,
        	   textstring);
	    }
	}
#endif

		

#ifdef USE_LOGFILE
#ifdef _WIN32
	/* Generate a log message if not using RADIUS Authentication */
    if (ErpcdOpt->UseLogfile && !ErpcdOpt->RadiusAuthentication)
#else
    if (ErpcdOpt->UseLogfile)
#endif	/* WIN32 */
    {
#ifdef _WIN32
	if (ErpcdOpt->UseSeconds)
	{
		if ((fprintf(Log, LOG_FORMAT_S, locname, logid, portname, (long)clock,
                 servicestr, eventstr, delimeter, portstats,
                 hostname, tcpportname, userdelim, username, textdelim,
                 textstring)) == EOF)
			rcode = ACP_ERROR;
	}
	else
    {
		if ((fprintf(Log, LOG_FORMAT, locname, logid, portname,
        Time->tm_year % 100, Time->tm_mon + 1, Time->tm_mday,
        Time->tm_hour, Time->tm_min, Time->tm_sec, 
        servicestr, eventstr, delimeter, portstats,
        hostname, tcpportname, userdelim, username, textdelim,
        textstring)) == EOF)
        rcode = ACP_ERROR;
	}
#else /* _WIN32 */
#ifdef USE_SECONDS
    if ((fprintf(Log, LOG_FORMAT_S, locname, logid, portname, (long)clock,
                 servicestr, eventstr, delimeter, portstats,
                 hostname, tcpportname, userdelim, username, textdelim,
                 textstring)) == EOF)
        rcode = ACP_ERROR;
#else /* !USE_SECONDS */
    if ((fprintf(Log, LOG_FORMAT, locname, logid, portname,
        Time->tm_year % 100, Time->tm_mon + 1, Time->tm_mday,
        Time->tm_hour, Time->tm_min, Time->tm_sec, 
        servicestr, eventstr, delimeter, portstats,
        hostname, tcpportname, userdelim, username, textdelim,
        textstring)) == EOF)
        rcode = ACP_ERROR;
#endif /* USE_SECONDS */
#endif /*_WIN32 */

/* who cares about errors? */
    if ((fflush(Log)) == EOF)
        rcode = ACP_ERROR;
#ifdef USE_FLOCK
    if ((flock(fileno(Log),LOCK_UN)) == ACP_ERROR)
        rcode = ACP_ERROR;
#else /* USE_FLOCK */
#ifdef _WIN32
	rewind(Log);
    if ((lockf(fileno(Log),F_ULOCK,1)) == ACP_ERROR)
#else
    if ((lockf(fileno(Log),F_ULOCK,0)) == ACP_ERROR)
#endif /* _WIN32 */
        rcode = ACP_ERROR;
#endif /* USE_FLOCK */
    if ((fclose(Log)) == ACP_ERROR)
        rcode = ACP_ERROR;
   }  /* use logfile */
#endif /* USE_LOGFILE */

#ifdef RADIUS_ACCT
    } /* end RADIUS log skip ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
#endif /* RADIUS_ACCT */

    /* advance acp log acknowledgement */
    if (rcode != ACP_ERROR && udp_protocol == FALSE) {
        globalacp->logseq = logid;
        if ((globalacp->logseq - globalacp->logack) >= MAXLOGACK) {
            alarm(0);
            log_timer();
        }
    }
    return(rcode);
}


void net_addr_free(victim_union)
NetAddr *victim_union;
{

    switch (victim_union->type) {
      /*type_of_struct makes sure that the correct struct*/
        /*is released from the union*/
      case LAT_ADDRT:
        if (victim_union->n.lat_addr.service)
            free(victim_union->n.lat_addr.service);
        if (victim_union->n.lat_addr.node)
            free(victim_union->n.lat_addr.node);
        if (victim_union->n.lat_addr.port)
            free(victim_union->n.lat_addr.port);
        break;
      
      case IPX_ADDRT:
        if  (victim_union->n.ipx_addr.node)
            free(victim_union->n.ipx_addr.node);
        break;
      
      default:
        break;
    }
}

void log_acknowledge(acp)
ACP *acp;
{
    char cbuff[MAXPDUSIZE];
    int datalength = MAXPDUSIZE;

    racp_send_ack(acp, cbuff, datalength, acp->logseq);
    acp->logack = acp->logseq;
}

char *error_log(rcode, msg)

UINT32 rcode; /*error code value*/
char *msg; /* allocated minimum 80 bytes */
{
    /* if not 0xdeaf????, then no error */
    if (!ISREJECT(rcode))
        return(strcpy(msg, ""));

    switch(REASON_TYPE(rcode)) {
    case REJ_REGDENY:
        if (REGIME_TYPE(rcode) == CODE_UNKNOWN)
            return(strcpy(msg, ""));
        if (REGIME_TYPE(rcode) == CODE_DENY)
            return(strcpy(msg, "deny in acp_regime"));
        sprintf(msg, "%s denied access",
                       security_keywords[REGIME_TYPE(rcode)].keyword);
	return(msg);

    case REJ_REGNOTAVAIL:
        if (REGIME_TYPE(rcode) == CODE_UNKNOWN)
            return(strcpy(msg, ""));
	sprintf(msg, "regime %s not available",
                       security_keywords[REGIME_TYPE(rcode)].keyword);
        return(msg);

    case REJ_DENYUSER:
        if (REGIME_TYPE(rcode) == CODE_UNKNOWN)
            return(strcpy(msg, "deny in acp_userinfo, regime unknown"));
        sprintf(msg, "deny in acp_userinfo");
	return(msg);

    case REJ_TIMEOUT:
	sprintf(msg, "");
	return(msg);
        
    case REJ_ERPCDDENY:
    case REJ_UNKNOWN:
    default:
	sprintf(msg, "erpcd denied access; code %d",
		       REASON_TYPE(rcode));
	return(msg);
    }

}

void log_message(inet, logid, port, ptype, service, type, Message)

UINT32        inet,
        logid;
int        port,ptype,
        service,
        type;
char        *Message;
{
    SECPORT pf;
    char err_msg[80];
    char global_msg[ACP_MAXUSTRING * 4];

    pf.type = ptype;
    pf.unit = port;
 
    err_msg[0] = '\0';
    strncpy(global_msg, Message, ACP_MAXUSTRING * 4);

    if (ISREJECT(type)) {
        err_msg[0] = '\0';

        error_log(type, err_msg);
        if (err_msg[0] != '\0') {
	    strcat(global_msg, ":");
            strcat(global_msg, err_msg);
        }
        if (service == SERVICE_SECRET || service == SERVICE_ARAP ||
	    service == SERVICE_AT_PROFILE)
            type = EVENT_NOPROVIDE;
        else if (REASON_TYPE(type) == REJ_TIMEOUT)
            type = EVENT_TIMEOUT;
        else
            type = EVENT_REJECT;
    }
    write_audit_log(inet, logid, &pf, service, type, 0, NULL, NULL, 
                    NULL, global_msg);
}

void inet_number(Dot_string, long_inet)

char		Dot_string[];		/*  Return string in dot notation  */
UINT32		long_inet;		/*  Internet address, in 32 bits   */
{
	struct 	in_addr	internet;
	char		*Inet;

	internet.s_addr = long_inet;	/*  Set up an internet structure  */
	Inet = (char *)inet_ntoa(internet);	/*  Get pointer to static storage */
	(void)strcpy(Dot_string, Inet);	/*  Caller better guarantee space */
	return;
}

inet_name(Host_name, long_inet)

char		Host_name[];		/*  Return name from /etc/hosts  */
UINT32		long_inet;		/*  Internet address, in 32 bits */
{
	union {
		UINT32	 addr;
		unsigned char bytes[4];
	} conv;

	conv.addr = long_inet;
	(void)sprintf(Host_name, "%d.%d.%d.%d", conv.bytes[0],
		      conv.bytes[1], conv.bytes[2], conv.bytes[3]);
	return 0;
}

/*************************************************************************/
/* FXN inet_match() moved to env_parser.c to resolve organizational      */
/* problems.  M_ALI 8/8/95.						 */
/*************************************************************************/

UINT32
inet_address(Host_string)
char	Host_string[];		/*  Dot notation or hostname  */
{

	UINT32	address;
	struct in_addr	*Inet;
	struct	hostent	*Host;
	if(isdigit(Host_string[0]))
	{
	    address = inet_addr(Host_string);		/* too damned bad! */
	    if(address != (UINT32)-1)
	        return address;
	}

	    Host = gethostbyname(Host_string);
	    if(!Host)
		address = 0;
	    else
	    {
		Inet = (struct in_addr *)Host->h_addr;
		address = Inet->s_addr;
	    }

	return address;
}



void reject_session(Acp, code)

ACP    *Acp;            /* pointer to ACP state structure */
int    code;            /* erpc reject reason code */
{
    erpc_reject(Acp->s, NULL, Acp->pid, (u_short)code, 0, 0);

    terminate_session();    /* no return */
    return;
}


/*
 *  acp_request_dialout_tcp()
 *
 *  Make a dialout remote procedure call
 *
 *  Initialize a socket, call  up SRPC and call srpc_create requesting prog
 *  COURRPN_SECURITY proc RPROC_SRPC_OPEN, make ACP_DO_DIALOUT SRPC call.
 *  If successful, convert response and return status and port number.
 */

acp_request_dialout_tcp(inet, username, access_code, phone, 
        job, port_mask, port, ptype, service, ipx_netnum)

UINT32        inet;
char    *username;
char    *access_code;
char    *phone;
char    *job;
unsigned char    *port_mask;
int  *port,*ptype;
UINT32        service; 
UINT32        ipx_netnum;
{
    ACP acp;
    RACP racp;
    KEYDATA rcv_key, send_key;
    struct in_addr hostaddr;
    errno_t rv;
    u_short serv_req;
    char *jobp;
    int timeout;
    NetAddr destaddr, *addrp;
    int grant;
    SECPORT reqport;
    SECPORT dialport;

    hostaddr.s_addr = inet;
    reqport.type = *ptype;
    reqport.unit = *port;
    
    /* initialize acp */
    bzero((char*)&acp, sizeof(ACP));
    bzero((char*)&racp, sizeof(RACP));
    acp.racp = &racp;
    acp.key = annex_key(inet);
    acp.racp->rcv_key = &rcv_key;
    acp.racp->send_key = &send_key;
    SETTCP(acp.state);
    acp.racp->capability = CAP_GLOBAL;
    acp.racp->options = NO_DATAENC;
    acp.racp->version = RACP_HI_VER;
    acp.inet = inet;

    if ((rv = racp_connect(&acp, hostaddr)) != DIAL_SUCC)
        return(rv);

    if (service == SERVICE_IPX) {
        serv_req = SERVICE_IPX_DIALBACK;
        jobp = NULL;
        addrp = &destaddr;
        bzero((char*)addrp, sizeof(NetAddr));
        destaddr.type = IPX_ADDRT;
        destaddr.n.ipx_addr.network = ipx_netnum;
    }
    else {
        serv_req = SERVICE_DIALBACK;
        jobp = (char*)job;
        addrp = NULL;
    }
    timeout = DIALB_TIMEOUT;
    
    rv = acp_lib_exec_req(&acp, service, serv_req, NULL, username, phone,
                      access_code, NULL, jobp, port_mask, NULL, &timeout,
                      NULL, addrp, NULL, &grant, &reqport, &dialport,
                      dial_timer);

    switch(rv) {
      case 0: /* success */
        *port = dialport.unit;
	*ptype = dialport.type;
        rv = grant;
        break;

      case -2: /* timeout */
        rv = DIAL_TIME;
        break;
        
      case -1: /* general failure */
      default:
        rv = DIAL_REJ;
        break;
    }
    
    return(rv);
}

/*
 *  acp_request_dialout_udp()
 *
 *  Make a dialout remote procedure call
 *
 *  Initialize a socket, call  up SRPC and call srpc_create requesting prog
 *  COURRPN_SECURITY proc RPROC_SRPC_OPEN, make ACP_DO_DIALOUT SRPC call.
 *  If successful, convert response and return status and port number.
 */

acp_request_dialout_udp(inet, username, access_code, phone, 
        job, port_mask, port, ptype, service, ipx_netnum)

UINT32        inet;
char    *username;
char    *access_code;
char    *phone;
char    *job;
unsigned char    *port_mask;
int  *port,*ptype;
UINT32        service; 
UINT32        ipx_netnum;
{
    int		srpc_retcd,		/* return code from SRPC layer */
		length,			/* actual message return length */
		return_code;		/* final return code for caller */

    ACP_DIALOUT		acp_dialout;
    ACP_DIALOUT_GRANT	response;
    SRPC	srpc;
    int		s;
    struct sockaddr_in sock_inet;		/* Inet address of Annex */
    struct servent *sp;

    /* Set Annex address. */
    bzero((char *)&sock_inet, sizeof (sock_inet));
    sock_inet.sin_addr.s_addr = inet;
    sock_inet.sin_family = AF_INET;
    sp = getservbyname("erpc", "udp");
    if (sp == 0) 
	return DIAL_ADDR;

    sock_inet.sin_port = sp->s_port;

    if (debug)
	printf("**** acp_request_dialout_udp:  address %X, port %d.\n",
	    sock_inet.sin_addr.s_addr,ntohs(sock_inet.sin_port));

    /* open srpc connection with the Annex */
    return_code = dialout_srpc_open(&srpc, &s, &sock_inet, COURRPN_ACP,ACP_VER);

    if (debug)
	printf("acp_request_dialout_udp:  dialout_srpc_open ret %d.\n",return_code);

    if(return_code != DIAL_SUCC) {
	    length = 4;
	    goto chkerr;
	    }

    {

	/*
	 *  Now that a session is open, calls can be made.
	 *  fill in the argument part of the message with the dial out info.
	 */

	bzero(&acp_dialout, sizeof(ACP_DIALOUT));

        acp_dialout.acp_cap = rand();
        strcpy(acp_dialout.username, (char *)username);
        strcpy(acp_dialout.access_code, (char *)access_code);
        bcopy(port_mask, acp_dialout.port_mask, LEN_PORT_MASK);
        strcpy(acp_dialout.phone, (char *)phone);
        strcpy(acp_dialout.un.job, (char *)job);
        if (service == SERVICE_IPX) {
                set_long(&acp_dialout.un.type, SERVICE_IPX);
                set_long(&acp_dialout.un.ipx.netnum, ipx_netnum);
        }

	if (debug) {
	    printf("acp_request_dialout_udp: Calling srpc_callresp(do_dialout).\n");
	}

	/*
	 * The srpc connection is open, now send the ACP_DO_DIALOUT rpc
	 * to the Annex to start the dialout.
	 */
	srpc_retcd =
	srpc_callresp(&srpc, s, &sock_inet, getpid(), COURRPN_ACP,
		      ACP_VER, (unsigned short)ACP_DO_DIALOUT,
		      &acp_dialout, sizeof(acp_dialout), REQUEST_DELAY, DIALB_TIMEOUT,
		      &response, sizeof(ACP_DIALOUT_GRANT), &length);
	if (debug)
	   printf("acp_request_dialout_udp:srpc_callresp returns %d.\n",srpc_retcd);

chkerr:

	/* return decoded parameters, or error reason code */

	if (debug)
	    printf("acp_request_dialout_udp:  srpc_retcd=%d.\n",srpc_retcd);

	switch (srpc_retcd)
	{
	    case S_SUCCESS:

		if (debug)
			printf("acp_request_dialout_udp:  grant=0x%x, port=%d.\n",
				response.grant, response.port);
		*port = ntohs(response.port);
		return_code = ntohl(response.grant);
		break;

	    case S_TIMEDOUT:

		return_code = DIAL_TIME;
		break;

	    default:
		return_code = DIAL_REJ;
	}

    }

/* exit: */

    if (debug)
	printf("acp_request_dialout_udp: returning with code %d.\n",return_code);

    return return_code;

}


/********************************************************************************
This fxn retrieves the current time stamp and stores it in the time field of the
environment struct. for the per-user and group environment spec. MA
********************************************************************************/

int get_time_stamp(incoming_time)
struct tm *incoming_time;
{
struct tm *temp;
struct timeval tp;
struct timezone tzp;

if (incoming_time == (struct tm *)NULL)return(FALSE);
if (gettimeofday(&tp, &tzp) != 0)return(FALSE);

#ifdef _WIN32						
time(&(tp.tv_sec));                /* Get time as long integer. */
#endif /* _WIN32 */

if (( temp = localtime(&(tp.tv_sec))) == NULL)return(FALSE);
/*copying the localtime to the caller's 
  incoming strucitre*/
*incoming_time = *temp;
return(TRUE);
}


#ifndef _WIN32		/* is this needed at all? */
int acp_annex_status_return(msg)
struct annex_status_return *msg;
{
if (msg->annex_errno == ESUCCESS)return(TRUE);
else return(FALSE);

}
#endif /* not _WIN32 */

int acp_add_filter()
{
/*** THIS IS A STUB*****/
return(-1);
}
