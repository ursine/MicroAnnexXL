/*
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 *     ACP:  Host Security Server - Remote program within /etc/erpcd
 *
 * Original Author: Dave Harris        Created on: July 21, 1986
 *
 * Module Reviewers:
 *
 *    lint parker
 *
 *
 *****************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include "../inc/config.h"
#include "../inc/port/port.h"

#ifndef _WIN32
#include <sys/wait.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <strings.h>
#else
#endif /* _WIN32 */

/*#include <sys/types.h>*/
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#ifndef _WIN32
extern int sys_nerr;
#endif /* not _WIN32 */

#include "../libannex/api_if.h"
#include "../libannex/srpc.h"
#include "../inc/courier/courier.h"
#include "../inc/erpc/erpc.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "../libannex/asn1.h"
#include "getacpuser.h"
#include "acp_policy.h"

#ifdef RADIUS_ACCT
#include "radius.h"
#ifndef _WIN32
#include "session_db.h"
#endif /* _WIN32 */
#endif


/* External Data Declarations */

/* Defines and Macros */

#define MAX_TIME        30      /* Seconds allowed between valid requests */

#ifndef TRUE
#define TRUE    -1
#define FALSE    0
#endif

#ifndef NULL
#define NULL    ((char *)0)
#endif

/* External Routine Declarations */

#ifdef _WIN32
void alarm();
void RegistAlarmHandler();
#endif
extern    UINT32        get_long();
void        timer();
void erpc_reject();
void display();
int api_rcvud();
void acp_req_appletalk_profile2();
int acp_hook_callback();
void acp_req_appletalk_profile();
void acp_req_dialup_address();
void acp_req_user_index();
void acp_request_log();
void acp_req_serial_validate();
void acp_logout_ppp_slip();
void acp_req_port_to_annex();
void acp_req_annex_to_lat();
void acp_req_annex_to_net();
void acp_req_net_to_port();
void acp_logout_port_to_annex();
void acp_logout_annex_to_lat();
void acp_logout_net_to_port();
void acp_logout_annex_to_net();
void acp_logout_net_to_port();
void acp_global_init();
void acp_srpc_open();
void log_acknowledge();
int acp_auth_req();
int acp_info_req();
int acp_exec_req();
int acp_audit_log();
void terminate_session();
void radius_close_actserver();

/* External Data Declarations */

extern	int  debug;		/* 1-5 if -D switch used; 0 otherwise */
extern	char *myname;
#if !defined(FREEBSD) && !defined(BSDI) && defined(USE_NDBM)
extern	char *sys_errlist[];	/* errno strings */
#endif

int acp_timer_enabled;

ACP *globalacp;

/* Static Declarations */

/*********************************************************************
*  Security Server for Annex - Access Control Protocol
*
*  Created by ERPC listener daemon to handle ACP and SRPC requests.
*
*  Files are assumed open as follows:
*
*       0,1,2   stdin, stdout, stderr from erpcd.
*       s       service supplying UDP socket connected to requester.
*********************************************************************/

acp(s, message, mlen, iaddr)

    int    s;        /*  file descriptor of a socket    */
    char    *message;    /*  pointer to first message    */
    int    mlen;        /*  length of indicated message    */
    UINT32    iaddr;    /*  Internet address of Annex */
{

    char            cbuff[BUFFSIZE];
    register struct chdr    *ch = (struct chdr *)cbuff;
    register char        *carg = (cbuff + CHDRSIZE);
    int            first_time = TRUE;

    static    ACP        Acp;
    static    SRPC        srpc;
    static char         *appl_nam="acp";
    char      cinaddr[18];

#ifdef SPT_TYPE
    strncpy(cinaddr, ipaddr_string(iaddr), 17);
    setproctitle("acp/udp: %s", cinaddr);
#endif

        /* Keep receiving requests on the UDP socket until an end  *\
        \* session request is received or a severe error occurs.   */


#ifdef _WIN32
		RegistAlarmHandler(timer);
#else
        (void)signal(SIGALRM, timer);
#endif

    bzero(&Acp, sizeof(ACP));
    globalacp = &Acp;

    Acp.Srpc = &srpc;
    Acp.s = s;
    Acp.inet = iaddr;
    SETUDP(Acp.state);

    Acp.key = annex_key(iaddr);
    acp_timer_enabled = 1;

        for (;;)    /* forever */
            {
            int cc, result;
        int lng;
            UINT32 pid;
        UINT32 rpnum;

        /* First time, copy message to global area*/

        if(first_time)
            {
        bcopy(message, cbuff, mlen);
        cc = mlen;
        first_time = FALSE;
            }
        else
        {

        /* Await next call message with timeout. */

        if (acp_timer_enabled)
            (void)alarm(MAX_TIME);

        cc = sizeof(cbuff);
        result = api_rcvud(&cc,(int *)0,s,NULL,cbuff,appl_nam,TRUE,
                    (struct sockaddr_in *)0);
        switch (result) {
            case 1:
            ErpcdExit(1);
            case 2:
            ErpcdExit(-1);
            case 3:
            continue;
            default:
            break;
        }
        (void)alarm(0);
        }

            /* Verify that packet length is at least long enough to
               contain required information.  If not, the packet is
               just ignored, since we can't be sure of the info to
               use in sending a reject.  */

            if(cc < CHDRSIZE)
                {
            if(debug)
            {
                    printf("Message ignored: %d too short to be valid\n", cc);
                    display(cbuff, cc);
                }
                continue;       /* for(;;) */
                }

            /* Make sure the client type is for the ERPC protocol
               and this is a courier CALL request. */

            if(ntohs(ch->ch_client) != PET_ERPC)
                {
            if(debug)
            {
                    printf("Message ignored: %x is not a valid client type.\n",
                           ntohs(ch->ch_client));
                    display(cbuff, cc);
                }
                continue;       /* for(;;) */
                }

        pid = get_long(ch->ch_id);

            if(ntohs(ch->ch_type) != C_CALL || ch->ch_tid)
                {
        (void)erpc_reject(s, NULL, pid,
                      CMJ_NOVERS, ACP_VER, ACP_VER);
            if(debug)
            {
                    printf("Message rejected: %x is an invalid cmc type.\n",
                           ntohs(ch->ch_type));
                    display(cbuff, cc);
                }
                continue;       /* for(;;) */
                }

        rpnum = get_long(ch->ch_rpnum);

            if(rpnum != ACP_PROG)
                {
                (void)erpc_reject(s, NULL, pid, CMJ_NOPROG, 0, 0);
            if(debug)
            {
                    printf("Message rejected: %x is an invalid cmc rpnum.\n",
                           rpnum);
                    display(cbuff, cc);
                }
                continue;       /* for(;;) */
                }

            if(ntohs(ch->ch_rpver) > ACP_VER)
                {
                (void)erpc_reject(s, NULL, pid,
                          CMJ_NOVERS, ACP_VER, ACP_VER);
            if(debug)
            {
                    printf("Message rejected: %x > %x is an invalid cmc rpver.\n",
                           ntohs(ch->ch_rpver), ACP_VER);
                    display(cbuff, cc);
                }
                continue;       /* for(;;) */
                }

        Acp.pid = pid;
        lng = cc - CHDRSIZE;

        /*  If one of the supported procedures, call it, else reject  */

            switch(ntohs(ch->ch_rproc)) {

        case ACP_REQUEST_APPLETALK_PROFILE2:
            if (debug > 1) {
		printf("ACP_REQUEST_APPLETALK_PROFILE2:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_APPLETALK_PROFILE2", cinaddr);
#endif
            acp_req_appletalk_profile2(&Acp, carg, lng, NULL);
            break;

        case ACP_HOOK_CALLBACK:
            if (debug > 1) {
		printf("ACP_HOOK_CALLBACK:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: HOOK_CALLBACK", cinaddr);
#endif
            acp_hook_callback(&Acp,carg,lng);
            break;

        case ACP_REQUEST_APPLETALK_PROFILE:
            if (debug > 1) {
		printf("ACP_REQUEST_APPLETALK_PROFILE:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_APPLETALK_PROFILE", cinaddr);
#endif
            acp_req_appletalk_profile(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_DIALUP_ADDRESS:
            if (debug > 1) {
		printf("ACP_REQUEST_DIALUP_ADDRESS:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_DIALUP_ADDRESS", cinaddr);
#endif
            acp_req_dialup_address(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_USER_INDEX:
            if (debug > 1) {
		printf("ACP_REQUEST_USER_INDEX:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_USER_INDEX", cinaddr);
#endif
            acp_req_user_index(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_LOG:
            if (debug) {
		printf("ACP_REQUEST_LOG:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_LOG", cinaddr);
#endif
            acp_request_log(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_PPP_SECURITY:
            if (debug) {
		printf("ACP_REQUEST_PPP_SECURITY:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_PPP_SECURITY", cinaddr);
#endif
            acp_req_serial_validate(&Acp, carg, lng, NULL);
            break;

        case ACP_LOGOUT_PPP_SLIP:
            if (debug > 1) {
		printf("ACP_LOGOUT_PPP_SLIP:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: LOGOUT_PPP_SLIP", cinaddr);
#endif
            acp_logout_ppp_slip(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_PORT_TO_ANNEX:
            if (debug > 1) {
		printf("ACP_REQUEST_PORT_TO_ANNEX:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_PORT_TO_ANNEX", cinaddr);
#endif
            acp_req_port_to_annex(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_ANNEX_TO_LAT:
            if (debug > 1) {
		printf("ACP_REQUEST_ANNEX_TO_LAT:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_ANNEX_TO_LAT", cinaddr);
#endif
            acp_req_annex_to_lat(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_ANNEX_TO_NET:
            if (debug > 1) {
		printf("ACP_REQUEST_ANNEX_TO_NET:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_ANNEX_TO_NET", cinaddr);
#endif
            acp_req_annex_to_net(&Acp, carg, lng, NULL);
            break;

        case ACP_REQUEST_NET_TO_PORT:
            if (debug > 1) {
		printf("ACP_REQUEST_NET_TO_PORT:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: REQUEST_NET_TO_PORT", cinaddr);
#endif
            acp_req_net_to_port(&Acp, carg, lng, NULL);
            break;

        case ACP_LOGOUT_PORT_TO_ANNEX:
            if (debug > 1) {
		printf("ACP_LOGOUT_PORT_TO_ANNEX:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: LOGOUT_PORT_TO_ANNEX", cinaddr);
#endif
            acp_logout_port_to_annex(&Acp, carg, lng, NULL);
            break;

        case ACP_LOGOUT_ANNEX_TO_LAT:
            if (debug > 1) {
		printf("ACP_LOGOUT_ANNEX_TO_LAT:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: LOGOUT_ANNEX_TO_LAT", cinaddr);
#endif
            acp_logout_annex_to_lat(&Acp, carg, lng, NULL);
            break;

        case ACP_LOGOUT_ANNEX_TO_NET:
            if (debug > 1) {
		printf("ACP_LOGOUT_ANNEX_TO_NET:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: LOGOUT_ANNEX_TO_NET", cinaddr);
#endif
            acp_logout_annex_to_net(&Acp, carg, lng, NULL);
            break;

        case ACP_LOGOUT_NET_TO_PORT:
            if (debug > 1) {
		printf("ACP_LOGOUT_NET_TO_PORT:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: LOGOUT_NET_TO_PORT", cinaddr);
#endif
            acp_logout_net_to_port(&Acp, carg, lng, NULL);
            break;

        case ACP_GLOBAL_INIT:
            if (debug > 1) {
		printf("ACP_GLOBAL_INIT:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: GLOBAL_INIT", cinaddr);
#endif
            acp_global_init(&Acp, carg, lng, NULL);
            break;

        case ACP_SRPC_OPEN:
            if (debug > 1) {
		printf("ACP_SRPC_OPEN:\n");
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: SRPC_OPEN", cinaddr);
#endif
            acp_srpc_open(&Acp, carg, lng, NULL);
            break;

        default:
            (void)erpc_reject(s, NULL, pid, CMJ_NOPROC, 0, 0);
            if (debug) {
		printf("Message rejected: %x is an invalid cmc rproc\n",
		       ntohs(ch->ch_rproc));
		display(cbuff, cc);
	    }
#ifdef SPT_TYPE
	    setproctitle("acp/udp: %s: INVALID", cinaddr);
#endif

        }   /* switch */
    }    /* for(;;) */
#ifdef _WIN32
    return 0;
#endif
} /* main() */


void log_timer()
{
    log_acknowledge(globalacp);
#ifdef _WIN32
	RegistAlarmHandler(log_timer);
#else
    (void)signal(SIGALRM, log_timer);
#endif
    (void)alarm(90);
}

void racp_timer()
{
    if (!globalacp)
		ErpcdExit(-1);
	racp_shutdown(globalacp);
}

void acp_tcp(socket, inaddr)
     int socket;
     UINT32 inaddr;
{
    char *app_nam = "acp_tcp:";
    errno_t rcode;
    static ACP acp;
    static RACP racp;
    KEYDATA rcv_key, send_key;
    char cbuff[BUFFSIZE];
    int pdulen = 0;
    unsigned char *pdu = NULL;
    u_char asn_type = 0;
    int audit_conn = FALSE;
    int log_timer_started = FALSE;
    char cinaddr[18];

#ifdef SPT_TYPE
    strncpy(cinaddr, ipaddr_string(inaddr), 17);
    setproctitle("acp/tcp: %s", cinaddr);
#endif

    globalacp = &acp;

    /* initialize acp */
    bzero(&acp, sizeof(ACP));
    bzero(&racp, sizeof(RACP));
    acp.s = socket;
    acp.racp = &racp;
    acp.key = annex_key(inaddr);
    acp.racp->rcv_key = &rcv_key;
    acp.racp->send_key = &send_key;
    SETOPEN(acp.state);
    SETTCP(acp.state);
    acp.racp->capability = CAP_GLOBAL;
    acp.racp->options = NO_DATAENC;
    acp.racp->version = RACP_HI_VER;
    acp.inet = inaddr;

    if ((racp_accept_conn(&acp, RACP_LO_VER) != ESUCCESS) ||
        !(ISCONN(acp.state))) {
        racp_shutdown(&acp);
        return;
    }
    /* we assume we are an audit logging connection */
#ifdef _WIN32
	RegistAlarmHandler(log_timer);
#else
    (void)signal(SIGALRM, log_timer);
#endif

    alarm(90);

    /*
     * We are now officially connected, lets process incoming PDUs
     *
     * If we timeout on a logging connection, we must assume that the
     * Annex went down for good and clean up the TMS database.  If it
     * was reset by the remote side, we must not clean up because the
     * cleanup was done when the new logging connection was created.
     */
    for(;;) {

        if ((rcode = racp_recv_pdu(&acp, cbuff, BUFFSIZE, &pdulen, &pdu))
             != ESUCCESS) {
            if (rcode == EINTR)
                continue;
#ifdef USE_NDBM
	    if (ISAUDIT(acp.state)) {
		struct in_addr ras_addr;
#endif  /* USE_NDBM */

#ifdef RADIUS_ACCT
        radius_close_actserver(inaddr, PW_CAUSE_LOST_SERVICE);
#ifndef _WIN32
        ses_nas_down(inaddr);
#endif  /* defined _WIN32 */
#endif
        
#ifdef USE_NDBM
        ras_addr.s_addr = acp.inet;
		switch (rcode) {
		case ETIMEDOUT:
		    if (debug)
			printf("acp_tcp: log conn to %s timed out\n",
			       inet_ntoa(ras_addr));
		    tms_terminate(ras_addr);
		    break;
		case ECONNRESET:
		default:
		    if (debug) {
			if (rcode >= 0 && rcode < sys_nerr)
			    printf("acp_tcp(): log conn to %s returned %s\n",
			       inet_ntoa(ras_addr), sys_errlist[rcode]);
			else
			    printf("acp_tcp(): log conn to %s returned unknown error %d\n",
			       inet_ntoa(ras_addr), rcode);
			}
		    break;
		}
	    }
#endif  /* USE_NDBM */
            break;
        }

	if (debug > 2) {
	    printf("acp_tcp: received %d-octet PDU:\n", pdulen);
	    display(pdu, pdulen);
	}

        if ((pdu = asn_parse_header(pdu, &pdulen, &asn_type)) == NULL) {
            /*reading header of the packet*/
	    if (debug)
		printf("acp_tcp: asn_parse_header() returned NULL\n");
            break;
        }

        switch(asn_type) {

          case RACP_AUTH_REQ:
            alarm(0);
            if (!(ISAUDIT(acp.state)))
                acp_auth_req(&acp, pdu, pdulen);
            else if (debug)
                printf(
                  "acp_tcp: audit log connection ignoring auth-req message\n");
            break;

          case RACP_INFO_REQ:
            alarm(0);
            if (!(ISAUDIT(acp.state)))
                acp_info_req(&acp, pdu, pdulen);
            else if (debug)
                printf(
                  "acp_tcp: audit log connection ignoring info-req message\n");
            break;

          case RACP_EXEC_REQ:
            alarm(0);
            if (!(ISAUDIT(acp.state)))
                acp_exec_req(&acp, pdu, pdulen);
            else if (debug)
                printf(
                  "acp_tcp: audit log connection ignoring exec-req message\n");
            break;

#ifdef USE_NDBM
          case RACP_TMS_REQ:
            alarm(0);
            if (!(ISAUDIT(acp.state)))
                tms_req_term(&acp, pdu, pdulen);
            else if (debug)
                printf(
                  "acp_tcp: audit log connection ignoring tms-req message\n");
            break;
#endif /* USE_NDBM */

          case RACP_AUDIT_LOG:
	    if (!(ISAUDIT(acp.state))) {
#ifdef USE_NDBM
		struct in_addr ras_addr;

		ras_addr.s_addr = acp.inet;
		tms_terminate(ras_addr);
#endif /* USE_NDBM */
                SETAUDIT(acp.state);
	    }
            acp_audit_log(&acp, pdu, pdulen);
            break;

          case RACP_AUDIT_VER:
            log_acknowledge(&acp);
#ifdef RADIUS_ACCT
            radius_close_actserver(inaddr, PW_CAUSE_ADMIN_RESET);
#ifndef _WIN32
	    ses_nas_down(inaddr);
#endif  /* defined _WIN32 */
#endif
            terminate_session();
            break;

          default:
            if (debug)
                printf("acp_tcp: bad RACP message type %x\n", asn_type);
            break;
        }
    }
}
