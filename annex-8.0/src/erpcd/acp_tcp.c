/*****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 *     %$(Description)$%
 *
 * Detailed Design Specification:
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 * Module Reviewers:
 *    %$(reviewers)$%
 *
 * Revision Control Information:
 * $Id: acp_tcp.c,v 1.1 1995/09/26 12:51:02 dfox Exp deluca $
 *
 * This file created by RCS from
 * $Source: /nfs/pigpen/u9/deluca/annex/mckinley/src/erpcd/RCS/acp_tcp.c,v $
 *
 * Revision History:
 * $Log: acp_tcp.c,v $
 * Revision 1.1  1995/09/26  12:51:02  dfox
 * Initial revision
 *
 * This file is currently under revision by: $Locker: deluca $
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *    DESIGN DETAILS
 *   This contains functions that handle RACP requests and dispatch to
 *   acp_policy.c
 *
 *    MODULE INITIALIZATION -
 *   All functions require a connected ACP link
 *
 *    PERFORMANCE CRITICAL FACTORS -
 *          Describe any special performance criteria pertaining to
 *              this module.
 *
 *      RESOURCE USAGE -
 *       Needs to allocate/free large buffers for parsing/building
 *
 *    SIGNAL USAGE -
 *
 *      SPECIAL EXECUTION FLOW -
 *
 *     SPECIAL ALGORITHMS -
 *
 ***************************************************************************
 */

/* Include Files */
#include "../inc/config.h"
#include <stdio.h>

#include "../inc/port/port.h"
#include <sys/types.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/uio.h>
#include <string.h>
#include <strings.h>
#endif
#include <errno.h>
#include "../inc/courier/courier.h"
#include "../libannex/asn1.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "acp_policy.h"
#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#include <arpa/inet.h>	/* inet_ntoa() defs */
#endif /* _WIN32 */

#if defined(ALPHA)
#define INT32 int
#define UINT32 unsigned int
#else
#ifndef INT32
#define INT32 long
#endif
#ifndef UINT32
#define UINT32 unsigned long
#endif
#endif


extern int debug;
extern StructErpcdOption *ErpcdOpt;
char sbuf[512];

/* External Routine Declarations */
extern UINT32 get_long(), get_unspec_long();

void reject_session();
void global_init();
void appletalk_profile();
void dialup_address();
void user_index();
void ipx_validate();
void ppp_security();
int ppp_slip_logout();
void port_to_annex();
void annex_to_net();
void annex_to_lat();
void net_to_port();
void port_to_annex_logout();
void annex_to_net_logout();
void annex_to_lat_logout();
void net_to_port_logout();
int hook_callback();
void terminate_session();
int srpc_decode();
int srpc_cmp();
int srpc_answer();
int acp_auth_resp();
int acp_info_resp();
int acp_exec_reply();
int write_audit_log();
void get_host_name();
void max_logon_val();
char *error_log();
int parse_domain();
#ifndef _WIN32
int tms_req_init();
#endif	/* _WIN32 */

/* Forward Routine Declarations */
int type_of_req();
#define DOMAIN_DELIMIT '@'
#define TLD_DELIMIT '.'
#define REQ_TYPE_DROP 0
#define REQ_TYPE_ACP  1
#define REQ_TYPE_TMS  2

#ifdef _WIN32
int syslog( int pri, const char *format, ...);
#endif

/*
 *          Global Data Declarations
 */
SECPORT *port_used = 0;
int *addr_used = 0;

/*****************************************************************************
 *
 * NAME: acp_auth_req
 *
 * DESCRIPTION:
 *  This parses a RACP authorization-request message and dispatches to
 *  acp_policy.c
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  *pdu - address of PDU
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

int acp_auth_req(acp, pdu, pdulen)
ACP *acp;
char *pdu;
int pdulen;
{

    int linet, rc;
    INT32 service_from = -1;
    INT32 service_request = -1;
    SECPORT port_from;
    SECPORT port_destination ;
    NetAddr from_addr;		/* FOR NOW, LETS LEAVE THIS NON-POINTER */
    NetAddr destination_addr;	/* FOR NOW, LETS LEAVE THIS NON-POINTER */
    ACP_USTRING user_name;
    ACP_USTRING tmp_uname;
    ACP_STRING pass_word;
    ACP_STRING phonenumber;
    CHAP_REQ chap;
    ACP_STRING called_number;
    ACP_STRING calling_number;
    ACP_STRING called_subaddress;
    ACP_STRING spb_name;
    ARQ_PROFILE opt_info;

    if (debug > 2)
	printf("Entering acp_auth_req()\n");

    bzero(&from_addr, sizeof(NetAddr));
    bzero(&destination_addr, sizeof(NetAddr));

    acp->auth.hmask = 0;  /* default no hooks */
    called_number[0] = '\0';
    calling_number[0] = '\0';
/* parsing segments from the ASN1 pdu*/

    bzero(&opt_info, sizeof(ARQ_PROFILE));
    opt_info.user_name = user_name;
    opt_info.pass_word = pass_word;
    opt_info.phonenumber = phonenumber;
    opt_info.from_Address = &from_addr;
    opt_info.dest_Address =  &destination_addr;
    opt_info.chap_req = &chap;
    opt_info.called_number = called_number;
    opt_info.calling_number = calling_number;
    opt_info.spb_name = spb_name;
    opt_info.called_subaddress = called_subaddress;
    if (racp_parse_auth_req(pdu, &pdulen, &service_from, &service_request,
                          &port_from, &port_destination, &opt_info) == NULL) {
	if (debug)
	    printf("acp_auth_req: racp_parse_auth_req() returned NULL\n");
        errno = EINVAL;
        return(ACP_ERROR);
    }

    linet = (from_addr.n.ip_addr.inet ? from_addr.n.ip_addr.inet : acp->inet);
    addr_used = &linet;

    /*
     * Check to see if we should authenticate, hand off to TMS, or drop user.
     * If there is no RAS address, that is a signal from the Annex that
     * tunnelling is disabled and ERPCD should not use TMS
     */
    if (opt_info.ras_addr != 0L) {
      char *user, *domain;
      struct in_addr rasid;

      /*
       * save user_name intact with potential domain,
       * in case we want to roll over from a tms
       * lookup to acp lookup (type_of_req() is
       * destructive to user_name).
       */
      (void) strcpy(tmp_uname, opt_info.user_name);
      rc = type_of_req(&opt_info, &user, &domain);

      if (rc == REQ_TYPE_DROP) {
	if (debug > 1)
	  printf("acp_auth_req: type_of_req() returned DROP for user \"%s\"\n",
		 opt_info.user_name);
	return(acp_auth_resp(acp, REQ_DENIED, NULL, NULL, NULL));
      }

#ifndef _WIN32
      if (debug > 1) {
        if (rc == REQ_TYPE_ACP) {
	  printf("acp_auth_req: type_of_req() no domain in username \"%s\"\n",
		 opt_info.user_name);
	} else {
	  printf("acp_auth_req: type_of_req() domain in username \"%s\"\n",
		 opt_info.user_name);
	}
      }

      rasid.s_addr = opt_info.ras_addr;
      rc = tms_req_init(acp, rasid, domain, opt_info.called_number, user);
      if (rc == ENOENT) {
	    rc = REQ_TYPE_ACP;
	    /* restore username with domain */
            (void) strcpy(opt_info.user_name, tmp_uname);
      } else {
	    return(rc);
      }
#endif	/* _WIN32 */
      if (debug > 1) {
        printf("acp_auth_req: no match on domain or dnis, trying ACP for user \"%s\"\n",
		     tmp_uname);
      }
    }

    switch (service_request) {
      case SERVICE_CLI_HOOK:
      case SERVICE_DIALBACK:
	port_used = &port_destination;
        port_to_annex(acp, 0, linet, port_destination.unit,
		      port_destination.type, service_request, &opt_info);
        return(0);

      case SERVICE_IPX:
      case SERVICE_IPX_DIALBACK:
	port_used = &port_from;
        ipx_validate(acp, 0, linet, port_from.unit, port_from.type,
		     service_request,
                user_name, pass_word, phonenumber,
                destination_addr.n.ipx_addr.network, &opt_info);
        return(0);

      case SERVICE_PPP:
      case SERVICE_SYNC_PPP:
      case SERVICE_VPN_PPP:  
      case SERVICE_SLIP:
      case SERVICE_FTP:
	port_used = &port_destination;
        ppp_security(acp, 0, linet, port_destination.unit,
		     port_destination.type, service_request, 0,
                   user_name, pass_word, &opt_info);
	return(0);

      case SERVICE_TELNET:
      case SERVICE_RLOGIN:
	port_used = &port_from;
        annex_to_net(acp, 0, linet, port_from.unit, port_from.type,
		     service_request,
                   destination_addr.n.ip_addr.inet, user_name,
                   destination_addr.n.ip_addr.port);
	return(0);

      case SERVICE_CONNECT:
	port_used = &port_from;
        annex_to_lat(acp, 0, acp->inet, port_from.unit, port_from.type,
		     service_request,
                            user_name, destination_addr.n.lat_addr.service);
	return(0);

      case SERVICE_PORTS:
	port_used = &port_destination;
	net_to_port(acp, 0, acp->inet, port_destination.unit,
		    port_destination.type,
		    service_request, from_addr.n.ip_addr.inet, &opt_info);
        return(0);

    case SERVICE_CHAP:
        acp->chap = &chap;
        chap_authenticate(acp, &port_from, user_name, &opt_info);
        return(0);

      default:
        break;
    }

    sprintf(sbuf, "acp_auth_req: unknown request %d denied",service_request);

    if (debug)
      printf(sbuf);

#ifdef USE_SYSLOG
    syslog(LOG_ERR, sbuf);
#endif

    return(acp_auth_resp(acp, REQ_DENIED, NULL, NULL, NULL));
}


/*****************************************************************************
 *
 * NAME: acp_info_req
 *
 * DESCRIPTION:
 *  This parses a RACP information-request message and dispatches to
 *  acp_policy.c
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  *pdu - address of PDU
 *  pdulen - length of PDU
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

int acp_info_req(acp, pdu, pdulen)
ACP *acp;
char *pdu;
int pdulen;
{
    SECPORT port_from;
    int service_from, service_request;
    ACP_USTRING username;
    NetAddr locaddr, remaddr;
    char node[6];
    UINT32 code = 0;
    IRQ_PROFILE opt_info;
    int mp_max_links, max_logon;
EndpDesc        *endpoint;                /* MP Endpoint Discriminator */

    bzero(&locaddr, sizeof(NetAddr));
    bzero(&remaddr, sizeof(NetAddr));
    bzero(&opt_info, sizeof(IRQ_PROFILE));

    opt_info.user_name = username;
    opt_info.local_Address = &locaddr;
    opt_info.remote_Address = &remaddr;
    opt_info.code = (long *)&code;
    opt_info.mp_max_links = &mp_max_links;
    opt_info.max_logon = &max_logon;


    if (racp_parse_info_req(pdu, pdulen, &service_from, &service_request,
                            &port_from, NULL, &opt_info)) {

        switch (service_request) {
        case SERVICE_DIALUP:
        case SERVICE_SYNC_DIALUP:
            dialup_address(acp, 0, acp->inet, port_from.unit, port_from.type,
                           service_from, service_request, username,
                           locaddr.n.ip_addr.inet,
                           remaddr.n.ip_addr.inet, node, (code & FILT_MASK),
                           (code & ROUT_MASK));
            return(0);

        case SERVICE_DIALUP_IPX:
            dialup_address(acp, 0, acp->inet, port_from.unit, port_from.type,
                           service_from, service_request, username,
                           locaddr.n.ipx_addr.network,
                           remaddr.n.ipx_addr.network,
                           remaddr.n.ipx_addr.node, 0, 0);
            return(0);

          case SERVICE_AT_PROFILE:
             appletalk_profile(acp, 0, acp->inet, port_from.unit,
			       port_from.type,
                                     SERVICE_ARAP, username, TRUE);
             return(0);

          case SERVICE_DYNDIALPASS:
          case SERVICE_SECRET:
          case SERVICE_MP:
            endpoint=&(opt_info.endpoint);
            endpoint->valid = 1;
            user_index(acp, 0, acp->inet, port_from.unit, port_from.type,
                          service_request, username, &opt_info.endpoint);
            return(0);
	  case SERVICE_MAX_LOGON:
            max_logon_val(acp, 0, acp->inet, port_from.unit,
                          service_request, username, NULL);
            return(0);


          default:
            break;
        }
    }

    sprintf(sbuf, "acp_info_req: unknown request %d denied",service_request);
    if (debug)
      printf(sbuf);
#ifdef USE_SYSLOG
    syslog(LOG_ERR, sbuf);
#endif
    return(acp_info_resp(acp, REQ_DENIED, NULL));
}

/*****************************************************************************
 *
 * NAME: acp_exec_req
 *
 * DESCRIPTION:
 *  This parses a RACP execution-request message and dispatches to
 *  acp_policy.c
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  *pdu - address of PDU
 *  pdulen - length of PDU
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

int acp_exec_req(acp, pdu, pdulen)
ACP *acp;
char *pdu;
int pdulen;
{
    int serv_req = 0;
    int code = 0;
#ifndef _WIN32
    ACP_LSTRING text;
#else   /* defined _WIN32 */
	ACP_USTRING text;
#endif   /* defined _WIN32 */

    ERQ_PROFILE opt_info;

    bzero(&opt_info, sizeof(ERQ_PROFILE));
    opt_info.text = text;
    opt_info.code = &code;
    if (racp_parse_exec_req(pdu, &pdulen, NULL, &serv_req, &opt_info)) {
        switch(serv_req) {

          case SERVICE_SHELL:
            return(hook_callback(acp, 0, code, text));
            break;

          default:
            break;
        }
    }

    sprintf(sbuf, "acp_exec_req: unknown request %d denied", serv_req);
    if (debug)
       printf(sbuf);
#ifdef USE_SYSLOG
    syslog(LOG_ERR, sbuf);
#endif
    return(acp_exec_reply(acp, REQ_DENIED, NULL, NULL, NULL, NULL));
}


/*****************************************************************************
 *
 * NAME: acp_audit_log
 *
 * DESCRIPTION:
 *  This parses a RACP audit-log request and writes the log
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  *pdu - address of PDU
 *  pdulen - length of PDU
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

int acp_audit_log(acp, pdu, pdulen)
ACP *acp;
char *pdu;
int pdulen;
{
    int servfrom, servreq;
    UINT32 event;
    UINT32 logid, ctime;
    SECPORT port;
    NetAddr remaddr;
    ACP_USTRING user;
    LOG_PORT_STATS stats;
#ifndef _WIN32
    ACP_LSTRING err_msg;
	char text[ACP_MAXLSTRING * 2];
#else   /* defined _WIN32 */
	ACP_USTRING err_msg;
	char text[ACP_MAXUSTRING * 2];
#endif   /* defined _WIN32 */

    ACP_STRING tcpport;
    NetAddr *remaddrp = &remaddr;
    char *userp = user;
    LOG_PORT_STATS *statsp = &stats;
    char *textp = text;
    u_char *end;
#ifdef USE_SYSLOG
    ACP_STRING hostname;
    struct in_addr tmpbuf;
#endif /* USE_SYSLOG */

    user[0] = text[0] = tcpport[0] = 0;
    bzero(&port, sizeof(SECPORT));
    bzero(statsp, sizeof(LOG_PORT_STATS));
    if ((end = racp_parse_audit_log(pdu, pdulen, &servfrom, &servreq,
        &port, (int *)&event, &ctime, &remaddrp, &userp, &statsp, &textp, &logid))
        == NULL) {
#ifdef USE_SYSLOG
		if (ErpcdOpt->UseSyslog)
		{
			hostname[0] = 0;
			get_host_name(hostname, acp->inet);
		/* Put the IP address into an in_addr struct so we can
		 * produce a printable version of the string.
		 */
			tmpbuf.s_addr = acp->inet;

			syslog(LOG_CRIT, "RACP parse error from annex %s", inet_ntoa(tmpbuf));
		}
#endif
        event = EVENT_PARSE;
    }

     if (ISREJECT(event)) {
         err_msg[0] = '\0';

         error_log(event, err_msg);
         if (err_msg[0] != '\0') {
             strncat(text, err_msg, ACP_MAXSTRING);
#ifndef _WIN32
            text[ACP_MAXLSTRING * 2 - 1] = '\0';
#else   
			text[ACP_MAXUSTRING * 2 - 1] = '\0';
#endif   /* defined _WIN32 */

	     textp=text;
         }
         if (servfrom == SERVICE_SECRET || servfrom == SERVICE_ARAP ||
	     servfrom == SERVICE_AT_PROFILE)
             event = EVENT_NOPROVIDE;
         else
             event = EVENT_REJECT;
     }

    return(write_audit_log(acp->inet, logid, &port, servfrom, (int)event,
                           (time_t)ctime, statsp, remaddrp, userp, textp));
}


/*****************************************************************************
 *
 * NAME: type_of_req
 *
 * DESCRIPTION:
 *  This function determines if an authentication request is for
 *  ACP, TMS or neither.  If TMS, the user and domain name pointers
 *  are returned.
 *
 * ARGUMENTS:
 *  oip - INPUT pointer to opt_info structure
 *  unp - OUTPUT pointer to user name pointer
 *  dnp - OUTPUT pointer to domain name pointer
 *
 * RETURN VALUE:
 *  REQ_TYPE_DROP	disconnect the user (for later)
 *  REQ_TYPE_ACP	do ACP authentication
 *  REQ_TYPE_TMS	do TMS handling
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *  The input username field is modified (the '@' becomes a '\0')
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

static int type_of_req(oip, unp, dnp)
ARQ_PROFILE *oip;
char **unp;
register char **dnp;
{
  int rc;
  rc = parse_domain(oip->user_name, unp, dnp);
  if (rc == ESUCCESS)
      return(REQ_TYPE_TMS);
  else
      return(REQ_TYPE_ACP);
}

/*****************************************************************************
 *
 * NAME: parse_domain
 *
 * DESCRIPTION:
 *  This function parses out the username and domain if they exist.
 *  If they exists, the user and domain name pointers are returned.
 *
 * ARGUMENTS:
 *  user - INPUT pointer to username w/domain
 *  unp - OUTPUT pointer to user name pointer
 *  dnp - OUTPUT pointer to domain name pointer
 *
 * RETURN VALUE:
 *  REQ_TYPE_DROP	disconnect the user
 *  REQ_TYPE_ACP	do ACP authentication
 *  REQ_TYPE_TMS	do TMS handling
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *  The input username field is modified (the DOMAIN_DELIMIT becomes a '\0')
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int parse_domain(user, unp, dnp)
char *user;
char **unp;
register char **dnp;
{
  char *tld, *dptr;

  *unp = user;
  *dnp = strchr(user, DOMAIN_DELIMIT);

  /*
   * iff one DOMAIN_DELIMIT and at least one TLD_DELIMIT after domain
   */
  if (*dnp == NULL)
    return(EINVAL);		/* no domain; must be ACP */

  if (strlen(*dnp) < 4)
    return(EINVAL);		/* invalidly short, try ACP */

  if (strchr(*dnp+1, DOMAIN_DELIMIT))
    return(EINVAL);		/* multiple domain delimiters are invalid */

  dptr = *dnp;			/* save pointer to domain delimiter */
  (*dnp)++;

  tld = strchr(*dnp, TLD_DELIMIT);
  if (tld != NULL && (tld == *dnp || strlen(tld) < 2))
    return(EINVAL);		/* zero length domain fields are invalid */

  *dptr = '\0';			/* null terminate the user name */
  *unp = user;
  return(ESUCCESS);		/* this is a TMS request */
}
