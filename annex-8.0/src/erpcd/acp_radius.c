/*****************************************************************************
 *
 *        Copyright 1996 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module: acp_radius.c
 *
 * Author: Daniel Fox
 *
 * Module Description: This module contains the ACP-RADIUS interface routines
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *    DESIGN DETAILS -
 *    The only external function is acp_radius_validate(), which
 *    authenticates a RADIUS user and authorizes the Annex Service that
 *    the user is using.
 *
 *    MODULE INITIALIZATION -
 *    None
 *
 *    PERFORMANCE CRITICAL FACTORS -
 *    Can block for a while, so make sure calling routine can handle that
 *
 *    RESOURCE USAGE -
 *
 *    SIGNAL USAGE -
 *
 *    SPECIAL EXECUTION FLOW -
 *
 *    SPECIAL ALGORITHMS -
 *
 ***************************************************************************
 */

/* Include Files */

#include <stdio.h>
#include <sys/types.h>
#include "../inc/config.h"
#include <string.h>

#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else /* not WIN32 */
#include <syslog.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/param.h>
#endif	/* _WIN32 */

#include "../inc/port/port.h"
#include "../libannex/srpc.h"
#include "radius.h"
#include "../inc/erpc/nerpcd.h"
#include "acp_policy.h"
#include "acp_regime.h"
#include "acp.h"
#include "../libannex/api_if.h"
#include "getacpuser.h"
#include "session_db.h"

extern int debug;
extern int api_open();
extern int api_bind();
extern int api_connect();
extern int api_send();
extern int api_recvwait();
extern int promptstring();
extern unsigned char random_byte();
static int radius_build_access_request();
static int radius_authorize();
#ifndef _WIN32
extern void bzero();
extern void bcopy();
#endif	/* _WIN32 */
void radius_release_alloc();

/* strings for Login-Service, see radius.h */
static char *login_cmd[NLOGIN]  = {
    "telnet", /* PW_TELNET */
    "rlogin", /* PW_RLOGIN */
    NULL, /* PW_TCP, unsupported */
    NULL, /* PW_PORTMASTER, unsupported */
    "connect" /* PW_LAT */
};

#define VPORT_MULT  1000        /* multiplier for virtual and unknown port types */

#ifdef DUMMY_TEST
u_char *dummy_accept();
#endif

/*****************************************************************************
 *
 * NAME: acp_radius_validate
 *
 * DESCRIPTION: Authenticates a user with the RADIUS regime
 *
 * ARGUMENTS:
 *  ACP *acp - INPUT ACP control information for this ACP connection
 *  char *user - INPUT The username
 *  char *pass - INPUT The user's password
 *  SECPORT *secport - INPUT The port the user is on
 *
 * RETURN VALUE: VALIDATED or NOT_VALIDATED
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

int acp_radius_validate(acp, prompt, user, pass, secport, opt_info)
ACP *acp;
int prompt;
char *user;
char *pass;
SECPORT *secport;
ARQ_PROFILE *opt_info;
{
    u_char *sendbuf, *recvbuf, current_id;
    int id;
    int buflen = 4096;
    int sendlen = 0;
    int dlen = 0;
    int socket = -1;
    struct sockaddr_in lsin, rsin;
    struct in_addr raaddr;
    char *app_nam = "acp_radius_validate";
    int show = FALSE;
    struct radius_serverinfo *sinfo;
    struct servent *svp = NULL;
    int rv, i, j, code, dcnt;
    void dial_timer();
    u_char chappwd[CHAP_RESP_LEN + 1];
    int code_val = 0;
    CHAP_REQ *chap = acp->chap;
    struct access_request req;

    if (debug) {
        printf("acp_radius_validate\n");
        show = TRUE;
    }

    if (ISUDP(acp->state)) {
        struct in_addr in;

        in.s_addr = acp->inet;
#ifdef USE_SYSLOG
        syslog(LOG_WARNING, "Annex %s does not support RADIUS", inet_ntoa(in));
#endif
        if (debug)
            printf("Annex %s does not support RADIUS\n", inet_ntoa(in));
        return(NOT_VALIDATED);
    }

    if (default_servers == NULL) {
        if (debug)
            printf("Bad configuration; no RADIUS host set in erpcd.conf\n");
        syslog(LOG_CRIT,
               "Bad configuration; no RADIUS host set in erpcd.conf");
        return(NOT_VALIDATED);
    }

    sendbuf = (u_char*)malloc(buflen);
    if (sendbuf == NULL)
        return(NOT_VALIDATED);
    recvbuf = (u_char*)malloc(buflen);
    if (recvbuf == NULL) {
        free(sendbuf);
        return(NOT_VALIDATED);
    }

    if (chap) {
        chappwd[0] = chap->id;
        bcopy(chap->response, &chappwd[1], CHAP_RESP_LEN);
    }

    sinfo = get_serverinfo(default_servers->auth_server);

    if (sinfo == NULL) {
	if(debug)
           printf("server info not found\n");
        free(sendbuf);
        free(recvbuf);
        return(NOT_VALIDATED);
    }

    lsin.sin_family = AF_INET;
    lsin.sin_addr.s_addr = INADDR_ANY;
    lsin.sin_port = 0;

    socket = api_open(IPPROTO_UDP, &lsin, app_nam, show);

    if (socket < 0) {
        free(sendbuf);
        free(recvbuf);
        return(NOT_VALIDATED);
    }

    rv = api_bind(socket, NULL, &lsin, app_nam, show);

    if (rv == 1 || rv == 2) {
        free(sendbuf);
        free(recvbuf);
        return(NOT_VALIDATED);
    }

    for(i = 0; i < 2 && dlen == 0; i++) {

        /* try backup */
        if (i == 1) {
            if (debug) {
                u_char backup[4];

                bcopy((char*)&sinfo->backup_address, (char*)backup, 4);

                printf("Trying Backup Server %u.%u.%u.%u\n",
                        backup[0], backup[1], backup[2], backup[3]);
            }

            sinfo = get_serverinfo(sinfo->backup_address);
        }
        else if (debug)
            printf("Trying Primary Server\n");

        if (sinfo == NULL){
            if(debug > 4)
                printf("server info not found\n");
            break;
        }

        if (debug)
            dump_serverinfo(sinfo);

        sendlen = 4096;
        raaddr.s_addr = acp->inet;

        bzero((char*)&req, sizeof(struct access_request));
        req.secret = (u_char*)sinfo->shared_secret;
        req.user = user;
        req.raaddr = raaddr;
        req.port = secport;
        req.service = acp->env->protocol;
        if (chap) {
            req.chappwd = chappwd;
            req.chapchal = chap->challenge;
        }
        else
            req.pwd = (char*)pass;

	if (debug)
	  printf ("Build access request %s, %s\n", opt_info->called_number, opt_info->calling_number);
        strncpy(req.called_number, opt_info->called_number, sizeof(req.called_number));
        strncpy(req.calling_number, opt_info->calling_number, sizeof(req.called_number));

        id = radius_build_access_request(sendbuf, &sendlen, &req);

        rsin.sin_family = AF_INET;

        svp = getservbyname("radius", "udp");
        if(!svp)
            rsin.sin_port = htons(PW_AUTH_UDP_PORT);
        else
            rsin.sin_port = svp->s_port;
        rsin.sin_addr = sinfo->host_address;

        rv = api_connect(socket, &rsin, IPPROTO_UDP, app_nam, show);

        if (rv == 1 || rv == 2) {
            free(sendbuf);
            free(recvbuf);
            return(NOT_VALIDATED);
        }
        for (dlen = 0, j = 0; j < (sinfo->retries + 1) && dlen == 0; j++) {

            rv = api_send(socket, sendbuf, sendlen, 0, app_nam, show);
            if (rv == -1)
                break;

            code_val = (int)*sendbuf;
            current_id = *(sendbuf + 1);
	    dcnt = 0;

            if (debug)
                printf("Sent RADIUS %s to %s\n",
                       (code_val < NCODETYPES && code_val > 0)? 
			codetype[code_val - 1]: "",
                       inet_ntoa(rsin.sin_addr));
#ifdef USE_SYSLOG
            syslog(LOG_DEBUG, "Sent RADIUS %s to %s",
                   (code_val < NCODETYPES && code_val > 0)? 
		    codetype[code_val - 1]: "",
                   inet_ntoa(rsin.sin_addr));
#endif

/* The next loop is to discard any recveived message that, does not have the current sent id */
	    do{
               rv = api_recvwait(socket, recvbuf, buflen, sinfo->resp_timeout,0,
                              show, app_nam);

	       dcnt++;
	       if(rv <= 0)
		 break;

	       /* The BaySecure Radius server sends a ACCESS-REJECT
		* with an ID of 0 if the server does not have a secret
		* for the client.
		*/
	       if (*(recvbuf + 1) == 0)
	         {
		 /* This should fool the top of the loop into trying
		  * the secondary server
		  */
		 dlen = 0;
		 break;
		 }
	       if(current_id != *(recvbuf + 1))
		  syslog(LOG_DEBUG, "Got radius ID %d when expecting %d\n",
			*(recvbuf + 1) & 0xFF, current_id);

            }while((current_id != *(recvbuf +1))  && (dcnt < DISCARD_COUNT));

            if (rv > 0) {
                dlen = rv;
            }

            else if (rv == -1)
                sleep(sinfo->resp_timeout);

        }
        if(dlen <= 0) {
            if (debug)
                printf("No response from RADIUS server %s",
                       inet_ntoa(rsin.sin_addr));
            syslog(LOG_DEBUG, "No response from RADIUS server %s",
                   inet_ntoa(rsin.sin_addr));
        }
    }

    if (dlen <= 0) {
        free(sendbuf);
        free(recvbuf);
        return(NOT_VALIDATED);
    }

    code_val = (int)*recvbuf;
    if (debug)
        printf("Received RADIUS %s from %s",
	       (code_val < NCODETYPES && code_val > 0)? 
		codetype[code_val - 1]: "\0",
               inet_ntoa(rsin.sin_addr));
#ifdef USE_SYSLOG
    syslog(LOG_DEBUG, "Received RADIUS %s from %s",
	    (code_val < NCODETYPES && code_val > 0)? 
             codetype[code_val - 1]: "\0",
            inet_ntoa(rsin.sin_addr));
#endif

    /* Access-Challenge loop */
    do {
        struct radius_attribute challprompt, state, *statep;
        u_char *aptr;
        u_short alen;

        code = radius_parse_server_response(recvbuf, dlen, id, sendbuf + 4,
                                            sinfo->host_address);
        if(debug > 4)
            display_mem(recvbuf, dlen);

        if (code == 0) {
            free(sendbuf);
            free(recvbuf);
            return(NOT_VALIDATED);
        }

        acp->auth.radius_packet = (u_char*)calloc(dlen, 1);
        if (acp->auth.radius_packet == NULL) {
            free(sendbuf);
            free(recvbuf);
            return(NOT_VALIDATED);
        }
        bcopy(recvbuf, acp->auth.radius_packet, dlen);

        if (code != PW_ACCESS_CHALLENGE || prompt == FALSE)
            continue;

        bzero((char*)&challprompt, sizeof(struct radius_attribute));
        challprompt.type = PW_PORT_MESSAGE;
        aptr = acp->auth.radius_packet + AUTH_HDR_LEN;
        bcopy(acp->auth.radius_packet + 2, (char*)&alen, 2);
        alen = ntohs(alen) - AUTH_HDR_LEN;

        if (!radius_get_attribute(&aptr, &alen, &challprompt)) {
            free(sendbuf);
            free(recvbuf);
            radius_release_alloc((char *)acp->auth.radius_packet);
            return(NOT_VALIDATED);
        }

        if (challprompt.strvalp == NULL) {
            free(sendbuf);
            free(recvbuf);
            radius_release_alloc((char *)acp->auth.radius_packet);
            return(NOT_VALIDATED);
        }

        statep = NULL;
        bzero((char*)&state, sizeof(struct radius_attribute));
        state.type = PW_STATE;
        aptr = acp->auth.radius_packet + AUTH_HDR_LEN;
        bcopy(acp->auth.radius_packet + 2, (char*)&alen, 2);
        alen = ntohs(alen) - AUTH_HDR_LEN;

        if (radius_get_attribute(&aptr, &alen, &state))
            statep = &state;

        recvbuf[0] = '\0';
        dlen = promptstring(acp, recvbuf, challprompt.strvalp, 0,
                            INPUT_TIMEOUT);

        radius_release_alloc(challprompt.strvalp);

        bzero((char*)&req, sizeof(struct access_request));
        req.secret = (u_char*)sinfo->shared_secret;
        req.user = user;
        req.pwd = (char*)recvbuf;
        req.raaddr = raaddr;
        req.port = secport;
        req.state = statep;
        id = radius_build_access_request(sendbuf, &sendlen, &req);

        radius_release_alloc(req.state);

        for (dlen = 0, j = 0; j < (sinfo->retries + 1) && dlen == 0; j++) {

            rv = api_send(socket, sendbuf, sendlen, 0, app_nam, show);
            if (rv == -1)
                break;

            code_val = (int)*sendbuf;
	    current_id = *(sendbuf + 1);
            dcnt = 0;

            if (debug)
                printf("Sent RADIUS %s to %s\n",
                       (code_val < NCODETYPES)? codetype[code_val - 1]: "",
                       inet_ntoa(rsin.sin_addr));
#ifdef USE_SYSLOG
            syslog(LOG_DEBUG, "Sent RADIUS %s to %s",
                   (code_val < NCODETYPES)? codetype[code_val - 1]: "",
                   inet_ntoa(rsin.sin_addr));
#endif

/* The next loop is to discard any recveived message that, does not have the current sent id */
	    do{
               rv = api_recvwait(socket, recvbuf, buflen, sinfo->resp_timeout,0,
                              show, app_nam);
	       dcnt++;
               if(rv <= 0)
                 break;
            }while((current_id != *(recvbuf +1))  && (dcnt < DISCARD_COUNT));


            if (rv > 0) {
                dlen = rv;
            }

            else if (rv == -1)
                sleep(sinfo->resp_timeout);

        }
        if(dlen <= 0) {
            if (debug)
                printf("No response from RADIUS server %s",
                       inet_ntoa(rsin.sin_addr));
            syslog(LOG_DEBUG, "No response from RADIUS server %s",
                   inet_ntoa(rsin.sin_addr));
            free(sendbuf);
            free(recvbuf);
            radius_release_alloc((char *)acp->auth.radius_packet);
            return(NOT_VALIDATED);
        }
    } while(code == PW_ACCESS_CHALLENGE); /* Access-Challenge loop */

    if (code) /* Always print the reply message if we got a valid response */
        radius_print_reply_message(acp);

#ifdef _WIN32
    free(sendbuf);
    free(recvbuf);
    if (code == PW_AUTHENTICATION_ACK)
        return(VALIDATED);
#else	/* not _WIN32 */
    if ((code == PW_AUTHENTICATION_ACK) &&
        (radius_authorize(acp, prompt) == VALIDATED) &&
        (ses_new(acp->env, acp->auth.radius_packet, opt_info) == 0)) {
        free(sendbuf);
        free(recvbuf);
        radius_release_alloc((char *)acp->auth.radius_packet);
        return(VALIDATED);
    }

    free(sendbuf);
    free(recvbuf);
    radius_release_alloc((char *)acp->auth.radius_packet);
#endif	/* _WIN32 */
    return(NOT_VALIDATED);

}

/*****************************************************************************
 *
 * NAME: radius_build_access_request
 *
 * DESCRIPTION: Builds a RADIUS Access-Request packet
 *
 * ARGUMENTS:
 *  u_char *buffer - INPUT buffer to build packet in
 *  int *buflenp - INPUT maximum size of buffer
 *                 OUTPUT actual size of packet (data portion)
 *  struct access_request *req - INPUT Access-Request attributes
 *
 * RETURN VALUE: identifier or -1 if error
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

/* returns identifier */
static int radius_build_access_request(buffer, buflenp, req)
u_char *buffer; /* pre-allocated buffer, at least 4096 bytes */
int *buflenp;
struct access_request *req;
{
    u_char *bp = buffer;
    u_char *newkey;
    UINT32 identifier;
    int type;
    u_char *authenticator;
    INT32 protocol;
    int keylen;

    type = radius_convert_type(req->port->type);
    identifier = (UINT32)random_byte();

    authenticator = radius_build_header(&bp, PW_AUTHENTICATION_REQUEST,
                                        identifier, req->chapchal);
    if (authenticator == NULL)
        return(-1);
    radius_add_attribute(&bp, PW_USER_NAME, strlen(req->user), req->user, 0);
    if (req->pwd) {
        keylen = ( ( (strlen(req->pwd) - 1) / KEYSZ) + 1 ) * KEYSZ;
        /* keylen % 16 == 0 */
        newkey = calloc(keylen, 1);
        if (newkey == NULL)
            return(-1);
        radius_crunch_password(newkey, authenticator, req->pwd,
                               strlen(req->pwd), req->secret);
        radius_add_attribute(&bp, PW_PASSWORD, keylen, newkey, 0);
        free(newkey);
    }
    if (req->chappwd) {
        radius_add_attribute(&bp, PW_CHAP_PASSWORD, CHAP_RESP_LEN + 1,
                             req->chappwd, 0);
    }
    if (xa2_service_type[req->service] != -1)
        radius_add_attribute(&bp, PW_USER_SERVICE_TYPE, sizeof(UINT32), NULL,
                             xa2_service_type[req->service]);
    switch(req->service) {
    case SERVICE_PPP:
    case SERVICE_SYNC_PPP:
    case SERVICE_VPN_PPP:
    case SERVICE_CHAP:
        protocol = (INT32)PW_PPP;
        break;

    case SERVICE_SLIP:
        protocol = (INT32)PW_SLIP;
        break;

    case SERVICE_IPX:
        protocol = (INT32)PW_IPXSLIP;
        break;

    case SERVICE_ARAP:
        protocol = (INT32)PW_ARAP;
        break;

    default:
        protocol = (INT32)-1;
        break;
    }

    if (protocol != -1)
        radius_add_attribute(&bp, PW_FRAMED_PROTOCOL, sizeof(UINT32), NULL,
                             (UINT32)protocol);

    radius_add_attribute(&bp, PW_NAS_IP_ADDRESS, sizeof(UINT32), NULL,
                         req->raaddr.s_addr);
    
    if ((type != PW_PORT_VIRTUAL) && (type != -1)) {
        radius_add_attribute(&bp, PW_NAS_PORT, sizeof(UINT32), NULL,
                         req->port->unit);
    }
    else {
        radius_add_attribute(&bp, PW_NAS_PORT, sizeof(UINT32), NULL,
                         ((req->port->type * VPORT_MULT) + req->port->unit));
    }

    if (type >= 0)
        radius_add_attribute(&bp, PW_NAS_PORT_TYPE, sizeof(UINT32), NULL,
                             type);

    if (strlen(req->called_number) > 0 )
    	radius_add_attribute(&bp, PW_CALLED_STATION_ID, strlen(req->called_number), req->called_number, 0);
    if (strlen(req->calling_number) > 0 )
    	radius_add_attribute(&bp, PW_CALLING_STATION_ID, strlen(req->calling_number), req->calling_number, 0);

    if (req->state)
        radius_build_attribute(&bp, req->state);

    radius_fix_length(buffer, bp);
    *buflenp = bp - buffer;
    return(identifier);
}

#ifdef DUMMY_TEST
u_char dummy_buffer[4096];

/* dummy_accept() is a test function only ! */
/* if I told you what it does, you might just */
/* do something stupid like use it in production */
/* code! */

u_char *dummy_accept(serv, prot, ipaddr, reply, routes, ipxnet, plim)
enum radius_service_type serv; /* Service-Type (6) */
enum radius_framed_protocol prot; /* Framed-Protocol (7) */
UINT32 ipaddr; /* Framed-IP-Address (8) */
char *reply; /* Reply-Message (18) */
STR_LIST *routes; /* Framed-Route (22) */
UINT32 ipxnet; /* Framed-IPX-Network (23) */
int plim; /* Port-Limit (62) */
{

    u_char *bp = dummy_buffer;
    STR_LIST *rte;
    u_char identifier;
    int rlen;

    bzero(dummy_buffer, 4096);
    identifier = (UINT32)random_byte();

    radius_build_header(&bp, PW_AUTHENTICATION_ACK, identifier, NULL);
    if (serv)
        radius_add_attribute(&bp, PW_USER_SERVICE_TYPE, sizeof(UINT32), NULL,
                             serv);
    if (prot)
        radius_add_attribute(&bp, PW_FRAMED_PROTOCOL, sizeof(UINT32), NULL,
                             prot);
    if (ipaddr)
        radius_add_attribute(&bp, PW_FRAMED_ADDRESS, sizeof(UINT32), NULL,
                             ipaddr);
    if (reply) {
        rlen = strlen(reply);
        if (rlen > 253)
            rlen = 253;
        if (rlen)
            radius_add_attribute(&bp, PW_PORT_MESSAGE, rlen, reply, 0);
    }
    for(rte = routes; rte; rte = rte->next) {
        rlen = rte->strlen;
        if (rlen > 253)
            rlen = 253;
        if (rlen)
            radius_add_attribute(&bp, PW_FRAMED_ROUTE, rlen, rte->str, 0);
    }
    if (ipxnet)
        radius_add_attribute(&bp, PW_FRAMED_IPXNET, sizeof(UINT32), NULL,
                             ipxnet);
    if (plim)
        radius_add_attribute(&bp, PW_PORT_LIMIT, sizeof(UINT32), NULL, plim);
    radius_fix_length(dummy_buffer, bp);
    return(dummy_buffer);
}
#endif

/*****************************************************************************
 *
 * NAME: radius_authorize
 *
 * DESCRIPTION:  Confirms that RADIUS authorized us to do what we've
 *               already told ACP we are doing.  (i.e., if the user came
 *               in PPP, but we get Service-Type=NAS-Prompt, we deny the
 *               user outright, since we know the Annex can't switch after
 *               the fact.
 *
 *               Also sets up any cli command list that is appropriate
 *
 *               Note:  if anybody has any time, this could be convertd to
 *               be table-driven.
 *
 * ARGUMENTS:
 *  ACP *acp - INPUT Connected ACP handle
 *
 * RETURN VALUE: VALIDATED or NOT_VALIDATED
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

static int radius_authorize(acp, prompt)
ACP *acp;
int prompt;
{
    struct radius_attribute service_type, attrib, host;
    enum radius_service_type service;
    enum radius_framed_protocol protocol;
    enum radius_login_service login;
    u_char *aptr, *aptrstart;
    u_short alen, alenstart;
    char *cmd = NULL;

    if (acp->auth.radius_packet == NULL)
        return(NOT_VALIDATED);

    bzero((u_char*)&service_type, sizeof(struct radius_attribute));
    service_type.type = PW_USER_SERVICE_TYPE;
    aptrstart = aptr = acp->auth.radius_packet + AUTH_HDR_LEN;
    bcopy(acp->auth.radius_packet + 2, (char*)&alen, 2);
    alenstart = alen = ntohs(alen) - AUTH_HDR_LEN;

    if (!radius_get_attribute(&aptr, &alen, &service_type)) {
        return(VALIDATED);
    }

    service = (enum radius_service_type) service_type.lvalue;

    switch(service) {
    case PW_LOGIN_USER:
        if (acp->env->protocol != SERVICE_CLI_HOOK &&
            acp->env->protocol != SERVICE_DIALBACK)
            return(NOT_VALIDATED);

        bzero((u_char*)&attrib, sizeof(struct radius_attribute));
        attrib.type = PW_LOGIN_SERVICE;
        aptr = aptrstart;
        alen = alenstart;
        if (!radius_get_attribute(&aptr, &alen, &attrib))
            return(VALIDATED); /* no Login-Service, just cli prompt */
        login = (enum radius_login_service) attrib.lvalue;
        if (login >= NLOGIN || login < 0 || (cmd = login_cmd[login])== NULL)
            return(VALIDATED); /* unknown Login-Service, just cli prompt */

        bzero((u_char*)&host, sizeof(struct radius_attribute));
        if (login == PW_TELNET || login == PW_RLOGIN)
            host.type = PW_LOGIN_HOST;
        else
            host.type = PW_LOGIN_LAT_SERVICE;
        aptr = aptrstart;
        alen = alenstart;
        if (!radius_get_attribute(&aptr, &alen, &host))
            return(VALIDATED); /* no Login-IP-Host or Login-LAT-Service, just
                                  cli prompt */
        /* addr 0 NAS *should* choose, but unsupported, so deny user */
        if (host.type == PW_LOGIN_HOST && host.lvalue == 0)
            return(NOT_VALIDATED);

        acp->auth.cmd_list = (struct cli_cmd_list *)
            calloc(1, sizeof(struct cli_cmd_list));
        if (acp->auth.cmd_list == NULL){
            if(host.type == PW_LOGIN_LAT_SERVICE)
                radius_release_alloc(host.strvalp);
            return(NOT_VALIDATED);
        }
        strcpy(acp->auth.cmd_list->clicmd, cmd);
        if (host.type == PW_LOGIN_HOST) {
            char portstr[16];
            struct in_addr haddr;

            strcat(acp->auth.cmd_list->clicmd, " ");
            if (host.lvalue == 0xffffffff) { /* Let user choose, no quals */
                if (prompt) {
                    char *hostname = acp->auth.cmd_list->clicmd +
                        strlen(acp->auth.cmd_list->clicmd);

                    promptstring(acp, hostname, "Enter Host Name: ", TRUE,
                                 INPUT_TIMEOUT);
                }
                else
                    return(VALIDATED);
            }
            else {
                haddr.s_addr = host.lvalue;
                strcat(acp->auth.cmd_list->clicmd, inet_ntoa(haddr));
            }

            bzero((u_char*)&attrib, sizeof(struct radius_attribute));
            attrib.type = PW_LOGIN_TCP_PORT;
            aptr = aptrstart;
            alen = alenstart;
            if (!radius_get_attribute(&aptr, &alen, &attrib))
                return(VALIDATED);
            if (attrib.lvalue == 0)
                return(VALIDATED);
            sprintf(portstr, "%d", (int)attrib.lvalue);
            strcat(acp->auth.cmd_list->clicmd, " ");
            strcat(acp->auth.cmd_list->clicmd, portstr);
            return(VALIDATED);
        }
        else {
            strcat(acp->auth.cmd_list->clicmd, " ");
            strcat(acp->auth.cmd_list->clicmd, host.strvalp);
            radius_release_alloc(host.strvalp);
            bzero((u_char*)&attrib, sizeof(struct radius_attribute));
            attrib.type = PW_LOGIN_LAT_NODE;
            aptr = aptrstart;
            alen = alenstart;
            if (!radius_get_attribute(&aptr, &alen, &attrib))
                return(VALIDATED);
            strcat(acp->auth.cmd_list->clicmd, " /node=");
            strcat(acp->auth.cmd_list->clicmd, attrib.strvalp);
            free(attrib.strvalp);
            bzero((u_char*)&attrib, sizeof(struct radius_attribute));
            attrib.type = PW_LOGIN_LAT_PORT;
            aptr = aptrstart;
            alen = alenstart;
            if (!radius_get_attribute(&aptr, &alen, &attrib))
                return(VALIDATED);
            strcat(acp->auth.cmd_list->clicmd, " /port=");
            strcat(acp->auth.cmd_list->clicmd, attrib.strvalp);
            free(attrib.strvalp);
            return(VALIDATED);
        }
        break;

    case PW_FRAMED_USER:
        bzero((u_char*)&attrib, sizeof(struct radius_attribute));
        attrib.type = PW_FRAMED_PROTOCOL;
        aptr = aptrstart;
        alen = alenstart;
        if (!radius_get_attribute(&aptr, &alen, &attrib))
            return(NOT_VALIDATED);

        protocol = (enum radius_framed_protocol) attrib.lvalue;
        if (acp->env->protocol == SERVICE_CLI_HOOK ||
            acp->env->protocol == SERVICE_DIALBACK) {
            acp->auth.cmd_list = (struct cli_cmd_list *)
                calloc(1, sizeof(struct cli_cmd_list));
            if (acp->auth.cmd_list == NULL)
                return(NOT_VALIDATED);

            switch(protocol) {
            case PW_PPP:
                strcpy(acp->auth.cmd_list->clicmd, "ppp");
                break;
            case PW_SLIP:
                strcpy(acp->auth.cmd_list->clicmd, "slip");
                break;
            case PW_IPXSLIP:
                strcpy(acp->auth.cmd_list->clicmd, "ipx");
                break;
            case PW_ARAP:
                strcpy(acp->auth.cmd_list->clicmd, "arap");
                break;
            default:
                free(acp->auth.cmd_list);
                acp->auth.cmd_list = NULL;
                return(NOT_VALIDATED);
                break;
            }
            return(VALIDATED);
        }

        switch(protocol) {
        case PW_PPP:
            if (acp->env->protocol != SERVICE_PPP &&
                acp->env->protocol != SERVICE_SYNC_PPP &&
                acp->env->protocol != SERVICE_VPN_PPP && 
                acp->env->protocol != SERVICE_CHAP)
                return(NOT_VALIDATED);
            return(VALIDATED);

        case PW_SLIP:
            if (acp->env->protocol != SERVICE_SLIP)
                return(NOT_VALIDATED);
            return(VALIDATED);

        case PW_IPXSLIP:
            if (acp->env->protocol != SERVICE_IPX &&
                acp->env->protocol != SERVICE_IPX_DIALBACK)
                return(NOT_VALIDATED);
            return(VALIDATED);

        case PW_ARAP:
            if (acp->env->protocol != SERVICE_AT_PROFILE &&
                acp->env->protocol != SERVICE_ARAP)
                return(NOT_VALIDATED);
            return(VALIDATED);

        default:
            return(NOT_VALIDATED);
        }
        break;

    case PW_DIALBACK_LOGIN_USER:
    case PW_DIALBACK_FRAMED_USER:
    case PW_CALLBACK_PROMPT_USER:
        return(NOT_VALIDATED);

    case PW_OUTBOUND_USER:
        if (acp->env->protocol != SERVICE_PORTS)
            return(NOT_VALIDATED);
        return(VALIDATED);

    case PW_ADMINISTRATIVE_USER:
        if (acp->env->protocol == SERVICE_FTP)
            return(VALIDATED);
    /* pass through */
    case PW_NAS_PROMPT_USER:
        if (acp->env->protocol != SERVICE_CLI_HOOK &&
            acp->env->protocol != SERVICE_DIALBACK)
            return(NOT_VALIDATED);
        return(VALIDATED);

    case PW_AUTHENTICATE_USER:
        if (acp->env->protocol == SERVICE_FTP) /* no admin access */
            return(NOT_VALIDATED);
        return(VALIDATED);

    default:
        return(NOT_VALIDATED);
    }

    /* shouldn't reach here */
    return(NOT_VALIDATED);

}

/*****************************************************************************
 *
 * NAME: xlate_route_attrib
 *
 * DESCRIPTION: Translates a RADIUS route format to an Annex format
 *
 * ARGUMENTS:
 * struct radius_attribute *attrib - radius route attribute
 *
 * RETURN VALUE:
 * STR_LIST *route - The Annex format route as a STR_LIST element
 *
 * RESOURCE HANDLING:
 * Allocates the route STR_LIST, which can be deallocated with
 * racp_destroy_strlist()
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

STR_LIST *xlate_route_attrib(attrib)
struct radius_attribute *attrib;
{
    char *start = (char*)calloc(attrib->length+1, sizeof(char));
    int len = 0, maskbits = 0, masklen, i, class_byte;
    char *dest = NULL, *hop = NULL, *metric = NULL, *maskbitstr = NULL;
    char *new = NULL, class_string[4];
    char *classastr = "/24", *classbstr = "/16", *classcstr = "/8";
    STR_LIST *route = NULL;

    bcopy(attrib->strvalp, start, attrib->length);
    dest = strtok(start, "/ \f\n\r\t\v"); /* '/' for subnet mask bits */
    if (dest == NULL) { /* bad syntax */
        free(start);
        return(NULL);
    }
    maskbitstr = strtok(NULL, " \f\n\r\t\v");
    if (maskbitstr == NULL) {  /* bad syntax */
        free(start);
        return(NULL);
    }
    if (strlen(maskbitstr) > 2) {
        /* RADIUS default submit mask bits based on network class */
        for (i = 0; i < 4; i++) {
            if (dest[i] == '.') {
                class_string[i] = '\0';
                break;
            }
            class_string[i] = dest[i];
        }
        class_byte = atoi(class_string);
        hop = maskbitstr;
        if (class_byte > 191)
            maskbitstr = classastr;
        else if (class_byte > 127)
            maskbitstr = classbstr;
        else
            maskbitstr = classcstr;
    }
    else {
        /* user supplied subet mask bits */
        hop = strtok(NULL, " \f\n\r\t\v");
        if (hop == NULL) {  /* bad syntax */
            free(start);
            return(NULL);
        }
    }
    if (strcmp(hop, "0.0.0.0") == 0) {
        /* replace 0.0.0.0 with * */
        hop[0] = '*';
        hop[1] = '\0';
    }
    metric = strtok(NULL, " \f\n\r\t\v");

    /* now build the Annex route */
    masklen = strlen(maskbitstr);
    if (masklen <= 2)
       masklen++;
    len = strlen(dest) + masklen + 1 + strlen(hop) + 1 + strlen(metric);

    new = (char*)calloc(len, sizeof(char));
    if (new != NULL) {
        if (masklen <= 3)
            sprintf(new, "%s/%s %s %s\n", dest, maskbitstr, hop, metric);
        else
            sprintf(new, "%s%s %s %s\n", dest, maskbitstr, hop, metric);
        route = racp_create_strlist(new, len);
        free(new);
    }

    free(start);
    return(route);
}

/*****************************************************************************
 *
 * NAME: netmask_to_route
 *
 * DESCRIPTION: Converts a netmask and a destination ip address to a route
 *
 * ARGUMENTS:
 * UINT32 netmask - The netmask in network order
 * UINT32 dest - The destination ip address in network order
 *
 * RETURN VALUE:
 * STR_LIST *route - The Annex format route as a STR_LIST element
 *
 * RESOURCE HANDLING:
 * Allocates the route STR_LIST, which can be deallocated with
 * racp_destroy_strlist()
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

STR_LIST *netmask_to_route(netmask, dest)
UINT32 netmask, dest;
{
    char *temp, *maskstr, *deststr, *routestr;
    struct in_addr maskaddr, destaddr;
    int len;
    STR_LIST *route = NULL;

    if (dest == 0xffffffff || dest == 0xfffffffe || netmask == 0xffffffff) /* special cases */
        return(NULL);

    dest = (dest & netmask);

    maskaddr.s_addr = netmask;
    destaddr.s_addr = dest;

    temp = inet_ntoa(maskaddr);
    maskstr = (char*)calloc(strlen(temp) + 1, sizeof(char));
    if (maskstr == NULL)
        return(NULL);

    bcopy(temp, maskstr, strlen(temp));

    deststr = inet_ntoa(destaddr);

    len = strlen(deststr) + 1 + strlen(maskstr) + 4;
    routestr = (char*)calloc(len, sizeof(char));
    if (routestr == NULL) {
        free(maskstr);
        return(NULL);
    }
    sprintf(routestr, "%s %s * 1", deststr, maskstr);
    route = racp_create_strlist(routestr, len);
    free(maskstr);
    free(routestr);
    return(route);
}

/* RADIUS test routine */

void policy_main()
{
    int valid;
    struct in_addr ipaddr;
    SECPORT port;
    u_char user[16];
    u_char pwd[16];
    ACP acp;

    bzero((char*)&acp, sizeof(ACP));

    port.type = DEV_SYNC;
    port.unit = 17;
    ipaddr.s_addr = ((unsigned long)132 << 24) + (245 << 16) + (12 << 8) + 243;
    acp.inet = ipaddr.s_addr;

    bzero(user, 16);
    bzero(pwd, 16);
    strcpy(user, "dfox");
    strcpy(pwd, "my_password");

    valid = acp_radius_validate(&acp, user, pwd, &port);

    if (valid == VALIDATED)
        printf("User %s validated\n", user);
    else
        printf("User %s not validated\n", user);
}

void radius_release_alloc(alloc_space_pointer)
char *alloc_space_pointer;
{
    if(alloc_space_pointer){
        free(alloc_space_pointer);
        alloc_space_pointer=NULL;
    }
}

