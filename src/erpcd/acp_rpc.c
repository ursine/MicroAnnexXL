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
 *     %$(Description)$%
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 * Module Reviewers:
 *
 *    %$(reviewers)$%
 *
 *****************************************************************************
 */

/* Include Files */
#include "../inc/config.h"
#include <stdio.h>

#include "../inc/port/port.h"
#include <sys/types.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/uio.h>
#include <strings.h>
#else 
#include <winsock.h>
#endif

#include "../inc/courier/courier.h"
#include "../libannex/asn1.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "acp_policy.h"

extern int debug;

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
void log_accounting();
void inet_number();
int return_log();
void log_message();
int acp_acknowledge();

void acp_global_init(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            inet;
    ACP_STRING    Boot_message;

    GLOBAL_INIT    gbl;

    if(debug)
        puts("global_init");

    if(length > SIZE_GBL)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&gbl), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&gbl)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(gbl.gbl_handle);
        logid = get_long(gbl.gbl_logid);
        inet = get_unspec_long(gbl.gbl_inet);
          gbl.gbl_msg[ACP_MAXSTRING - 1] = '\0';
        (void)strcpy(Boot_message, gbl.gbl_msg);
        global_init(Acp, logid, inet, Boot_message);
    }
    return;        /*  void  */
}

/*
 * acp_req_appletalk_profile2() - Called via acp switch table to handle
 * annex request for appletalk profile data.   This also adds in return 
 * NVE profile stuff. 
 *
 * Acp - ACP state structure
 * message - pointer to ACP_REQUEST_APPLETALK_PROFILE params
 * length - length of above params
 * to - optional socket arg, not used here.
 */
void acp_req_appletalk_profile2(Acp, message, length)
ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid, inet;
    int        nve, port, service;
    APPLETALK_PROFILE rat;


    if(debug)
        puts("acp_request_appletalk_profile2");

    if(length != SIZE_RAT)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&rat), length);
        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&rat))) {
            reject_session(Acp, CMJ_SRPC);    /* no return */
        }

        Acp->handle = get_long(rat.rat_handle);
        logid = get_long(rat.rat_logid);
        inet = get_unspec_long(rat.rat_inet);
        port  = ntohs(rat.rat_port);
        service = ntohs(rat.rat_service);
        nve = 1;
        appletalk_profile(Acp, logid, inet, port, DEV_SERIAL, service, 
            rat.rat_uname, nve);
    }
    return;        /*  void  */
}

/*
 * acp_req_appletalk_profile() - Called via acp switch table to handle
 * annex request for appletalk profile data.  
 *
 * Acp - ACP state structure
 * message - pointer to ACP_REQUEST_APPLETALK_PROFILE params
 * length - length of above params
 * to - optional socket arg, not used here.
 */
void acp_req_appletalk_profile(Acp, message, length)
ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid, inet;
    int        port, service;
    APPLETALK_PROFILE rat;


    if(debug)
        puts("acp_request_appletalk_profile");

    if(length != SIZE_RAT)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&rat), length);
        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&rat))) {
            reject_session(Acp, CMJ_SRPC);    /* no return */
        }

        Acp->handle = get_long(rat.rat_handle);
        logid = get_long(rat.rat_logid);
        inet = get_unspec_long(rat.rat_inet);
        port  = ntohs(rat.rat_port);
        service = ntohs(rat.rat_service);
        appletalk_profile(Acp, logid, inet, port, DEV_SERIAL, service, 
            rat.rat_uname, 0);
    }
    return;        /*  void  */
}

void acp_req_dialup_address(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid, inet;
    int        port, service;
    UINT32        loc,rem;
    u_char node[6];
    RDA        rda;

    if(debug)
        puts("acp_request_dialup_address");

    if(length > SIZE_RDA) {
        reject_session(Acp, CMJ_INVARG);    /* no return */
        return;
    }
    else if (length < SIZE_RDA)
        bzero(node, 6);
    else
        bcopy(rda.rda_node, node, 6);

    srpc_decode(Acp->Srpc, message, (char *)(&rda), length);
    if(!srpc_cmp(Acp->Srpc, (SHDR *)(&rda))) {
        reject_session(Acp, CMJ_SRPC);    /* no return */
    }

    Acp->handle = get_long(rda.rda_handle);
    logid = get_long(rda.rda_logid);
    inet = get_unspec_long(rda.rda_inet);
    port  = ntohs(rda.rda_port);
    service = ntohs(rda.rda_service);
    loc = get_unspec_long(rda.rda_loc);
    rem = get_unspec_long(rda.rda_rem);
    dialup_address(Acp, logid, inet, port,DEV_SERIAL, 0, service,
		   rda.rda_uname, loc, rem,
                   node, FALSE, FALSE);
    return;        /*  void  */
}

void acp_req_user_index(Acp, message, length)

ACP     *Acp;
char    *message;
int     length;
{
        UINT32   logid, inet;
        int             port, service;
        RUI             rui;

        if(debug)
                puts("acp_request_user_index");

        if(length != SIZE_RUI)
        {
                reject_session(Acp, CMJ_INVARG);    /* no return */
        }
        else
        {
                srpc_decode(Acp->Srpc, message, (char *)(&rui), length);
                if(!srpc_cmp(Acp->Srpc, (SHDR *)(&rui))) {
                    reject_session(Acp, CMJ_SRPC);  /* no return */
                }

                Acp->handle = get_long(rui.rui_handle);
                logid = get_long(rui.rui_logid);
                inet = get_unspec_long(rui.rui_inet);
                port  = ntohs(rui.rui_port);
                service = ntohs(rui.rui_service);
                user_index(Acp, logid, inet, port, DEV_SERIAL, service,
                        rui.rui_uname, NULL);
        }
        return;         /*  void  */
}

void acp_request_log(Acp, message, length)

ACP     *Acp;
char    *message;
int     length;
{
        UINT32   logid, inet;
        int             port, service, event;
        RL              rl;

        if(debug)
                puts("acp_request_log");

        if(length != SIZE_RL)
        {
                reject_session(Acp, CMJ_INVARG);    /* no return */
        }
        else
        {
                srpc_decode(Acp->Srpc, message, (char *)(&rl), length);
                if(!srpc_cmp(Acp->Srpc, (SHDR *)(&rl))) {
                    reject_session(Acp, CMJ_SRPC);  /* no return */
                }

                Acp->handle = get_long(rl.rl_handle);
                logid = get_long(rl.rl_logid);
                inet = get_unspec_long(rl.rl_inet);
                port  = ntohs(rl.rl_port);
                service = ntohs(rl.rl_service);
        event = ntohs(rl.rl_event);
		(void)return_log(Acp, REQ_GRANTED);
		if (ISUDP(Acp->state))
		    log_message(inet, logid, port, DEV_SERIAL, service, event, rl.rl_message);
        }
        return;         /*  void  */
}


void acp_req_serial_validate(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid, inet;
    int        port, service;
    short        direction;
    UINT32        netnum;
    SERVAL        sval;


    if(debug)
        puts("serial_validate");


    srpc_decode(Acp->Srpc, message, (char *)(&sval), length);
    if(!srpc_cmp(Acp->Srpc, (SHDR *)(&sval))) {
        reject_session(Acp, CMJ_SRPC);    /* no return */
    }

        Acp->handle     = get_long     (sval.serval_handle);
        logid         = get_long     (sval.serval_logid);
        inet         = get_unspec_long(sval.serval_inet);
        port          = ntohs         (sval.serval_port);
    service     = ntohs         (sval.serval_service);

    switch (service) {
    case SERVICE_IPX:
        netnum = ntohl(sval.serval_un.ipx.netnum);
                ipx_validate(Acp, logid, inet, port, DEV_SERIAL,
            service,
            sval.serval_uname,
            sval.serval_pword,
            sval.serval_un.ipx.phone,
            netnum);
        break;

    case SERVICE_SLIP:
    case SERVICE_PPP:
    default:
        direction = ntohs((unsigned short)sval.serval_direction);
        ppp_security(Acp, logid, inet, port, DEV_SERIAL,
            service, 
            direction, 
            sval.serval_uname, 
            sval.serval_pword);
        break;
    }

    return;        /*  void  */
}

void acp_logout_ppp_slip(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            inet;
    int        service,
            port,
            ip, op, ic, oc, et;

    ACP_USTRING    Username;
    NET        net;

    if(debug)
        puts("logout_ppp_slip");

    if(length > SIZE_NET)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&net), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&net)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(net.net_handle);
        logid = get_long(net.net_logid);
        inet = get_unspec_long(net.net_inet);
        port = ntohs(net.net_port);
        service = ntohs(net.net_service);
          net.net_username[ACP_MAXUSTRING - 1] = '\0';
        (void)strcpy(Username, net.net_username);
        ip = get_long(net.net_ipkts);
        op = get_long(net.net_opkts);
        ic = get_long(net.net_ichars);
        oc = get_long(net.net_ochars);
        et = get_long(net.net_elapsed_time);

        ppp_slip_logout(Acp, logid, inet, port,DEV_SERIAL, service, Username);

        if (length == SIZE_NET && service != SERVICE_FTP && 
            (ip || op || ic || oc)) {
          log_accounting(Acp, logid, inet, port,DEV_SERIAL, service, ip, op, ic, oc, et, Username);
        }

        terminate_session();
    }
    return;        /*  void  */
}

void acp_req_port_to_annex(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            inet;
    int        service,
            port;

    P2A        p2a;
    char Inum[60];

    if(debug)
        puts("port_to_annex");

    if(length != SIZE_P2A)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&p2a), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&p2a)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(p2a.p2a_handle);
        logid = get_long(p2a.p2a_logid);
        inet = get_unspec_long(p2a.p2a_inet);
        port = ntohs(p2a.p2a_port);
        service = ntohs(p2a.p2a_service);
        
        inet_number(Inum, inet); /* get dot notation string */
        if (debug)
            printf("acp_req_port_to_annex -------- from  %s\n", Inum);
        port_to_annex(Acp, logid, inet, port, DEV_SERIAL, service, (ARQ_PROFILE *)NULL);
    }
    return;        /*  void  */
}

void acp_req_annex_to_net(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            linet,
            rinet;
    int        service,
            port,
            tcp_port_req;
    ACP_USTRING    Username;

    A2N        a2n;

    if(debug)
        puts("annex_to_net");

    if(length > SIZE_A2N)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&a2n), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&a2n)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(a2n.a2n_handle);
        logid = get_long(a2n.a2n_logid);
        linet = get_unspec_long(a2n.a2n_client_inet);
        port = ntohs(a2n.a2n_port);
        service = ntohs(a2n.a2n_service);
        rinet = get_unspec_long(a2n.a2n_remote_inet);
        if (length == SIZE_A2N)
            tcp_port_req = get_long(a2n.a2n_tcp_port_req);
        else
            tcp_port_req = -1; /* must be an old annex */
          a2n.a2n_username[ACP_MAXUSTRING - 1] = '\0';
        (void)strcpy(Username, a2n.a2n_username);
        annex_to_net(Acp, logid, linet, port, DEV_SERIAL,
                 service, rinet, Username, tcp_port_req);
    }
    return;        /*  void  */
}


void acp_req_annex_to_lat(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            linet;
    int            service,
            port;
    ACP_USTRING        Service_name;
    ACP_USTRING       Username;

    A2L        a2l;

    if(debug)
    puts("annex_to_lat");

    if(length > SIZE_A2L)
    {
    reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
    srpc_decode(Acp->Srpc, message, (char *)(&a2l), length);

    if(!srpc_cmp(Acp->Srpc, (SHDR *)(&a2l)))
        reject_session(Acp, CMJ_SRPC);    /* no return */

    Acp->handle = get_long(a2l.a2l_handle);
    logid = get_long(a2l.a2l_logid);
    linet = get_unspec_long(a2l.a2l_client_inet);
    port = ntohs(a2l.a2l_port);
    service = ntohs(a2l.a2l_service);
        a2l.a2l_username[ACP_MAXUSTRING - 1] = '\0';
    (void)strcpy(Username, a2l.a2l_username);
        a2l.a2l_service_name[ACP_MAXUSTRING - 1] = '\0';
    (void)strcpy(Service_name, a2l.a2l_service_name);
    annex_to_lat(Acp, logid, linet, port, DEV_SERIAL,
             service, Username, Service_name);
    }
    return;        /*  void  */
}

void acp_req_net_to_port(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            linet,
            rinet;
    int        port,
            service;
    N2P        n2p;

    if(debug)
        puts("net_to_port");

    if(length != SIZE_N2P)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&n2p), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&n2p)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(n2p.n2p_handle);
        logid = get_long(n2p.n2p_logid);
        linet = get_unspec_long(n2p.n2p_client_inet);
        port = ntohs(n2p.n2p_port);
        service = ntohs(n2p.n2p_service);
        rinet = get_unspec_long(n2p.n2p_remote_inet);
        net_to_port(Acp, logid, linet, port, DEV_SERIAL, service, rinet);
    }
    return;        /*  void  */
}

void acp_logout_port_to_annex(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32 logid, inet;
    int    service, port, ic, oc;

    ACP_USTRING    Username;
    PXA        pxa;

    if(debug)
        puts("logout_port_to_annex");

    if(length > SIZE_PXA)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&pxa), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&pxa)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(pxa.pxa_handle);
        logid = get_long(pxa.pxa_logid);
        inet = get_unspec_long(pxa.pxa_inet);
        port = ntohs(pxa.pxa_port);
        service = ntohs(pxa.pxa_service);
          pxa.pxa_username[ACP_MAXUSTRING - 1] = '\0';
        (void)strcpy(Username, pxa.pxa_username);
        ic = get_long(pxa.pxa_ichars);
        oc = get_long(pxa.pxa_ochars);

        port_to_annex_logout(Acp, logid, inet, port, DEV_SERIAL, service, 
                                     Username);

        if (length == SIZE_PXA && (ic || oc)) {
          log_accounting(Acp, logid, inet, port, DEV_SERIAL, service, 0, 0,
			 ic, oc, 0, Username);
        }

        terminate_session();

    }
    return;        /*  void  */
}

void acp_logout_annex_to_net(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            linet,
            rinet;
    int        service,
            port;

    ACP_USTRING    Username;
    AXN        axn;

    if(debug)
        puts("logout_annex_to_net");

    if(length > SIZE_AXN)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&axn), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&axn)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(axn.axn_handle);
        logid = get_long(axn.axn_logid);
        linet = get_unspec_long(axn.axn_client_inet);
        port = ntohs(axn.axn_port);
        service = ntohs(axn.axn_service);
        rinet = get_unspec_long(axn.axn_remote_inet);
          axn.axn_username[ACP_MAXUSTRING - 1] = '\0';
        (void)strcpy(Username, axn.axn_username);
        annex_to_net_logout(Acp, logid, linet, port, DEV_SERIAL,
                    service, rinet, Username);
    }
    return;        /*  void  */
}


void acp_logout_annex_to_lat(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32        logid,
            linet;
    int            service,
            port;

    ACP_USTRING    Username;
    ACP_USTRING    Service_name;
    AXL        axl;

    if(debug)
    puts("logout_annex_to_lat");

    if(length > SIZE_AXL)
    {
    reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
    srpc_decode(Acp->Srpc, message, (char *)(&axl), length);

    if(!srpc_cmp(Acp->Srpc, (SHDR *)(&axl)))
        reject_session(Acp, CMJ_SRPC);    /* no return */

    Acp->handle = get_long(axl.axl_handle);
    logid = get_long(axl.axl_logid);
    linet = get_unspec_long(axl.axl_client_inet);
    port = ntohs(axl.axl_port);
    service = ntohs(axl.axl_service);
          axl.axl_username[ACP_MAXUSTRING - 1] = '\0';
    (void)strcpy(Username, axl.axl_username);
          axl.axl_service_name[ACP_MAXUSTRING - 1] = '\0';
    (void)strcpy(Service_name, axl.axl_service_name);
    annex_to_lat_logout(Acp, logid, linet, port, DEV_SERIAL,
            service, Username, Service_name);
    }
    return;        /*  void  */
}

void acp_logout_net_to_port(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    UINT32 logid, linet, rinet;
    int    service, port, ic, oc;

    ACP_USTRING    Username;
    NXP        nxp;

    if(debug)
        printf("logout_net_to_port\n");

    if(length > SIZE_NXP)
    {
        reject_session(Acp, CMJ_INVARG);    /* no return */
    }
    else
    {
        srpc_decode(Acp->Srpc, message, (char *)(&nxp), length);

        if(!srpc_cmp(Acp->Srpc, (SHDR *)(&nxp)))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(nxp.nxp_handle);
        logid = get_long(nxp.nxp_logid);
        linet = get_unspec_long(nxp.nxp_client_inet);
        port = ntohs(nxp.nxp_port);
        service = ntohs(nxp.nxp_service);
        rinet = get_unspec_long(nxp.nxp_remote_inet);
        nxp.nxp_username[ACP_MAXUSTRING - 1] = '\0';
        (void)strcpy(Username, nxp.nxp_username);
        ic = get_long(nxp.nxp_ichars);
        oc = get_long(nxp.nxp_ochars);

        net_to_port_logout(Acp, logid, linet, port, DEV_SERIAL, service, rinet,
                   Username);

        if (length == SIZE_NXP && (ic || oc)) {
          log_accounting(Acp, logid, linet, port, DEV_SERIAL, service, 0, 0, ic, oc, 0,
                         Username);
        }

        terminate_session();

    }
    return;        /*  void  */
}

int
acp_hook_callback(Acp,message,length)
ACP    *Acp;
char    *message;
int    length;
{
    int code;
    HOOK_CALLBACK callback;
    UINT32 logid;

    if (debug)
        puts("hook_callback");

    if (length > SIZE_HOOK_CALLBACK)
        reject_session(Acp, CMJ_INVARG);    /* no return */
    else {
        bzero(&callback,sizeof(callback));
        srpc_decode(Acp->Srpc,message,(char *)&callback,length);

        if (!srpc_cmp(Acp->Srpc,(SHDR *)&callback))
            reject_session(Acp, CMJ_SRPC);    /* no return */

        Acp->handle = get_long(callback.hcb_handle);
        logid = get_long(callback.hcb_logid);
        code = ntohs(callback.hcb_code);
        callback.hcb_text[HCB_TEXT_MAX] = '\0';
        hook_callback(Acp,logid,code,callback.hcb_text);
    }
    return 0;
}

void acp_srpc_open(Acp, message, length)

ACP    *Acp;
char    *message;
int    length;
{
    int ret;

    if(debug)
        puts("open");

    ret =
    srpc_answer(Acp->Srpc, Acp->s, NULL, Acp->pid, Acp->key, message, length);

    if(debug && ret)
        printf("acp_srpc_open: srpc_answer returned %d\n", ret);

    if(ret)
        terminate_session();

    return;
}

 
/*
 *    log_accounting()
 *
 *      This function logs an accounting event.
 *
 */
void log_accounting(Acp, logid, inet, port,ptype, service, ip, op, ic, oc, et, Username)
 
ACP           *Acp;                      /* Handle for various ACP calls */
UINT32                logid,                         /* Log file sequence number */
              inet;                            /* Annex Internet address */
int           port,                      /* physical/virtual port number */
              service;               /* service, expect SERVICE_PPP/SLIP */
UINT32                ip,                        /* # pkts received this session */
              op,                            /* # pkts sent this session */
              ic,                       /* # bytes received this session */
              oc,                           /* # bytes sent this session */
              et;
char          *Username;                    /* user associated with port */
int ptype;
{
#ifndef _WIN32
    ACP_LSTRING Message;
#else   /* defined _WIN32 */
	ACP_USTRING Message;
#endif   /* defined _WIN32 */
 
    sprintf(Message, "%u:%u:%u:%u:%u:%s", ip, op, ic, oc, et, Username);
    if (ISUDP(Acp->state))
        log_message(inet, logid, port,ptype, service, EVENT_ACCT, Message);
    return;
}
 
/*
 *    ppp_slip_logout()
 *
 *    This function is called remotely by the Annex when the PPP or SLIP
 *    session terminates, but only if enable_security is set to Y when PPP/SLIP begins.
 */
 
ppp_slip_logout(Acp, logid, inet, port,ptype, service, Username)
 
ACP           *Acp;           /* Handle for various ACP calls */
UINT32                logid,          /* Log file sequence number */
              inet;           /* Annex Internet address */
int           port,           /* physical/virtual port number */
              service;        /* service, expect SERVICE_PPP/SLIP */
char          *Username;      /* user associated with port */
int ptype;
{
    /*  generic acknowledge - return to remote caller  */
 
    (void)acp_acknowledge(Acp);
 
    if (ISUDP(Acp->state))
              log_message(inet, logid, port,ptype,service, EVENT_LOGOUT, Username);
 
    /*  terminate (exit()) this session  */
    /* terminate_session() is now in acp_logout_ppp_slip() in acp_rpc.c */
 
    /*  dummy return  */
    return 0;
}











