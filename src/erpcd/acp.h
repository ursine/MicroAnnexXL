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
 * Include file description:
 *    %$(description)$%
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 ****************************************************************************
 */


#ifndef ACP_H
#define ACP_H
#include "../inc/port/port.h"
#include "../libannex/srpc.h"
#include "../inc/erpc/nerpcd.h"
#include "environment.h"

#define COURRPN_ACP 3
#define ACP_VER 1

#define SECURITY_VERSION 1

#define RACP_HI_VER 1 /* highest racp version we'll support */
#define RACP_LO_VER 1 /* lowest racp version we'll support */

/*
 *    Security System Remote Program Numbers
 *
 *     Note: these numbers must match the defines is
 *        ...src/oper/erpc/remote.h
 */ 

#define ACP_INPUTSTRING                0
#define ACP_OUTPUTSTRING            1
#define ACP_PROMPTSTRING            2
#define ACP_REQUEST_PORT_TO_ANNEX        3
#define ACP_REQUEST_ANNEX_TO_NET        4
#define ACP_REQUEST_NET_TO_PORT            5
#define ACP_LOGOUT_PORT_TO_ANNEX        6
#define ACP_LOGOUT_ANNEX_TO_NET            7
#define ACP_LOGOUT_NET_TO_PORT            8
#define ACP_PORT_TO_ANNEX_AUTHORIZE        9
#define ACP_ANNEX_TO_NET_AUTHORIZE        10
#define ACP_NET_TO_PORT_AUTHORIZE        11
#define ACP_SET_ENVIRONMENT            12
#define ACP_GLOBAL_INIT                13
#define ACP_SRPC_CHANGE_KEY            14
#define ACP_SRPC_OPEN                15
#define ACP_SRPC_CLOSE                18

#define ACP_REQUEST_PPP_SECURITY        19 
#define ACP_PPP_SECURITY_AUTHORIZE        20    
#define ACP_REQUEST_DIALUP_ADDRESS        21 
#define ACP_DIALUP_ADDRESS_AUTHORIZE        22    
#define ACP_LOGOUT_PPP_SLIP            23
#define    ACP_REQUEST_ANNEX_TO_LAT        24
#define    ACP_LOGOUT_ANNEX_TO_LAT            25
#define ACP_DO_DIALOUT                26
#define ACP_REQUEST_APPLETALK_PROFILE           27
#define ACP_APPLETALK_PROFILE_AUTHORIZE         28
#define ACP_REQUEST_APPLETALK_PROFILE2          29
#define ACP_HOOK_CALLBACK            30
#define ACP_HOOK_RETURN                31
#define ACP_SERIAL_VALIDATE_AUTHORIZE        32
#define ACP_REQUEST_USER_INDEX            33
#define ACP_USER_INDEX_AUTHORIZE        34
#define ACP_REQUEST_LOG                35
#define ACP_LOG_AUTHORIZE            36

/*    Miscellaneous ACP defines    */

#define ACP_LONGSTRING                80
#define AUTH_TIMEOUT                5
#define DIALB_TIMEOUT                300    /* 5 min. */
#define GET_TERMINATOR                0x0001  /* securID code */
#define MAXPDUHEAD                  4
#define ESUCCESS                    0
#define SUCCESS                     ESUCCESS
/*#define ERROR                       -1	 conflict with windows' defination*/
#define ACP_ERROR                       -1
#define BUFFSIZE    2048    /* Maximum possible message to be read    */

/* RACP states */

#define S_OPEN  0x00000001
#define S_NEGO  0x00000002
#define S_CONN  0x00000004
#define S_AUDIT 0x00000008
#define S_HOOK  0x00000010

#define P_UDP   0x00010000
#define P_TCP   0x00020000

#define ISCONN(s)  (s & S_CONN)
#define ISAUDIT(s) (s & S_AUDIT)
#define ISHOOK(s)  (s & S_HOOK)
#define ISTCP(s)   (s & P_TCP)
#define ISUDP(s)   (s & P_UDP)

#define SETZERO(s) (s = 0)
#define SETNEGO(s) (s |= S_NEGO)
#define CLRNEGO(s) (s &= ~S_NEGO)
#define SETCONN(s) (s |= S_CONN)
#define CLRCONN(s) (s &= ~S_CONN)
#define SETTCP(s)  (s |= P_TCP)
#define SETUDP(s)  (s |= P_UDP)
#define SETAUDIT(s) (s |= S_AUDIT)
#define SETOPEN(s) (s |= S_OPEN)
#define SETCLOSED(s) (s &= 0xffff0000)

/* Reliable ACP capability mask */
#define CAP_GLOBAL  NC_ENIGMA

/*    Structures for ACP state data    */
typedef struct racp {
  KEYDATA *rcv_key;
  KEYDATA *send_key;
  u_short usage;
  u_short capability;
  u_short options;
  u_char version;
} RACP;

typedef struct attribute_block
{
    u_char *buf;
    u_short len;
} ABLOCK;

typedef struct authorization_profile 
{
    UINT32 ret_err_code;
    UINT32 blacklisted;
    UINT32 hmask;
    struct cli_cmd_list *cmd_list;
    struct sesdbrec *sesrec;
    u_char *radius_packet;
} AUTH_PROF;

typedef struct acp_state
{
    UINT32        state;
    int        s;
    UINT32        pid;
    KEYDATA        *key;
    UINT32        handle;
    UINT32      inet;
    SRPC        *Srpc;
    RACP        *racp;
    struct environment_spec *env;
    CHAP_REQ    *chap;
    struct authorization_profile auth;
    UINT32 logseq;
    UINT32 logack;
}    ACP;

/*    define remote procedure call parameters        */

typedef struct global_init
{
    UINT32        gbl_srpc_id;
    UINT32        gbl_sequence;
    unsigned short    gbl_handle[2];
    unsigned short    gbl_logid[2];
    unsigned short    gbl_inet[2];
    ACP_STRING    gbl_msg;

}    GLOBAL_INIT;

#define SIZE_GBL    (sizeof(GLOBAL_INIT))


typedef struct dialup_address_parameters
{

    UINT32        rda_srpc_id;
    UINT32        rda_sequence;
    unsigned short    rda_handle[2];
    unsigned short    rda_logid[2];
    unsigned short    rda_inet[2];
    unsigned short    rda_port;
    unsigned short    rda_service;
    unsigned short    rda_loc[2];
    unsigned short    rda_rem[2];
    ACP_USTRING    rda_uname;
    unsigned char rda_node[6];
    unsigned short	dummy;	/* keep the struct longword aligned! */
}    RDA;
#define SIZE_RDA    (sizeof(RDA))


typedef struct user_index_parameters
{

        UINT32   rui_srpc_id;
        UINT32   rui_sequence;
        unsigned short  rui_handle[2];
        unsigned short  rui_logid[2];
        unsigned short  rui_inet[2];
        unsigned short  rui_port;
        unsigned short  rui_service;
        ACP_USTRING      rui_uname;
}       RUI;
#define SIZE_RUI        (sizeof(RUI))

typedef struct req_log_parameters
{

        UINT32          rl_srpc_id;
        UINT32          rl_sequence;
        unsigned short  rl_handle[2];
        unsigned short  rl_logid[2];
        unsigned short  rl_inet[2];
        unsigned short  rl_port;
        unsigned short  rl_service;
    unsigned short  rl_event;
    ACP_USTRING     rl_message;
}       RL;
#define SIZE_RL        (sizeof(RL))


typedef struct ppp_sec_parameters
{
    UINT32        pppsec_srpc_id;
    UINT32        pppsec_sequence;
    unsigned short    pppsec_handle[2];
    unsigned short    pppsec_logid[2];
    unsigned short    pppsec_inet[2];
    unsigned short    pppsec_port;
    unsigned short    pppsec_service;
    UINT32        pppsec_direction;
    ACP_USTRING    pppsec_uname;
    ACP_STRING    pppsec_pword;
}    PPPSEC;

#define SIZE_PPPSEC    (sizeof(PPPSEC))

typedef struct serval_parameters
{
        UINT32        serval_srpc_id;
        UINT32        serval_sequence;
        unsigned short  serval_handle[2];
        unsigned short  serval_logid[2];
        unsigned short  serval_inet[2];
        unsigned short  serval_port;
        unsigned short  serval_service;
        UINT32        serval_direction;
        ACP_STRING      serval_uname;  /* still 16 chars; used by UDP erpcd only */
        ACP_STRING      serval_pword;

        union {

                char    filler[100];

                struct {
                ACP_STRING phone;
                int netnum;
                } ipx;

                struct {
                ACP_STRING phone;
                int netnum;
                } arap;

        }       serval_un;

}       SERVAL;

#define SIZE_SERVAL     (sizeof(SERVAL))


typedef struct port_to_annex_parameters
{
    UINT32        p2a_srpc_id;
    UINT32        p2a_sequence;
    unsigned short    p2a_handle[2];
    unsigned short    p2a_logid[2];
    unsigned short    p2a_inet[2];
    unsigned short    p2a_port;
    unsigned short    p2a_service;

}    P2A;

#define SIZE_P2A    (sizeof(P2A))

typedef struct annex_to_net_parameters

{
    UINT32        a2n_srpc_id;
    UINT32        a2n_sequence;
    unsigned short    a2n_handle[2];
    unsigned short    a2n_logid[2];
    unsigned short    a2n_client_inet[2];
    unsigned short    a2n_port;
    unsigned short    a2n_service;
    unsigned short    a2n_remote_inet[2];
    ACP_USTRING    a2n_username;
    unsigned short    a2n_tcp_port_req[2];

}    A2N;

#define SIZE_A2N    (sizeof(A2N))

typedef struct annex_to_lat_parameters

{
    UINT32        a2l_srpc_id;
    UINT32        a2l_sequence;
    unsigned short    a2l_handle[2];
    unsigned short    a2l_logid[2];
    unsigned short    a2l_client_inet[2];
    unsigned short    a2l_port;
    unsigned short    a2l_service;
    ACP_USTRING    a2l_username;
    ACP_USTRING    a2l_service_name;

}    A2L;

#define SIZE_A2L    (sizeof(A2L))

typedef struct net_to_port_parameters
{
    UINT32        n2p_srpc_id;
    UINT32        n2p_sequence;
    unsigned short    n2p_handle[2];
    unsigned short    n2p_logid[2];
    unsigned short    n2p_client_inet[2];
    unsigned short    n2p_port;
    unsigned short    n2p_service;
    unsigned short    n2p_remote_inet[2];

}    N2P;

#define SIZE_N2P    (sizeof(N2P))

typedef struct net_logout
{
    UINT32        net_srpc_id;
    UINT32        net_sequence;
    unsigned short    net_handle[2];
    unsigned short    net_logid[2];
    unsigned short    net_inet[2];
    unsigned short    net_port;
    unsigned short    net_service;
    ACP_USTRING    net_username;
    unsigned short    net_ipkts[2];
    unsigned short    net_opkts[2];
    unsigned short    net_ichars[2];
    unsigned short    net_ochars[2];
    unsigned short    net_elapsed_time[2];

}    NET;

#define SIZE_NET    (sizeof(NET))

typedef struct port_to_annex_logout
{
    UINT32        pxa_srpc_id;
    UINT32        pxa_sequence;
    unsigned short    pxa_handle[2];
    unsigned short    pxa_logid[2];
    unsigned short    pxa_inet[2];
    unsigned short    pxa_port;
    unsigned short    pxa_service;
    ACP_USTRING    pxa_username;
    unsigned short    pxa_ichars[2];
    unsigned short    pxa_ochars[2];

}    PXA;

#define SIZE_PXA    (sizeof(PXA))

typedef struct annex_to_lat_logout
{
    UINT32        axl_srpc_id;
    UINT32        axl_sequence;
    unsigned short    axl_handle[2];
    unsigned short    axl_logid[2];
    unsigned short    axl_client_inet[2];
    unsigned short    axl_port;
    unsigned short    axl_service;
    ACP_USTRING    axl_username;
    ACP_USTRING    axl_service_name;

}    AXL;

#define SIZE_AXL    (sizeof(AXL))

typedef struct annex_to_net_logout
{
    UINT32        axn_srpc_id;
    UINT32        axn_sequence;
    unsigned short    axn_handle[2];
    unsigned short    axn_logid[2];
    unsigned short    axn_client_inet[2];
    unsigned short    axn_port;
    unsigned short    axn_service;
    unsigned short    axn_remote_inet[2];
    ACP_USTRING    axn_username;

}    AXN;

#define SIZE_AXN    (sizeof(AXN))

typedef struct net_to_port_logout
{
    UINT32        nxp_srpc_id;
    UINT32        nxp_sequence;
    unsigned short    nxp_handle[2];
    unsigned short    nxp_logid[2];
    unsigned short    nxp_client_inet[2];
    unsigned short    nxp_port;
    unsigned short    nxp_service;
    unsigned short    nxp_remote_inet[2];
    ACP_USTRING    nxp_username;
    unsigned short    nxp_ichars[2];
    unsigned short    nxp_ochars[2];

}    NXP;

#define SIZE_NXP    (sizeof(NXP))

typedef struct acp_authorize_dialup
{
    UINT32        auth_srpc_id;
    UINT32        auth_sequence;
    unsigned short    auth_handle[2];
    unsigned short    auth_grant[2];
    UINT32        auth_loc;
    UINT32        auth_rem;
    unsigned char auth_node[6];

}    AUTH_RDA; 

#define SIZE_AUTH_RDA    (sizeof(AUTH_RDA))

typedef struct acp_pend_dialup
{
	UINT32		auth_srpc_id;
	UINT32		auth_sequence;
	unsigned short	auth_handle[2];
	unsigned short	auth_grant[2];
	UINT32		auth_loc;
	UINT32		auth_rem;

}	PEND_RDA; 

#define SIZE_PEND_RDA	(sizeof(PEND_RDA))

typedef struct acp_authorize_ppp
{
    UINT32        auth_srpc_id;
    UINT32        auth_sequence;
    unsigned short    auth_handle[2];
    unsigned short    auth_grant[2];

}    AUTH_PPP;

#define SIZE_AUTH_PPP    (sizeof(AUTH_PPP))

typedef struct acp_authorize_serval
{
        UINT32        auth_srpc_id;
        UINT32        auth_sequence;
        unsigned short  auth_handle[2];
        unsigned short  auth_grant[2];

}       AUTH_SERVAL;

#define SIZE_AUTH_SERVAL (sizeof(AUTH_SERVAL))


typedef struct acp_authorize_user_index
{
        UINT32          auth_srpc_id;
        UINT32          auth_sequence;
        unsigned short  auth_handle[2];
        unsigned short  auth_grant[2];
    ACP_STRING    auth_index;

}       AUTH_RUI;

#define SIZE_AUTH_RUI   (sizeof(AUTH_RUI))

typedef struct acp_authorize_log
{
        UINT32          auth_srpc_id;
        UINT32          auth_sequence;
        unsigned short  auth_handle[2];
        unsigned short  auth_grant[2];

}       AUTH_RL;

#define SIZE_AUTH_RL    (sizeof(AUTH_RL))

typedef struct acp_authorize_cli
{
    UINT32        auth_srpc_id;
    UINT32        auth_sequence;
    unsigned short    auth_handle[2];
    unsigned short    auth_grant[2];
    unsigned short    auth_mask[2];
    ACP_STRING    auth_username;  /* still 16 chars; used by UDP erpcd only */
    unsigned short    auth_hooks[2];

}    AUTH_CLI;

#define SIZE_AUTH_CLI    (sizeof(AUTH_CLI))

typedef struct acp_authorize
{
    UINT32        auth_srpc_id;
    UINT32        auth_sequence;
    unsigned short    auth_handle[2];
    unsigned short    auth_grant[2];

}    AUTH;

#define SIZE_AUTH    (sizeof(AUTH))

typedef struct acp_acknowledge
{
    UINT32        ack_srpc_id;
    UINT32        ack_sequence;
    unsigned short    ack_handle[2];
    unsigned short    ack_ack[2];

}    ACK;

#define SIZE_ACK    (sizeof(ACK))

typedef struct input_string
{
    UINT32        inp_srpc_id;
    UINT32        inp_sequence;
    unsigned short    inp_handle[2];
    unsigned short    inp_timeout;
    unsigned short    inp_echo;

}    INPUT_STRING;

#define SIZE_INPUT    (sizeof(INPUT_STRING))

typedef struct output_string
{
    UINT32        out_srpc_id;
    UINT32        out_sequence;
    unsigned short    out_handle[2];
    ACP_STRING    out_string;

}    OUTPUT_STRING;

#define SIZE_OUTPUT    (sizeof(OUTPUT_STRING))

typedef struct prompt_string
{
    UINT32        pmt_srpc_id;
    UINT32        pmt_sequence;
    unsigned short    pmt_handle[2];
    unsigned short    pmt_timeout;
    unsigned short    pmt_echo;
    ACP_STRING    pmt_string;
     unsigned short    pmt_flags;

}    PROMPT_STRING;

#define SIZE_PROMPT    (sizeof(PROMPT_STRING))

typedef struct return_string
{
    UINT32        ret_srpc_id;
    UINT32        ret_sequence;
    unsigned short    ret_handle[2];
    ACP_USTRING    ret_string;
     unsigned short    ret_flags;

}    RETURN_STRING;

#define SIZE_STRING    (sizeof(RETURN_STRING))

/*
 *    AppleTalk Profile structures
 */

typedef struct appletalk_profile 
{
    UINT32        rat_srpc_id;
    UINT32        rat_sequence;
    unsigned short    rat_handle[2];
    unsigned short    rat_logid[2];
    unsigned short    rat_inet[2];
    unsigned short    rat_port;
    unsigned short    rat_service;
    ACP_USTRING    rat_uname;
} APPLETALK_PROFILE;

#define SIZE_RAT (sizeof(APPLETALK_PROFILE))


typedef struct 
{
    UINT32        rap_srpc_id;
    UINT32        rap_sequence;
    unsigned short    rap_handle[2];
    unsigned short    rap_grant[2];
        unsigned short  rap_connect_time[2];
    unsigned short    rap_zones[2];
    unsigned short    rap_zone_count[2];
        unsigned char     rap_passwd[ATPASSWD+1];
    unsigned char     rap_zones_list[ATZONELIST];
} APPLETALK_RETURN_OLD;

#define SIZE_RAP_OLD (sizeof(APPLETALK_RETURN_OLD))

typedef struct 
{
    UINT32        rap_srpc_id;
    UINT32        rap_sequence;
    unsigned short    rap_handle[2];
    unsigned short    rap_grant[2];
        unsigned short  rap_connect_time[2];
    unsigned short    rap_zones[2];
    unsigned short    rap_zone_count[2];
        unsigned char     rap_passwd[ATPASSWD+1];
    unsigned char     rap_zones_list[ATZONELIST];
    unsigned char     rap_nve[ATFILTERLEN +1];
    unsigned short  rap_nve_exclude[2];
} APPLETALK_RETURN;

#define SIZE_RAP (sizeof(APPLETALK_RETURN))

typedef struct
    {
    UINT32        hcb_srpc_id;
    UINT32        hcb_sequence;
    unsigned short    hcb_handle[2];
    unsigned short    hcb_logid[2];
    unsigned short    hcb_code;
    unsigned short    hcb_reserved;
    char        hcb_text[HCB_TEXT_MAX+1];
    } HOOK_CALLBACK;
#define SIZE_HOOK_CALLBACK    (sizeof(HOOK_CALLBACK))

typedef struct acp_dialout {
        SHDR            shdr;
        UINT32        acp_cap;
        char            access_code[LEN_ACCESS_CODE];
        char            username[LEN_USERNAME];
         char            phone[LEN_PHONE];
        char            port_mask[LEN_PORT_MASK];
        union {
                char    job[LEN_JOB];

                int     type;

                struct {
                        int     filler;
                        int     netnum;
                } ipx;
        } un;

} ACP_DIALOUT;

typedef struct {
    SHDR        shdr;
    UINT32        acp_cap;
    UINT32        grant;        /* grant, deny, pend, error */
    unsigned short    port;        /* port doing the dialout */
} ACP_DIALOUT_GRANT;

#ifdef USE_CLIENT_REC
#ifndef _WIN32
struct clientrec {
  struct in_addr host;
  unsigned short port;
  unsigned short tcpflag;
  int pid;
};
#endif
#endif

#endif
