/*
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.  Unauthorized
 * duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains definitions for data structures shared by
 *	the Annex and the TMS facility in ERPCD, as well as extern
 *	definitions for the external accessible functions.
 *
 * Original Author: Gary Malkin
 * Created on: July 25, 1996
 */

#ifndef _ACP_TMS_H_
#define _ACP_TMS_H_

/*
 * TMS grant structure
 */
#define TMS_HWADDR_LEN 20	/* Maximum length of HW address */
#define TMS_KEY_LEN 32		/* Maximum length of each encrypt key */
#define TMS_DOMAIN_LEN 64	/* Length of domain part of ndbm key */
#define TMS_DNIS_LEN 20		/* Length of DNIS part of ndbm key */
#define TMS_PASSWD_LEN 16	/* Maximum length of L2TP challenge passwd */
#define NUM_SCND_GW  10
#define TMS_HN_NAME_LEN 32      /* Maximum length of ATMP HN Name */

struct te_t 
{  
  struct in_addr  te_addr;		/* IP address of Tunnel Endpoint */
  u_char          hw_type;		/* type of net between GW and CPE */
  u_char          hw_addr_len; 	        /* length of HW address */
  u_char          hw_addr[ TMS_HWADDR_LEN ];	   /* left-justified HW addr */
  u_char          rip_timeout; /* interval between rips */            
  u_char          rip_limit;  /* maximum number of rip packets */     
  struct in_addr  rip_src_addr; /* source address of the rip packet */
  int             tried;
};


typedef struct {
    struct in_addr tg_te_addr;		/* IP address of Tunnel Endpoint */
    u_char tg_hw_type;			/* type of net between GW and CPE */
    u_char tg_hw_addr_len;		/* length of HW address */
    u_char tg_hw_addr[TMS_HWADDR_LEN];	/* left-justified HW addr */
    u_char          rip_timeout; /* interval between rips */
    u_char          rip_limit;  /* maximum number of rip packets */
    struct in_addr  src_addr; /* source address of the rip packet */

    struct te_t  prim_gw;               /* primary tunnel endpoint */
    struct te_t  scnd_gw[NUM_SCND_GW];  /* secondary tunnel endpoint list */
    u_char       ge_select_mode;
    u_char       num_scnd_gw;
    u_char       last_gw_selected;

    u_short tg_auth_proto;		/* auth protocol between GW & AS */
    u_short tg_acct_proto;		/* accounting proto between GW & AS */
    struct in_addr tg_pauth_addr;	/* IP address of primary AS */
    struct in_addr tg_sauth_addr;	/* IP address of secondary AS */
    struct in_addr tg_pacct_addr;	/* IP address of primary acct server */
    struct in_addr tg_sacct_addr;	/* IP address of secondary acct srvr */
    u_long tg_spi;			/* security protocol index */
    u_char tg_ta_type;			/* tunnel authentication type */
    u_char tg_ta_mode;			/* tunnel authentication mode */
    u_char tg_ta_key[TMS_KEY_LEN];     	/* left-justified authentication key */
    u_short tg_addr_proto;		/* address resolution protocol */
    struct in_addr tg_paddr_addr;	/* IP address of primary ad res srv */
    struct in_addr tg_saddr_addr;	/* IP address of secondary ad res srv*/
    u_char tg_tunnel_type;		/* type of tunnel */
    u_char tg_server_loc;		/* location of auth,acct,addr servers*/
    u_char tg_passwd[TMS_PASSWD_LEN];	/* L2TP password */
    u_char tg_tag;                      /* tag used for radius attribs */
    u_char tg_med_type;                 /* describes the medium over which
                                           the tunnel works currently IP*/
    char   tg_domain[TMS_DOMAIN_LEN];	/* domain name (as parsed by ERPCD) */
    u_short tg_te_port;                 /* Tunnel Endpoint UDP port */
    char   hn_name[TMS_HN_NAME_LEN];    /* Home Network Name */
} tms_grant;				/* provisioned info in database */

/*
 * enumerated values for tms_grant and tms_db_entry fields
 */
#define TG_HWTYP_SL	1		/* hw_type = serial line */
#define TG_HWTYP_PPP	2		/* hw_type = ppp */
#define TG_HWTYP_FR	3		/* hw_type = frame relay */

#define TG_AUTHP_ACP	1		/* auth protocol = acp */
#define TG_AUTHP_RAD	2		/* auth protocol = radius */

#define TG_ACCTP_RAD	2		/* accounting protocol = radius */

#define TG_TATYP_KMD5_128 1		/* tun auth type = 128-bit keyed MD5 */

#define TG_TAMOD_PREFSUFF 1		/* tun auth mode = prefix/suffix */

#define TG_ADDRP_DHCP	1		/* address resolution proto = dhcp */

#define TG_TUTYPE_NONE 0		/* tunnel type = NONE */
#define TG_TUTYPE_L2TP 2		/* tunnel type = L2TP */
#define TG_TUTYPE_DVS  3		/* tunnel type = BAY DVS */
#define TG_TUTYPE_ATMP 4		/* tunnel type = ATMP */

#define TG_SRVLOC_NONE   0		/* auth type = none */
#define TG_SRVLOC_LOCAL  1		/* auth type = local */
#define TG_SRVLOC_REMOTE 2		/* auth type = remote */

/*
 * external function definitions
 */
#if defined(ANNEX) && (NUDAS > 0)
extern errno_t acp_tms_term();	/* oper/acp/local_acp.c */
#endif

#endif /*_ACP_TMS_H_*/
