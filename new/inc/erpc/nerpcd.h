/*
 *****************************************************************************
 *
 *        Copyright 1993, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *
 *    Define NERPC-related (New Erpc) constants
 *
 * Original Author: James Carlson    Created on: 05MAR93
 *
 ****************************************************************************
 */


#ifndef NERPCD_H
#define NERPCD_H

#include "acp_const.h"

#ifndef ANNEX
/* Each NVE filter is at worst 99 bytes */
typedef u_long errno_t;
#else
#include "devtypes.h"
#endif

/* chap challenge/response lengths */
#define CHAP_CHAL_LEN 16
#define CHAP_RESP_LEN 16

/* ------------- NERPC SET-UP PROTOCOL ------------- */

/* Usage definitions -- in host order */
#define NU_IDENTIFY    0
#define NU_PRINTING    1
#define NU_PACCESS    2
#define NU_ADMIN    3
#define NU_SECURITY    4

/* Capability definitions -- in host order */
#define NC_CRYPT    0x0001
#define NC_DES        0x0002
#define NC_ENIGMA    0x0004

/* Option definitions -- in host order */
#define NO_DATAENC    0x0001

/* ------------- PRINTER PORT ACCESS PROTOCOL ------------- */

#define PPA_ANYLINE    ((u_short)0xFFFF)
#define PPA_ANYTYPE    ((u_short)0xFFFF)
#define PPA_SERIAL    ((u_char)0)
#define PPA_PARALLEL    ((u_char)1)

#define PPS_ACK        ((u_char)0)    /* Simple acknowledgment */
#define PPS_NREADY    ((u_char)1)    /* Not immediately ready */
#define PPS_TIME    ((u_char)2)    /* Not ready for a long time */
#define PPS_NPORT    ((u_char)3)    /* No port -- waiting */
#define PPS_END        ((u_char)0x80)    /* Read to end of file */
#define PPS_ABEND    ((u_char)0x81)    /* Error on physical port */
#define PPS_CANCEL    ((u_char)0x82)    /* Job cancel */
#define PPS_ISTERM(x)    ((x) >= 0x80)    /* Is termination request */

#define PPL_EOF        ((u_short)0)
#define PPL_FLUSH    ((u_short)0xFFFF)    /* Sent as urgent */

/* ------------- RELIABLE ACCESS CONTROL PROTOCOL ------------- */

#define MAXPDUSIZE 4096

/* Acp_message.command CHOICE */
#define RACP_AUTH_REQ   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define RACP_AUTH_RESP  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define RACP_INFO_REQ   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define RACP_INFO_RESP  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)
#define RACP_EXEC_REQ   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x04)
#define RACP_EXEC_REPLY (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x05)
#define RACP_AUDIT_LOG  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x06)
#define RACP_AUDIT_VER  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x07)
#define RACP_TMS_REQ    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x08)

/* Acp_message.command.authorization-request.data SET */
#define ARQ_USERNAME   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define ARQ_PASSWORD   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define ARQ_PHONE      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define ARQ_FROMADDR   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)
#define ARQ_DESTADDR   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x04)
#define ARQ_CHAP       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x05)
#define ARQ_ENDPOINT   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x06)
#define ARQ_CALLED_NUM (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x07)
#define ARQ_RAS_ADDR   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x08)
#define ARQ_CALLING_NUM (ASN_CONTEXT| ASN_CONSTRUCTOR | 0x09)
#define ARQ_CALLED_SUB (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0A)
#define ARQ_SPB_NAME   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0B)
#define ARQ_BEARER_TYPE (ASN_CONTEXT| ASN_CONSTRUCTOR | 0x0C)
#define ARQ_DETECT_L1  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0D)
#define ARQ_DETECT_L2  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0E)
#define ARQ_WAN_INDEX  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0F)
#define ARQ_DS0_INDEX  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x10)

/* Acp_message.command.authorization-response.data SET */
#define ARS_CLIMASK    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define ARS_HOOKMASK   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define ARS_USERNAME   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define ARS_TMS_TE     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)
#define ARS_TMS_HW     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x04)
#define ARS_TMS_AUTH   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x05)
#define ARS_TMS_ACCT   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x06)
#define ARS_TMS_TAUTH  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x07)
#define ARS_TMS_ADDR   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x08)
#define ARS_TMS_EXT1   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x09)

/* Acp_message.command.information-request.data SET */
#define IRQ_USERNAME   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define IRQ_TEXT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define IRQ_CODE       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define IRQ_LOCADDR    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)
#define IRQ_REMADDR    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x04)
#define IRQ_ENDPOINT   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x05)
#define IRQ_MAX_LOGON  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x06)


/* Acp_message.command.information-response.data SET */
#define IRS_ATPROFILE  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define IRS_TEXT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define IRS_CODE       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define IRS_LOCADDR    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)
#define IRS_REMADDR    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x04)
#define IRS_FILTERS    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x05)
#define IRS_ROUTES     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x06)
#define IRS_MPMAXLINKS (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x07)
#define IRS_MAX_LOGON  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x08)

/* Acp_message.command.execution-request.data SET */
#define ERQ_USERNAME   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define ERQ_PHONE      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define ERQ_ACCESS     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define ERQ_TEXT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)
#define ERQ_PORTMASK   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x04)
#define ERQ_FLAGS      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x05)
#define ERQ_TIMEOUT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x06)
#define ERQ_ECHO       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x07)
#define ERQ_DESTADDR   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x08)
#define ERQ_CODE       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x09)
#define ERQ_JOB        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0A)
#define ERQ_PORT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0B)

/* Acp_message.command.execution-reply.data SET */
#define ERP_PORT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define ERP_FLAGS      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define ERP_TEXT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define ERP_CODE       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)

/* Acp_message.command.audit-log.data SET */
#define ALG_REMADDR    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define ALG_USERNAME   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define ALG_PORTSTATS  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)
#define ALG_TEXT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x03)

/* NetAddr */
#define NETADDR_LAT (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define NETADDR_IP  (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define NETADDR_IPX (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)

/* NetAddr.lat-addr SEQ */
#define LATADDR_SERVICE    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define LATADDR_NODE       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define LATADDR_PORT       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)

/* NetAddr.ip-addr SEQ */
#define IPADDR_PORT        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)

/* NetAddr.ipx-addr SEQ */
#define IPXADDR_NETNUM     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define IPXADDR_NODE       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define IPXADDR_SOCKET     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)

/* AppletalkProfile.data SET */
#define ATP_CONTIME    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x00)
#define ATP_ZONES      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x01)
#define ATP_NVE        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x02)

/* ------------------- info code mask -------------------- */
#define FILT_MASK 0x00000001
#define ROUT_MASK 0x00000002
#define LADD_MASK 0x00000004
#define RADD_MASK 0x00000008

/* ------------------- port struct--- -------------------- */

typedef struct port {
  u_long type; /* device type */
  u_long unit; /* unit number */
} SECPORT;

typedef struct port_stats {
  u_long bytes_rx, bytes_tx, pkts_rx, pkts_tx, elapsed_time;
} LOG_PORT_STATS;

/* ------------------- port dev types -------------------- */
/*
 * When adding a port type to this list, please remember to
 * update DEV_MAX and PORT_DEV_IDENTS in this file, and add
 * a new entry to ptypenames[] in erpcd/env_parser.c
 */
#define DEV_SERIAL   0
#define DEV_SYNC     1
#define DEV_VIRTUAL  2
#define DEV_DIALOUT  3
#define DEV_ETHERNET 4
#define DEV_RCF      5
#define DEV_V120     6
#define DEV_CONTROL  7
#define DEV_MP       8
#define DEV_VPN      9
#define DEV_GENSYNC  10

/*change this when adding port device types*/
#define DEV_MAX      11

#define PORT_DEV_IDENTS /*NOSTR*/"#svdertcmVg"

/* min length of ASN.1 PORT */
#define PORT_MIN     6
/* appletalk stuff */

typedef struct at_profile_return
{
  unsigned long connect_time; /* maximum allowed connect time */
  unsigned long zones_len; /* total length of all zones, including length 
                  byte, in zones_list */
  unsigned long zone_count; /* total number of zones in zone_list */
  unsigned long nve_exclude; /* TRUE-exclusion, FALSE-inclusion */
  unsigned long nves_len; /* total length of all nves, including length byte,
                 in nve */
  unsigned long nve_count; /* total number of nves */
  unsigned char passwd[ATPASSWD+1]; /* user password */
  unsigned char zones_list[ATZONELIST]; /* the list of zones, NULL term. */
  unsigned char nve[ATFILTERLEN +1]; /* the list of nves, NULL term. */
} AT_PROFILE_RETURN;

/* Chap authentication request structure */
typedef struct chap_req
{
    u_char id;
    u_char challenge[CHAP_CHAL_LEN];
    u_char response[CHAP_RESP_LEN];
} CHAP_REQ;

/* discovery stuff */

typedef struct probehead {
    u_long pid;
    u_short client;
    u_short devclass;
    u_long pcode;
} PROBEHEAD;

typedef struct probe {
    PROBEHEAD head;
    u_char version[3];
    u_char res;
    u_short af;
    u_char addr[32];
    u_short htype;
    u_char haddr[32];
    u_char idstring[128];
} PROBE;

#define DC_ANY       0xFFFF
#define DC_LOGHOST   0x0001
#define DC_AUTHHOST  0x0002
#define DC_FILEHOST  0x0004
#define DC_BOOTHOST  0x0008
#define DC_SERVER    0x8000

#define PC_ANY       0xFFFFFFFF
#define PC_HOST      0x00000001
#define PC_ANNEX3    0x00000002
#define PC_MICROXL   0x00000004
#define PC_RA2000    0x00000008
#define PC_RA4000    0x00000010
#define PC_5390      0x00000020
#define PC_T1CSMIM   0x00000040
#define PC_ANNEX4    0x00000080
#define PC_MICROCS   0x00000100
#define PC_5391      0x00000200
#define PC_RA6100    0x00000400
#define PC_RA6300    0x00000800
#define PC_5393      0x00001000
#define PC_RA8000    0x00002000
#define PC_5399      0x00004000

#define ADDR_END        0x00
#define ADDR_EXCL       0x01
#define ADDR_INCL       0x02
#define ADDR_RANGE_EXCL 0x03
#define ADDR_RANGE_INCL 0x04

/* dialback return error codes */
#define DIAL_SUCC       0       /* success: no errors */
#define DIAL_ADDR       1       /* unsupported address family */
#define DIAL_TIME       2       /* timeout */
#define DIAL_SOCK       3       /* socket error */
#define DIAL_REJ        9       /* erpc message rejected: details unknown */
#define DIAL_PROG       10      /* erpc mes reject: invalid program number */
#define DIAL_VER        11      /* erpc mes reject: invalid version number */
#define DIAL_PROC       12      /* erpc mes reject: invalid procedure number */
#define DIAL_EIO        4       /* I/O error (as in errno.h on the annex) */
#define DIAL_EBUSY      10      /* ports busy (as in errno.h on the annex) */
#define DIAL_EINVAL     12      /* inval.modem (as in errno.h on the annex) */
#define DIAL_ETIMEDOUT  35      /* timeout (as in errno.h on the annex) */

/* string list stuff */

/* WARNING: It is assumed that 'struct fltline' in dfe/dfe_filters.c */
/*          is equivalent to 'STR_LIST' */

typedef struct str_list {
    struct str_list *next;
    u_short strlen; /* ALWAYS includes NULL termination */
    char str[2]; /* 2 for alignment, code relies on packed structure */
                 /* ALWAYS NULL terminated */
} STR_LIST;

/* Codes used in auth_hook bit-mask */
#define CHOOK_PROMPTING  0x00000001    /* About to prompt user */
#define CHOOK_USERLINE   0x00000002    /* Got user input */
#define CHOOK_BADCMND    0x00000004    /* Got unknown cmnd from user */
#define CHOOK_GOODCMND   0x00000008    /* Got good cmnd from user/erpcd */

/* Codes used in hcb_code field */
#define HCB_PENDING       0
#define HCB_RETURN        1
#define HCB_TERMINATE     2 /* terminate hook connection but not cli */
#define HCB_BEFORE_PROMPT 3
#define HCB_USER_LINE     4
#define HCB_BAD_COMMAND   5
#define HCB_GOOD_COMMAND  6
#define HCB_LAST_CMND     7 /* terminate hook connection and cli */

#ifdef ANNEX
#define RACP_FREE(ptr,size) (free(ptr, size))
#define RACP_VERSION(acp) (((ACP_STATE*)acp)->cs->version)
#define RACP_SOCKET(acp) (((ACP_STATE*)acp)->cs->socket)
#define RACP_CAP(acp) (((ACP_STATE*)acp)->cs->capability)
#define RACP_OPTIONS(acp) (((ACP_STATE*)acp)->cs->options)
#define RACP_USAGE(acp) (((ACP_STATE*)acp)->cs->usage)
#define RACP_PEER_ADDR(acp) (((ACP_STATE*)acp)->hostaddr.s_addr)
#define RACP_SHARED_KEY(acp) (((ACP_STATE*)acp)->cs->shared_key)
#define RACP_SEND_KEY(acp) (((ACP_STATE*)acp)->cs->tx_key)
#define RACP_RECV_KEY(acp) (((ACP_STATE*)acp)->cs->rx_key)
#define RACP_SHARED_KEY_SET(acp) (RACP_SHARED_KEY(acp)->password[0])
#define RACP_MAKE_KEY(rand, key) (key = make_table(rand))
#define RACP_NULL_KEY(key) (key = NULL)
#else
#define RACP_FREE(ptr,size) (free(ptr))
#define RACP_VERSION(acp) (((ACP*)acp)->racp->version)
#define RACP_SOCKET(acp) (((ACP*)acp)->s)
#define RACP_CAP(acp) (((ACP*)acp)->racp->capability)
#define RACP_USAGE(acp) (((ACP*)acp)->racp->usage)
#define RACP_OPTIONS(acp) (((ACP*)acp)->racp->options)
#define RACP_PEER_ADDR(acp) (((ACP*)acp)->inet)
#define RACP_SHARED_KEY(acp) (((ACP*)acp)->key)
#define RACP_SEND_KEY(acp) (((ACP*)acp)->racp->send_key)
#define RACP_RECV_KEY(acp) (((ACP*)acp)->racp->rcv_key)
#define RACP_SHARED_KEY_SET(acp) (RACP_SHARED_KEY(acp))
#define RACP_MAKE_KEY(rand, key) (key = make_table(rand, key))
#define RACP_NULL_KEY(key) (bzero(key, sizeof(key)))
#endif

/* Universal regime codes */
/* must match security_keywords in erpcd/env_parser.c */
#define CODE_ACP         0x00
#define CODE_SAFEWORD    0x01
#define CODE_KERBEROS    0x02
#define CODE_NATIVE      0x03
#define CODE_SECURID     0x04
#define CODE_DENY        0x05
#define CODE_NONE        0x06
#define CODE_UNKNOWN     0x22

/* Reject reason codes */
#define REJ_REGDENY      0x01
#define REJ_REGNOTAVAIL  0x02
#define REJ_ERPCDDENY    0x03
#define REJ_DENYUSER     0x04
#define REJ_TIMEOUT      0x05
#define REJ_NOUSERINFO   0x06 /* user has no acp_userinfo entry (chap/arap) */
#define REJ_NOPWDINFO    0x07 /* user has no acp_userinfo password(chap/arap */
#define REJ_UNKNOWN      0x22

#ifdef ANNEX
#define REJ_CODE 0xDEAF0000ul
#define REJ_MASK 0xFFFF0000ul
#else
#define REJ_CODE 0xDEAF0000
#define REJ_MASK 0xFFFF0000
#endif
#define REJECT_CODE(regime,reason) (REJ_CODE | (regime << 8) | reason)
#define REGIME_TYPE(rcode) ((rcode & 0x0000ff00) >>8)
#define REASON_TYPE(rcode) (rcode & 0x000000ff)
#define ISREJECT(rcode) ((rcode & REJ_MASK) == REJ_CODE)

/*
 *      Capability definitions - actually just a handle
 */
 
typedef u_long ACP_CAP;         /*  Access Control Protocol CAPability  */
 
/*
 *      Standard string sizes for ACP protocol
 */
 
typedef char            ACP_STRING[ACP_MAXSTRING];
typedef char            ACP_USTRING[ACP_MAXUSTRING];
typedef char            ACP_LSTRING[ACP_MAXLSTRING];
typedef char            RADIUS_STRING[RADIUS_MAXSTRING];


typedef struct netaddr {
  int type; /* type of address, LAT, IP or IPX */
  union {
    struct {
      char *service; /* service name */
      char *node; /* node name */
      char *port; /* port name */
    } lat_addr;
    struct {
      int inet; /* internet address */
      int port; /* transport port number */
    } ip_addr;
    struct {
      u_char flag;
      u_long network; /* network number */
      char node[6]; /* node address */
      u_short socket; /* socket number */
    } ipx_addr;
  } n;
} NetAddr;

/* Address types for NetAddr */
#define IP_ADDRT  1
#define LAT_ADDRT 2
#define IPX_ADDRT 3

/* MP LCP Endpoint discriminator data structure */
typedef struct endpdesc {
        int     class;
        int     length;
	u_short valid;
        u_char  address[20];
} EndpDesc;

/* Values for bearer_type */
#define RACP_BT_NONE	0
#define RACP_BT_VOICE	1
#define RACP_BT_DATA	2

/* Values for detected_l1 (set to 'none' if no detect was run) */
#define RACP_L1_NONE	0
#define RACP_L1_V120_56	1
#define RACP_L1_V120_64	2
#define RACP_L1_PPP_56	3
#define RACP_L1_PPP_64	4
#define RACP_L1_MODEM	5
#define RACP_L1_UNKNOWN	6

/* Values for detected_l2 (set to 'none' if no detect was run) */
#define RACP_L2_NONE	0
#define RACP_L2_ARAP	1
#define RACP_L2_PPP	2
#define RACP_L2_CLI	3
#define RACP_L2_IPX	4
 
/* Authorize Request Optional Information */

typedef struct arq_profile {
  char         *user_name;            /* name of the user */
  char         *pass_word;            /* password of the user */
  char         *phonenumber;          /* user callback number */
  NetAddr      *from_Address;         /* suggested local network address */
  NetAddr      *dest_Address;         /* suggested remote network address */
  EndpDesc      endpoint;             /* Endpoint Descriminator */
  CHAP_REQ     *chap_req;             /* CHAP information */
  char	       *called_number;	      /* called-number (DNIS) by the user */
  int		ras_addr;             /* IP address of RAS */
  void	       *tms_info;             /* pointer to tms_grant structure */
  SECPORT	port;                 /* port to be secured */
  u_short	req_type;             /* requested service type */
  u_char	bearer_type;	      /* Call bearer type (voice/data) */
  u_char	req_direction;        /* direction of requested auth */
  char	       *calling_number;	      /* Calling number (ANI) of user */
  char	       *called_subaddress;    /* Called subaddress (ISDN) by user */
  char	       *spb_name;	      /* Session parameter block name */
  u_short	detected_l1;	      /* Protocol sniffed (V.120/sPPP/modem) */
  u_short	detected_l2;	      /* Protocol detected (aPPP,ARAP) */
  u_short	wan_index;	      /* WAN module number (1's based) */
  u_short	ds0_index;	      /* DS0 on WAN (1's based) */
  char         *callback_id;          /* RADIUS Attribute Type 20 */
  char         *tg_domain;            /* Domain Name returned by RADIUS */
} ARQ_PROFILE;


/* Information Request Optional Information */

typedef struct irq_profile {
   char        *user_name;            /* name of the user */
   char        *text;                 /* extra information (VisibleString) */
   long        *code;                 /* pointer to code */
   AT_PROFILE_RETURN *at_profile;     /* appletalk profile to return */
   NetAddr     *local_Address;        /* suggested local network address */	
   NetAddr     *remote_Address;       /* suggested remote network address */
   STR_LIST    *filters;              /* filters for user */
   STR_LIST    *routes;               /* routes for user */
   EndpDesc    endpoint;              /* MultiPoint EndPoint Discriminator */
   int         *mp_max_links;         /* MultiPoint Max Links */
   int         *max_logon;            /* max logon time for user */
} IRQ_PROFILE;

/* Execute Request Optional Information */

typedef struct erq_profile {
   char        *username;             /* username */
   char        *phone;                /* user phone number */
   char        *access;               /* user access code */
   char        *text;                 /* other relevant text */
   char        *job;                  /* job to perform */
   char        *portmask;             /* 8-byte mask of async ports allowed for request */
   int         *flags;                /* flag of execution options */
   int         *timeout;              /* timeout in seconds for duration of execution */
   int         *echo;                 /* TRUE/FALSE should user entered text be echo'd */
   NetAddr     *destaddr;             /* destination network address */
   int         *code;                 /* code */
   SECPORT     *port_from;            /* port user is on */
} ERQ_PROFILE;

/* NERPC and RACP function declarations */

#ifndef INT32
#ifdef ANNEX
#define INT32 long
#define UINT32 u_long
#else

#ifdef _WIN32
/* #include "port/port.h"	Must be changed for NT builds. SON 9/3/96 */
#include "../inc/port/port.h"
#else
#include "port/port.h"
#endif	/* WIN32 */

#endif
#endif

#ifndef ANNEX
#define _(x)	()
#endif

extern STR_LIST *racp_create_strlist _((char *buffer, u_short strlen));
extern STR_LIST *racp_destory_strlist _((STR_LIST *strlist));
extern void racp_destory_strlist_chain _((STR_LIST *strlist));
extern errno_t racp_shutdown _((caddr_t acp));
extern errno_t racp_connect _((ACP_STATE *acp, struct in_addr hostaddr));
extern errno_t racp_recv_pdu _((ACP_STATE *acp, char *buf, int bufsize,
                         int *pdulen_p, char **pdu));
extern errno_t racp_recv_raw _((struct socket *socket, char *buf, int datalen));
extern errno_t racp_send_pdu _((ACP_STATE *acp, char *buf, int datalen));
extern errno_t racp_send_raw _((struct socket *socket, char *buf, int datalen));
extern errno_t racp_init_conn _((caddr_t acp));
extern errno_t racp_accept_conn _((caddr_t acp, u_char lover));
extern errno_t racp_send_exec_reply _((caddr_t acp, u_char *data, int datalength,
                                int grant, SECPORT *port, int *flags,
                                char *text));
extern errno_t racp_send_info_req _((caddr_t acp, u_char *data, int datalength,
                              u_short sf, u_short sr, SECPORT *pf, SECPORT *pt,
                              IRQ_PROFILE *opt_info));
extern errno_t racp_send_exec_req _((caddr_t acp, u_char *data, int datalength,
                              int service_from, int service_req, char *rtext,
                              ERQ_PROFILE *opt_info));
#ifdef ANNEX
extern errno_t racp_send_auth_req _((caddr_t acp, u_char *data, int datalength,
                              int service_from, int service_req,
                              SECPORT *port_from, SECPORT *port_dest,
                              ARQ_PROFILE *opt_info));
#else
extern errno_t racp_send_auth_resp _((caddr_t acp, u_char *data, int datalength,
                               u_long grant, u_long *cli_mask,
                               u_long *hooks_mask, char *user_name,
			       tms_db_entry *tms_info));
#endif
extern errno_t racp_send_info_resp _((caddr_t acp, u_char *data, int datalength,
                               u_long grant, AT_PROFILE_RETURN *atprofile,
                               char *text, int *codep, NetAddr *locaddr,
                               NetAddr *remaddr));
extern errno_t racp_send_ack _((caddr_t acp, u_char *data, int datalength,
				u_long sequence));
#ifdef ANNEX
extern u_char *racp_build_auth_req _((u_char *data, int *datalength,
				u_long version, long service_from,
				long service_request, SECPORT *port_from,
				SECPORT *port_destination,
				ARQ_PROFILE *opt_info));
extern u_char *racp_parse_auth_reply _((u_char *data, int datalength,
				int *grant, char *user_name, long *cli_mask,
				long *hooks_mask, tms_grant *tms_info));
#else
extern u_char *racp_parse_auth_req _((u_char *pdu, int *pdulen,
				long *service_from, long *service_request,
				SECPORT *port_from, SECPORT *port_destination,
				char *user_name, ARQ_PROFILE *opt_info));
extern u_char *racp_build_auth_resp _((u_char *data, int *datalength,
				u_long version, u_long grant, u_long *cli_mask,
				u_long *hooks_mask, char *user_name,
				tms_db_entry *tms_info));
#endif
#ifdef ANNEX
extern errno_t racp_send_tms_req _((caddr_t acp, u_char *data, int datalen,
				UINT32 rasid, char *domain, char *dnis));
extern u_char *racp_build_tms_req _((u_char *data, int *datalen, INT32 acp_version,
				UINT32 rasid, char *domain, char *dnis));
#else
extern u_char *racp_parse_tms_req _((u_char *pdu, int *pdulen, UINT32 *rasid,
				tms_db_key *key));
#endif /*ANNEX*/
extern u_char *racp_build_info_req _((u_char *data, int *datalength, u_long version,
                               long service_from, long service_request,
                               SECPORT *port_from, SECPORT *port_to,
                               IRQ_PROFILE *opt_info));
extern u_char *racp_parse_info_req _((u_char *data, int datalength, int *servfromp,
                               int *servreqp, SECPORT *port_from,
                               SECPORT *port_to, IRQ_PROFILE *opt_info));
extern u_char *racp_build_info_resp _((u_char *data, int *datalength, u_long version,
                                long grant, long *codep, char *text,
                                NetAddr *local_Address,
                                NetAddr *remote_Address,
                                AT_PROFILE_RETURN *at_profile));
extern u_char *racp_parse_info_resp _((u_char *data, int datalength, int *grantp,
                                AT_PROFILE_RETURN *at_profile, char *text,
                                int *codep, NetAddr *local_Address,
                                NetAddr *remote_Address));
extern u_char *racp_build_exec_req _((u_char *data, int *datalength, u_long version,
                               int service_from, service_req, ERQ_PROFILE *opt_info));
extern u_char *racp_parse_exec_req _((u_char *data, int *datalength, int *servfrom,
                               int *servreq, ERQ_PROFILE *opt_info));
extern u_char *racp_build_exec_reply _((u_char *data, int *datalength,
                                 u_long version, long grant, SECPORT *port,
                                 long *flags, char *text));
extern u_char *racp_parse_exec_reply _((u_char *data, int *datalength, int *grantp,
                                 SECPORT *portp, int *flagsp, char *text,
                                 int *codep));
extern u_char *racp_build_audit_log _((u_char *data, int *datalength, u_long version,
                                long service_from, long service_request,
                                SECPORT *port_from, long event,
                                NetAddr *remote_Address, char *user_name,
                                LOG_PORT_STATS *port_Stats, char *text));
extern errno_t racp_add_logid _((u_char *pdu, int *pdulen, int size,
                          u_long log_sequence));
extern u_char *racp_parse_audit_log _((u_char *data, int datalength,
                                int *service_from, int *service_request,
                                SECPORT *port, int *event,
                                NetAddr **remote_Address, char **user_name,
                                LOG_PORT_STATS **port_Stats, char **text,
                                unsigned long *logid));
extern u_char *racp_build_ack _((u_char *data, int *datalength, u_long version,
                          u_long sequence));
extern char *racp_parse_ack _((char *pdu, int pdulen, UINT32 *ack));

#ifdef ANNEX
/* These are in dfe/security.c */
extern int devtype_to_dev[];	/* Convert regular devtype to RACP dev */
extern enum device_types dev_to_devtype[];	/* Convert back */
#endif

#endif /* NERPCD_H */
