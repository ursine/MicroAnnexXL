/*
 *
 *	RADIUS
 *	Remote Authentication Dial In User Service
 *
 *
 *	Livingston Enterprises, Inc.
 *	6920 Koll Center Parkway
 *	Pleasanton, CA   94566
 *
 *	Copyright 1992 Livingston Enterprises, Inc.
 *
 *	Permission to use, copy, modify, and distribute this software for any
 *	purpose and without fee is hereby granted, provided that this
 *	copyright and permission notice appear on all copies and supporting
 *	documentation, the name of Livingston Enterprises, Inc. not be used
 *	in advertising or publicity pertaining to distribution of the
 *	program without specific prior permission, and notice be given
 *	in supporting documentation that copying and distribution is by
 *	permission of Livingston Enterprises, Inc.
 *
 *	Livingston Enterprises, Inc. makes no representations about
 *	the suitability of this software for any purpose.  It is
 *	provided "as is" without express or implied warranty.
 *
 */

/*
 *  radius.h	RADIUS Protocol definitions
 *				Based on Livingston RADIUS.H file
 *				@(#)radius.h	1.9 11/14/94
 *
 *				Modified for use within Xylogics, Bay Networks
 *				Dave Mitton		4/10/96
 *
 *	4/10/96		Remove Livingston data structures, add draft 2 fields and values
 */

#ifndef _WIN32
#include <netinet/in.h>
#endif
#include "acp.h"
#include "acp_regime.h"
#include "../inc/erpc/acp_const.h"

/* allow prototype checking, but only when requested */
#ifdef _
#undef _
#endif
#ifndef _
#if (__STDC__ && PROTOTYPES)
#define _(x)  x
#else
#define _(x)  ()
#endif /* STDC */
#endif /* _ */

#define PW_AUTH_UDP_PORT		1645		/* use getservbyname() */
#define PW_ACCT_UDP_PORT		1646		/* use getservbyname() */

#define AUTH_HDR_LEN			20
#define AUTH_INTEGER_LEN		4
#define AUTH_STRING_LEN			253

#define AUTH_PASS_LEN			128
#define CHAP_VALUE_LENGTH		16

/* VALUE TYPES */
#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3

/* MESSAGE CODES	*/
#define	PW_AUTHENTICATION_REQUEST	1
#define	PW_AUTHENTICATION_ACK		2
#define	PW_AUTHENTICATION_REJECT	3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6		/* not IETF */
#define PW_PASSWORD_REQUEST			7		/* not IETF */
#define PW_PASSWORD_ACK				8		/* not IETF */
#define PW_PASSWORD_REJECT			9		/* not IETF */
#define	PW_ACCOUNTING_MESSAGE		10		/* not IETF */
#define PW_ACCESS_CHALLENGE			11
#define PW_STATUS_SERVER			12		/* experimental */
#define PW_STATUS_CLIENT			13		/* experimental */

						   /* value 255 reserved - do not use */

/*  ATTRIBUTE TYPES	*/
#define	PW_USER_NAME			1
#define	PW_PASSWORD			2
#define	PW_CHAP_PASSWORD		3
#define	PW_CLIENT_ID			4
#define PW_NAS_IP_ADDRESS		4			/* dup */
#define	PW_CLIENT_PORT_ID		5
#define	PW_NAS_PORT			5			/* dup */
#define	PW_USER_SERVICE_TYPE		6
#define	PW_FRAMED_PROTOCOL		7
#define	PW_FRAMED_ADDRESS		8
#define	PW_FRAMED_NETMASK		9
#define	PW_FRAMED_ROUTING		10
#define	PW_FRAMED_FILTER_ID		11
#define	PW_FRAMED_MTU			12
#define	PW_FRAMED_COMPRESSION		13
#define	PW_LOGIN_HOST			14
#define	PW_LOGIN_SERVICE		15
#define	PW_LOGIN_TCP_PORT		16
#define PW_OLD_PASSWORD			17			/* not IETF */
#define PW_PORT_MESSAGE			18
#define PW_DIALBACK_NO			19
#define PW_DIALBACK_NAME		20
#define PW_EXPIRATION			21			/* not IETF */
#define PW_FRAMED_ROUTE			22
#define PW_FRAMED_IPXNET		23
#define PW_STATE			24
#define PW_CLASS                25
#define PW_VENDOR_SPECIFIC      26
#define PW_SESSION_TIMEOUT      27
#define PW_IDLE_TIMEOUT         28
#define PW_TERMINATION_ACTION   29
#define PW_CALLED_STATION_ID    30
#define PW_CALLING_STATION_ID   31
#define PW_NAS_IDENTIFIER       32
#define PW_PROXY_STATE          33
#define PW_LOGIN_LAT_SERVICE    34
#define PW_LOGIN_LAT_NODE       35
#define PW_LOGIN_LAT_GROUP      36
#define PW_FRAMED_AT_LINK       37
#define PW_FRAMED_AT_NETWORK    38
#define PW_FRAMED_AT_ZONE       39

#define PW_ACCT_STATUS_TYPE		40
#define PW_ACCT_DELAY_TIME		41
#define PW_ACCT_INPUT_OCTETS		42
#define PW_ACCT_OUTPUT_OCTETS		43
#define PW_ACCT_SESSION_ID		44
#define PW_ACCT_AUTHENTIC		45
#define PW_ACCT_SESSION_TIME		46
#define PW_ACCT_INPUT_PACKETS   	47
#define PW_ACCT_OUTPUT_PACKETS  	48
#define PW_ACCT_TERMINATE_CAUSE 	49
#define PW_ACCT_MULTI_SESSION_ID	50
#define PW_ACCT_LINKCOUNT		51

#define PW_CHAP_CHALLENGE       60
#define PW_NAS_PORT_TYPE        61
#define PW_PORT_LIMIT           62
#define PW_LOGIN_LAT_PORT	63

/* Reserved ranges:
 *	192-223 : Experimental use
 *	224-240 : Implementation specific
 *  241-255 : Reserved - Do not use
 */

/*
 *	INTEGER TRANSLATIONS
 */

/*	USER TYPES	*/

enum radius_service_type {
    PW_LOGIN_USER = 1, PW_FRAMED_USER /*2*/, PW_DIALBACK_LOGIN_USER /*3*/,
    PW_DIALBACK_FRAMED_USER /*4*/, PW_OUTBOUND_USER /*5*/,
    PW_ADMINISTRATIVE_USER /*6*/, PW_NAS_PROMPT_USER /*7*/,
    PW_AUTHENTICATE_USER /*8*/, PW_CALLBACK_PROMPT_USER /*9*/
};


/*	FRAMED PROTOCOLS	*/

enum radius_framed_protocol {
    PW_PPP = 1, PW_SLIP /*2*/, PW_ARAP /*3*/, PW_GANDALF_SLMLP /*4*/,
    PW_IPXSLIP /*5*/
};

/*	FRAMED ROUTING VALUES	*/

#define	PW_NONE				0
#define	PW_BROADCAST		1
#define	PW_LISTEN			2
#define	PW_BROADCAST_LISTEN	3

/*	FRAMED COMPRESSION TYPES	*/

#define	PW_VAN_JACOBSEN_TCP_IP		1
#define PW_IPX_HEADER_COMP		2

/*	LOGIN SERVICES	*/

#define NLOGIN 5
enum radius_login_service {
    PW_TELNET = 0, PW_RLOGIN /*1*/, PW_TCP_CLEAR /*2*/, PW_PORTMASTER /*3*/,
    PW_LAT /*4*/
};

/*	ACCOUNTING STATUS TYPES	*/

#define PW_STATUS_START			1
#define PW_STATUS_STOP			2
#define PW_STATUS_ALIVE			3		/* not IETF */
#define PW_MODEM_START			4		/* not IETF */
#define PW_MODEM_STOP			5		/* not IETF */
#define PW_CANCEL			6		/* not IETF */
#define PW_ACCT_ON				7
#define PW_ACCT_OFF				8
#define PW_IPCP_START			103809027


/*	ACCOUNTING AUTHENTICATION LEVEL	*/

#define PW_AUTH_NONE			0
#define PW_AUTH_RADIUS			1
#define PW_AUTH_LOCAL			2

/* ACCOUNTING TERMINATION CAUSE */

#define PW_CAUSE_USER_REQUEST	1
#define PW_CAUSE_LOST_CARRIER	2
#define PW_CAUSE_LOST_SERVICE	3
#define PW_CAUSE_IDLE_TIMEOUT	4
#define PW_CAUSE_SESS_TIMEOUT	5
#define PW_CAUSE_ADMIN_RESET	6
#define PW_CAUSE_ADMIN_REBOOT	7
#define PW_CAUSE_PORT_ERROR		8
#define PW_CAUSE_NAS_ERROR		9
#define PW_CAUSE_NAS_REQUEST	10
#define PW_CAUSE_NAS_REBOOT		11
#define PW_CAUSE_PORT_UNNEEDED	12
#define PW_CAUSE_PORT_PREEMPTED	13
#define PW_CAUSE_PORT_SUSPENDED	14
#define PW_CAUSE_SERVICE_UNAVAIL	15
#define PW_CAUSE_CALLBACK		16


/*  NAS PORT TYPES		*/

#define PW_PORT_ASYNC		0
#define PW_PORT_SYNC		1
#define PW_PORT_ISDN_SYNC	2
#define	PW_PORT_ISDN_V120	3
#define	PW_PORT_ISDN_V110	4
#define PW_PORT_VIRTUAL		5


#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		100
#define DISCARD_COUNT		6  /*number of extraneous messages to discard
				     before rexmitting */

struct radius_attribute
{
    u_char *next;    /* next attribute in packet (not a linked list!) */
    UINT32 type;     /* If VS, high 3 bytes are Vendor ID */
    UINT32 length;   /* length of value portion ONLY */
    u_char *strvalp; /* if string, pointer to value */
    UINT32 lvalue;   /* type specifies network or host order */
};

struct attrib_handle
{
    struct sesdbrec *sesrec;
    u_char *aptr; /* moving pointer inside the attributes */
    u_short alen; /* length remaining in the attribute portion */
};

struct access_request
{
    u_char *secret;
    char *user;
    char *pwd; /* clear */
    u_char *chappwd;
    u_char *chapchal;
    struct in_addr raaddr; /* network order */
    SECPORT *port;
    ACP_STRING called_number;
    ACP_STRING calling_number;
    struct radius_attribute *state; /* Access-Challenge state */
    UINT32 service;
};

/* md5.c prototypes */
void MDString _ ((char *string, unsigned int len, unsigned char result[16]));

/* radius_parser.c prototypes */
u_char *radius_build_header _((u_char **bufp, UINT32 code, UINT32 id,
                               u_char *authenticator));
void radius_uncrunch_password _((u_char *pwd, u_char *authenticator,
                                 u_char *hidpwd, u_char *secret));
void radius_crunch_password _((u_char *newkey, u_char *authenticator,
                               u_char *pwd, UINT32 pwdlen, u_char *secret));
void radius_add_attribute _((u_char **bufp, UINT32 type, UINT32 length,
                             u_char *strvalp, UINT32 lvalue));
void radius_fix_length _((u_char *start, u_char *end));
int radius_convert_type _((int acptype));
int radius_parse_server_response _((u_char *dgram, int dlen, int id,
                                    u_char *reqauth, struct in_addr remaddr));
int radius_get_attribute _((u_char **bufp, u_short *buflenp,
                            struct radius_attribute*));
u_char *radius_get_secret _((UINT32 host));
void display_mem _((char *buf, int len));
void dump_attributes _((u_char *packet));
void radius_print_reply_message _((ACP*));
STR_LIST *xlate_route_attrib _((struct radius_attribute *));
void radius_build_attribute _((u_char **bufp, struct radius_attribute *));
STR_LIST *netmask_to_route _((UINT32 netmask, UINT32, dest));

/* acp_radius.c prototypes */
int acp_radius_validate _((ACP*, int prompt, char *user, char *pass,
                           SECPORT*));

/* radius_config.c prototypes */
void dump_serverinfo _((Radius_serverinfo *));

#define NCODETYPES 13 /* size of codetype array in radius_parser.c */
extern char *codetype[]; /* defined in radius_parser.c */
extern char xa2_service_type[NSERVICES]; /* defined in radius_acct.c */
#ifdef _WIN32
#define MAXHOSTNAMELEN  64
extern char	config_file[];
#endif
