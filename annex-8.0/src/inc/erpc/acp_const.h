/*
 *****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	Access Control Protocol (ACP) remote procedure constants
 *
 * Original Author: James Carlson		Created on: 31MAR95
 *
 ****************************************************************************
 */


#ifndef ACP_CONST_H
#define ACP_CONST_H

/*
 *	Miscellaneous defines
 */

#define REQUEST_DELAY		2	/* network turnaround max. in seconds */
#define REQUEST_TIMEOUT		6	/* timeout when expecting a return */
#define RESPONSE_TIMEOUT	30	/* timeout when listening for calls */
#define ACP_MAX_HOSTNAME_LEN 32 /* Maximum length for a host name */
/*
 *	Standard string sizes for ACP protocol
 */

#define ACP_MAXSTRING	32
#define ACP_MAXUSTRING	129
#define ACP_MAXLSTRING	256
#define RADIUS_MAXSTRING 253
#define LEN_ACCESS_CODE 16
#define LEN_USERNAME    ACP_MAXUSTRING
#define LEN_PHONE       32
#define LEN_PORT_MASK   8
#define LEN_JOB         80

#ifndef ANNEX
#define REQ_GRANTED     ((u_long)0xface1111)
#define REQ_DENIED      ((u_long)0xdeaf2222)
#define REQ_GRANT_DHCP  ((u_long)0xdcdc7777)	/* Username OK, use DHCP to get address. */
#define REQ_PENDING     ((u_long)0xbabe3333)
#define REQ_INVALID     ((u_long)0xdead4444)
#define REQ_DIALB_GRANT ((u_long)0xbeef5555)
#define REQ_GRANT_HOOK  ((u_long)0xfeed6666)
#define ACP_ACK		((u_long)0xe1e1e1e1)	/* acknowledge value */
#else
#define REQ_GRANTED     0xface1111ul
#define REQ_DENIED      0xdeaf2222ul
#define REQ_GRANT_DHCP  0xdcdc7777ul		/* Username OK, use DHCP to get address. */
#define REQ_PENDING     0xbabe3333ul
#define REQ_INVALID     0xdead4444ul
#define REQ_DIALB_GRANT 0xbeef5555ul
#define REQ_GRANT_HOOK  0xfeed6666ul
#define REQ_REM_IP_CLNT 0xcafe3456ul
#define ACP_ACK		0xe1e1e1e1ul		/* acknowledge value */
#endif

#define ACP_PROG	((u_long)COURRPN_SECURITY)	/* ACP program number */
#define ACP_VERSION	((u_short)SECURITY_VERSION)	/* ACP prog. version */
#define ACP_VERLO	((u_short)0)			/* lowest acceptable */
#define ACP_VERHI	((u_short)99)			/* highest acceptable */

#define HCB_TEXT_MAX	255

/* 
 *	Request AppleTalk Profile
 */

#define ATPASSWD	8
#define ATZONELIST	524
/* Each NVE filter is at worst 99 bytes */
#define ATFILTERCOUNT	10
#ifndef ATFILTERLEN
#define ATFILTERLEN     (ATFILTERCOUNT * 99) 
#endif


/*
 *    Define services which may be secured
 *	  any additions to this list requires that the switch in ntsupport.c
 *    be updated for the NT server tools.
 */

#define SERVICE_SECURITY                0
#define SERVICE_CLI                     1
#define SERVICE_CALL                    2
#define SERVICE_RLOGIN                  3
#define SERVICE_TELNET                  4
#define SERVICE_PORTS                   5
#define SERVICE_DIALUP                  6
#define SERVICE_SLIP                    7
#define SERVICE_PPP                     8
#define SERVICE_CONNECT                 9
#define SERVICE_SLIP_DYNDIAL            10
#define SERVICE_PPP_DYNDIAL             11
#define SERVICE_DIALBACK                12
#define SERVICE_ARAP                    13
#define SERVICE_FTP                     14
#define SERVICE_CLI_HOOK                15
#define SERVICE_IPX                     16
#define SERVICE_IPX_DIALBACK            17
#define SERVICE_RCF                     18
#define SERVICE_PPP_TMOUT               19
#define SERVICE_PPP_DYNDIAL_TMOUT       20
#define SERVICE_SLIP_TMOUT              21
#define SERVICE_SLIP_DYNDIAL_TMOUT      22
#define SERVICE_VMS                     23
#define SERVICE_SYNC_PPP                24
#define SERVICE_SYNC_DIALUP             25
#define SERVICE_DYNDIALPASS             26
#define SERVICE_SECRET                  27
#define SERVICE_CH_GOOD                 28
#define SERVICE_CH_BAD                  29
#define SERVICE_CH_OPT_REF              30
#define SERVICE_DIALUP_IPX              31
#define SERVICE_OUTPUTSTRING            32
#define SERVICE_PROMPTSTRING            33
#define SERVICE_AT_PROFILE              34
#define SERVICE_NONE                    35
#define SERVICE_AUDITLOG                36
#define SERVICE_SHELL                   37
#define SERVICE_FILTERS                 38
#define SERVICE_PRIMGR                  39
#define SERVICE_CHAP                    40
#define SERVICE_MP                      41
#define SERVICE_MODEM                   42
#define SERVICE_MAX_LOGON               43
#define SERVICE_DVS                     44
#define SERVICE_VPN_PPP                 45
#define SERVICE_RADIUS_PU               46
#define NSERVICES                       47

/*
 *    Define events that may be logged
 *	  any additions to this list requires that the switch in ntsupport.c
 *    be updated for the NT server tools.
 */

#define EVENT_BOOT		0
#define EVENT_LOGIN		1
#define EVENT_REJECT		2
#define EVENT_LOGOUT		3
#define EVENT_TIMEOUT		4
#define EVENT_PROVIDE		5
#define EVENT_NOPROVIDE		6
#define EVENT_DIAL		7
#define EVENT_BADRESP		8
#define EVENT_OPT_REF		9
#define EVENT_ACCT		10
#define EVENT_PARSE		11
#define EVENT_BLACKLIST		12
#define EVENT_ACCEPT_CALL	13
#define EVENT_REJECT_CALL	14
#define EVENT_DISC_CALL		15
#define EVENT_NEGO_ADDR	        16
#define EVENT_CONNECT_CALL	17
#define EVENT_MP_ATTACH     18
#define EVENT_MP_DETACH     19
#define EVENT_LINE_SEIZURE	20
#define NEVENTS			21

#endif /* ACP_CONST_H */





