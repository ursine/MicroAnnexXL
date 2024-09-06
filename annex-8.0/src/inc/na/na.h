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
 *	%$(description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 ****************************************************************************
 */


#ifndef NA_H
#define NA_H

#ifndef UINT32
#include "../port/port.h"
#endif
#ifndef NACONST_H
#include "naconst.h"
#endif

/* selectable modules */

#ifdef NA

#define NDPTG	1
#define NHMUX	0	/* Never! */
#define NPPP	1
#define NSLIP	1
#define NLAT	1
#define NDEC	1
#define NTSTTY	1
#define NPRONET_FOUR	0	/* Never! */
#define NTFTP_PROTO	1
#define NRDRP		0	/* Never! */
#define NCMUSNMP	1
#define NARAP		1
#define NATALKII	1
#define NCLITN3270	1
#define NT1_ENG		1
#define NSLYNC		1
#define NPRI		1
#define NPRINTER	1
#define NMLPPP		1
#define NDIGIMODEM	1
#define NDHCPCLIENT	1
#define NTMUX		1
#define NIPXOPT		1
#define NNAME_SERVERS	1
#define NEDIT		1
#define NIGMP           1
#define NOSPF           1
#define NIPPOOL           1

#else

#include "ppp.h"
#include "slip.h"
#include "tstty.h"
#include "lat.h"
#include "dec.h"
#include "tftp_proto.h"
#include "cmusnmp.h"
#include "arap.h"
#include "atalkII.h"
#include "clitn3270.h"
#include "t1_eng.h"
#include "slync.h"
#include "pri.h"
#include "printer.h"
#include "mlppp.h"
#include "digimodem.h"
#include "dhcpclient.h"
#include "tmux.h"
#include "ipxopt.h"
#include "name_servers.h"
#include "edit.h"

#endif

/* misc defines */

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define WHITE_SPACE " \t\n"
#define PUNCTUATION ",;@=#-"
#define SEPARATORS  "\\ \t\n,;@=-"
#define TERMINATORS " \t\n,;"

#define SETBIT(a,i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define CLRBIT(a,i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))

#define SETPORTBIT(a,i)	((a)[(i-1)/NBBY] |= 1<<((i-1)%NBBY))
#define PORTBITSET(a,i)	((a)[(i-1)/NBBY] & (1<<((i-1)%NBBY)))
#define CLRPORTBIT(a,i)	((a)[(i-1)/NBBY] &= ~(1<<((i-1)%NBBY)))
#define PORTBITCLR(a,i)	(((a)[(i-1)/NBBY] & (1<<((i-1)%NBBY))) == 0)

#define SETPRINTERBIT(a,i)	((a)[(i-1)/NBBY] |= 1<<((i-1)%NBBY))
#define PRINTERBITSET(a,i)	((a)[(i-1)/NBBY] & (1<<((i-1)%NBBY)))
#define CLRPRINTERBIT(a,i)	((a)[(i-1)/NBBY] &= ~(1<<((i-1)%NBBY)))
#define PRINTERBITCLR(a,i)	(((a)[(i-1)/NBBY] & (1<<((i-1)%NBBY))) == 0)

#define SETINTERFACEBIT(a,i)	((a)[(i-1)/NBBY] |= 1<<((i-1)%NBBY))
#define INTERFACEBITSET(a,i)	((a)[(i-1)/NBBY] & (1<<((i-1)%NBBY)))
#define CLRINTERFACEBIT(a,i)	((a)[(i-1)/NBBY] &= ~(1<<((i-1)%NBBY)))
#define INTERFACEBITCLR(a,i)	(((a)[(i-1)/NBBY] & (1<<((i-1)%NBBY))) == 0)

#define SETGROUPBIT(ptr,bit)	((ptr)[(bit)/NBBY] |= 1<<((bit)%NBBY))
#define CLRGROUPBIT(ptr,bit)	((ptr)[(bit)/NBBY] &= ~(1<<((bit)%NBBY)))

#define PG_ALL		0x0001		/* context-sensitive "all" */
#define PG_VIRTUAL	0x0002		/* explicit "virtual" */
#define PG_SERIAL	0x0004		/* explicit "serial */
#define PG_PRINTER	0x0008		/* explicit "printer" */
#define PG_SYNC		0x0010		/* explicit "synchronous" */
#define PG_VPN      0x0020      /* explicit "vpn" */
#define MG_ALL		0x0001		/* context-sensitive "all" */

#define PRINTER_OK	TRUE
#define PRINTER_NOT_OK	FALSE
#define VIRTUAL_OK	TRUE
#define VIRTUAL_NOT_OK	FALSE

#define NULLSP	((char *)0)

/* names for things */

#include "names.h"

/* sizes */

#ifdef NA
#define LINE_LENGTH 1024	/* length of input line */
#endif

/* return codes */

#define LEX_OK     0	/* for lex() */
#define LEX_EOS    1
#define LEX_EOSW   2   /* for lex_switch() */

#define BADTIME  -1  /* returned by delay_time when an error occurs */

/* special categories used by na in parameter tables */

#define GRP_CAT		99
#define ALL_CAT		9999
#define VOID_CAT	-1

/* special categories used by na/admin for displaying group category  */
#define B_GENERIC_CAT		981
#define B_VCLI_CAT		982
#define B_NAMESERVER_CAT 	983
#define B_SECURITY_CAT		984
#define B_TIME_CAT		985
#define B_SYSLOG_CAT		986
#define B_LAT_CAT 		987
#define B_ATALK_CAT		988
#define B_ROUTER_CAT		989

#define P_GENERIC_CAT		990
#define P_FLOW_CAT		991
#define P_SECURITY_CAT		992
#define P_EDITING_CAT		993
#define P_SERIAL_CAT		994
#define P_SLIP_CAT		995
#define P_PPP_CAT		996
#define P_LAT_CAT		997
#define P_TIMERS_CAT		998
#define P_ATALK_CAT		999
#define P_TN3270_CAT		1000

/* New BIG_BIRD display categories */
#define B_KERB_CAT       	1001
#define B_MOP_CAT        	1002
#define B_IPX_CAT        	1003
#define B_TMUX_CAT       	1004
#define P_LOGIN_CAT      	1005
#define S_GENERIC_CAT    	1006
#define S_SECURITY_CAT		1007
#define S_NET_CAT        	1008
#define S_PPP_CAT        	1009

/* T1 display catorgaries */
#define T1_GEN_CAT   		1010
#define T1_DS0_CAT   		1011

#define WAN_GEN_CAT   		1012
#define WAN_CHAN_CAT   		1013
#define MODEM_GEN_CAT		1014
#define P_SYNC_CAT		1015

#define B_DHCP_CAT              1016
#define B_SNMP_CAT		1017
#define P_VPN_CAT       1018 
#define B_IGMP_CAT              1019
#define B_SIG_CAT               1020
#define B_OSPF_CAT               1021
#define B_POOLSYSTEM_CAT    1022
#define B_NTP_CAT		1023

/* conversion techniques */

#define CNV_STRING	0	/* ASCII string; max 16 characters */
#define CNV_INT		1	/* unsigned integer */
#define CNV_DFT_N	2	/* Boolean, default N */
#define CNV_DFT_Y	3	/* Boolean, default Y */
#define CNV_PS		4	/* port speed */
#define CNV_BPC		5	/* bits per character */
#define CNV_SB		6	/* stop bits */
#define CNV_P		7	/* parity */
#define CNV_MC		8	/* modem control */
#define CNV_PT		9	/* port type */
#define CNV_PM		10	/* port mode */
#define CNV_FC		11	/* flow control type */
#define CNV_PRINT	12	/* expanded control character "^X" */
#define CNV_NET		13	/* Internet address, zero illegal */
#define CNV_NET_Z	14	/* Internet address, zzero legal */
#define CNV_NS		15	/* name server type */
#define CNV_HT		16	/* host table size (stored divided by 2) */
#define CNV_MS		17	/* maximum sessions (0 == 16) */
#define CNV_SEQ		18	/* load/dump sequence */
#define	CNV_IPENCAP	19	/* IP encapsulation type */
#define CNV_SCAP	20	/* server capability */
#define CNV_SYSLOG	21	/* syslog priority */
#define CNV_SYSFAC	22	/* syslog facility code */
#define CNV_VCLILIM	23	/* VCLI limit */
#define CNV_DLST	24	/* Daylight savings */
#define	CNV_ZERO_OK	25	/* integar value that could be zero */
#define CNV_RESET_IDLE	26	/* Reset Idle direction */
#define CNV_PROMPT	27	/* encoded CLI prompt */
#define CNV_DPORT	28	/* convert a dedicated port # */
#define CNV_RNGPRI	29	/* token ring priority */
#define CNV_INT0OFF	30	/* unsigned int, or "off"=0 */
#define CNV_INACTCLI	31	/* INACTCLI value, INT0FF+"immediate"=255 */
#define CNV_FS		32	/* packet size */
#define CNV_T1T		33	/* T1 timer */
#define CNV_T2T		34 	/* T2 timer */
#define CNV_N2N		35	/* N2 Number */
#define CNV_TIT		36	/* Trunk Interface Type */
#define CNV_X25A	37	/* trunk address */
#define CNV_TCT		38	/* trunk connector type */
#define CNV_PL		39	/* trunk lowest PVC */
#define CNV_PH		40	/* trunk highest PVC */
#define CNV_SL		41	/* trunk lowest SVC */
#define CNV_SH		42	/* trunk highest SVC */
#define CNV_TS		43	/* trunk speed conversion */
#define CNV_WS		44	/* window size */
#define CNV_RBCAST	45	/* reverse broadcast {net, port} */
#define CNV_PTYPE	46 	/* printer interface type */

/* LAT fields */
#define CNV_HOST_NUMBER		47 	/* LAT host number type */
#define CNV_SERVICE_LIMIT	48 	/* LAT service limit type */
#define CNV_KA_TIMER		49 	/* LAT keep alive timer type */
#define CNV_CIRCUIT_TIMER	50 	/* LAT circuit timer type */
#define CNV_RETRANS_LIMIT	51 	/* LAT retrans limit type */
#define CNV_ADM_STRING		52 	/* LAT string size type */
#define CNV_GROUP_CODE		53 	/* LAT group code type */
#define CNV_QUEUE_MAX		54 	/* LAT HIC max queue depth */

#define CNV_DPTG		55	/* DPTG settings string */
#define CNV_BML			56	/* Async Control Bit Mask (Longword) */ 
#define CNV_SEC			57	/* Port security mode */ 
#define CNV_MRU			58	/* Maximum receive unit size */
#define CNV_LG_SML		59	/* boolean settings str large/small */

#define CNV_ATTN		60	/* strip ^ from string */

#define CNV_SELECTEDMODS	61	/* selectable software modules */

#define CNV_PSPEED		62 	/* printer interface speed */
#define CNV_PORT		63 	/* port range conversion */
#define CNV_TZ_MIN		64 	/* tz_minutes */
#define CNV_NET_TURN		65 	/* net turnaround */
#define CNV_BYTE		66 	/* 1 - 255 is valid */
#define CNV_BYTE_ZERO_OK	67 	/* 0 - 255 is valid */
#define CNV_HIST_BUFF		68 	/* 0 - 32767 is valid */

/* ARAP fields */
#define CNV_PPP_NCP		69 	/* ipcp, atcp or all */
#define CNV_A_BYTE		70 	/* 0 - 253 is valid */
#define CNV_ARAP_AUTH		71 	/* des or none */
#define CNV_DEF_ZONE_LIST	72 	/* 100 chars MAX */
#define CNV_THIS_NET_RANGE	73 	/* 0x0 - 0xfefe is valid */

#define CNV_INT5OFF		74	/*  FWDTIMER value, 5OFF */
#define CNV_RIP_ROUTERS		75 	/* a list of up to eight IP addr */
#define CNV_RIP_SEND_VERSION	76 	/* 1, 2 or compatibility */
#define CNV_RIP_RECV_VERSION	77 	/* 1, 2 or both */
#define CNV_RIP_HORIZON		78 	/* off, split or poison */
#define CNV_RIP_DEFAULT_ROUTE	79 	/* 0 .. 15 or off (off same as 0) */
#define CNV_RIP_OVERRIDE_DEF	80 	/* 0 .. 15 or none or all */
#define CNV_RIP_NEXT_HOP	81 	/* never, needed or always */
#define CNV_BOX_RIP_ROUTERS	82 	/* a list of up to eight IP addr */

#define CNV_ENET_ADDR           83      /* ethernet address in hex */
#define CNV_MULTI_TIMER         84      /* multicast timer */
#define CNV_PASSLIM             85      /* password retry limit */
#define CNV_SESS_MODE           86      /* default session mode for lat */
#define CNV_USER_INTF           87      /* user interface type */
#define CNV_DUIFC               88      /* UNUSED */
#define CNV_ZONE		89	/* Annex AppleTalk Zone */

/* New conversion types for BIG_BIRD ...*/

#define CNV_SESS_LIM   		90   /* 1 to <ports>*16 or 0 */
#define CNV_PASS_LIM          	91   /* 1 to 10          */
#define CNV_KERB_HOST    	92   /* 1 to 4 net addresses */
#define CNV_TIMER        	93   /* 1 to 60 (minutes)     */
#define CNV_IPX_FMTY     	94   /* raw802_3, ethernetII, */
				     /* 802_2 or 802_2snap */
#define CNV_TMAX_HOST    	95   /* 10 t0 255 TMUX hosts */
#define CNV_TDELAY       	96   /* 0 to 255 (mS)    */
#define CNV_TMAX_MPX     	97   /* 5 to 65535       */
#define CNV_CLI_IF       	98   /* uci or vci       */
#define CNV_IPSO_CLASS 		99   /* topsecret, secret, confidential, */
				     /* unclassified, or none */
#define CNV_SMETRIC      	102  /* 1 to 15 hops */
#define CNV_CRC_TYPE     	103  /* crc16 or ccitt */
#define CNV_IPX_STRING		104  /* length == MAX_IPX_STRING */
#define CNV_MOP_PASSWD          105  /* MOP Password */
#define CNV_SESSION_LIMIT       106  /* Annex session limit */
#define CNV_INACTDUI            107   /* DEC Inactivity Timer (1-255) */
#define	CNV_UNITS		109  /* net_inactivity_units */

#define CNV_DFT_OFF             110  /* on/off Boolean */
#define CNV_DFT_ON              111  /* on/off Boolean */

#define CNV_DFT_ALL             112  /* all/none Boolean */
#define CNV_DFT_NONE            113  /* all/none Boolean */

/* New conversion types for channelized T1 */

#define CNV_TNI_CLOCK           114  /* loop, local, external */
#define CNV_TNI_LINE_BUILDOUT   115  /* 0, 7.5, 15, or 22.5 */
#define CNV_T1_FRAMING          116  /* esf, d4 */
#define CNV_T1_LINE_CODE        117  /* b8zs, ami */
#define CNV_T1_ESF_FDL          118  /* ansi, att */
#define CNV_T1_DISTANCE         119  /* integer: 0 - 655 */
#define CNV_T1_MAP              120  /* T1 maps */ 
#define CNV_T1_SIG_PROTOCOL     121
#define CNV_T1_PROTO            122
#define CNV_T1_RING             123  /* Array of 24 no/yes bytes */
#define CNV_STRING_P_120        124  /* String with max length = 128 */
#define CNV_T1_SWITCH_TYPE      125 

#define CNV_RESOLVE		126  /* resolve protocol */

#define CNV_LONG_HEX		127	/* 32-bit hex number */
#define CNV_STRING_NOSPACE      128  /* same as CNV_STRING, except it does 
					not allow strings with spaces */
#define CNV_WAN_REMADDR		129	/* Array of 32 IP addresses */
#define CNV_WAN_IPXNET		130	/* Array of 32 IPX networks */
#define CNV_WAN_IPXNODE		131	/* Array of 32 IPX nodes */
#define CNV_WANDIST		132	/* DS1-to-CSU distance */
#define CNV_V120_MRU		133	/* v120 mru */
#define CNV_WANANALOG		134	/* Encoding mu versus A law */
#define CNV_MP_ENDP_OPT         135     /* MLPPP endpoint_option */
#define CNV_MP_ENDP_VAL         136     /* MLPPP endpoint value - just PSNDN */
#define CNV_PRIBUILD		137	/* DS1-to-CSU Attenuation */
#define CNV_PRIFDL		138	/* CSU TYPE ATT/ANSI */
#define CNV_MRRU		139	/* MP Maximum receive unit size */

#define CNV_ADDR_ORIGIN		140	/* address_origin */
#define CNV_AUTH_PROTOCOL   141 /* which security protocol to be used */
#define CNV_RADIUS_SECRET     142 /* radius port to send packet to */
#define CNV_RAD_ACCT_LEVEL 143 /* acctng level for radius */
#define CNV_RAD_PORT_ENCODING 144 /* port encoding, dev or channel*/

#define CNV_WAN_LINECODE        145
#define CNV_WAN_FRAMING         146
#define CNV_WAN_SIGPROTO        147
#define CNV_WAN_RING            148
#define CNV_WAN_RING_RAW        149
#define CNV_BUSYSIG             150
#define CNV_STRING_100		151	/* ASCII string; max 100 characters */
#define CNV_STRING_120		152	/* ASCII string; max 120 characters */
#define CNV_STRING_128		153	/* ASCII string; max 128 characters */
#define CNV_BANNER		154	/* Banner Option */
#define CNV_PROMPT_32		155	/* Annex prompt parameters for radius */
#define CNV_COMPAT_MODE         156 /* RADIUS compatibility_mode parameter */


#define CNV_IGMP_VERSION        157
#define CNV_IGMP_NIBBLE         158
#define CNV_IGMP_QUERY_TIME     159
#define CNV_IGMP_RESPONSE_TIME  160
#define CNV_IGMP_START_QUERY_TIME 161
#define CNV_IGMP_LAST_QUERY_TIME  162
#define CNV_IGMP_JOIN_QUERY_TIME  163
#define CNV_IGMP_V1_TIMEOUT       164

#define CNV_OSPF_ENABLE        165
#define CNV_OSPF_TRANSDELAY    166
#define CNV_OSPF_RETRANSINTERVAL          167
#define CNV_OSPF_RETRANSINTERVAL_PTP      168
#define CNV_OSPF_HELLOINTERVAL            169
#define CNV_OSPF_HELLOINTERVAL_PTP        170
#define CNV_OSPF_DEADINTERVAL             171
#define CNV_OSPF_DEADINTERVAL_PTP         172
#define CNV_OSPF_AUTHTYPE                 173
#define CNV_OSPF_HOLDDOWN                 174
#define CNV_OSPF_COMPAT1583               175
#define CNV_OSPF_AREATYPE                 176
#define CNV_RTABLE_SIZE                   177

#define CNV_IGMP_MAX_QUEUE_SIZE           178
#define CNV_IGMP_MAX_MCAST                179
#define CNV_ROUTE_PREF                    180
#define CNV_OSPF_AUTHKEY                  181
#define CNV_OSPF_MD5K                     182
#define CNV_OSPF_ACTIVEMD5                183
#define CNV_OSPF_COST                     184

#define CNV_PPP_TRACE_LVL                 185
#define CNV_OSPF_ASBDR                    186
#define CNV_RAD_ACCT_DEST                 187
#define CNV_DEF_AUTOD_MODE                188

#define CNV_IPPORT                      189

#define CNV_NFAS_INT_ID           190	 
#define CNV_NFAS_BACKUP_ID         191 
#define CNV_STRING_NTP                    192
#define CNV_NTP_TIMER                     193
#define CNV_STRING_PREFSERVER             194


/* annex version defintions */

#define VERS_1		0x0001
#define VERS_2		0x0002
#define VERS_3		0x0004
#define VERS_4		0x0008
#define VERS_4_1	0x0010
#define VERS_5          0x0020
#define VERS_6          0x0040
#define VERS_6_1        0x0080
#define VERS_6_2        0x0100
#define VERS_7		0x0200
#define VERS_7_1	0x0400
#define VERS_7_1_DEC	0x0800
#define VERS_8		0x1000
#define VERS_8_1	0x2000
#define VERS_BIG_BIRD	0x4000
#define VERS_POST_BB	0x8000
#define VERS_DENALI	0x8001
#define VERS_MCK2	0x8002
#define VERS_PRIMATE	0x8003
#define VERS_RUSHMORE	0x8004
#define VERS_WASHINGTON	0x8005
#define VERS_WASH_2	0x8006
#define VERS_14_0	0x8007
#define VERS_14_1	0x8008
#define VERS_14_2	0x8009
#define VERS_15_0	0x800a
#define VERS_15_1	0x800b
#define VERS_16_0	0x800c
#define VERS_GREYLOCK	0x800d
/* #define V_GREYLOCK	0x800d */
/* next line needs adding when parameters are added post-R14.1 */
/*#define VERS_POST_14_1   0x8009 */

#ifndef ANNEX
/*
 * these are some goofy masks used for defining masks with specific ranges
 * of supported versions of code.
 *
 * EXAMPLE: V_6_8 is used when the parameter is only supported between versions
 * 6.0 and 8.0 inclusive.
 *
 * These defines are only needed for opsoleting parameters...
 */

/*
 * This one is for version 1.0 only!?!?!
 */
#define VS_1		ver_vs1_mask

#define V_3_8	        ver_3_8_mask
#define V_5_8		ver_5_8_mask
#define V_6_8		ver_6_8_mask
#define V_6_1_8		ver_6_1_8_mask	

#define V_6_BB		ver_6_bb_mask
#define V_6_1_BB	ver_6_1_bb_mask
#define V_7_1_BB	ver_7_1_bb_mask
#define V_8_BB		ver_8_bb_mask

#define V_6_2_RUSHMORE	ver_6_2_rushmore_mask

#define V_7_11		ver_7_11_mask
#define V_7_1_11	ver_7_1_11_mask

#define V_PRIMATE_14_1	ver_primate_14_1_mask

/*
 * these are the normal masks used!!!
 */
#define V_1_N		ver_1_mask	
#define V_2_N		ver_2_mask	
#define V_3_N		ver_3_mask	
#define V_4_N		ver_4_mask	
#define V_4_1_N		ver_4_1_mask	
#define V_5_N		ver_5_mask	
#define V_6_N		ver_6_mask	
#define V_6_1_N		ver_6_1_mask	
#define V_6_2_N		ver_6_2_mask	
#define V_7_N		ver_7_mask	
#define V_7_1_N		ver_7_1_mask	
#define V_7_1_DEC	ver_7_1_dec_mask	
#define V_8_N		ver_8_mask	
#define V_8_1_N		ver_8_1_mask	
/* V_BIG_BIRD_N is also known as 9.0 or 9.2 */
#define V_BIG_BIRD_N	ver_bb_mask	
/* V_POST_BB_N is also known as 9.1 or 9.3 */
#define V_POST_BB_N	ver_pbb_mask	
/* V_DENALI_N is also known as 10.1 */
#define V_DENALI_N	ver_denali_mask
#define V_MCK2_N	ver_mck2_mask
#define V_PRIMATE_N	ver_primate_mask
#define V_RUSHMORE_N	ver_rushmore_mask
#define V_WASHINGTON_N	ver_washington_mask
#define V_WASH_2_N	ver_wash_2_mask
#define V_14_0_N	ver_14_0_mask
#define V_14_1_N	ver_14_1_mask
#define V_15_0_N	ver_15_0_mask
#define V_14_2_N	ver_14_2_mask
#define V_15_1_N	ver_15_1_mask
#define V_16_0_N	ver_16_0_mask
#define V_17_0_N	ver_17_0_mask
#define V_GREYLOCK	ver_greylock_mask
/*
 * These aren't defined yet, but supposedly the name will be Ernie.
 * When someone starts adding parameters for post-Rushmore, uncomment
 * this line, change the name if appropriate, and uncomment the
 * vers_ern_mask
 */
/*#define V_NEXTNAME_N       ver_nextname_mask */

/* the meaning of the array elements is as follows:
Array element 0 is the bit mask to use when the annex 
version is VERS_POST_BB or earlier.  Array element 1 is for the 
VERS_ERNIE version.  Array element 2 is for the post ernie
version, etc...  */ 

/*
 * These are the defines for parameters supported in previous version ranges.
 */
static UINT32 ver_vs1_mask[10] = {0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000}; 

static UINT32 ver_3_8_mask[10] = {0x1ffc, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_5_8_mask[10] = {0x1fe0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000}; 
static UINT32 ver_6_8_mask[10] = {0x1fc0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_6_1_8_mask[10] = {0x1f80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

static UINT32 ver_6_bb_mask[10] = {0x7fc0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_6_1_bb_mask[10] = {0x7f80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_7_1_bb_mask[10] = {0x7c00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_8_bb_mask[10] = {0x7000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_6_2_rushmore_mask[10] = {0xff00, 0x000f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

static UINT32 ver_7_11_mask[10] = {0xfe00, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};
static UINT32 ver_7_1_11_mask[10] = {0xfc00, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

static UINT32 ver_primate_14_1_mask[10] = {0x0000, 0x00fc, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

/*
 * These are the defines for parameters supported in the current revisions.
 */
static UINT32 ver_1_mask[10] = {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_2_mask[10] = {0xfffe, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_3_mask[10] = {0xfffc, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_4_mask[10] = {0xfff8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_4_1_mask[10] = {0xfff0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,0xffff, 0xffff, 0xffff, 0xffff}; 
static UINT32 ver_5_mask[10] = {0xffe0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_6_mask[10] = {0xffc0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_6_1_mask[10] = {0xff80, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,0xffff, 0xffff, 0xffff, 0xffff}; 
static UINT32 ver_6_2_mask[10] = {0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,0xffff, 0xffff, 0xffff, 0xffff}; 
static UINT32 ver_7_mask[10] = {0xfe00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_7_1_mask[10] = {0xfc00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,0xffff, 0xffff, 0xffff, 0xffff}; 
static UINT32 ver_7_1_dec_mask[10] = {0xf800, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_8_mask[10] = {0xf000, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_8_1_mask[10] = {0xe000, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,0xffff, 0xffff, 0xffff, 0xffff}; 
static UINT32 ver_bb_mask[10] = {0xc000, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_pbb_mask[10] = {0x8000, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,0xffff, 0xffff, 0xffff, 0xffff}; 
static UINT32 ver_denali_mask[10] = {0x0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_mck2_mask[10] = {0x0, 0xfffe, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_primate_mask[10] = {0x0, 0xfffc, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_rushmore_mask[10] = {0x0, 0xfff8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};  
static UINT32 ver_washington_mask[10] = {0x0, 0xfff0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};  
static UINT32 ver_wash_2_mask[10] = {0x0, 0xffe0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_14_0_mask[10] = {0x0, 0xffc0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_14_1_mask[10] = {0x0, 0xff80, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_14_2_mask[10] = {0x0, 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_15_0_mask[10] = {0x0, 0xfe00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_15_1_mask[10] = {0x0, 0xfc00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_16_0_mask[10] = {0x0, 0xf800, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_17_0_mask[10] = {0x0, 0xf000, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
static UINT32 ver_greylock_mask[10] = {0x0, 0xe000, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};

/* mask definitions for the next version */
/* static UINT32 ver_nextname_mask[10] = {0x0, 0xf800, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};  */

#endif

/* annex hardware types */

#define ANX_I		0
#define ANX_II		1
#define ANX_II_EIB	2
#define ANX3		3
#define ANX_MICRO	4
#define X25		5
#define ANX_MICRO_ELS	6
#define ANX_PRIMATE	7
#define N_HW_TYPES	8

/* Codes used by get_port_eib(). */
#define ANX_IIE		0x0100 		/* For historical reasons. */
#define ANX_MICRO_V11	0x0002 
#define ANX_802_5	0x0004
#define ANX_RDRP	0x0008

#define ANX_DIALOUT_ENA	0x0001
#define ANX_APPTALK_ENA	0x0020
#define ANX_TN3270_ENA	0x0040

/* Maximum number of modules for now */
#define MAX_MODULES 10

typedef struct
    {
    struct sockaddr_in  addr;
    UINT32		version;
    UINT32		sw_id;
    u_short		flag;
    UINT32		hw_id;
    short		port_count;
    short		sync_count;
    short		trunk_count;
    short		printer_count;
    unsigned char Interface[MAX_BIT_STRING];
    short		lat;
    short		self_boot;
    short		vhelp;
    short		t1_count;
    short		ta_count;
    short		pri_count;
    short		b_count[ MAX_MODULES ]; /* forward compatable */
    short       vpn_count;
    }			ANNEX_ID;

#ifdef NA

typedef struct annex_list
    {
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID		annex_id;
    struct annex_list  *next;
    }                   ANNEX_LIST;

typedef struct port_group
    {
    int			pg_bits;
    unsigned char	serial_ports[ALL_PORTS/NBBY];
    }			PORT_GROUP;

typedef struct port_set
    {
    PORT_GROUP		ports;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID		annex_id;
    struct port_set    *next;
    }                   PORT_SET;

typedef struct printer_group
    {
    int			pg_bits;
    unsigned char	ports[(ALL_PRINTERS + (NBBY - 1))/NBBY];
    }			PRINTER_GROUP;

typedef struct printer_set
    {
    PRINTER_GROUP	printers;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID		annex_id;
    struct printer_set  *next;
    }                   PRINTER_SET;

typedef struct interface_group
    {
    int			pg_bits;
    unsigned char	interface_ports[(ALL_INTERFACES + (NBBY - 1))/NBBY];
    }			INTERFACE_GROUP;

typedef struct interface_set
    {
    INTERFACE_GROUP		interfaces;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID		annex_id;
    struct interface_set    *next;
    }                   INTERFACE_SET;

typedef struct t1_ds0_info
    {
    u_char              t1_data[64];
    u_char              t1_ds0mask[4];
    }                   T1_DS0_INFO;

typedef struct t1_group
    {
    int                 reset_type;
    unsigned char       engines[(ALL_T1S + (NBBY - 1))/NBBY];
    }                   T1_GROUP;

typedef struct ds0_group
    {
    unsigned char       ds0s[(ALL_DS0S + (NBBY - 1))/NBBY];
    }                   DS0_GROUP;

typedef struct t1_set
    {
    T1_GROUP            t1s;
    DS0_GROUP           ds0s;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID            annex_id;
    struct t1_set       *next;
    }                   T1_SET;

typedef struct pri_b_info
    {
    u_char              pri_data[192];
    u_char              pri_bmask[4];
    }                   PRI_B_INFO;

typedef struct pri_group
    {
    int                 reset_type;
    unsigned char       modules[(ALL_PRIS + (NBBY - 1))/NBBY];
    }                   PRI_GROUP;

typedef struct b_group
    {
    unsigned char       bs[(ALL_BS + (NBBY - 1))/NBBY];
    }                   B_GROUP;

typedef struct pri_set
    {
    PRI_GROUP		pris;
    B_GROUP		bs;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID            annex_id;
    struct pri_set      *next;
    }                   PRI_SET;

typedef struct modem_group
    {
    int			mg_bits;
    unsigned char	modems[ALL_PORTS/NBBY];
    }			MODEM_GROUP;

typedef struct modem_set
    {
    MODEM_GROUP		modems;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID		annex_id;
    struct modem_set	*next;
    }                   MODEM_SET;

typedef struct intmod_group
    {
    int                 reset_type;
    unsigned char       intmods[(ALL_INTMODS + (NBBY - 1))/NBBY];
    }                   INTMOD_GROUP;

typedef struct intmod_set
    {
    INTMOD_GROUP        intmods;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID            annex_id;
    struct intmod_set   *next;
    }                   INTMOD_SET;

typedef struct trunk_group
    {
    int			pg_bits;
    UINT32		serial_trunks;
    }			TRUNK_GROUP;

typedef struct trunk_set
    {
    TRUNK_GROUP		trunks;
    char                name[FILENAME_LENGTH + 2];
    ANNEX_ID		annex_id;
    struct trunk_set    *next;
    }                   TRUNK_SET;

#define ALLTRUNK(Pgrp) \
    (((Pgrp)->trunks.pg_bits & (PG_ALL | PG_SERIAL)) ? \
     ALL_TRUNKS : \
     (Pgrp)->trunks.serial_trunks)

typedef struct show_list
    {
    int               param_num;
    struct show_list *next;
    }                 SHOW_LIST;


typedef struct set_list
    {
    int              param_num;
    char             value[LINE_LENGTH + 2];
    DS0_GROUP	     t1ds0s;
    B_GROUP	     pribs;
    struct set_list *next;
    }                SET_LIST;

#endif /* NA */

/* define structures to contain parameter descriptions for na */

typedef struct
{
	char   *d_key;
	short	d_usage;
	short	d_index;
#ifdef NA
	char   *d_text;
#endif

}	definition;

typedef struct
{
	short	pt_index;
	short	pt_category;
	short	pt_catid;
	short	pt_displaycat;
	short	pt_type;
	short	pt_convert;
#ifdef NA
	UINT32	*pt_version[N_HW_TYPES];
#endif

}	parameter_table;

/*	Use these defines to reference entries in the help dictionary	    */

#define D_key(x)	(dictionary[x].d_key)
#define D_usage(x)	(dictionary[x].d_usage)
#define D_index(x)	(dictionary[x].d_index)
#ifdef NA
#define D_text(x)	(dictionary[x].d_text)
#endif

/*	Use these defines to reference in annex parameter table entries     */

#define Ap_index(x)	(annexp_table[x].pt_index)
#define Ap_category(x)	(annexp_table[x].pt_category)
#define Ap_catid(x)	(annexp_table[x].pt_catid)
#define Ap_displaycat(x) (annexp_table[x].pt_displaycat)
#define Ap_type(x)	(annexp_table[x].pt_type)
#define Ap_convert(x)	(annexp_table[x].pt_convert)

#ifdef NA
#define Ap_version(x, h)	(annexp_table[x].pt_version[h])
#endif

/*	Use these defines to reference the serial port parameter table	    */

#define Sp_index(x)	(portp_table[x].pt_index)
#define Sp_category(x)	(portp_table[x].pt_category)
#define Sp_catid(x)	(portp_table[x].pt_catid)
#define Sp_displaycat(x) (portp_table[x].pt_displaycat)
#define Sp_type(x)	(portp_table[x].pt_type)
#define Sp_convert(x)	(portp_table[x].pt_convert)
#ifdef NA
#define Sp_version(x, h)	(portp_table[x].pt_version[h])
#endif


/*	Use these defines to reference the serial trunk parameter table	    */

#define St_index(x)	(trunkp_table[x].pt_index)
#define St_category(x)	(trunkp_table[x].pt_category)
#define St_catid(x)	(trunkp_table[x].pt_catid)
#define St_displaycat(x) (trunkp_table[x].pt_displaycat)
#define St_type(x)	(trunkp_table[x].pt_type)
#define St_convert(x)	(trunkp_table[x].pt_convert)
#ifdef NA
#define St_version(x, h)	(trunkp_table[x].pt_version[h])
#endif


/*	Use these defines to reference the centronics port parameter table  */

#define Cp_index(x)	(printp_table[x].pt_index)
#define Cp_category(x)	(printp_table[x].pt_category)
#define Cp_catid(x)	(printp_table[x].pt_catid)
#define Cp_displaycat(x) (printp_table[x].pt_displaycat)
#define Cp_type(x)	(printp_table[x].pt_type)
#define Cp_convert(x)	(printp_table[x].pt_convert)
#ifdef NA
#define Cp_version(x, h)	(printp_table[x].pt_version[h])
#endif

/*	Use these defines to reference the interface parameter table  */

#define Ip_index(x)	(interfacep_table[x].pt_index)
#define Ip_category(x)	(interfacep_table[x].pt_category)
#define Ip_catid(x)	(interfacep_table[x].pt_catid)
#define Ip_displaycat(x) (interfacep_table[x].pt_displaycat)
#define Ip_type(x)	(interfacep_table[x].pt_type)
#define Ip_convert(x)	(interfacep_table[x].pt_convert)
#ifdef NA
#define Ip_version(x, h)	(interfacep_table[x].pt_version[h])
#endif

/* defines for referencing T1 parameter table entries...*/

#define T1p_index(x)      (t1p_table[x].pt_index)
#define T1p_category(x)   (t1p_table[x].pt_category)
#define T1p_catid(x)      (t1p_table[x].pt_catid)
#define T1p_displaycat(x) (t1p_table[x].pt_displaycat)
#define T1p_type(x)       (t1p_table[x].pt_type)
#define T1p_convert(x)    (t1p_table[x].pt_convert)
#ifdef NA
#define T1p_version(x, h) (t1p_table[x].pt_version[h])
#endif
#define T1ds0p_category(x) (t1ds0p_table[x].pt_category)

/* defines for referencing PRI parameter table entries...*/

#define Prip_index(x)		(prip_table[x].pt_index)
#define Prip_category(x)	(prip_table[x].pt_category)
#define Prip_catid(x)		(prip_table[x].pt_catid)
#define Prip_displaycat(x)	(prip_table[x].pt_displaycat)
#define Prip_type(x)		(prip_table[x].pt_type)
#define Prip_convert(x)		(prip_table[x].pt_convert)
#ifdef NA
#define Prip_version(x, h)	(prip_table[x].pt_version[h])
#endif
#define Pribp_category(x)	(pribp_table[x].pt_category)

/* defines for referencing modem parameter table entries...*/

#define Modemp_index(x)		(modemp_table[x].pt_index)
#define Modemp_category(x)	(modemp_table[x].pt_category)
#define Modemp_catid(x)		(modemp_table[x].pt_catid)
#define Modemp_displaycat(x)	(modemp_table[x].pt_displaycat)
#define Modemp_type(x)		(modemp_table[x].pt_type)
#define Modemp_convert(x)	(modemp_table[x].pt_convert)
#ifdef NA
#define Modemp_version(x, h)	(modemp_table[x].pt_version[h])
#endif


#ifdef NA

#ifdef IN_MAIN
#define EXTERN	/* */
#else
#define EXTERN	extern
#endif

/* global variables */

EXTERN
FILE *cmd_file;		/* pointer to file descriptor of command file. */

EXTERN
short erpc_port;	/* port number of erpc server */

EXTERN
int status;		/* exit status: 0 no errors, 1 something went wrong */

EXTERN
int done,		/* TRUE when quit command has been recognized */
    eos,		/* TRUE when command line is empty */
    prompt_mode,	/* TRUE when the human is to be prompted for args */
    symbol_length,	/* length of current symbol */
    script_input,	/* TRUE iff input is from a script file */
    inswitch,           /* TRUE if in a switch ie -abcd, abcd are in a switch */
    is_super;		/* TRUE iff userid is root */

EXTERN
char command_line[LINE_LENGTH + 1],	/* last line typed by human */
     *Psymbol,			/* lex pointer; points to next unlexed char */
     symbol[LINE_LENGTH + 1];	/* nul-delimited copy of current symbol */

EXTERN
ANNEX_LIST *Pdef_annex_list,
           *Pdef_annex_tail,
	   *Pspec_annex_list,
	   *Pspec_annex_tail;

EXTERN
PORT_SET   *Pdef_port_set,
           *Pdef_port_tail,
	   *Pspec_port_set,
	   *Pspec_port_tail;

EXTERN
PRINTER_SET *Pdef_printer_set,
            *Pdef_printer_tail,
	    *Pspec_printer_set,
	    *Pspec_printer_tail;

EXTERN
INTERFACE_SET   *Pdef_interface_set,
           *Pdef_interface_tail,
	   *Pspec_interface_set,
	   *Pspec_interface_tail;

EXTERN
T1_SET     *Pdef_t1_set,
           *Pdef_t1_tail,
           *Pspec_t1_set,
           *Pspec_t1_tail;

EXTERN
PRI_SET    *Pdef_pri_set,
           *Pdef_pri_tail,
           *Pspec_pri_set,
           *Pspec_pri_tail;

EXTERN
MODEM_SET  *Pdef_modem_set,
           *Pdef_modem_tail,
           *Pspec_modem_set,
           *Pspec_modem_tail;

EXTERN
INTMOD_SET *Pdef_intmod_set,
           *Pdef_intmod_tail,
           *Pspec_intmod_set,
           *Pspec_intmod_tail;

EXTERN
TRUNK_SET  *Pdef_trunk_set,
           *Pdef_trunk_tail,
	   *Pspec_trunk_set,
	   *Pspec_trunk_tail;

EXTERN
SHOW_LIST  *Pshow_list,
           *Pshow_tail;

EXTERN
SET_LIST   *Pset_list,
           *Pset_tail;

EXTERN
jmp_buf cmd_env;
EXTERN
jmp_buf prompt_env;

#endif /* NA */

/* for lat specific conversion */

struct mask_options {
    UINT32 mask;
    char *name;
    };

#define	ALL_LAT_GROUPS	"0-255"
#define	ALL_STR		"all"
#define	NONE_STR	"none"

#ifdef NA
#define puntv(x,y)		punt(x,y)
#else
#define punt(x,y)		return(-1)
#define puntv(x,y)		return
#define match(x,y,z)		matchit(x,y)
#define match_flag(v,w,x,y,z)	matchflag(v,w,x,z)
#endif

#ifdef NA
EXTERN void open_pager(),close_pager(),initialize_pager(),stop_pager();
#endif /* NA */

/*
 *      Structure Definitions for conversion routines
 */
   
typedef struct
{
	unsigned short  C_length;
	char            C_string[MAX_STRING_128];
		 
}       COURIER_STRING;
		  
typedef union
{
	UINT32		*I_long;
	unsigned short  *I_short;
	char            *I_char;
	struct in_addr  *I_inet;
        COURIER_STRING  *I_courier;
	 
}       INTERN;
	  
#define Linternal       (Internal.I_long)
#define Sinternal       (Internal.I_short)
#define Cinternal       (Internal.I_char)
#define Ninternal       (Internal.I_inet)
#define CS_length       (Internal.I_courier)->C_length
#define CS_string       (Internal.I_courier)->C_string

#endif /* NA_H */
