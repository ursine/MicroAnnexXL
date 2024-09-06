/******************************************************************************
 *
 *        Copyright 1989,1990 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *  %$(description)$%
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 *****************************************************************************/


#ifndef NETADMP_H
#define NETADMP_H

/* Defines constants used in the NETwork ADMinistration Protocol. */

/* When adding remote procedure or parameter numbers, be sure to coordinate
   with the file /annex/doc/parm.doc. */
  

#define NETADM_VERSION 1

/* remote procedure numbers */
#define RPROC_BOOT           0
#define RPROC_DUMPBOOT       1
#define RPROC_RESET_LINE     2
#define RPROC_RESET_ALL      3
#define RPROC_READ_MEMORY    4
#define RPROC_SET_INET_ADDR  5
#define RPROC_GET_DLA_PARAM  6
#define RPROC_GET_LINE_PARAM 7
#define RPROC_SET_DLA_PARAM  8
#define RPROC_SET_LINE_PARAM 9
#define RPROC_GET_REV	     10
#define RPROC_GET_PORTS	     11
#define RPROC_BCAST_TO_PORT  12
#define RPROC_SRPC_OPEN	     13
#define RPROC_RESET_ANNEX    14
#define RPROC_GET_TRUNKS     15
#define RPROC_SHUTDOWN	     16 
#define RPROC_GET_EIB	     17
#define RPROC_GET_OPTS	     18
#define RPROC_GET_PRINTERS   19
#define RPROC_GET_IF_PARAM   20
#define RPROC_SET_IF_PARAM   21 
#define RPROC_GET_IFS        22
#define RPROC_SET_MODEM_PARAM 23
#define RPROC_GET_MODEM_PARAM 24
#define RPROC_GET_SYNCS      25 
#define RPROC_RESET_T1       26
#define RPROC_RESET_INT_MOD  27
#define RPROC_SET_T1_PARAM   28
#define RPROC_GET_T1_PARAM   29
#define RPROC_GET_T1S        30
#define RPROC_GET_TAS        31
#define RPROC_GET_PRI_PARAM	32
#define RPROC_SET_PRI_PARAM	33
#define RPROC_RESET_PRI		34
#define RPROC_GET_PRIS		35
#define RPROC_GET_BS		36
#define RPROC_GET_ALL_BS	37

#define NETADM_NPROCS	     38

/*
 * Annex device types (actually categories)
 * (Order must match entries in oper/adm/net_line.c device_table[].)
 * These are *NOT* the same as the numbers used in h/devtypes.h.  Do not
 * confuse the two.
 */
#define SERIAL_DEV	1
#define P_PRINT_DEV	2
#define SBX_DEV		3
#define ACT_SERIAL_DEV	4
#define INTERFACE_DEV	5
#define PSEUDO_DEV	6		/* Used by SNMP */
#define T1_DEV          7
#define MODEM_DEV	8
#define PRI_DEV		9

#define DLA_NDEVS	9		/* Should match last type */

/* The parameters for some of the categories are split up into groups.
 * Thus associated with each category is a cat table with an entry for
 * each group in the category. Here are the symbols for indexing those
 * category tables (Don't ask why these symbols have "CAT" as their
 * suffix. There seems to be no consistency in the use of the terms
 * "group" and "category".)
*/

/*
 * Annex Synchronous device types
 * Only the one generic to start with???
 */
#define SYNC_DEV	1

#define SYNC_NDEVS	1

/* annex device type categories */
#define DLA_CAT 1
#define DFE_CAT 2
#define LAT_CAT 3
#define ARAP_CAT 4
#define RIP_CAT 5

#define DLA_PARM_NCATS   5

/* serial line parameter categories */
#define DEV_CAT		1
#define EDIT_CAT	2
#define INTF_CAT	3
#define NET_CAT	        4
#define SLIP_CAT        4
#define DEV2_CAT        5

#define LINE_PARM_NCATS   5

/* Synchronous parameter groups */
#define SYNC_CAT	1

#define SYNC_PARM_NCATS	1

/* centronics port categories */
#define LP_CAT		1
#define CX_CAT		2

#define LP_PARM_NCATS	2

/* SBX port categories */
#define SBX_CAT		1

#define SBX_PARM_NCATS	1

/* interface parameter groups */
#define IF_CAT		1

#define IF_PARM_NCATS   1

/* per annex statistics categories */
#define TCP_IP_CAT    1
#define HW_CONFIG_CAT 2
#define MXL_CAT	      3

#define DLA_STAT_NCATS 3

/* per annex line statistics categories */
#define SERIAL_LINE_CAT  1

#define LINE_STAT_NCATS  1

   /* Channelized T1 groups */

#define T1_CAT         1

#define T1_PARM_NCATS	1

#define WAN_CAT         1
#define WAN_PARM_NCATS	1

#define MODEM_CAT         1
#define MODEM_PARM_NCATS	1

/* parameter types */
#define NULL_P          	0
#define BYTE_P          	1
#define STRING_P        	2
#define CARDINAL_P      	3
#define LONG_CARDINAL_P 	4
#define FLOAT_P         	5
#define BOOLEAN_P       	6
#define LONG_UNSPEC_P   	7
#define RAW_BLOCK_P		8
#define ARBL_STRING_P        	9
#define STRING_P_100        	10
#define ADM_STRING_P           	11
#define LAT_GROUP_P        	12
#define RIP_ROUTERS_P		13
#define ENET_ADDR_P		14
#define FILLER_P		15		/* basically a void */
#define KERB_HOST_P		16
#define IPX_STRING_P		17
#define MOP_PASSWD_P		18
#define BLOCK_32_X_2            19
#define BLOCK_32                20
#define STRING_P_120            21
#define BLOCK_32_X_4		22
#define BLOCK_32_X_6		23
#define STRING_P_128        24

#define DATA_TYPE_COUNT  24

/* interface parameter numbers */
#define INTER_REV		1
#define INTER_IBAUD		3
#define INTER_OBAUD		4
#define INTER_BCHAR		5
#define INTER_STOPB		6
#define INTER_PCHECK		7
#define INTER_PGEN		8
#define INTER_MODEM		12
#define INTER_IMASK7		13
#define INTER_ABAUD		14

#define INTER_LPVC		15
#define INTER_HPVC		16
#define INTER_LSVC		17
#define INTER_HSVC		18
#define INTER_TRADD		19
/* overlapping params for X.25 */
#define INTER_WNDSZ		5
#define INTER_FRMSZ		6
#define INTER_TRSPEED		7
#define INTER_X25T2		8
#define INTER_TRCNCTR		9
#define INTER_X25T1		10
#define INTER_X25N2		11
#define INTER_TRNK		12

/* device parameter numbers */
#define DEV_REV			1
#define DEV_NSBRK		2
#define DEV_NLBRK		3
#define DEV_NAUTOBAUD		4
#define DEV_LOGINT		5
#define DEV_HMUX		6
#define DEV_IFLOW		7
#define DEV_ISTOPC		8
#define DEV_ISTARTC		9
#define DEV_OFLOW		10
#define DEV_OSTOPC		11
#define DEV_OSTARTC		12
#define DEV_ATTN		13
#define DEV_ISIZE		14
#define DEV_TIMOUT		15
#define DEV_INACTIVE		16
#define DEV_LTYPE		17
#define DEV_NAME_OLD		18
#define DEV_TERM		19
#define DEV_MODE		20
#define DEV_CARRIER_OVERRIDE	21
#define DEV_NBROADCAST		22
#define DEV_CLI_SECURITY	23
#define DEV_CONNECT_SECURITY	24
#define DEV_PORT_SECURITY	25
#define DEV_SESSIONS		26
#define DEV_IXANY		27
#define DEV_DEFAULT_HPCL	29
#define DEV_LOCATION		30
#define DEV_INPUT_ACT		31
#define DEV_OUTPUT_ACT		32
#define DEV_RESET_IDLE		33
#define DEV_DEDICATED_ADDR	34
#define DEV_DEDICATED_PORT	35
#define DEV_INACTCLI		36
#define DEV_RBCAST		37    /* maps to na BROADCAST_DIR */
#define DEV_CLI_IMASK7		38 
#define DEV_FORWARD_COUNT	39 
#define DEV_NEED_DSR		40
#define DEV_TELNET_CRLF		41
#define DEV_LATB_ENABLE		42
#define LAT_AUTHORIZED_GROUPS	43
#define DEV_PS_HISTORY_BUFF	44
#define DEV_BANNER		45
#define DEV_KEEPALIVE		46
#define DEV_MODEM_VAR		47
#define TN3270_PRINTER_HOST    	48
#define TN3270_PRINTER_NAME	49
#define DEV_DFLOW               50
#define DEV_DIFLOW              51
#define DEV_DOFLOW              52
#define DEV_SESS_MODE           53
#define DEV_DUI_TIMEOUT         54
#define DEV_DUI_PASSWD          55
#define DEV_IPSO_CLASS		56
#define DEV_IPX_SECURE		57
#define DEV_DEDICATED_ARGUMENTS	58
#define DEV_RESOLVE_PROTOCOL	59
#define DEV_FORWARD_KEY		60
#define DEV_BACKWARD_KEY	61
#define DEV_MULTISESS		62
#define DEV_AUTOD_TIMEOUT       63
#define DEV_V120_MRU		64
#define DEV_NAME		65
#define DEV_PROXY_ARP_ENABLED	66
#define DEV_SILENT_MODE_ENABLE	67

/* device parameter numbers */
#define DEV2_REV		 1
#define DEV2_PORT_PASSWD         2
#define DEV2_DPTG_SETTINGS       3

/* editing parameter numbers */
#define EDIT_REV		1
#define EDIT_NEWLIN		2
#define EDIT_INECHO		3
#define EDIT_IUCLC		4
#define EDIT_OLCUC		5
#define EDIT_OCRTCERA		6
#define EDIT_OCRTLERA		7
#define EDIT_OTABS		8
#define EDIT_CERA		9
#define EDIT_LERA		10
#define EDIT_WERA		11
#define EDIT_LDISP		12
#define EDIT_FLUSH		13
#define EDIT_DOLEAP		14
#define EDIT_PROMPT		15
#define EDIT_TESC		16
#define EDIT_USER_INTF          17

/* NET parameter numbers */
#define SLIP_REV		1
#define SLIP_NODUMP		2
#define SLIP_LOCALADDR		3
#define SLIP_REMOTEADDR		4
#define SLIP_NETMASK		5
#define SLIP_LOADUMPADDR	6
#define SLIP_METRIC		7
#define SLIP_DO_COMP		8
#define SLIP_EN_COMP		9
#define SLIP_NO_ICMP		10
#define SLIP_FASTQ		11
#define SLIP_LGMTU		12
#define SLIP_SECURE             13
#define PPP_DIALUP_ADDR		14 /* Should be renamed: SLIP_DIALUP_ADDR */

#define FILLER			15 /* R7.0 bug left PPP_ACTOPEN field */
#define PPP_MRU			16
#define PPP_ACM			17
#define PPP_SECURITY		18
#define PPP_UNAMERMT_OLD	19
#define PPP_PWORDRMT		20
#define PPP_NCP			21

#define ARAP_AT_GUEST     	22
#define ARAP_AT_NODEID     	23
#define ARAP_AT_SECURITY     	24
#define ARAP_V42BIS    		25

#define SLIP_DEMAND_DIAL        26
#define SLIP_NET_INACTIVITY     27
#define SLIP_PHONE              28
#define	SLIP_NET_INACT_UNITS	29

#define PPP_IPX_NETNUM		30
#define PPP_IPX_NODENUM		31
#define PPP_SEC_AUTO            32 

#define MP_MRRU                 33
#define MP_ENDP_OPT             34
#define MP_ENDP_VAL             35
#define SLIP_ADDR_ORIGIN	36
#define IPCP_UNNUMBERED		37
#define DROP_FIRST_REQ		38
#define PPP_UNAMERMT		39

/* Synchronous parameter numbers */
#ifdef unused
#define SYNC_REV            1
#define SYNC_MODE           2
#define SYNC_LOCATION       3
#define SYNC_CLOCKING       4
#define SYNC_FORCE_CTS      5
#define SYNC_USRNAME        6
#define SYNC_PORT_PASSWD    7
#define SYNC_LOCAL_ADDR     8
#define SYNC_REMOTE_ADDR    9
#define SYNC_NETMASK        10
#define SYNC_METRIC         11
#define SYNC_ALW_COMP       12
#define SYNC_SECURE         13
#define SYNC_DIAL_ADDR      14
#define SYNC_PPP_MRU        15
#define SYNC_PPP_SECURE_PROTO   16
#define SYNC_PPP_USRNAME_REMOTE 17
#define SYNC_PPP_PASSWD_REMOTE  18
#define SYNC_PPP_NCP        19
#define SYNC_PPP_SCR_AUTO   20 
#endif

/* Channelized T1 parameter numbers */
#define T1_REV                   1
#define T1_TDI_DISTANCE          2             
#define T1_MAP                   3 
#define T1_SIGPROTO              4 
#define T1_PROTO_ARG             5 
#define T1_RING                  6 
#define T1_TNI_CLOCK             7   
#define T1_TNI_LINE_BUILDOUT     8   
#define T1_TNI_FRAMING           9   
#define T1_TNI_LINE_CODE         10   
#define T1_TNI_ESF_FDL           11  
#define T1_TDI_FRAMING           12  
#define T1_TDI_LINE_CODE         13  
#define T1_LOG_ALARM             14
#define T1_BYPASS                15
#define T1_TNI_ONES_DENSITY      16       
#define T1_TNI_CIRCUIT_ID        17  
#define T1_INFO                  18
#define T1_SWITCH_TYPE           19

/* WAN parameter numbers */
#define WAN_SWITCH_TYPE		1
#define WAN_NUM_BCHAN		2
#define WAN_REMOTE_ADDRESS	3
#define WAN_IPX_NETWORK		4
#define WAN_IPX_NODE		5
#define WAN_DISTANCE		6
#define WAN_BUILDOUT		7
#define WAN_FDLTYPE		8
#define WAN_ANALOG		9
#define WAN_FRAMING             10
#define WAN_LINECODE            11
#define WAN_DNIS                12
#define WAN_ANI                 13
#define WAN_DIGITWIDTH          14
#define WAN_INTERDIGIT          15
#define WAN_DIGITPOWER_1        16
#define WAN_DIGITPOWER_2        17
#define WAN_SIGPROTO            18
#define WAN_RINGBACK            19
#define WAN_BUSYSIGTYPE		20
#define WAN_LOCALPHONENO	21
#define WAN_AUTOBUSYENA		22

/* Modem parameter numbers */
#define MODEM_BUSY_OUT		1

/* dla parameter numbers */
#define DLA_REV			1
#define DLA_INETADDR		2
#define DLA_IMAGE		3
#define DLA_PREF_LOAD   	4
#define DLA_PREF_DUMP   	5
#define DLA_SUBNET		6
#define DLA_BROAD_ADDR  	7
#define DLA_LOADUMP_GATE	8
#define DLA_LOADUMP_SEQ		9
#define	DLA_IPENCAP		10
#define DLA_RING_PRIORITY	11
#define DLA_TFTP_DIR		12
#define DLA_TFTP_DUMP		13
#define DLA_MOP_HOST            14
#define DLA_IPX_FILE_SERVER	15
#define DLA_IPX_FRAME_TYPE	16
#define DLA_IPX_DMP_USER_NAME	17
#define DLA_IPX_DMP_PASSWD	18
#define DLA_IPX_DMP_PATH	19
#define DLA_IPX_DO_CHECKSUM     20
#define DLA_IPX_DMP_SERVER      21
#define DLA_MP_ENABLED		22

/* dfe parameter numbers */
#define DFE_REV			1
#define DFE_1ST_NS		2
#define DFE_2ND_NS		3
#define DFE_HTABLE_SZ		4
#define DFE_PREF1_SECURE 	5
#define DFE_1ST_NS_ADDR		6
#define DFE_2ND_NS_ADDR		7
#define DFE_NET_TURNAROUND	8
#define DFE_SECURE		9
#define DFE_SERVER_CAP		10
#define DFE_SYSLOG_MASK		11
#define DFE_SYSLOG_FAC		12
#define DFE_SYSLOG_ADDR		13
#define DFE_PROMPT		14
#define DFE_TZ_MINUTES		15
#define	DFE_TZ_DLST		16
#define DFE_VCLI_LIMIT		17
#define DFE_PASSWORD		18
#define DFE_ACP_KEY		19
#define DFE_NRWHOD		20
#define DFE_NMIN_UNIQUE		21
#define DFE_NROUTED		22
#define DFE_MOTD		23
#define DFE_NAMESVR_BCAST       24
#define DFE_SECRSVR_BCAST       25
#define DFE_TIMESVR_BCAST       26
#define DFE_LOADSVR_BCAST       27
#define DFE_PREF2_SECURE 	28
#define DFE_VCLI_SEC_ENA        29
#define DFE_VCLI_PASSWD         30
#define DFE_AGENT         	31
#define LAT_HOST_ID        	32	/* sys_location used for lat and snmp */
#define LAT_KEY_VALUE        	33
#define	DFE_SNMPSET		34
#define DFE_SELECTED_MODULES	35
#define DFE_CONFIG		36
#define DFE_SYSLOG_PORT		37
#define DFE_LOOSE_SOURCE_RT	38
#define DFE_FWDBCAST		39
#define DFE_LOCK_ENABLE		40
#define DFE_PASSWD_LIMIT	41
#define DFE_KEEPALIVE		42
#define DFE_TIMESERVE		43
#define DFE_OPTION_KEY		44
#define DFE_LOGIN_PASSWD        45
#define DFE_LOGIN_PROMPT        46
#define DFE_DUI_TIMER           47
#define DFE_MOP_PASSWD          48
#define DFE_SESSION_LIMIT       49
#define DFE_MODEM_ACC_ENTRIES	50
#define DFE_SEG_JUMPER_BAY5K	51
#define DFE_OUTPUT_TTL		52
#define	DFE_KERB_SECUREN 	53
#define	DFE_KERB_HOST		54
#define	DFE_TGS_HOST		55
#define	DFE_TELNETD_KEY		56
#define	DFE_KERBCLK_SKEW	57	
#define	DFE_TMUX_ENA		58
#define	DFE_TMUX_MAX_HOST	59
#define	DFE_TMUX_DELAY		60
#define	DFE_MAX_MPX		61
#define	DFE_CHAP_AUTH_NAME	62
#define DFE_VCLI_INACTIV        63 
#define DFE_PREF1_DHCPADDR      64
#define DFE_PREF2_DHCPADDR      65
#define DFE_DHCP_BCAST          66
#define DFE_MAX_CHAP_CHALL_INT  67
#define DFE_FAIL_TO_CONNECT     68
#define DFE_TRAPHOST            69
#define DFE_CALLBEGIN           70
#define DFE_CALLEND             71
#define DFE_INACTIVITY_TRAP     72
#define DFE_UNEXPECTED_TRAP     73
#define DFE_BIPOLAR_THRESHOLD   74
#define DFE_FRAMING_THRESHOLD   75
#define DFE_ERRSECS_THRESHOLD   76
#define DFE_DIALLNK_TRAP_EN     77
#define DFE_SELMODS2		78
#define DFE_CALL_HISTORY	79
#define DFE_CV_THRESHOLD	80
#define DFE_ESF_THRESHOLD	81
#define DFE_SES_THRESHOLD	82
#define DFE_UAS_THRESHOLD	83
#define DFE_BES_THRESHOLD	84
#define DFE_LOFC_THRESHOLD	85
#define DFE_CSS_THRESHOLD	86
#define DFE_DS0ERR_THRESHOLD	87
#define DFE_MODEM_THRESHOLD	88
#define DFE_RADIUS_AUTH_PORT    89
#define DFE_RADIUS_ACCT_PORT    90
#define DFE_RADIUS_SECRET       91
#define DFE_RADIUS_TIMEOUT      92
#define DFE_RADIUS_RETRIES      93
#define DFE_AUTHENTICATION_PROTOCOL 94
#define DFE_ENABLE_RADIUS_ACCT  95
#define DFE_RAD_ACCT_LEVEL      96
#define DFE_RAD_PORT_ENCODING   97
#define DFE_1ST_NBNS_ADDR	98
#define DFE_2ND_NBNS_ADDR	99
#define DFE_RADIUS_USER_PROMPT	100
#define DFE_RADIUS_PASSWD_PROMPT 101
#define DFE_NS_OVERRIDE		102
#define DFE_RADIUS_ACCT1_HOST    103
#define DFE_RADIUS_ACCT2_HOST    104
#define DFE_RADIUS_AUTH2_PORT    105
#define DFE_RADIUS_ACCT2_PORT    106
#define DFE_RADIUS_AUTH2_SECRET  107
#define DFE_RADIUS_ACCT1_SECRET  108
#define DFE_RADIUS_ACCT2_SECRET  109
#define DFE_ATTN_KILL_ENABLE     110
#define DFE_PASS_BREAK           111
#define DFE_DHCP_GIADDR          112
#define DFE_RADIUS_ACCT_TIMEOUT  113
#define DFE_TOGGLE_UNARP         114
#define DFE_ARPT_TTKILLC         115

/*
 * If you add something here, make sure dfe_types[] in parm_tables.c is
 * in the same order, or you'll get very strange behavior!
 */

/* LAT parameter numbers */
#define LAT_HOST_NAME           1
#define LAT_HOST_NUMBER         2
#define LAT_SERVICE_LIMIT       3
#define LAT_KA_TIMER            4
#define LAT_CIRCUIT_TIMER       5
#define LAT_RETRANS_LIMIT       6
#define LAT_GROUP_CODE          7
#define LAT_QUEUE_MAX           8
#define LAT_VCLI_GROUPS         9
#define LAT_MULTI_TIMER         10
#define LAT_MULTISESS           11



/* ARAP parameter numbers */
#define ARAP_A_ROUTER     	1
#define ARAP_DEF_ZONE_LIST     	2
#define ARAP_NODE_ID     	3
#define ARAP_ZONE   	  	4

/* Annex RIP parameter numbers */
#ifdef NOT_USED
#define RIP_IP_TTL	     	1
#define RIP_ND_FORWARD     	2
#define RIP_ASD_FORWARD     	3
#define RIP_SD_FORWARD     	4
#endif
#define RIP_RIP_ROUTERS     	1
#define RIP_RIP_AUTH    	2
#define RIP_RIP_FORCE_NEWRT     3

/* centronics parameter numbers */
#define PRINTER_OLTOU		2
#define PRINTER_MCOL		3
#define	PRINTER_OTABS		4
#define PRINTER_TYPE		5
#define PRINTER_SPEED		6
#define PRINTER_CRLF		7
#define PRINTER_KEEPALIVE 	8

/* interface RIP parameter numbers */
#define IF_RIP_SEND_VERSION    	1
#define IF_RIP_RECV_VERSION    	2
#define IF_RIP_HORIZON    	3
#define IF_RIP_DEFAULT_ROUTE   	4
#define IF_RIP_NEXT_HOP    	5
#define IF_RIP_SUB_ADVERTISE   	6
#define IF_RIP_SUB_ACCEPT    	7
#define IF_RIP_ADVERTISE    	8
#define IF_RIP_ACCEPT    	9

/* abort codes */
#define BAD_TYPE		1
#define BAD_COUNT		2
#define BAD_PARAM		3
#define WRITE_FAILURE		4
#define	TOO_MANY_SESSIONS	5
#define BAD_DEVICE		6
#define INTERNAL_ERROR		7
#define BAD_T1DS0_VAL		8
#define BAD_BOOT_ARG		9

/* miscellaneous */
#define READ_MEM_MAX 0x400

/* RESET_ANNEX parameter values. These values should match with reset_params
 table defined cmd.h*/

#define RESET_ANNEX_ALL		0
#define RESET_ANNEX_SECURITY	1
#ifndef MICRO_ELS
#define RESET_ANNEX_MOTD	2
#define RESET_ANNEX_NAMESERVER	3
#define RESET_ANNEX_MACRO	4
#define RESET_ANNEX_LAT		5
#define RESET_ANNEX_MODEM_TAB	6
#define RESET_ANNEX_DIALOUT_TAB	7
#define RESET_ANNEX_SYSLOG	8
#define RESET_ANNEX_SESSION	9
#define RESET_ANNEX_DNIS        10
#define RESET_ANNEX_FILTERS     11
#define RESET_ANNEX_MAX		11    /* bump this count when adding a reset */
#else
#define RESET_ANNEX_NAMESERVER  2
#define RESET_ANNEX_MACRO       3
#define RESET_ANNEX_LAT         4
#define RESET_ANNEX_SYSLOG	5
#define RESET_ANNEX_MAX         5
#endif

/*
 * The "reset int_modem" types; must match reset_modem_params table in
 * inc/na/cmd.h.
 */
#define RESET_INTMODEM_HARD	1
#define RESET_INTMODEM_SOFT	2

#define T1_DS0_INFO_SZ		(64+4)
#define PRI_B_INFO_SZ		(192+4)


/***************************************************
 * Added READ_AFD_CONFIG for Non-PRI IMAGES to
 * Allow the AFD subsystem to do its own parse
 * of the annex config file.
 ***************************************************/


/* parser configuration file parameters */
#define READ_GATEWAYS		0x0001
#define READ_ROTARIES		0x0002
#define READ_MACROS		0x0004
#define RESET_MACROS		0x0008
#define READ_SERVICES		0x0010
#define RESET_SERVICES		0x0020
#define READ_MODEM_TABLE	0x0040
#define RESET_MODEM_TABLE	0x0080
#define READ_DIALOUT_TABLE      0x0100
#define RESET_DIALOUT_TABLE     0x0200
#define READ_PRISPB             0x0400
#define READ_AFD_CONFIG         0x0800
#define READ_DNIS               0x1000
#define READ_DIGIMODEM_TABLE	0x2000
#define RESET_DIGIMODEM_TABLE	0x4000
#define READ_FILTERS		0x8000
#define READ_LOCALUSER         0x10000
#define RESET_LOCALUSER        0x20000 

#endif /* NETADMP_H */
