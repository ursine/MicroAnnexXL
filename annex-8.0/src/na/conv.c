/*
 *****************************************************************************
 *
 *        Copyright 1989,1990 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 * 	Network administrator command format conversion routines.
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *****************************************************************************
 */

/*
 *	Include Files
 */

#ifdef NA

/* This file must be first -- in the host NA only! */

#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/uio.h>
#include <syslog.h>
#else 
#include "../inc/port/xuio.h"
#include "../inc/rom/syslog.h"
#endif 

#include <fcntl.h>
#include <setjmp.h>
#include <ctype.h>
#else
#include "../inc/port/port.h"
#include "types.h"
#include "stdio.h"
#include "../netinet/in.h"
#include "netdb.h"
#include "strings.h"
#include "uio.h"
#include "setjmp.h"
#include "ctype.h"
#include "externs.h"
#include "../machine/endian.h"
#include "../inc/rom/syslog.h"
#endif

#include "../inc/na/na.h"
#include "../inc/na/iftype.h"
#include "../inc/na/server.h"
#include "../inc/na/na_selmods.h"
#include "../inc/erpc/netadmp.h"
#include "../na/conv.h"


/*
 *	Defines and Macros
 */

/*
 * Max # of elements, excluding NULL, of the arrays with corresponding prefix.
 * Shouldn't they be defined in term of sizeof(array_name) ?
 */
#define PS_MAX  23	/* port speed value index maximum */
#define TS_MAX  17	/* trunk speed value index maximum */
#define BPC_MAX 4	/* bits per character value index maximum */
#define SB_MAX  3	/* stop bits value index maximum */
#define P_MAX   3	/* parity value index maximum */
#define MC_MAX  4	/* modem control value index maximum */
#define PT_MAX  8	/* port type value index maximum */
#define PM_MAX  19	/* port mode value index maximum */
#define SEC_MAX 4	/* PPP security mode value index maximum */
#define FC_MAX  5	/* flow control value index maximum */
#define NS_MAX  4	/* name service value index maximum */
#define DLST_MAX 8	/* daylight savings time index max */
#define THIS_NET_RANGE_MAX  	0xfefe	/* this_net_range parameter maximum */

#define lower_case(x) 	(isalpha(x) ? (islower(x) ? x : tolower(x)) : x)

#define CHUNK_SZ	5
#define INVALID_POLL_VALUE -5
/*
 * TCP port definitions for dedicated ports.
 *
 * The first two (and all three on UMAX) should be obtained portably via
 * getservbyname(), but /etc/services is subject to local variation and
 * the Annex has fixed ideas as to what these ports are.
 */
#ifndef IPPORT_TELNET
#define IPPORT_TELNET		23
#endif
#ifndef IPPORT_LOGINSERVER
#define IPPORT_LOGINSERVER	513
#endif
#ifndef HRPPORT
#define HRPPORT			1027
#endif

#if NDPTG > 0
/*
 * Defines for the characters allowed in dptg_settings string
 */
#define	DPTG_LEN	16
#define	DPTG_SPLIT	8
#define	DPTG_CLI	"CcDE"
#define	DPTG_SLAVE	"SsTU"
#define	DPTG_ALL	"CcDESsTU"
#endif /* NDPTG */

/*
 *	External Routine Definitions
 */

#ifndef _WIN32
extern UINT32
	inet_addr();
extern char 
	*inet_ntoa(); 
#endif
extern int
	print_to_c(), str_to_inet(), matchit(), matchflag(),
	encode_rip_routers(), encode_box_rip_routers(), encode_nodeid(),
	decode_rip_routers(), decode_box_rip_routers(), decode_kerberos_list(),
	encode_zone(), encode_def_zone_list(), encode_kerberos_list(),
	str_to_mop_passwd();
extern void
	c_to_print(), decode_sequence(), decode_mask(), 
        decode_anxsyslog_mask(), decode_ppp_trace_lvl();
extern int
	trans_prompt();

extern int
	str_to_enet(),
#ifdef NA
        match(),
        match_flag();
void punt();
#else
        matchit(),
        matchflag();
#endif

	char * strtokNA();

#ifdef NA
/* Can't use prototypes for portability reasons. */
int validate_epd_address();
#else
int validate_epd_address(char *mp_addr);
#endif


/*
 *	Forward Routine Definitions
 */

UINT32
	parse_sequence(), parse_list();
unsigned short 
	parse_scap();
char	*lex_token();

static int  encode_enum();
static int  encode_range_ck();
static int  encode_string();
static int  encode_range_ckntp();

static void     decode_boolean();
static void     decode_enum();
static void     decode_string();
int lex();
/*
 *	Global Data Declarations
 */

#ifdef NA
static char *range_error = "number out of range, see Help: ";
#endif

/*
 * IMPORTANT: Do not forget to update the corresponding defines when
 * the arrays below are changed.
 */
static char   *ps_values[] =    /* port speed values */
    {
	/*NOSTR*/"default",
	/*NOSTR*/"50",
	/*NOSTR*/"75",
	/*NOSTR*/"110",
	/*NOSTR*/"134.5",
	/*NOSTR*/"150",
	/*NOSTR*/"200",
	/*NOSTR*/"300",
	/*NOSTR*/"600",
	/*NOSTR*/"1200",
	/*NOSTR*/"1800",
	/*NOSTR*/"2000",
	/*NOSTR*/"2400",
	/*NOSTR*/"3600",
	/*NOSTR*/"4800",
	/*NOSTR*/"7200",
	/*NOSTR*/"9600",
	/*NOSTR*/"19200",
	/*NOSTR*/"38400",
	/*NOSTR*/"57600",
	/*NOSTR*/"64000",
	/*NOSTR*/"76800",
	/*NOSTR*/"115200",
	/*NOSTR*/"56000",
	(char *)NULL
    };
static char *bpc_values[] =    /* bits per character values */
    {
	"default",
	/*NOSTR*/"5",
	/*NOSTR*/"6",
	/*NOSTR*/"7",
	/*NOSTR*/"8",
	(char *)NULL
    };
static char   *sb_values[] =   /* stop bits values */
    {
	"default",
	/*NOSTR*/"1",
	/*NOSTR*/"1.5",
	/*NOSTR*/"2",
	(char *)NULL
    };
static char   *p_values[] =    /* parity values */
    {"default", "none", "even", "odd", (char *)NULL};
static char   *mc_eib_values[] =    /* eib modem control values */
    {"default", "none", "flow_control","modem_control","both", (char *)NULL};
static char   *pt_values[] =    /* port type values */
    {"default", "hardwired", "dial_in", "x.25", "3270", "pc", "terminal",
     "printer", "modem", (char *)NULL};
static char   *sec_values[] =    /* port security mode values */
    {"default", "none", "pap", "chap", "chap-pap", (char *)NULL};
static char   *pm_values[] =    /* port mode values */
/*	0	  1	  2	    3		4	5 */
    {"default", "cli", "slave", "adaptive", "unused", "slip",
/*	6	    7	   8	    9            10           11 */
     "dedicated", "ppp", "arap", "printer","auto_detect", "auto_adapt",
/*     12      13     14       15         16        17        18   */
     "ndp",  "ipx", "call", "connect", "rlogin", "telnet", "tn3270",
/*     19     */
     "any", (char *)NULL};
#define P_DEDICATED 6	/* value must match "dedicated" in pm_values */
#define P_PPP 7		/* value must match "ppp" in pm_values */
#define P_ARAP 8	/* value must match "arap" in pm_values */
#define P_PRINTER 9	/* value must match "printer" in pm_values */
#define P_NDP 12	/* value must match "ndp" in pm_values */
#define P_IPX 13	/* value must match "ipx" in pm_values */
#define P_TELNET 17	/* value must match "telnet" in pm_values */
#define P_CALL 14	/* value must match "call" in pm_values */
#define P_CONNECT 15	/* value must match "connect" in pm_values */
#define P_TN3270 18	/* value must match "tn3270" in pm_values */
#define P_ANY 19	/* value must match "any" in pm_values */
static char   *duipm_values[] =    /* port mode values */
    {"default", "local", "remote", "dynamic", "none", (char *)NULL};

static char   *duifc_values[] =    /* dui flow control values */
    {"default", "cts", "disabled", "xon", (char *)NULL};

static char   *sess_mode_values[] =    /* dui session mode value */
    {"default", "interactive", "pasthru", "passall", "transparent", (char *)NULL};

static char   *dui_values[] =    /* dui user interface type */
    {"default", "uci", "vci", (char *)NULL};
static char   *t1_clock_values[] =
    {"default", "loop", "local", "external", (char *) NULL};
static char   *t1_framing_values[] =
    {"default", "esf", "d4", (char *) NULL}; 
static char   *t1_line_code_values[] =
    {"default", "b8zs", "ami", (char *) NULL};
static char   *t1_esf_fdl_values[] =
    {"default", "att", "ansi", (char *) NULL};
static char   *t1_buildout_values[] =
    {"default", "0dB", "7.5dB", "15dB", "22.5dB", (char *) NULL}; 
static char   *t1_mapping[] =
    {"default", "unused", "ds1_modem", "di_modem", "voice","data",(char *)NULL};
#define T1_MAP_DS1_MODEM 2 /* offset for ds1_modem above */
#define T1_MAP_DI_MODEM  3 /* offset for di_modem above */
static char   *t1_sig_proto[] =
    {"default", "none", "loop_start", "ground_start", "wink_start",
		"immediate_start",(char *)NULL};
static char   *t1_switch_type_values[] =
    {"default", "standard", "hk", "1aess", (char *)NULL};
static char   *fc_values[] =    /* flow control values */
    {"default", "none", "eia", "start/stop", "bell", "both", (char *)NULL};
static char   *ns_values[] =    /* name server values */
    {"default", "none", "ien_116", "dns", "bind", (char *)NULL};
static char   *dlst_values[] =    /* Daylight savings values */
    {"default", "us", "australian", "west_european", "mid_european",
     "east_european", "canadian", "british", "none", (char *)NULL};
/* These are used for compatibility with earlier (bad) spelling */
static char   *dlst_values_bad[] =    /* Daylight savings values */
    {"default", "usa", "australian", "west_europe", "mid_europe",
     "east_europe", "canadian", "great_britian", "none", (char *)NULL};
static char   *sf_values[] =    /* syslog facility values */
    {"default", "log_local0", "log_local1", "log_local2", "log_local3",
     "log_local4", "log_local5", "log_local6", "log_local7", (char *)NULL};

static char *ht_values[] = /* host table size keywords */
    {"default","none","unlimited", (char *)NULL};

static char *ipxfmy_values[] = /* IPX Frame Type values */
    {"raw802_3", "ethernetII", "802_2", "802_2snap", (char*)NULL };

static char *boolean_values[] = /* boolean values */
    {"yes","no", "true","false", "enabled","disabled",
     "on", "off", (char *) NULL};

static char *all_or_none_values[] =
    {"all", "none", "enabled", "disabled", (char *) NULL};

static char *ipso_values[] = /* ipso class values */
    {"none", "secret", "topsecret", "confidential", "unclassified", (char *)NULL};

static char *pridist_values[] =
    { "default", "0-25", "26-65", "66-100", "101-135", "136-165", "166-185",
	"186-210", (char *)NULL };

static char *pribuild_values[] =
    { "default", "0", "7", "15", "22", (char *)NULL };

static char   *prifdl_values[] =
    {"default", "ATT", "ANS", (char *) NULL};

static char *prianalog_values[] =
    { "default", "auto", "mu_law", "a_law", (char *)NULL };

static char *wan_framing_values[] = 
    {"default", "ESF", "D4", "DDF", "MFF_CRC4", "MFF_CRC4_G706", "OTHER", (char *) NULL}; 

static char   *wan_linecode_values[] =
    {"default", "B8ZS", "AMI", "HDB3", "JBZS", "ZBTSI", "OTHER", (char *) NULL};

static char *wan_sig_proto[] = {
  "default", "none", "loop_bi", "gnd_bi", "wink_bi",
                     "loop_in", "gnd_in", "wink_in", "imm_in",
                     "loop_out", "gnd_out", "wink_out", "imm_out",
  "r1_bi", "r1_in", "r1_out", "r2_bi", "r2_in", "r2_out",
  "p7_bi", "p7_in", "p7_out",
  (char *)NULL };

#define SIZE_SWPROTO_TAB 22
static u_short wan_sig_proto_table[]  = {
    0x0000, 0x0101, 0x0202, 0x0303, 0x0404,
                    0x0201, 0x0301, 0x0401, 0x0501,
                    0x0102, 0x0103, 0x0104, 0x0105,
    0x0606, 0x0601, 0x0106, 0x0707, 0x0701, 0x0107,
    0x0808, 0x0801, 0x0108,
    0x0000 };

static char *mp_values[] = /* mp endpoint discriminator values */
    {"default", "null", "local", "ip", "mac", "magic", "psndn", (char *)NULL};

static char *addr_origin_values[] = 
    {"default", "auth_server", "local", "dhcp", "acp","ippool", (char *)NULL};

static char *rip_horizon_values[] = {
  "default", "off", "split", "poison", (char *)NULL };

static char *rip_nexthop_values[] = {
  "default", "never", "needed", "always", (char *)NULL
};


static char *busysig_values[] = {
  "default", "00", "01", "10", "11", (char *)NULL
};

static char *banner_values[] = {
  "default", "none", "before_sec", "after_sec", "motd_before_sec", "motd_after_sec", "yes", "unset", (char *)NULL};

static char *igmp_version_values[] = {
  "default", "off", "1", "2", (char *)NULL
};

static char *rtable_size_values[] = {
  "default", "1", "2", "4", "8", (char *)NULL
};

static char *route_pref_values[] = {
  "default", "rip", "ospf", (char *)NULL
};

static char *ospf_areatype_values[] = {
  "default", "stub", "nssa", (char *)NULL
};

static char *ospf_authtype_values[] = {
  "default", "none", "simple", "md5", (char *)NULL
};


static char *auth_protocol_values[] =
    {"default", "acp", "radius", (char *)NULL };   
                                    /* if the indices change then you need to
                                       change the enum in conv.h
                                     */

static char *rad_acct_level_values[] = 
 {"default", "standard", "advanced", "basic", (char *)NULL}; 
				      /*if the indices change then you need to
                                        change the enum in conv.h
                                       */

static char *rad_port_encoding_values[] = 
    {"default", "device", "channel", (char *)NULL};  
                                      /* if the indices change then you need to
                                         change the enum in conv.h
                                       */  

static char *compat_mode_values[] =
    {"default", "BayNetworks", "USR", "Ascend", (char *)NULL };   
                                    /* if the indices change then you need to
                                       change the enum in conv.h
                                     */

static char * rad_acct_dest_values[] =
    {"acct_server", "both", (char *)NULL };

static char * def_autod_mode_values[] =
{"cli","ppp", (char *)NULL};

#define FAC_BASE (((LOG_LOCAL0) >> 3) - 1)
#define FAC_HIGH ((LOG_LOCAL7) >> 3)

#define PPP_MRU_MIN	64
#define PPP_MRU_MAX	1600
#define PPP_MRU_DEF	1500
#define MP_MRRU_MAX	1600
#define BML_LEN		8
#define NONE	1
#ifndef ALL
#define ALL	(~0)
#endif
#ifdef NA
static char   *ts_values[] =    /* trunk speed values */
    {
    "default", "150", "200", "300", "600", "1200", "1800", "2000",
    "2400", "3600", "4800", "7200", "9600", "19200", "38400", "48000",
    "56000", "64000", (char *)NULL
    };
#endif	/* NA */

extern char oct_digits[];
extern char hex_digits[];
extern struct mask_options syslog_levels[];
extern struct mask_options serv_options[];
extern struct mask_options selectable_mods[];
extern struct mask_options ncp_options[];
extern struct mask_options ppp_trace_lvl_options[];

#define SYSLOG_ALL	0xff



/* Check for autobaud string.  This should be case-insensitive, but ... */
static int
is_autob(str,len)
char *str;
int len;
{
	if (len <= 0)
		return 0;
	return	strncasecmp(str,"autobaud",len)==0;
}

int
convert_long_hex(external,longp)
char *external;			/*  external representation (for human) */
u_long *longp;			/*  internal representation (for Annex) */
{
  int low,indx,length,factor,num;
  u_long sum;
  char c;

  if (external[0] == '0' && external[1] == 'x')
    low = 2;
  else
    low = 0; 
  length = strlen(external);
  if ((indx = length) - (int)low > 8)
    return 1;
  for (factor = 1, sum = 0; indx > (int)low; indx--, factor *= 0x10) {
    c = external[indx-1];
    if (isupper(c)) 
      num = (u_char)c - (u_char)'A' + 10;
    else if (islower(c))
      num = (u_char)c - (u_char)'a' + 10;
    else if (isdigit(c))
      num = (u_char)c - (u_char)'0';
    else
      return 2;
    sum += factor * num; 
  }
  *longp = sum;
  return 0;
}

/*  Human to machine conversion */


#ifdef NA
void
#else
int
#endif
encode(conversion, external, internal, Pannex_id)

int  conversion;		/*  type of conversion to be performed	*/
char *external;			/*  external representation (for human) */
char *internal;			/*  internal representation (for Annex) */
ANNEX_ID *Pannex_id;		/*  Annex converting to			*/
{
	INTERN		Internal;	/*  union of pointers to types	*/
	int		length = 0,	/*  length of a string		*/
			max_length,	/*  maximum string length	*/
			err,		/*  error flag			*/
			flag,		/*  flag for cvn_ht		*/
			i, j,
			indx;		/*  index to array of (char *)	*/
	char		*ptr, c;
	u_char          low;
	int		Sinternal_int;
#ifdef NA
	u_short		group,
			disable = 0,
			enable = 0,
			loop;
	u_char		high;
	int		low_int;
#endif

	UINT32	 	sum,factor;
	u_char		num;

	num = err = 0;

	Cinternal = internal;	/*  move to pointer to various types	*/
	length = strlen(external);

	/*  Perform conversion from external to internal formats	*/

	switch(conversion)
	{
	    case CNV_PRINT:

		err = print_to_c(external, Sinternal);
		break;

            case CNV_DFT_Y:     /* Note the use of fall-through here */
            case CNV_DFT_ON:
                num = 1;
            case CNV_DFT_N:
            case CNV_DFT_OFF:
                indx = match(external, boolean_values, "boolean value");
                /* No match in table */
                if (indx < 0) 
                   punt("Invalid boolean value.", external);
                /*
                 * An odd valued indx indicates "no".
                 */
                else if (indx & 0x01)
                   *Sinternal = num;
                else
                   *Sinternal = !num;
                break;

            case CNV_DFT_ALL:   /* Note the use of fall-through here */
                num = 1;
            case CNV_DFT_NONE:
                indx = match(external, all_or_none_values, "boolean value");
                /* No match in table */
                if (indx < 0) 
                   punt("Invalid boolean value.",(char *)0);
                /*
                 * An even valued for indx indicates "all".
                 */
                else if (indx & 0x01)
                   *Sinternal = num;
                else
                   *Sinternal = !num;
                break;

	    case CNV_BYTE:

		if (encode_range_ck(Sinternal, external, 1, 255, 1)) {
			punt(range_error, external);
		}
		break;

	    case CNV_BYTE_ZERO_OK:

		if (encode_range_ck(Sinternal, external, 0, 255, 0)) {
			punt(range_error, external);
		}
		break;

 	     case CNV_NTP_TIMER:
                if (encode_range_ckntp(Sinternal, external, 10, 14, 0)) {
#ifdef NA
                        punt(range_error, external); 
#else
			return INVALID_POLL_VALUE;
#endif
                }
                break;

        case CNV_OSPF_ACTIVEMD5:
        if (encode_range_ck(Sinternal, external, 1, 2, 1)) {
            punt(range_error, external);
        }
        break;

        case CNV_NFAS_INT_ID:

        if (encode_range_ck(Sinternal, external, 0, 19, 0)) {
            punt(range_error, external);
        }
        break;

        case CNV_NFAS_BACKUP_ID:

        if (encode_range_ck(Sinternal, external, 1, 19, 1)) {
            punt(range_error, external);
        }
        break;
 
       	case CNV_INT:

		if (encode_range_ck(Sinternal, external, 0, 65535, 0)) {
			punt(range_error, external);
		}
		break;

	    case CNV_PROMPT:
		if ((err = trans_prompt(external, TRUE)) < 0)
			break;
		/* fall through to normal string processing */
            case CNV_OSPF_AUTHKEY:
                err = encode_string(external, MAX_STRING_8, Internal);
                if (err != 0)
                  punt("string too long",NULL);
                break;
            case CNV_OSPF_MD5K:
                if (strlen(external) && strlen(external) < MAX_E2_STRING)
                   {
                   punt("string is shorter than expected",NULL);
                   }
                else
                   {
                   err = encode_string(external, MAX_E2_STRING, Internal);
                   } 
                if (err != 0)
                  punt("string is longer than expected",NULL);
                break;

	    case CNV_STRING:
                err = encode_string(external, MAX_E2_STRING, Internal);
		if (err != 0)
		  punt("string too long",NULL);
		break;

            

 	    case CNV_STRING_NTP:
                if (!( strcmp(external,"u")&&strcmp(external,"m")&&strcmp(external,"b"))) {
                err = encode_string(external, MAX_E2_STRING, Internal);
                if (err != 0)
                  punt("string too long",NULL);
                } else {
                  punt(" only unicast, broadcast and multicast modes allowed",NULL);
                }
                break;

 	    case CNV_STRING_PREFSERVER:
                if(check_pref_server(external)) {
                err = encode_string(external, MAX_E2_STRING, Internal);
                if (err != 0)
                  punt("string too long",NULL);
                } else {
                  punt("string too long",NULL);
		}
                break;
 
	    case CNV_PROMPT_32:
		if ((err = trans_prompt(external, FALSE)) < 0)
			break;
		/* fall through to string processing */
    case CNV_STRING_100:
        
		if (Pannex_id->hw_id < MIN_HW_FOR_LONG)
		    max_length = SHORTPARAM_LENGTH;
		else if (Pannex_id->hw_id == ANX3 ||
                 Pannex_id->hw_id == ANX_MICRO ||
                 Pannex_id->hw_id == ANX_MICRO_ELS ||
                 Pannex_id->hw_id == ANX_PRIMATE) {
		    max_length = (conversion == CNV_PROMPT_32) ?
		    	MAX_ADM_STRING : MAX_STRING_100;
		}
		else
		    max_length = LONGPARAM_LENGTH;

        err = encode_string(external, max_length, Internal);
		if (err != 0)
            punt("string too long",NULL);
		break;
        
    case CNV_STRING_120:
        
		if (Pannex_id->hw_id < MIN_HW_FOR_LONG)
		    max_length = SHORTPARAM_LENGTH;
		else if (Pannex_id->hw_id == ANX3 ||
                 Pannex_id->hw_id == ANX_MICRO ||
                 Pannex_id->hw_id == ANX_MICRO_ELS ||
                 Pannex_id->hw_id == ANX_PRIMATE)
		    max_length = MAX_STRING_120;
		else
		    max_length = LONGPARAM_LENGTH;
        
        err = encode_string(external, max_length, Internal);
		if (err != 0)
            punt("string too long",NULL);
		break;
        
    case CNV_STRING_128:
        
		if (Pannex_id->hw_id < MIN_HW_FOR_LONG)
		    max_length = SHORTPARAM_LENGTH;
		else if (Pannex_id->hw_id == ANX3 ||
                 Pannex_id->hw_id == ANX_MICRO ||
                 Pannex_id->hw_id == ANX_MICRO_ELS ||
                 Pannex_id->hw_id == ANX_PRIMATE)
		    max_length = MAX_STRING_128;
		else
		    max_length = LONGPARAM_LENGTH;
        
        err = encode_string(external, max_length, Internal);
		if (err != 0)
            punt("string too long",NULL);
		break;
        
    case CNV_STRING_NOSPACE:
		if (index(external,' '))
            err = -1;
		else
            err = encode_string(external, MAX_E2_STRING, Internal);
		if (err != 0)
            punt("string too long",NULL);
		break;
        
    case CNV_ATTN:
		for (i = 0, j = 0; external[i] != '\0'; i++, j++) {
		  if (j >= MAX_E2_STRING) {
#ifdef NA
		    printf("\tWarning:  String parameter truncated to %d characters.\n",
			   max_length);
#else
		    punt("converted string too long; max 16 characters",0);
#endif
		    break;
		  }
		    if (external[i] == '^' && external[i+1] != '\0') {
		        if (external[i+1] == '?') 
			    CS_string[j] = RIP_LEN_MASK;
			else if (external[i+1] == '@')
			    CS_string[j] = (char)0x80;
		        else 
			    CS_string[j] = external[i+1] & 0x1f;
			i++;
		    } else {
		        if (external[i] == '\\' && external[i+1] != '\0')
			    i++;
			CS_string[j] = external[i];
		    }
		}
		CS_length = j;
		break;

#if NDPTG > 0
	    case CNV_DPTG:
		/*
		 * Special case a zero length string
		 */
		if(length == 0){
			CS_length = 0;
			(void)strcpy(CS_string, /*NOSTR*/"");
			break;
		}

		/*
		 * Otherwise we must have exactly DPTG_LEN characters
		 */
		if(length != DPTG_LEN){
			printf("\tString must be empty or of length %d",
								DPTG_LEN);
			punt((char *)NULL,(char *)NULL);
		}

		/*
		 * It's correct length, so check to see if
		 * the characters are acceptable ones.
		 */
		if((char *)index(DPTG_CLI,external[0]) == (char *)NULL){
			punt("First character must be one of: ",DPTG_CLI);
		}

		for(indx = 1; indx < DPTG_SPLIT; indx++){
			if((char *)index(DPTG_ALL,external[indx]) == (char *)NULL){
				printf("\tCharacter %d must be one of ",indx+1);
				punt((char *)NULL,DPTG_ALL);
			}
		}

		for(indx = DPTG_SPLIT; indx < DPTG_LEN; indx++){
			if((char *)index(DPTG_SLAVE,external[indx]) == (char *)NULL){
				printf("\tCharacter %d must be one of ",indx+1);
				punt((char *)NULL,DPTG_SLAVE);
			}
		}

		CS_length = length;
		(void)strcpy(CS_string, external);
		break;
#endif /* NDPTG */

	    case CNV_FC:

		indx = match(external, fc_values, "flow_control value");
		if (indx < 0)
			err = -1;
		else if (
		    (Pannex_id->flag == ANX_MICRO_V11 &&
			(indx == 2 || indx == 5)) ||
		    ((Pannex_id->hw_id == ANX_II ||
		     Pannex_id->hw_id == ANX_II_EIB) &&
			indx == 5))
			punt("Invalid flow_control value", (char *)0);

		*Sinternal = (unsigned short)(indx);
		break;

            case CNV_DUIFC:

                err = encode_enum(external, duifc_values,
                                  "flow_control value", Internal);
                break;

            case CNV_SESS_MODE:
                err = encode_enum(external, sess_mode_values,
                                  "session_mode value", Internal);
                break;

            case CNV_USER_INTF:
                err = encode_enum(external, dui_values,
                                  "user_interface value", Internal);
                break;

            case CNV_IPSO_CLASS:
                err = encode_enum(external, ipso_values,
                                  "ipso_class value", Internal);
                break;

            case CNV_IPX_FMTY:
                err = encode_enum(external, ipxfmy_values,
                                  "ipx_frame_type value", Internal);
                break;
           
            case CNV_RAD_ACCT_DEST:
                err = encode_enum(external, rad_acct_dest_values,
                                "rad_acct_dest values", Internal);
                break;

	    case CNV_BML:
		  
		if (external[0] == '0' && external[1] == 'x')
		  low = 2;
		else
		  low = 0; 
		if ((indx = length) - (int)low > BML_LEN)
                  punt("Incorrect format for PPP_acm bit mask.",(char *)0);
		for (factor = 1, sum = 0;

		     indx > (int)low;
		     indx--, factor *= 0x10) {
		  c = external[indx-1];
		  if (isxdigit(c)) {
		    if (isupper(c)) 
		      num = (u_char)c - (u_char)'A' + 10;
		    else if (islower(c))
		      num = (u_char)c - (u_char)'a' + 10;
		    else if (isdigit(c))
		      num = (u_char)c - (u_char)'0';
		    sum += factor * num; 
		  }
		  else
                    punt("Invalid character in PPP_acm bit mask.",(char *)0);
		}
		*Linternal = sum;
#ifndef NA
		*Linternal = htonl(*Linternal);
		*Sinternal = htons(*Sinternal);  /* gets switched back below */
#endif
		break;

	    case CNV_NET_Z:

		err = str_to_inet(external, Linternal, TRUE, 1);
		if (err)
		    punt("invalid parameter value: ", external);
#ifndef NA
		*Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
		break;


	    case CNV_NET:

		err = str_to_inet(external, Linternal, FALSE, 1);
		if (err)
		    punt("invalid parameter value: ", external);
#ifndef NA
		*Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
		break;

            case CNV_ENET_ADDR:

                err = str_to_enet(external, Linternal);
		if (err)
		    punt("invalid parameter value: ", external);
#ifndef NA
                *Sinternal = htons(*Sinternal); /* gets switch back below */
#endif
                break;

	    case CNV_MOP_PASSWD:

		err = str_to_mop_passwd(external, Linternal);
		if (err)
		    punt("invalid parameter value: ", external);
#ifndef NA
		*Sinternal = htons(*Sinternal); /* gets switch back below */
#endif
		break;

	    case CNV_PS:

		flag = 0;
		ptr = (char *)index(external,'/');
		if (ptr != (char *)NULL)
			if (is_autob(external,ptr-external)) {
				flag = 0x80;
				ptr++;
				}
			else if (is_autob(ptr+1,strlen(ptr+1))) {
				flag = 0x80;
				*ptr = '\0';
				ptr = external;
				}
			else
				punt("invalid speed value: ",external);
		else if (is_autob(external,length)) {
			*Sinternal = (unsigned short)0xff;
			break;
			}
		else
			ptr = external;

		indx = match(ptr, ps_values, "speed value");
		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)(indx | flag);
		break;

            case CNV_BPC:
                err = encode_enum(external, bpc_values,
                                  "data_bits value", Internal);
                break;

            case CNV_SB:

                err = encode_enum(external, sb_values,
                                  "stop_bits value", Internal);
                break;

            case CNV_P:
                err = encode_enum(external, p_values,
                                  "parity value", Internal);
                break;

            case CNV_DEF_AUTOD_MODE:
                err = encode_enum(external, def_autod_mode_values,
                                  "default autodetect mode", Internal);
                if (err == -1)
                     punt("invalid default_autodetect_mode value", external);
                break;

	    case CNV_MC:
		indx = match(external,mc_eib_values,
			"control_lines value");
		if (indx == 4 &&
		    Pannex_id->hw_id != ANX_II_EIB &&
		    Pannex_id->hw_id != ANX3 &&
		    Pannex_id->hw_id != ANX_MICRO &&
		    Pannex_id->hw_id != ANX_MICRO_ELS &&
		    Pannex_id->hw_id != ANX_PRIMATE)

			punt("invalid control_lines value: ",external);

		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)(indx);
		break;

            case CNV_PT:
                err = encode_enum(external, pt_values,
                                  "type value", Internal);
                break;

	    case CNV_PM:

		indx = match(external, pm_values, "mode value");

#ifndef NA
                /* if not in pm_values, check duipm_values */
                if (indx < 0) {
                    indx = match(external, duipm_values, "access value");
                }
#endif

		/* get standardized version number for later comparison */
		convert_version(Pannex_id->sw_id, &Pannex_id->version);

		/* Check for platforms without PPP */
		if (indx == P_PPP &&
		    (Pannex_id->hw_id == ANX_II ||
		     Pannex_id->hw_id == ANX_II_EIB ||
		     Pannex_id->hw_id == ANX_MICRO_ELS))
			punt("invalid mode value: ",external);

		if ((indx == P_DEDICATED || indx == P_NDP ||
		     indx == P_IPX) &&
		    Pannex_id->hw_id == ANX_PRIMATE)
			punt("invalid mode value: ",external);

		/* disable IPX and NDP modes */
		if ((indx == P_IPX || indx == P_NDP) &&
		    Pannex_id->version >= VERS_RUSHMORE)
			punt("invalid mode value: ",external);

		/* disable arap, call, connect, printer, tn3270 from V15.0 and later */
		if ( ((indx == P_ARAP) || (indx == P_CALL) || (indx == P_CONNECT) ||
		      (indx == P_PRINTER) || (indx == P_TN3270)) &&
		    (Pannex_id->version >= VERS_15_0))
			punt("invalid mode value: ",external);

		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)(indx);
		break;

            case CNV_MRU:

		if (encode_range_ck(Sinternal, external, PPP_MRU_MIN,
				    PPP_MRU_MAX, PPP_MRU_DEF)) {
			punt(range_error, external);
		}
		break;

            case CNV_MRRU:

		if (encode_range_ck(Sinternal, external, 0, MP_MRRU_MAX,
				    PPP_MRU_DEF) ||
		    (*Sinternal != 0 && *Sinternal < PPP_MRU_MIN)) {
			punt(range_error, external);
		}
		break;

            case CNV_SEC:
                err = encode_enum(external, sec_values,
                                  "ppp_security_protocol value", Internal);
                break;

	    case CNV_NS:
		indx = match(external, ns_values, "name server value");
		/* Map "bind" to "dns". */
		if (indx == 4)
		    indx = 3;
		else if (indx < 0)
		    err = -1;
		*Sinternal = (unsigned short)(indx);
		break;

	    case CNV_PORT:
		if (encode_range_ck(Sinternal, external,
					0, Pannex_id->port_count, 0))
			punt(range_error, external);
		break;

	    case CNV_IPPORT:
		if (encode_range_ck(Sinternal, external,
					1025, 32767, 0))
			punt(range_error, external);
		break;

	    case CNV_SMETRIC:

                if (encode_range_ck(Sinternal, external,
                                        1, 15, 1))
                        punt(range_error, external);
                break;

	    case CNV_HT:

#ifdef NA
		if(Pannex_id->version < VERS_5) {
		    if (isdigit(*external)) {
			*Sinternal = (unsigned short)(atoi(external) / 2);
		    }
		    else {
			punt("invalid non-numeric value: ", external);
		    }
		}
		else
#endif
		{
		    if (isdigit(*external)) {
			if (encode_range_ck(Sinternal, external, 1, 250, 64))
			    punt(range_error, external);
		    }
		    else { 
			indx = match(external, ht_values, "host table value");
			if (indx < 0)
				err = -1;
			switch (indx) {
			    case 1:		/*none*/
				*Sinternal = (unsigned short)HTAB_NONE;
				break;
			    case 2:		/*unlimited*/
				*Sinternal = (unsigned short)HTAB_UNLIMITED;
				break;
			    case 0:		/*default*/
			    default:
			    	*Sinternal = (unsigned short)0;
				break;
			}
		    }
		}
		break;

	    case CNV_MS:

                if (!strcasecmp(external,"none")) {
                        *Sinternal = 16;
                } else if (encode_range_ck(Sinternal, external, 1, 16, 3)) {
			punt(range_error, external);
		}

		break;

	    case CNV_SEQ:

		*Linternal = parse_sequence(external, Pannex_id->port_count);
		if (*Linternal == (UINT32) -1)
			err = -1;
#ifndef NA
		*Sinternal = htons(*Sinternal);  /* gets switched back below */
#endif
		break;

	    case CNV_IPENCAP:

		indx = match_flag(external, "ethernet", "ieee802",
			   "IP encapsulation type", 0);
		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)(indx);
		break;

	    case CNV_RNGPRI:

		Sinternal_int = atoi(external);
		if ((Sinternal_int < 0) || (Sinternal_int > 3))
			punt ("invalid priority selection, see Help",
				(char *)0);
		*Sinternal = (u_short)Sinternal_int;
		break;

	    case CNV_SCAP:

		*Sinternal = (unsigned short) parse_list(external,
					serv_options);
		if (*Sinternal == (unsigned short) -1)
		    err = -1;
		break;

	    case CNV_SELECTEDMODS:
		if (*external == '\0')
		  Sinternal_int = -1;
		else
		  Sinternal_int = parse_list(external,selectable_mods);

		if (Sinternal_int == -1 || Sinternal_int == 0)
		  err = -1;
		else {
		  Sinternal[0] = Sinternal_int&0xFFFF;
		  Sinternal[1] = (Sinternal_int>>16)&0xFFFF;
		  if (Sinternal[0] == 0)
		    Sinternal[0] = OPT_SELEC_NONE;
#ifndef NA
		  Sinternal[1] = htons(Sinternal[1]);
#endif
		}
		break;

	    case CNV_SYSLOG:

		*Sinternal = (unsigned short) parse_list(external,
		      		syslog_levels);
		if (*Sinternal == (unsigned short) -1)
		                err = -1;
		break;

	    case CNV_SYSFAC:

		if(isdigit(*external)) {
			if (encode_range_ck(Sinternal, external, 0, 255, -1)) {
				punt(range_error, external);
			}
		} else if(!strcasecmp(external,"default")) {
			*Sinternal = (unsigned short)-1;
		} else {
			indx = match(external, sf_values,
				    "syslog facility code");
		        if (indx < 0)
		        	err = -1;
			*Sinternal = (unsigned short)(indx + FAC_BASE);
		}

		(*Sinternal)++;
		break;

	    case CNV_VCLILIM:

		if(isdigit(*external)) {
			*Sinternal = (unsigned short)atoi(external);
			if(*Sinternal > 254)
				punt("invalid max_vcli: ", external);
			if(*Sinternal == 0)
				*Sinternal = 255;
		}
		else if(!strncasecmp(external, "default", length)
		     || !strncasecmp(external, "unlimited", length))
			*Sinternal = 0;
		else
			punt("invalid max_vcli: ", external);
		break;

	    case CNV_DLST:

		indx = match(external, dlst_values, NULL);
		if (indx < 0) {
			indx = match(external, dlst_values_bad, "Daylight Savings Time");
			if (indx < 0)
				err = -1;
			}
#ifdef NA
		if(Pannex_id->version < VERS_5 && indx >= DLST_MAX) {
		    if (!strncasecmp(external, "great_britian", length) ||
		        !strncasecmp(external, "british", length)) {
			punt("invalid option on annex software: ", external);
		    }
		    else {
			indx = DLST_MAX - 1;
		    }
		}
#endif
		*Sinternal = (unsigned short)(indx);
		break;

	    case CNV_NET_TURN:

		if (encode_range_ck(Sinternal, external, 1, 255, 0))
			punt(range_error, external);
		break;

	    case CNV_TZ_MIN:
		if (encode_range_ck(Sinternal, external, -900, 900, 0))
			punt(range_error, external);
		(*Sinternal)++;
		break;

	    case CNV_ZERO_OK:

		if((isdigit(*external)) ||
		            (*external == '-' && isdigit(external[1])))
			*Sinternal = (unsigned short)(atoi(external) + 1);
		else
		{
			if(!strncasecmp(external,"default", length))
			    *Sinternal = 0;
			else
			    punt("invalid value: ", external);
		}
		break;

	    case CNV_RESET_IDLE:

		indx = match_flag(external, "input", "output",
			   "reset idle time", 0);
		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)indx;
		break;

	    case CNV_DPORT:
		if(!strncasecmp(external, "default", length) ||
		   !strncasecmp(external, "telnet", length))
		    *Sinternal = 0;
		else if(!strncasecmp(external, "rlogin", length) ||
			!strncasecmp(external, "login", length))
		    *Sinternal = IPPORT_LOGINSERVER;
		else if(!strncasecmp(external, "call", length) ||
			!strncasecmp(external, "mls", length))
		    *Sinternal = HRPPORT;
		else
		{
		  if (encode_range_ck(Sinternal, external, 1, 65535, 0)) {
			punt(range_error, external);
		      }
		}
		break;

	    case CNV_INT0OFF:
	    case CNV_INT5OFF:
		if (!strncasecmp(external, "off", length))
		  *Sinternal = 0;
		else if (encode_range_ck(Sinternal, external, 0, 255, 0)) {
		  punt(range_error, external);
		}
		break;

	    case CNV_INACTCLI:
		if (!strncasecmp(external, "off", length))
		  *Sinternal = 0;
		else if (!strncasecmp(external, "immediate", length))
		  *Sinternal = 255;
		else if (encode_range_ck(Sinternal, external, 0, 254, 0)) {
		  punt(range_error, external);
		}
		break;

	    case CNV_INACTDUI:
		if (encode_range_ck(Sinternal, external, 1, 255, 30))
		    punt(range_error, external);
		break;

	    case CNV_RBCAST:
		indx = match_flag(external, "port","network",
					"broadcast direction value",0);
		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)indx;
		break;

	    case CNV_PTYPE:
		indx = match_flag(external, "centronics", "dataproducts",
				   "printer type value", 0);
		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short)indx;
		break;
		
	    case CNV_PSPEED:
		indx = match_flag(external, "normal", "high_speed",
				"printer speed value", 0);
		if (indx < 0)
			err = -1;
		*Sinternal = (unsigned short) indx;
		break;

	    case CNV_HOST_NUMBER:

		if (encode_range_ck(Sinternal, external, 0, 32767, 42))
		    punt(range_error, external);
		break;

	    case CNV_SERVICE_LIMIT:

		if (encode_range_ck(Sinternal, external, 16, 2048, 256))
		    punt(range_error, external);
		break;

	    case CNV_KA_TIMER:

		if (encode_range_ck(Sinternal, external, 10, 255, 20))
		    punt(range_error, external);
		break;

            case CNV_MULTI_TIMER:

                if (encode_range_ck(Sinternal, external, 10, 180, 30))
                    punt(range_error, external);
                break;

	    case CNV_CIRCUIT_TIMER:

		if (encode_range_ck(Sinternal, external, 1, 25, 8))
		    punt(range_error, external);
		break;

	    case CNV_RETRANS_LIMIT:

		if (encode_range_ck(Sinternal, external, 4, 120, 8))
		    punt(range_error, external);
		break;

	    case CNV_QUEUE_MAX:

		if (!strcasecmp(external,"none")) {
		    *Sinternal = (unsigned short) 255;
                } else {
		    if (encode_range_ck(Sinternal, external, 1, 255, 4))
		        punt(range_error, external);
		}
		break;

            case CNV_PASSLIM:

		if (!strcasecmp(external,"none")) {
		    *Sinternal = (unsigned short) 10;
                } else {
		    if (encode_range_ck(Sinternal, external, 0, 10, 3))
                        punt(range_error, external);
		}
                break;

            case CNV_ADM_STRING:
                err = encode_string(external, MAX_ADM_STRING, Internal);
		if (err != 0)
		  punt("string too long",NULL);
                break;

            case CNV_IPX_STRING:
                err = encode_string(external, MAX_IPX_STRING, Internal);
		if (err != 0)
		  punt("string too long",NULL);
                break;

            case CNV_STRING_P_120:
                err = encode_string(external, MAX_STRING_120, Internal);
		if (err != 0)
		  punt("string too long",NULL);
                break;

	    case CNV_LG_SML:

		if(!strncasecmp(external, "small", length) ||
		   !strncasecmp(external, "default", length)) {
		    *Sinternal = (unsigned short)(0x0);
		}
		else {
		    if(!strncasecmp(external, "large", length)) {
			*Sinternal = (unsigned short)(0x1);
		    }
		    else {
			err = -1;
			punt("invalid size value: ", external);
		    }
		}
		break;

#ifdef NA
	    case CNV_GROUP_CODE:
{	
		u_short shortcut = FALSE;	
   		eos = 0;
		bzero(internal, LAT_GROUP_SZ);
		Psymbol = external;
		(void)lex();
		while (!eos) {

			if (enable || disable) {
				punt ("command syntax error, see Help",
						(char *)0);
			}

			if (strncasecmp(symbol, "enable", strlen(symbol)) == 0) {
                                if (shortcut == NONE)
			           disable = 1;
                                else
				   enable=1;
                                shortcut = FALSE;
				(void)lex();
				continue;
			}

			if (strncasecmp(symbol, "disable", strlen(symbol)) == 0) {
				if (shortcut == NONE)
                                   enable = 1;
                                else
				   disable=1;
                                shortcut = FALSE;
				(void)lex();
				continue;
			}

			if (symbol[0] == ',') {
				(void)lex();
				continue;
			}

			if (strcasecmp(symbol, ALL_STR) == 0) {
				(void)lex();
				for(group = 0; group < LAT_GROUP_SZ; group++) {
				    internal[group] = (char)0xff;
				}
                                shortcut = ALL;

			} else if (strcasecmp(symbol, NONE_STR) == 0) {
				(void)lex();
				for(group = 0; group < LAT_GROUP_SZ; group++) {
				    internal[group] = (char)0xff;
                                }
                                shortcut = NONE;
			} else {
				low_int = atoi(symbol);
				if ((low_int < 0) || (low_int > 255)) {
					punt ("number out of range, see Help",
						(char *)0);
				}
				low = (u_short)low_int;
				(void)lex();

				if (symbol[0] == '-') {
				  int             high_int;

				    (void)lex();
				    high_int = atoi(symbol);
				    if ((high_int < 0) || (high_int > 255)) {
					punt ("number out of range, see Help",
						(char *)0);
				    }
				    high = (u_short)high_int;
				    (void)lex();

				    for (loop = low; loop <= high; loop++) {
					SETGROUPBIT(internal,loop);
				    }
				} else {
				    SETGROUPBIT(internal,low);
				}
			}
		}
                if (shortcut )
		   if (shortcut == NONE)
			disable = TRUE;
		   else
			enable = TRUE;
		if (!enable && !disable) {
			punt ("command syntax error - format of command is:\n set <ann | port>  <param name> <all | none | group range> <enable | disable>\n see Help", (char *)0);
		}
		if (enable) {
			internal[LAT_GROUP_SZ] = TRUE;
		} else {
			internal[LAT_GROUP_SZ] = FALSE;
		}

		break;
}
#endif

	    case CNV_HIST_BUFF:

		if (encode_range_ck(Sinternal, external, 0, 32767, 0))
		    punt(range_error, external);
		break;

            case CNV_PPP_NCP:
		*Sinternal = (unsigned short) parse_list(external,
					ncp_options);
		if (*Sinternal == (unsigned short) -1) {
			err = -1;
			punt("invalid protocol type: ", external);
		   }
		break;

            case CNV_PPP_TRACE_LVL:
		*Sinternal = (unsigned short) parse_list(external,
					ppp_trace_lvl_options);

		if (*Sinternal == (unsigned short) -1) {
			err = -1;
			punt("invalid trace level: ", external);
		
		/* Check for at least Control or Data if Hex set */
		} else 	if ((*Sinternal & PPTRC_HEX) 
			&&  (*Sinternal & (PPTRC_CNTL|PPTRC_DATA)) == 0) {
			err = -1;
			punt("must set Control or Data: ", external);
		}
		break;

	    case CNV_ARAP_AUTH:

		if (!strncasecmp(external, "none", length))
		    *Sinternal = (unsigned short)(1);

		else if (!strncasecmp(external, "des", length))
		    *Sinternal = (unsigned short)(2);

		else 
		    punt("invalid parameter value : ", external);

		break;

	    case CNV_A_BYTE:
		if (encode_range_ck(Sinternal, external, 0, 253, 0))
		    punt(range_error, external);
		break;

	    case CNV_ZONE:
		if ((err = encode_zone( external, internal)) != 0)
		  if (err == -1)
		    punt("Zone name too long", (char *)0);
                  else
		    punt("Invalid character in this parameter : ",external);
                break;
                 
		
	    case CNV_DEF_ZONE_LIST:

		err = encode_def_zone_list(external, internal);
		switch (err) {
		    case -1:
			punt("Default zone list too long", (char *)0);
			break;
		    case -2:
			punt("Invalid character in this parameter : ",external);
			break;
		    case -3:
			punt("Default zone name too long", (char *)0);
			break;
		    default:
			break;
		}
		break;

	    case CNV_THIS_NET_RANGE:
		err = encode_nodeid(external, internal);
		switch (err) {
		    case -1:
			punt("Incorrect format for this parameter: ", external);
			break;
		    case -2:
			punt("Invalid character in this parameter: ", external);
			break;
		    case -3:
			punt("Invalid range in this parameter: ", external);
			break;
		    default:
			break;
		}

#ifndef NA
		*Linternal = htonl(*Linternal);
		*Sinternal = htons(*Sinternal);  /* gets switched back below */
#endif
		break;

	    case CNV_RIP_ROUTERS:

		err = encode_rip_routers(external, internal);
		if (err == 1)
		    punt("invalid parameter value: ", external);
		else if (err == -1)
		    punt("invalid syntax: ", external);
		else if (err != 0)
		    punt("error while parsing router list: ", external);
		break;

	    case CNV_RIP_SEND_VERSION:

		if(isdigit(*external)) {
		  if (encode_range_ck(Sinternal, external, 1, 2, 0)) {
			punt(range_error, external);
		      }
		  *Sinternal *= 2;
		}
		else if (!strncasecmp(external, "compatibility", length) ||
			 !strncasecmp(external, "default", length)) {
		    	*Sinternal = (unsigned short)(3);
		}
		else				
		    	punt("invalid parameter value: ", external);

		break;

	    case CNV_RIP_RECV_VERSION:

		if (!strncasecmp(external, "both", length)) {
		    	*Sinternal = (unsigned short)(3);
			break;
		}

		if (encode_range_ck(Sinternal, external, 1, 2, 3)) {
			punt(range_error, external);
		      }
		break;

	    case CNV_RIP_HORIZON:

		err = encode_enum(external, rip_horizon_values,
				  "RIP horizon", Internal);
		break;

	    case CNV_RIP_DEFAULT_ROUTE:
	    case CNV_RIP_OVERRIDE_DEF:

		if (!strncasecmp(external, "off", length) ||
		    !strncasecmp(external, "none", length)) {
		    	*Sinternal = (unsigned short)(0);
			break;
		}

		if (encode_range_ck(Sinternal, external, 0, 15, 0)) 
			punt(range_error, external);
		break;

            case CNV_OSPF_TRANSDELAY:
 
                if (encode_range_ck(Sinternal, external, 1, 3600, 1))
                        punt(range_error, external);
                break;

            case CNV_OSPF_RETRANSINTERVAL:
 
                if (encode_range_ck(Sinternal, external, 1, 3600, 5))
                        punt(range_error, external);
                break;

            case CNV_OSPF_RETRANSINTERVAL_PTP:
 
                if (encode_range_ck(Sinternal, external, 1, 3600, 10))
                        punt(range_error, external);
                break;

            case CNV_OSPF_HELLOINTERVAL:
 
                if (encode_range_ck(Sinternal, external, 1, 65535, 10))
                        punt(range_error, external);
                break;

            case CNV_OSPF_HELLOINTERVAL_PTP:
 
                if (encode_range_ck(Sinternal, external, 1, 65535, 15))
                        punt(range_error, external);
                break;

            case CNV_OSPF_DEADINTERVAL:
 
                if (encode_range_ck(Sinternal, external, 1, 65535, 40))
                        punt(range_error, external);
                break;

            case CNV_OSPF_DEADINTERVAL_PTP:
 
                if (encode_range_ck(Sinternal, external, 1, 65535, 60))
                        punt(range_error, external);
                break;

            case CNV_OSPF_AUTHTYPE:
                err = encode_enum (external, ospf_authtype_values,
					"ospf_authtype", Internal);
                break; /* CNV_OSPF_AUTHTYPE */

            case CNV_OSPF_COST:
                if (encode_range_ck(Sinternal, external, 1, 65535, 1))
                        punt(range_error, external);
                break;


	    case CNV_PASS_LIM:

		if (encode_range_ck(Sinternal, external, 1, 10, 3)) 
			punt(range_error, external);
		break;

	    case CNV_TIMER:

		if (encode_range_ck(Sinternal, external, 1, 60, 30)) 
			punt(range_error, external);
		break;

	    case CNV_TMAX_HOST:

		if (encode_range_ck(Sinternal, external, 10, 255, 64)) 
			punt(range_error, external);
		break;

	    case CNV_TDELAY:

		if (encode_range_ck(Sinternal, external, 0, 255, 20)) 
			punt(range_error, external);
		break;

	    case CNV_TMAX_MPX:

		if (encode_range_ck(Sinternal, external, 5, 65535, 700)) 
			punt(range_error, external);
		break;

	    case CNV_RIP_NEXT_HOP:

		err = encode_enum(external, rip_nexthop_values,
				  "RIP-2 next hop", Internal);
		break;

	    case CNV_SESS_LIM:

		if (!strncasecmp(external, "none", length) ){
		    	*Sinternal = (unsigned short)(0);
			break;
		}
		if( encode_range_ck(Sinternal, external, 1, ALL_PORTS*16, 1152))
			punt( range_error, external );
		break;

	    case CNV_BOX_RIP_ROUTERS:

		err = encode_box_rip_routers(external, internal);
		if (err == 1)
		    punt("invalid parameter value: ", external);
		else if (err == -1)
		    punt("invalid syntax: ", external);
		else if (err != 0)
		    punt("error while parsing router list: ", external);
		break;

	    case CNV_KERB_HOST:

                err = encode_kerberos_list(external, internal);
                if (err == 1)
                    punt("invalid parameter value: ", external);
                else if (err == -1)
                    punt("invalid syntax: ", external);
                else if (err != 0)
                    punt("error while parsing kerberos list: ", external);
                break;

	    case CNV_UNITS:

		if(!strncasecmp(external, "MINUTES", length) ||
		   !strncasecmp(external, "default", length)) {
		    *Sinternal = (unsigned short)(0x0);
		}
		else {
		    if(!strncasecmp(external, "SECONDS", length)) {
			*Sinternal = (unsigned short)(0x1);
		    }
		    else {
			err = -1;
			punt("invalid units value: ", external);
		    }
		}
		break;

	    case CNV_LONG_HEX:
		err = convert_long_hex(external,Linternal);
		if (err == 1)
                   punt("Incorrect number format.",(char *)0);
		if (err == 2)
                    punt("Invalid character in number.",(char *)0);
#ifndef NA
		*Linternal = htonl(*Linternal);
		*Sinternal = htons(*Sinternal);  /* gets switched back below */
#endif
		break;

            case CNV_TNI_CLOCK:
                err = encode_enum(external, t1_clock_values,
                                  "tni_clock value", Internal);
                break;

            case CNV_TNI_LINE_BUILDOUT:
                err = encode_enum(external, t1_buildout_values,
                                  "tni_line_buildout value", Internal);
                break;

            case CNV_T1_FRAMING:
                err = encode_enum(external, t1_framing_values,
                                  "framing value", Internal);
                break;

            case CNV_T1_LINE_CODE:
                err = encode_enum(external, t1_line_code_values,
                                  "line_code value", Internal);
                break;

            case CNV_T1_ESF_FDL:
                err = encode_enum(external, t1_esf_fdl_values,
                                  "esf_fdl value", Internal);
                break;

	    case CNV_T1_DISTANCE:
		if (encode_range_ck(Sinternal, external, 0, 655, 0))
		    punt(range_error, external);
		break;

	    case CNV_T1_MAP:
		{
		char *args=external;
		char symbol[MAX_STRING_100+1];
		char modem_number=0;
		
                /* if arg is too long, something is wrong */
		if(strlen(args) > MAX_STRING_100) {
                    err = -1;
		    break;
		    }

                /* do mapping first */
                args = lex_token(args, symbol, (char *) NULL);
		indx = match(symbol, t1_mapping, "map value");
                if (indx < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
                    err = -1;
                    *Sinternal = (unsigned short)(0);
		    }
                else
		    {
                    /* do mapping */
                    Cinternal[0] = (unsigned char)(indx);

		    if((indx == T1_MAP_DS1_MODEM) || (indx == T1_MAP_DI_MODEM))
			{
                	/* now do modem number */
                	args = lex_token(args, symbol, (char *) NULL);
			if(isdigit(*symbol))
			    modem_number = (char)atoi(symbol);
			if((modem_number < 1) || (modem_number > ALL_INTMODS))
			    {
                            err = -1;
                            *Sinternal = (unsigned short)(0);
		            }
			else
                            Cinternal[1] = (unsigned char)(modem_number);
			}
#ifndef NA
		    *Sinternal = htons(*Sinternal);  /* switch back */
#endif
		    }
		}
		break;

	    case CNV_T1_SIG_PROTOCOL:
		{
		char *args=external;
		char symbol[MAX_STRING_100+1];
		
                /* if arg is too long, something is wrong */
		if(strlen(args) > MAX_STRING_100) {
                    err = -1;
		    break;
		    }
		
                /* do inbound first */
                args = lex_token(args, symbol, (char *) NULL);
		indx = match(symbol, t1_sig_proto, "sigproto value");
                if (indx < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
                    err = -1;
                    *Sinternal = (unsigned short)(0);
		    }
                else
		    {
                    /* do inbound */
                    Cinternal[0] = (unsigned char)(indx);

                    /* now do outbound */
                    args = lex_token(args, symbol, (char *) NULL);
		    indx = match(symbol, t1_sig_proto, "sigproto value");
                    if (indx < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
                        err = -1;
                        *Sinternal = (unsigned short)(0);
		        }
                    else
			{
                        Cinternal[1] = (unsigned char)(indx);
#ifndef NA
			*Sinternal = htons(*Sinternal);  /* switch back */
#endif
		        }
		    }
		}
		break;

           case CNV_T1_SWITCH_TYPE:
                err = encode_enum(external, t1_switch_type_values,
                                  "switch_type value", Internal);
                break;

	    case CNV_T1_RING:
		{
		char *args=external;
		char symbol[MAX_STRING_100+1];

                /* if arg is too long, something is wrong */
		if(strlen(args) > MAX_STRING_100) {
                    err = -1;
		    break;
		    }
                args = lex_token(args, symbol, (char *) NULL);
                indx = match(symbol, boolean_values, "boolean value");
		
                if (indx < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
                    err = -1;
                    *Sinternal = (unsigned short)(0);
		    }
                else
		    {
		    /* yes=0, no=1, default is yes */
		    *Sinternal = (unsigned short)(indx & 0x0001);
#ifndef NA
		    *Sinternal = htons(*Sinternal);  /* switch back */
#endif
		    }
		}
		break;

	    case CNV_WAN_RING:
		{
		char *args=external;
		char symbol[MAX_STRING_100+1];

                /* if arg is too long, something is wrong */
		if(strlen(args) > MAX_STRING_100) {
                    err = -1;
		    break;
		    }
                args = lex_token(args, symbol, (char *) NULL);
                indx = match(symbol, boolean_values, "boolean value");
		
                if (indx < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
                    err = -1;
#ifdef NA
		    *Cinternal = (0);
#else
                    *Sinternal = (unsigned short)(0);
#endif
		    }
                else
		    {
#ifdef NA
		      *Cinternal = (indx & 0x01);
#else
		    /* yes=0, no=1, default is yes */
		    *Sinternal = (unsigned short)(indx & 0x0001);
		    *Sinternal = htons(*Sinternal);  /* switch back */
#endif
		    }
		}
		break;

            case CNV_WAN_FRAMING:
                err = encode_enum( external, wan_framing_values,
                                   "framing value", Internal);
                break;

            case CNV_WAN_LINECODE:
                err = encode_enum( external, wan_linecode_values,
                                   "line_code value", Internal);
                break;

	    case CNV_WAN_SIGPROTO:
		{
		char *args=external;
		char symbol[MAX_STRING_100+1];
		
                /* if arg is too long, something is wrong */
		if(strlen(args) > MAX_STRING_100) {
                    err = -1;
		    break;
		    }
		
		/* do inbound first */
		args = lex_token(args, symbol, (char *) NULL);
		indx = match(symbol, wan_sig_proto, "sigproto value");
		if (indx < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
		    err = -1;
		    *Sinternal = (unsigned short)(0);
		}
		else
		    *Sinternal = (unsigned short)(wan_sig_proto_table[indx]);
	        }
		break;

	    case CNV_RESOLVE: {

		u_short indx;

		switch ((indx = match(external, pm_values, "xxx"))) {
			case P_TELNET:
			case P_CONNECT:
			case P_ANY:
			    *Sinternal = indx;
			    break;
			default:
			    err = -1;
			    punt("invalid RESOLVE PROTOCOL value: ", external);
			    break;
			}
		}
		break;

	    case CNV_WAN_REMADDR: {
	      char *sp;

	      sp = index(external,' ');
	      if (sp != NULL) {
		*sp++ = '\0';
		err = str_to_inet(sp, Linternal+1, TRUE, 1);
		if (err)
		  punt("invalid parameter value: ",sp);
	      } else
		Linternal[1] = 0;
	      err = str_to_inet(external, Linternal, TRUE, 1);
	      if (err)
		punt("invalid parameter value: ", external);
#ifndef NA
	      *Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
	    }
		break;

	    case CNV_WAN_IPXNET: {
	      char *sp;

	      sp = index(external,' ');
	      Cinternal = internal+4;
	      if (sp != NULL) {
		*sp++ = '\0';
		err = convert_long_hex(sp,Linternal);
		if (err == 1)
                   punt("Incorrect number format.",(char *)0);
		if (err == 2)
                   punt("Invalid character in number.",(char *)0);
#ifndef NA
		*Linternal = htonl(*Linternal);
		*Sinternal = htons(*Sinternal);  /* gets switched back below */
#endif
		if (err)
		  punt("invalid parameter value: ",sp);
	      } else
		*Linternal = 0;
	      Cinternal = internal;
	      err = convert_long_hex(external,Linternal);
	      if (err == 1)
		punt("Incorrect number format.",(char *)0);
	      if (err == 2)
		punt("Invalid character in number.",(char *)0);
#ifndef NA
	      *Linternal = htonl(*Linternal);
	      *Sinternal = htons(*Sinternal);  /* gets switched back below */
#endif
	    }
		break;

	    case CNV_WAN_IPXNODE: {
	      char *sp;

	      sp = index(external,' ');
	      if (sp != NULL) {
		*sp++ = '\0';
		err = str_to_enet(sp, internal+6, TRUE, 1);
		if (err)
		  punt("invalid parameter value: ",sp);
	      } else
		bzero(internal+6,6);
	      err = str_to_enet(external, internal, TRUE, 1);
	      if (err)
		punt("invalid parameter value: ", external);
#ifndef NA
	      *Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
	    }
		break;

	    case CNV_WANDIST:
		if (index(external,'-') != NULL)
		  err = encode_enum(external, pridist_values,
				    "dsx1_line_length value", Internal);
		else {
		  i = atoi(external);
		  if (i < 0 || i > 210)
		    punt(range_error, external);
		  else if (i < 26)
		    i = 1;
		  else if (i < 66)
		    i = 2;
		  else if (i < 101)
		    i = 3;
		  else if (i < 136)
		    i = 4;
		  else if (i < 166)
		    i = 5;
		  else if (i < 186)
		    i = 6;
		  else
		    i = 7;
		  *Sinternal = i;
		}
		break;

            case CNV_V120_MRU:
		if((strlen(external) == 1) && (*external == '0')) {
		    *Sinternal = (unsigned short)(atoi(external));
		    }
		else {
		    if (encode_range_ck(Sinternal, external, 30, 260, 0))
			punt(range_error, external);
		    }
		break;

	    case CNV_WANANALOG:
		err = encode_enum(external, prianalog_values,
				  "analog encoding value", Internal);
		break;

            case CNV_MP_ENDP_OPT:
                err = encode_enum(external, mp_values,
                                  "endpoint_discriminator class", Internal);
                break;  /* CNV_MP_ENDP_OPT */


            case CNV_MP_ENDP_VAL:
                i = validate_epd_address(external);
                
                if (i == 0)
                {
                    punt("EPD Address length exceeded", external);
                }
                else  /* it must be of appropriate length (0-16)*/
                {
                    strcpy (CS_string, external);
                    CS_length = strlen (external);
                }
                
                break;  /* CNV_MP_ENDP_VAL */

	        case CNV_ADDR_ORIGIN:
		        err = encode_enum(external, addr_origin_values,
					  "dialup address origin", Internal);
                        if(*Sinternal == ACP_ADDR_ORIG)
                           *Sinternal = AUTH_SERVER_ADDR_ORIG; 
		        break; /* CNV_ADDR_ORIGIN */

            case CNV_AUTH_PROTOCOL:
                 max_length = LONGPARAM_LENGTH;
                 err = encode_enum(external, auth_protocol_values,
                                   "auth_protocol_values", Internal); 
                 break;

            case CNV_COMPAT_MODE:
                 max_length = LONGPARAM_LENGTH;
                 err = encode_enum(external, compat_mode_values,
                                   "compat_mode_values", Internal); 
                 break;                 

            case CNV_RAD_ACCT_LEVEL:
                 max_length = LONGPARAM_LENGTH;
                 err = encode_enum(external, rad_acct_level_values,
                                   "rad_acct_level_values", Internal); 
                 break;

            case CNV_RAD_PORT_ENCODING:
                 max_length = LONGPARAM_LENGTH;
                 err = encode_enum(external, rad_port_encoding_values,
                                   "rad_acct_level_values", Internal); 
                 break;

            case CNV_RADIUS_SECRET:
                 max_length = MAX_STRING_100;
                 if(strstr(external, "0x") || strstr(external, "0X")){
                     ptr = external + 2;
                     while(*ptr != '\0'){
                         if(!isxdigit(*ptr++))
                             punt("Invalid hex characters in string", external);
                     }
                     
                 }
                  err = encode_string(external, max_length, Internal);
                 
                 break;


    case CNV_BUSYSIG:
		err = encode_enum(external, busysig_values,
                          "busy signal bits", Internal);
        
		break; /* CNV_BUSYSIG */

    case CNV_BANNER:
	        indx = match(external, banner_values, "banner values");
                /* No match in table */
                if (indx < 0) 
                   punt("Invalid value.",(char *)0);
                else 
		  switch (indx) {
		  case 0:
		  case 6:
		  case 7:
		    *Sinternal = 0;
		    break;
		  default:
		    *Sinternal = indx;
		    break;
		  }
		break;

    default:

	         *Linternal = (UINT32)(0);


            case CNV_IGMP_VERSION:
                err = encode_enum (external, igmp_version_values,
					"igmp_version", Internal);
                break; /* CNV_IGMP_VERSION */

            case CNV_IGMP_NIBBLE:
                if (encode_range_ck (Sinternal, external, 1, 15, 2))
		    punt (range_error, external);
                break; /* CNV_IGMP_NIBBLE */

            case CNV_IGMP_QUERY_TIME:
                if (encode_range_ck (Sinternal, external, 1, 65535, 1250))
		    punt (range_error, external);
                break; /* CNV_IGMP_QUERY_TIME */

            case CNV_IGMP_RESPONSE_TIME:
                if (encode_range_ck (Sinternal, external, 1, 65535, 100))
		    punt (range_error, external);
                break; /* CNV_IGMP_RESPONSE_TIME */

            case CNV_IGMP_START_QUERY_TIME:
                if (encode_range_ck (Sinternal, external, 1, 65535, 313))
		    punt (range_error, external);
                break; /* CNV_IGMP_START_QUERY_TIME */

            case CNV_IGMP_LAST_QUERY_TIME:
                if (encode_range_ck (Sinternal, external, 1, 256, 10)) {
		    punt (range_error, external);
		}

                break; /* CNV_IGMP_LAST_QUERY_TIME */

            case CNV_IGMP_JOIN_QUERY_TIME:
                if (encode_range_ck (Sinternal, external, 1, 256, 100)) {
		    punt (range_error, external);
		}
                break; /* CNV_IGMP_JOIN_QUERY_TIME */

            case CNV_IGMP_V1_TIMEOUT:
                if (encode_range_ck (Sinternal, external, 1, 65535, 4000))
		    punt (range_error, external);
                break; /* CNV_IGMP_START_QUERY_TIME */

            case CNV_RTABLE_SIZE:
                err = encode_enum (external, rtable_size_values,
                                        "rtable_size", Internal);
                break; /* CNV_RTABLE_SIZE */
 
            case CNV_ROUTE_PREF:
                err = encode_enum (external, route_pref_values,
                                        "route_pref", Internal);
                break; /* CNV_ROUTE_PREF */

	    case CNV_IGMP_MAX_QUEUE_SIZE:
                if (encode_range_ck (Sinternal, external, 80, 3000, 160))
		    punt (range_error, external);
                break; /* CNV_IGMP_MAX_QUEUE_SIZE */

	    case CNV_IGMP_MAX_MCAST:
                if (encode_range_ck (Sinternal, external, 20, 2840, 80))
		    punt (range_error, external);
                break; /* CNV_IGMP_MAX_MCAST */

	    case CNV_OSPF_HOLDDOWN:

		if (encode_range_ck(Sinternal, external, 0, 255, 10)) {
			punt(range_error, external);
		}
		break;

            case CNV_OSPF_AREATYPE:
                err = encode_enum (external, ospf_areatype_values,
					"ospf_areatype", Internal);
                break; /* CNV_OSPF_AREATYPE */


	}
#ifndef NA
	*Sinternal = htons(*Sinternal);
	return(err);
#else
	return;	/* void */
#endif

}	/*  encode()  */


/*****************************************************************************
 *
 * NAME: encode_string              
 *
 * DESCRIPTION:
 *    encode any of the standard variable length string parameters
 *
 * ARGUMENTS:
 *    external          # the string to be encoded
 *    max_length        # the longest string length allowed
 *    Internal          # the encoded version of the string, trimmed
 *                      #    as needed to fit (cast as an INTERN).
 *
 * RETURN VALUE:        error flag
 *
 * SIDE EFFECTS:        none
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

static int
encode_string(external, max_length, Internal)
char              *external;    /*  external representation (for human) */
int               max_length;
INTERN            Internal;     /*  internal representation (for Annex) */
{
    int        length = strlen(external);

    if (length > max_length) {
#ifdef NA
      printf("\tWarning:  String parameter truncated to %d characters.\n",
	     max_length);
#else
	/* Sadly, we cannot get a message to the user here! */
      return -1;
#endif
       length = max_length;
    }

    CS_length = length;
    (void) strncpy(CS_string, external, length);
    
    return 0;
}

/*****************************************************************************
 *
 * NAME: encode_enum
 *
 * DESCRIPTION:
 *    encode any of the standard enumerated parameters
 *
 * ARGUMENTS:
 *    external          # the string to be encoded
 *    value_list        # the list of values in the data type represented
 *                      #    as a vector of pointers to character strings
 *                      #    terminated with a NULL pointer.
 *    type_string       # An explanatory string identifying the parameter,
 *                      #    that is currently unused but may be in for
 *                      #    error messages in the future? (It was there
 *                      #    when I got here.)
 *    Internal          # the encoded version of the input, of type INTERN
 *
 * RETURN VALUE:        error flag
 *
 * SIDE EFFECTS:        none
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

static int
encode_enum(external, value_list, type_string, Internal)
char              *external;    /*  external representation (for human) */
char              **value_list;
char              *type_string;
INTERN            Internal;     /*  internal representation (for Annex) */
{
   int            index;
   int            error = 0;

   index = match(external, value_list, type_string);

   if (index < 0) { /* NOTUNIQUE, NOSUCHVALUE, or NOTHING */
      error = -1;
      *Sinternal = (unsigned short)(0);
  }
   else
      *Sinternal = (unsigned short)(index);

   return error;
}



/* Machine to human conversion   */

void
decode(conversion, internal, external,Pannex_id)
int  conversion;		/*  type of conversion to be performed	*/
char *internal;			/*  internal representation (for Annex) */
char *external;			/*  external representation (for human) */
ANNEX_ID *Pannex_id;		/*  Annex converting from		*/
{
	char		*ptr;
	INTERN		Internal;	/*  union of pointers to types	*/
	int		length = 0,		/*  length of a string		*/
			byte, err,
			lastone = LAT_GROUP_SZ * NBBY, /* initially large */
			span = FALSE,
			i, j = 0,
			bit;
	u_short		net_value;
	u_short		node_value;  	
	UINT32	 	sum,sum2;
	Cinternal = internal;	/*  move to pointer to various types	*/

	
	/*  Perform conversion from internal to external formats	*/

#ifndef NA
	*Sinternal = ntohs(*Sinternal);		/* assume we need a change */
#endif

	switch(conversion)
	{
	    case CNV_PRINT:

		c_to_print(*Sinternal, external);
		break;

	    case CNV_DFT_N:

		external[0] = (*Sinternal ? 'Y' : 'N');
		external[1] = 0;
		break;

	    case CNV_DFT_Y:

		external[0] = (*Sinternal ? 'N' : 'Y');
		external[1] = 0;
		break;

            case CNV_DFT_OFF:
                decode_boolean(*Sinternal, 1, &boolean_values[6], external);
                break;

            case CNV_DFT_ON:
                decode_boolean(*Sinternal, 0, &boolean_values[6], external);
                break;

            case CNV_DFT_NONE:
                decode_boolean(*Sinternal, 1, all_or_none_values, external);
                break;

            case CNV_DFT_ALL:
                decode_boolean(*Sinternal, 0, all_or_none_values, external);
                break;

	    case CNV_MOP_PASSWD:

	    /* this is a special case */
	    /* it is not a string, but a string */
	    /* (<set> or <unset>) is returned */

        case CNV_RADIUS_SECRET:
            case CNV_OSPF_AUTHKEY:
            case CNV_OSPF_MD5K:
	    case CNV_STRING:
            case CNV_STRING_NTP:
	    case CNV_STRING_PREFSERVER:
	    case CNV_STRING_NOSPACE:
	    case CNV_STRING_100:
	    case CNV_STRING_120:
	    case CNV_STRING_128:
	    case CNV_ZONE:
	    case CNV_DPTG:
            case CNV_MP_ENDP_VAL:
		length = CS_length;

		if ((length > LONGPARAM_LENGTH) &&
		    (Pannex_id->hw_id < ANX3))
		{
		    puntv("exceeded length ", (char *)0);
		}
		else
		{
		    if ((length > MAX_STRING_128) && 
			((Pannex_id->hw_id == ANX3 || 
			  Pannex_id->hw_id == ANX_MICRO ||
			  Pannex_id->hw_id == ANX_MICRO_ELS ||
			  Pannex_id->hw_id == ANX_PRIMATE)))
		      puntv("exceeded length ", (char *)0);
		    else
			{
			external[0] = '\"';
			(void)strncpy(&external[1], CS_string, length);
			external[length + 1] = '\"';
			external[length + 2] = 0;
			}
		}
		break;

	    case CNV_DEF_ZONE_LIST:

		length = CS_length;

		if ((length > LONGPARAM_LENGTH) &&
		    (Pannex_id->hw_id < ANX3))
		{
		  puntv("exceeded length ", (char *)0);
		}
		else
		{
		    if ((length > MAX_STRING_128) && 
			((Pannex_id->hw_id == ANX3 || 
			  Pannex_id->hw_id == ANX_MICRO ||
			  Pannex_id->hw_id == ANX_MICRO_ELS ||
			  Pannex_id->hw_id == ANX_PRIMATE)))
		      puntv("exceeded length ", (char *)0);
		    else
			{
                        char *in_ptr, *out_ptr;
                        int i =0, err =0, zone_len;

                        in_ptr = CS_string;
                        out_ptr = external;
			*out_ptr++ = '\"';
			while (i<length) {
                          zone_len = *in_ptr++; /* first bytes is a zone len */
                          if (zone_len > 32 || zone_len <= 0 || 
                              (i+zone_len+1 > length)) {
			    puntv("invalid zone length", (char *)0);
                            err = 1;
                            break;
                          }
                          i += (zone_len +1);
                          while( zone_len-- ) {
			    if (*in_ptr == ',')
			      *out_ptr++ = '\\';
                            *out_ptr++ = *in_ptr++;
                          }
                          if (i < length) /* another zone is comming */
			    *out_ptr++ = ',';
		        }
              		if (!err) {
			  *out_ptr++ = '\"';
			  *out_ptr =  0;
			}
                        }
		}
		break;

	    case CNV_ATTN:

		length = CS_length;
		if ((length > LONGPARAM_LENGTH) && (Pannex_id->hw_id < ANX3))
		{
		  puntv("exceeded length ", (char *)0);
		}
		else
		{
		    if ((length > MAX_STRING_128) && 
			((Pannex_id->hw_id == ANX3 || 
				Pannex_id->hw_id == ANX_MICRO)))
		      puntv("exceeded length ", (char *)0);
		    else {
			external[0] = '\"';
		        for (i = 0, j = 1; i < length; i++, j++) {
			    if (CS_string[i] < ' ') {
			        external[j++] = '^';
			        external[j] = CS_string[i] + 0x40;
		            } else if (CS_string[i] == RIP_LEN_MASK) {
			        external[j++] = '^';
			        external[j] = '?';
			    } else if ((u_char)CS_string[i] == 
							(u_char)0x80) {
				external[j++] = '^';
				external[j] = '@';
		            } else {
				external[j++] = '\\';
				external[j] = CS_string[i];
			    }
		        }
		    }
			external[j++] = '\"';
			external[j] = 0;
		}

		break;

	    case CNV_FC:
		decode_enum(*Sinternal, external, fc_values, 1, FC_MAX);
		break;

            case CNV_DUIFC:
                decode_enum(*Sinternal, external, duifc_values, 1, 3);
                break;

            case CNV_SESS_MODE:
                decode_enum(*Sinternal,external,sess_mode_values,1,4);
                break;

            case CNV_USER_INTF:

                decode_enum(*Sinternal, external, dui_values, 1, 2);
                break;

	    case CNV_IPSO_CLASS:

                decode_enum(*Sinternal, external, ipso_values, 0, 4);
                break;

	    case CNV_IPX_FMTY:

                decode_enum(*Sinternal, external, ipxfmy_values, 0, 3);
                break;

           case CNV_DEF_AUTOD_MODE:

                decode_enum(*Sinternal, external, def_autod_mode_values, 0, 1);
                break;
            case CNV_RAD_ACCT_DEST:
                decode_enum(*Sinternal, external, rad_acct_dest_values, 0, 1);
                break;

	    /*  CNV_NETZ and CNV_NET are identical when decoding  */

	    case CNV_NET_Z:
	    case CNV_NET:

#ifdef NA
		(void)strcpy(external, inet_ntoa(*Ninternal));
#else
		*Sinternal = ntohs(*Sinternal);	/* we need a change back */
		inet_ntoa(external, *Ninternal);
#endif
		break;

            case CNV_ENET_ADDR:
	    case CNV_WAN_IPXNODE:

#ifndef NA
             *Sinternal = ntohs(*Sinternal); /* change back */
#endif
                (void)sprintf(external,/*NOSTR*/"%02x-%02x-%02x-%02x-%02x-%02x",
                        (u_char) internal[0], (u_char) internal[1],
                        (u_char) internal[2], (u_char) internal[3],
                        (u_char) internal[4], (u_char) internal[5]);
                break;

	    case CNV_BML:
#ifndef NA
		*Sinternal = ntohs(*Sinternal); /* we need a change back */
		*Linternal = ntohl(*Linternal);
#endif
		sprintf(external, /*NOSTR*/"0x%x",(unsigned)*Linternal);
		break;

	    case CNV_PS:

		if (*Sinternal == (unsigned short)0xff)
			(void)strcpy(external, "autobaud");
		else {
			external[0] = '\0';
			if (*Sinternal & (unsigned short)0x80)
				(void)strcpy(external,"autobaud/");
			decode_enum(*Sinternal&0x7F,
				external+strlen(external),
				ps_values, 1, PS_MAX);
			}
		break;

	    case CNV_BPC:

		decode_enum(*Sinternal, external, bpc_values, 1, BPC_MAX);
		break;

	    case CNV_SB:

		decode_enum(*Sinternal, external, sb_values, 1, SB_MAX);
		break;

	    case CNV_P:

		decode_enum(*Sinternal, external, p_values, 1, P_MAX);
		break;

	    case CNV_MC:

		decode_enum(*Sinternal, external, mc_eib_values, 1,
			(Pannex_id->hw_id == ANX_II_EIB ||
			 Pannex_id->hw_id == ANX3 ||
			 Pannex_id->hw_id == ANX_MICRO ||
			 Pannex_id->hw_id == ANX_MICRO_ELS ||
			 Pannex_id->hw_id == ANX_PRIMATE) ?
				MC_MAX : (MC_MAX-1));
		break;

	    case CNV_PT:

		decode_enum(*Sinternal, external, pt_values, 1, PT_MAX);
		break;

	    case CNV_SEC:
		decode_enum(*Sinternal, external, sec_values, 1, SEC_MAX);
		break;

	    case CNV_PM:
		if (*Sinternal == P_PPP && /* platforms without PPP */
		    (Pannex_id->hw_id == ANX_II ||
		     Pannex_id->hw_id == ANX_II_EIB ||
		     Pannex_id->hw_id == ANX_MICRO_ELS))
		  puntv("PPP not supported", (char *)0);
		else
			decode_enum(*Sinternal, external, pm_values,
				1, PM_MAX);
		break;

	    case CNV_NS:
		decode_enum(*Sinternal,external,ns_values,1,NS_MAX);
		break;

	    case CNV_HT:

#ifdef NA
		if(Pannex_id->version < VERS_5)
			sprintf(external, /*NOSTR*/"%d", *Sinternal * 2);
		else
#endif
			if (*Sinternal == HTAB_NONE)
				sprintf(external, /*NOSTR*/"%s", "none");
			else 
				if (*Sinternal == HTAB_UNLIMITED)
					sprintf(external, /*NOSTR*/"%s",
						"unlimited");
				else
					sprintf(external,/*NOSTR*/"%d",
						*Sinternal);
		break;

	    case CNV_SEQ:

#ifndef NA
		*Sinternal = ntohs(*Sinternal);	/* we need a change back */
#endif
		decode_sequence(external, *Linternal);
		break;

	    case CNV_IPENCAP:

		sprintf(external, /*NOSTR*/"%s", *Sinternal ? "ieee802" :
			"ethernet");
		break;

	    case CNV_SCAP:

		if(*Sinternal == 0)
			(void)strcpy(external, "none");
		else if (*Sinternal == SERVE_ALL)
			(void)strcpy(external, "all");
		else
			decode_mask(external, (UINT32)*Sinternal, serv_options);
		break;

	    case CNV_SELECTEDMODS:

		sum = *Sinternal;
#ifndef NA
		Sinternal[1] = ntohs(Sinternal[1]);
#endif
		sum |= Sinternal[1]<<16;
		if (sum == OPT_SELEC_NONE)
		    (void)strcpy(external, "none");
		else if (sum == OPT_ALL)
		    (void)strcpy(external, "all");
		else
		    decode_mask(external, sum&~OPT_SELEC_NONE,
				selectable_mods);
		break;

	    case CNV_SYSLOG:

		if(*Sinternal == 0)
			(void)strcpy(external, "none");
		else if (*Sinternal == SYSLOG_ALL)
			(void)strcpy(external, "all");
		else
		  decode_anxsyslog_mask(external, (UINT32)*Sinternal); 
		break;

	    case CNV_SYSFAC:

		(*Sinternal)--;
		if(   *Sinternal <= (u_short)FAC_BASE
		   || *Sinternal >  (u_short)FAC_HIGH)
		    sprintf(external, /*NOSTR*/"%d", *Sinternal);
		else
		    (void)strcpy(external, sf_values[*Sinternal - FAC_BASE]); 
		break;

	    case CNV_VCLILIM:

		if(*Sinternal == 0)
			(void)strcpy(external, "unlimited");
		else if(*Sinternal == 255)
			(void)strcpy(external, /*NOSTR*/"0");
		else
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_DLST:

#ifdef NA
		if (Pannex_id->version < VERS_5 &&
		    *Sinternal == DLST_MAX - 1)
			*Sinternal = DLST_MAX;
#endif
		decode_enum(*Sinternal, external, dlst_values, 1, DLST_MAX);
		break;


	    case CNV_TZ_MIN:
	    case CNV_ZERO_OK:

		sprintf(external, /*NOSTR*/"%d", (short)*Sinternal - 1);
		break;

	    case CNV_RESET_IDLE:

		sprintf(external, /*NOSTR*/"%s", *Sinternal ? "output" :
			"input");
		break;

	    case CNV_PROMPT_32:

		length = CS_length;

		if ((length > LONGPARAM_LENGTH) &&
		    (Pannex_id->hw_id < MIN_HW_FOR_LONG))
		{
		    puntv("exceeded length ", (char *)0);
		    break;
		}
		/* else fall thru' */
	    case CNV_PROMPT:

		if(conversion == CNV_PROMPT)
			length = CS_length;

		if(conversion == CNV_PROMPT && length > LONGPARAM_LENGTH)
		{
		  puntv("exceeded length ", (char *)0);
		}
		else
		{
		    conv_prompt( CS_string, external, length );
		}
		break;

	    case CNV_DPORT:
		switch(*Sinternal)
		{
		    case HRPPORT:		/* mls ("hrp") port, "call" */
			strcpy(external, "call");
			break;

		    case IPPORT_LOGINSERVER:	/* login port, "rlogin" */
			strcpy(external, "rlogin");
			break;

		    case IPPORT_TELNET:		/* "telnet" */
		    case 0:
			strcpy(external, "telnet");
			break;

		    default:
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
			break;
		}
		break;

	    case CNV_INT0OFF:
	    case CNV_INT5OFF:
	    case CNV_INACTCLI:
	    case CNV_INACTDUI:

		if (conversion == CNV_INACTCLI && *Sinternal == 255)
			(void)strcpy(external, "immediate");
		else if(*Sinternal == 0 ||
			(*Sinternal == 5 && conversion == CNV_INT5OFF))
			(void)strcpy(external, "off");
		else
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_RBCAST:
		
		if (*Sinternal)
			(void)strcpy(external,"network");
		else
			(void)strcpy(external,"port");
		break;

	    case CNV_PTYPE:
		
		sprintf(external, /*NOSTR*/"%s", *Sinternal ? "dataproducts"
						   : "centronics");
		break;
		
	    case CNV_PSPEED:
		
		sprintf(external, /*NOSTR*/"%s", *Sinternal ? "high_speed"
						   : "normal");
		break;
	
	    case CNV_IGMP_VERSION:
	        decode_enum (*Sinternal, external, igmp_version_values, 1, 3);
                break;

	    case CNV_RTABLE_SIZE:
	        decode_enum (*Sinternal, external, rtable_size_values, 1, 4);
                break;

	    case CNV_ROUTE_PREF:
	        decode_enum (*Sinternal, external, route_pref_values, 1, 2);
                break;

	    case CNV_OSPF_AUTHTYPE:
	        decode_enum (*Sinternal, external, ospf_authtype_values, 1, 4);
                break;

	    case CNV_OSPF_AREATYPE:
	        decode_enum (*Sinternal, external, ospf_areatype_values, 1, 2);
                break;

            case CNV_NTP_TIMER: 
	case CNV_OSPF_ACTIVEMD5:
		case CNV_NFAS_INT_ID:
		case CNV_NFAS_BACKUP_ID:
	    case CNV_INT:
	    case CNV_RNGPRI:
	    case CNV_MS:
	    case CNV_HOST_NUMBER:
	    case CNV_SERVICE_LIMIT:
	    case CNV_KA_TIMER:
        case CNV_MULTI_TIMER:
        case CNV_PASSLIM:
	    case CNV_CIRCUIT_TIMER:
	    case CNV_RETRANS_LIMIT:
	    case CNV_QUEUE_MAX:
	    case CNV_PORT:
	    case CNV_NET_TURN:
	    case CNV_BYTE:
	    case CNV_BYTE_ZERO_OK:
	    case CNV_HIST_BUFF:
	    case CNV_A_BYTE:
	    case CNV_PASS_LIM:
	    case CNV_TIMER:
	    case CNV_TMAX_HOST:
	    case CNV_TDELAY:
	    case CNV_TMAX_MPX:
	    case CNV_SMETRIC:
            case CNV_T1_DISTANCE:
            case CNV_V120_MRU:
	    case CNV_MRRU:
	    case CNV_MRU:
	    case CNV_IGMP_NIBBLE:
	    case CNV_IGMP_QUERY_TIME:
	    case CNV_IGMP_RESPONSE_TIME:
	    case CNV_IGMP_START_QUERY_TIME:
	    case CNV_IGMP_LAST_QUERY_TIME:
	    case CNV_IGMP_JOIN_QUERY_TIME:
	    case CNV_IGMP_V1_TIMEOUT:
            case CNV_OSPF_HOLDDOWN:
            case CNV_OSPF_TRANSDELAY:
            case CNV_OSPF_RETRANSINTERVAL:
            case CNV_OSPF_RETRANSINTERVAL_PTP:
            case CNV_OSPF_HELLOINTERVAL:
            case CNV_OSPF_HELLOINTERVAL_PTP:
            case CNV_OSPF_DEADINTERVAL:
            case CNV_OSPF_DEADINTERVAL_PTP:
            case CNV_OSPF_COST:
	case CNV_IGMP_MAX_QUEUE_SIZE:
	    case CNV_IGMP_MAX_MCAST:
	    case CNV_IPPORT:
		sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_THIS_NET_RANGE:
#ifndef NA
		*Sinternal = ntohs(*Sinternal); /* we need a change back */
		*Linternal = ntohl(*Linternal);
#endif
		sum = *Linternal;
		sum2 = sum;
		/*
		 * See encode mechanism for datail.
		 */
		net_value = (unsigned short)(sum >> 16);
		node_value = (unsigned short)(sum2 & 0x0000ffff);
		sprintf(external, /*NOSTR*/"%d.%d",net_value, node_value);
		break;

            case CNV_ADM_STRING:
                decode_string(Internal, MAX_ADM_STRING, external);
                break;

            case CNV_IPX_STRING:
                decode_string(Internal, MAX_IPX_STRING, external);
                break;

            case CNV_STRING_P_120:
                decode_string(Internal, MAX_STRING_120, external);
                break;

	    case CNV_GROUP_CODE:
#ifndef NA
		*Sinternal = ntohs(*Sinternal);	/* change it back */
#endif
		external[0] = '\0';
		ptr = Cinternal;
		for (byte = 0; byte < LAT_GROUP_SZ; byte++) {
		    for (bit = 0; bit < NBBY; bit++) {
			length = strlen(external);
			if (*ptr & 0x01) {
			    if ((lastone + 1) == (byte * NBBY) + bit) {
				span = TRUE;
			    } else {
			        sprintf(&external[length], /*NOSTR*/"%d,",
				        (byte * NBBY) + bit);
			    }
			    lastone = (byte * NBBY) + bit;
			} else {
			    if (span) {
				length--;
			        sprintf(&external[length], /*NOSTR*/"-%d,",
					lastone);
			    }
			    span = FALSE;
			}
			*ptr >>= 1;
		    }
		    ptr++;
		}
		if (span) {
		    length--;
		    sprintf(&external[length], /*NOSTR*/"-%d", lastone);
		}
		length = strlen(external);
		if (length) {
		    if (external[length - 1] == ',') {
		        external[length - 1] = '\0';
		    }
		    if (!strcmp(external, /*NOSTR*/ ALL_LAT_GROUPS)) {
			strcpy(external, ALL_STR);
		    }
		} else {
		    strcpy(external, NONE_STR);
		}
		break;

	    case CNV_LG_SML:

		if (*Sinternal)
			(void)strcpy(external,"large");
		else
			(void)strcpy(external,"small");
		break;

	    case CNV_PPP_NCP:

		if (*Sinternal & 0x1) 	/* NCP_ALL */
			(void)strcpy(external, "all");
		else
			decode_mask(external, (UINT32)*Sinternal, ncp_options);
		break;

	    case CNV_PPP_TRACE_LVL:

		if(*Sinternal == 0)
			(void)strcpy(external, "none");
		else
			decode_ppp_trace_lvl(external, (UINT32)*Sinternal);
		break;

	    case CNV_ARAP_AUTH:

		if (*Sinternal == (unsigned short)2)
		    (void)strcpy(external, "des");
		else
		    (void)strcpy(external, "none");
		break;

	    case CNV_SESS_LIM:

		if( *Sinternal == (unsigned short)0 ){
			(void)strcpy( external, "none" );
		}
		else{
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
		}
		break;

	    case CNV_RIP_ROUTERS:

		err = decode_rip_routers(internal, external);
		if (err)
		    puntv("bad value read from eeprom ", (char *)0);
		break;
		
	    case CNV_RIP_SEND_VERSION:

		if (*Sinternal == (unsigned short)3) {
		    	(void)strcpy(external, "compatibility");
			break;
		}
		else if (*Sinternal == (unsigned short)4)
		 	*Sinternal = (unsigned short)2; 

		else if (*Sinternal == (unsigned short)2)
		 	*Sinternal = (unsigned short)1;
		
		sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_RIP_RECV_VERSION:

		if (*Sinternal == (unsigned short)3)
		    	(void)strcpy(external, "both");
		else
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_RIP_NEXT_HOP:
		decode_enum(*Sinternal, external, rip_nexthop_values, 0, 3);
		break;

	    case CNV_RIP_HORIZON:
		decode_enum(*Sinternal, external, rip_horizon_values, 0, 3);
		break;

	    case CNV_RIP_DEFAULT_ROUTE:

		if (*Sinternal == (unsigned short)0)
		    	(void)strcpy(external, "off");
		else
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_RIP_OVERRIDE_DEF:

		if (*Sinternal == (unsigned short)0)
		    	(void)strcpy(external, "none");
		else
			sprintf(external, /*NOSTR*/"%d", *Sinternal);
		break;

	    case CNV_BOX_RIP_ROUTERS:

		err = decode_box_rip_routers(internal, external);
		if (err)
		    puntv("bad value read from eeprom ", (char *)0);
		break;

	    case CNV_KERB_HOST:

		err = decode_kerberos_list(internal, external);
                if (err)
                    puntv("bad value read from eeprom ", (char *)0);
                break;

	    case CNV_UNITS:

		if (*Sinternal)
			(void)strcpy(external,"seconds");
		else
			(void)strcpy(external,"minutes");
		break;

	    case CNV_LONG_HEX:
#ifndef NA
            	*Sinternal = ntohs(*Sinternal);  /* we need a change back */
            	*Linternal = ntohs(*Linternal);
#endif
		sprintf(external, /*NOSTR*/"%08x",(unsigned)*Linternal);
		break;

	    case CNV_WAN_IPXNET:
#ifndef NA
            	*Sinternal = ntohs(*Sinternal);  /* we need a change back */
#endif
		sprintf(external, /*NOSTR*/"%08x",(unsigned)*Linternal);
		break;

            case CNV_TNI_CLOCK:
                decode_enum(*Sinternal, external, t1_clock_values, 0, 3);
                break;

            case CNV_TNI_LINE_BUILDOUT:
                decode_enum(*Sinternal, external, t1_buildout_values, 0, 4);
                break;

            case CNV_T1_FRAMING:
                decode_enum(*Sinternal, external, t1_framing_values, 0, 2);
                break;

            case CNV_T1_LINE_CODE:
                decode_enum(*Sinternal, external, t1_line_code_values, 0, 2);
                break;

            case CNV_T1_ESF_FDL:
                decode_enum(*Sinternal, external, t1_esf_fdl_values, 0, 2);
                break;

            case CNV_T1_MAP:
		/* ds0 format: <channel number> <mode> <modem number> */
	        /*                  ptr[0]      ptr[1]   ptr[2]       */
#ifndef NA
		*Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
		ptr = Cinternal;

		/* decode internal representation into external */
		/* modems are base-1, 0 = not used */
                if(ptr[2] == 0) {
		    /* modem is NOT being used, don't display it */
		    sprintf( external, 
			     /*NOSTR*/"ds0=%d %s\n",
			     ptr[0],
			     t1_mapping[ (int)ptr[1] ] );
		    }
		else {
		    /* modems are being used */
		    sprintf( external, 
			     /*NOSTR*/"ds0=%d %s %d\n",
			     ptr[0],
			     t1_mapping[ (int)ptr[1] ], 
			     ptr[2] );
		    }
                break;

            case CNV_T1_SIG_PROTOCOL:
		/* ds0 format:<channel number><inbound proto><outbound proto> */
	        /*                 ptr[0]          ptr[1]         ptr[2]      */
#ifndef NA
		*Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
		ptr = Cinternal;

		/* decode internal representation into external */
		sprintf( external,
			 /*NOSTR*/"ds0=%d %-15s %s\n",
			 ptr[0],
			 t1_sig_proto[ (int)ptr[1] ], 
			 t1_sig_proto[ (int)ptr[2] ] );
                break;

              case CNV_T1_SWITCH_TYPE:
                decode_enum(*Sinternal, external, t1_switch_type_values, 0, 3);
                break;

            case CNV_T1_RING:
		/* ds0 format:<channel number> <boolean ring flag on bit 0> */
	        /*                 ptr[0]                 ptr[1]            */
		/* yes=0, no=1, default is yes */
#ifndef NA
		*Sinternal = htons(*Sinternal);	/* gets switch back below */
#endif
		ptr = Cinternal;
		/* decode internal representation into external */
		sprintf( external, 
			 /*NOSTR*/"ds0=%d %5s\n",
			 ptr[0],
			 boolean_values[ (int)ptr[1] & 0x0001] );
                break;

	    case CNV_RESOLVE:

		switch (*Sinternal) {
		    case P_TELNET:
		    case P_CONNECT:
		    case P_ANY:
			(void)strcpy(external,
					pm_values[*Sinternal]);
			break;
		default:
			puntv("Bad value from eeprom for RESOLVE  ",
			    *Sinternal);
			break;
		}
		break;

	    case CNV_WAN_REMADDR:
#ifdef NA
		(void)strcpy(external, inet_ntoa(*Ninternal));
#else
		*Sinternal = ntohs(*Sinternal);	/* we need a change back */
		inet_ntoa(external, *Ninternal);
#endif
		break;

            case CNV_WAN_FRAMING:
                decode_enum( *Sinternal, external, wan_framing_values, 0, 6);
                break;

            case CNV_WAN_LINECODE:
                decode_enum(*Sinternal, external, wan_linecode_values, 0, 6);
                break;

            case CNV_WAN_RING:
		/* ds0 format:<channel number> <boolean ring flag on bit 0> */
	        /*                 ptr[0]                 ptr[1]            */
		/* yes=0, no=1, default is yes */
#ifdef NA
		external[0] = (((*internal) != 0) ? 'n' : 'y');
		external[1] = 0;
#else
		*Sinternal = htons(*Sinternal);	/* gets switch back below */
		ptr = Cinternal;
		/* decode internal representation into external */
		sprintf( external, /*NOSTR*/"%c",
			(((int)ptr[1] & 0x0001) ? 'n' : 'y'));
#endif
                break;

            case CNV_WAN_SIGPROTO:
		/* ds0 format:<inbound proto><outbound proto> */
	        /*                 ptr[1]         ptr[2]      */
		{
		    int indx;
		    u_short testval;
		    testval = *Sinternal;
		    for (indx = 0; indx < SIZE_SWPROTO_TAB; indx++)
			if (wan_sig_proto_table[indx] == (u_short)testval)
			    break;
		    if (indx >= SIZE_SWPROTO_TAB)
		      strcpy(external,"unknown");
		    else
		      sprintf(external, /*NOSTR*/"%s", wan_sig_proto[indx]);
		}
                break;

	    case CNV_WANDIST:
		decode_enum(*Sinternal, external, pridist_values, 0, 7);
		break;

	    case CNV_PRIBUILD:
		decode_enum(*Sinternal, external, pribuild_values, 0, 4);
		break;

	    case CNV_PRIFDL:
		decode_enum(*Sinternal, external, prifdl_values, 0, 2);
		break;

	    case CNV_WANANALOG:
		decode_enum(*Sinternal, external, prianalog_values,0,3);
		break;

        case CNV_MP_ENDP_OPT:
            decode_enum(*Sinternal, external, mp_values, 1, 6);
            break;  /* CNV_MP_ENDP_OPT */

	    case CNV_ADDR_ORIGIN:
		decode_enum(*Sinternal, external, addr_origin_values, 0, 5);
		break; /* CNV_ADDR_ORIGIN */

	    case CNV_BUSYSIG:
		decode_enum(*Sinternal, external, busysig_values, 1, 4);
		break; /* CNV_BUSYSIG */

	    case CNV_BANNER:
		decode_enum(*Sinternal, external, banner_values, 0, 5);
		break;

        case CNV_AUTH_PROTOCOL:
        decode_enum(*Sinternal, external, auth_protocol_values, 0, 2);
        break;
        case CNV_COMPAT_MODE:    
        decode_enum(*Sinternal, external, compat_mode_values, 0, 3);
        break;        
        case CNV_RAD_ACCT_LEVEL:
        decode_enum(*Sinternal, external, rad_acct_level_values, 0, 3);
        break;
        case CNV_RAD_PORT_ENCODING:
        decode_enum(*Sinternal, external, rad_port_encoding_values, 0, 2);
        break;



	    default:
		puntv("bad conversion code", (char *)0);
	}
	return;	/* void */

}	/*  decode()  */

static int
encode_range_ck(to, from, lo, hi, def)
unsigned short *to;
char *from;
int lo, hi, def;
{
    int val;

    if (!strncasecmp(from, "default", strlen(from))) {
        *to = (unsigned short) def;
    } else {
        val = strlen(from);
        while (val-- > 0) {
	  if (!(isdigit(from[val]))) {
              if(val == 0 && from[val] == '-') /* Negative number */
                      break;
                return(-1);
	    }
	  }
	val = atoi(from);
        *to = (unsigned short) val;

        if (val < lo || val > hi) {
            return(-1);
        }
    }
    return(0);
}

static int
encode_range_ckntp(to, from, lo, hi, def)
unsigned short *to;
char *from;
int lo, hi, def;
{
    int val;

    if (!strncasecmp(from, "default", strlen(from))) {
        *to = (unsigned short) def;
    } else {
        val = strlen(from);
        while (val-- > 0) {
	  if (!(isdigit(from[val]))) {
              if(val == 0 && from[val] == '-') /* Negative number */
                      break;
                return(-1);
	    }
	  }
	val = atoi(from);
        *to = (unsigned short) val;

        if ((val < lo || val > hi)&&(val != 0)) {
            return(-1);
        }
    }
    return(0);
}
static void
decode_enum(indx, external, table, lo, hi)
unsigned short indx;
char *external;
char *table[];
unsigned short lo, hi;
{

if (indx < lo || indx > hi)
    *external = '\0';
else
    strcpy(external, table[indx]);

return;
}

/*****************************************************************************
 *
 * NAME: decode_boolean
 *
 * DESCRIPTION:
 *    decode any of the standard boolean parameters
 *
 * ARGUMENTS:
 *    value             # the value to be decoded
 *    yes               # the value specifying "yes", "on", etc.
 *    string_table      # an array of two pointers, the first to the
 *                      #    string for the affirmative response,
 *                      #    the second to that for the negative.
 *    external          # the string equivalent of value.
 *
 * RETURN VALUE:        none
 *
 * SIDE EFFECTS:        none
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

static void
decode_boolean(value, yes, string_table, external)
int               value;
int               yes;
char              *string_table[];
char              *external;    /*  external representation (for human) */
{
   if (yes)
      if (value) strcpy(external, string_table[0]);
      else       strcpy(external, string_table[1]);
   else
      if (value) strcpy(external, string_table[1]);
      else       strcpy(external, string_table[0]);
   return;
}

/*****************************************************************************
 *
 * NAME: decode_string              
 *
 * DESCRIPTION:
 *    decode any of the standard variable length string parameters
 *
 * ARGUMENTS:
 *    Internal          # the string to be decoded cast as an INTERN
 *    max_length        # maximum string length allowed by the parti-
 *                      #    cular data type.
 *    external          # the decoded string.
 *
 * RETURN VALUE:        none
 *
 * SIDE EFFECTS:        none
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

static void
decode_string(Internal, max_length, external)
INTERN            Internal;     /*  internal representation (for Annex) */
int               max_length;
char              *external;    /*  external representation (for human) */
{
   int            length = CS_length;

   if (length > max_length) {
     puntv("exceeded length", (char *)0);
   }
   else {
      external[0] = '\"';
      (void) strncpy(&external[1], CS_string, length);
      external[length + 1] = '\"';
      external[length + 2] = 0;
   }

   return;
}


/************************************************************************
 * Quick check to make sure the mp epd address length is correct.
 ************************************************************************/
int validate_epd_address(mp_addr)
char *mp_addr;
{
    return((strlen(mp_addr) <=16)?1:0);
}

/****************************************************************
* check to validity of teh preferred server string in ntp module.
*****************************************************************/
int check_pref_server(external)
char *external;
{
char *prefString;
char *context ;
int flag = 0 ;
int server = 0;
int length = 0;
char pref_string[MAX_E2_STRING+1];

                if(strlen(external) > MAX_E2_STRING){
                        return(0);
                }

                strcpy(pref_string,external);
                if(strcmp(pref_string,"none") == 0) {
                        return(1);
                }

                prefString = strtokNA(pref_string,",",&context );
                while (prefString != NULL) {
                server = atoi(prefString);
                switch(server) {
                case 1 :
                case 2 :
                case 3 :
                case 4 :
                case 5 :
                 flag = 1 ;
                 break;
                default :
                 return(0);
                }
                prefString = strtokNA(NULL,",",&context );
                }


return(1);

}
/* get tokens from string */

char *
strtokNA(s, p, t)
char *s;                /* the string to scan */
char *p;                /* the pattern to use */
char **t;               /* termporary pointer for intermediate results */

{
   char *result, *pattern, *ending;

   if (s)
      result = s;       /* initial call */
   else
      result = *t;      /* done one already */
   if (result == NULL)
      return(result);
   while(*result)
   {
      pattern = p;
      while(*pattern)
      {
         if (*pattern == *result)
            break;
         pattern++;
      }
      if (*pattern)
         result++;      /* skip this character */
      else
         break;         /* found first character of token */
   }
   if (*result == 0)
   {
      result = NULL;
      *t = NULL;
      return(result);
   }
   ending = result+1;   /* now look for end of token */
   while(*ending)
   {
      pattern = p;
      while(*pattern)
      {
         if (*pattern == *ending)
            break;
         pattern++;
      }
      if (*pattern)
         break;         /* found separator */
      ending++;
   }
   if (*ending)
   {
      *ending = 0;      /* terminate token */
      *t = ending + 1;  /* for next call */
   } else
      *t = NULL;        /* all done */
   return(result);
}

/* END OF MODULE conv.c */

