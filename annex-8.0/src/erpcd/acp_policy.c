/*
 *****************************************************************************
 *
 *        Copyright 1989, 1990, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed MAterial - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 * 	Security Policy - Annex Security Server
 *
 * Original Author: Dave Harris		Created on: July 1986
 *
 * Module Reviewers:
 *
 *	lint harris parker
 *
 *****************************************************************************
 */


#include "comdefs.h"
/* Include Files */
#include <stdlib.h>
#include "../inc/port/install_dir.h"
#include "../inc/erpc/acp_const.h"
#include <sys/types.h>
#include "../inc/config.h"
#include "../inc/port/port.h"
#include "radius.h"
#include "acp_policy.h"

#include <ctype.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#define SECURID_CARD
#define ACE2_0
#ifndef BAY_ALPHA    /* Safeword not supported on DEC Alpha */
#define ENIGMA_SAFEWORD
#define NET_ENIGMA_ACP
#endif
#include "..\ntsrc\registry\xyreg.h"
#include <winbase.h>
#else /* not _WIN32 */
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include "erpc/nerpcd.h"
#include <netdb.h>
#include <netinet/in.h>
#include "acp_group.h"
#endif /* not _WIN32 */

#include "acp_regime.h" /*contains proto. 4 get_security_regime() */
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#ifdef USE_NDBM
#include <ndbm.h>
#include "acp_dbm_lib.h"
#endif

#include "getacpuser.h"
#include "environment.h"
#include "acp_lib.h"
#include "acp_trap.h"
#ifndef _WIN32
#include "session_db.h"
#endif /* _WIN32 */


#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else /* not WIN32 */
#include <syslog.h>
#endif /* not _WIN32 */

#include <sys/stat.h>
#include <fcntl.h>
#ifdef USESHADOW
#ifdef NATIVESHADOW
#include "shadow.h"
#else
#include "ashadow.h"
#endif
#endif

/* external variables */
extern int deny_all_users;            /* Defined in getacpuser.c
				       * Set to true if userinfo database is corrupted
				       * due to an invalid acp_userinfo file. All access
				       * is denied.
				       */

extern int acp_timer_enabled;         /* Defined in acp.c If set to true, invokes the
				       * SIGALRM and vice versa.
				       */

extern StructErpcdOption *ErpcdOpt;   /* Defined in erpcd.c Handles logging options for
				       * acp logging.
				       */
extern char szDefaultDomain[];

extern int alarm_flag;

#ifdef KERBEROS
#include <sys/param.h>
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
#include "krb.h"
#include "des.h"

#define KRB_TK_DIR "/tmp/tkt_erpcd_"
#endif

#ifdef SECURID_CARD
#ifdef ACE1_1
#include "sdcli.h"
#endif /* ACE1_1 */
#if (defined(ACE1_2) || defined(ACE2_0)) && !defined(_WIN32)
#include "sdi_athd.h"
#include "sdi_size.h"
#include "sdi_type.h"
#include "sdacmvls.h"
#include "sdconf.h"
union config_record configure;
#ifdef ACE2_0
#include "../sdclient/sdi_defs.h"
#endif /*ACE2_0*/
#endif /*(ACE1_2 || ACE2_0) && not _WIN32)*/
#if defined(_WIN32)
/* this vendor may be #defining const (tsk! tsk!) */
/* if so, undefine it afterwards */
#ifndef const
#define APC_POLICY_C_CONST_NOT_DEFINED
#endif /* not const */
#include "../sdiclient/sdathd.h"
#include "../sdiclient/sdacmvls.h"
#if defined(const) && defined(APC_POLICY_C_CONST_NOT_DEFINED)
#undef const
#endif /* defined(const) && defined(APC_POLICY_C_CONST_NOT_DEFINED) */
#endif /* _WIN32 */
#endif /* SECURID_CARD */

#if defined(ENIGMA_SAFEWORD) && !defined(_WIN32)
#include "custpb.h"
#include "custfail.h"
#endif /* defined(ENIGMA_SAFEWORD) && !defined(_WIN32) */

#if defined(ENIGMA_SAFEWORD) && defined(_WIN32)
#undef PROTOTYPING	/* (buggy swecapi.h can't handle it) */
#include "../enigma/swecapi.h"
#endif /* defined(ENIGMA_SAFEWORD) && defined(_WIN32) */

#include "../inc/erpc/netadmp.h"

/*
 * Create srtings that can indicate how the build was done. This must be done
 * only after reading in the acp_policy.h which has the final say on
 * definitions.  Since customers may build differently this can help the
 * technical support people figure out what is in the system. They can do a
 * "strings erpcd | grep XY" to get the information they need.
 */

/* The supported regimes.
 */
#ifdef ACPPASSWD
static char *xy_def1 = "\nXY defines: ACPPASSWD\n";
#endif
#ifdef NATIVEPASSWD
static char *xy_def2 = "\nXY defines: NATIVEPASSWD\n";
#endif
#if defined(ENIGMA_SAFEWORD) && !defined(NET_ENIGMA_ACP)
static char *xy_def3 = "\nXY defines: ENIGMA_SAFEWORD\n";
#endif
#ifdef SECURID_CARD
static char *xy_def4 = "\nXY defines: SECURID_CARD\n";
#endif
#ifdef KERBEROS
static char *xy_def5 = "\nXY defines: KERBEROS\n";
#endif

/* Using stub shared libraries?
 */
#ifdef STUB_SW
static char *xy_def6 = "\nXY defines: STUB_SW\n";
#endif
#ifdef STUB_SID
static char *xy_def7 = "\nXY defines: STUB_SID\n";
#endif
#ifdef STUB_KRB
static char *xy_def8 = "\nXY defines: STUB_KRB\n";
#endif

/* Variety of secureid regime
 */
#ifdef ACE1_1
static char *xy_def9 = "\nXY defines: ACE1_1\n";
#endif
#ifdef ACE1_2
static char *xy_def10 = "\nXY defines: ACE1_2\n";
#endif
#ifdef ACE2_0
static char *xy_def11 = "\nXY defines: ACE2_0\n";
#endif
#ifdef PASS_SEC
static char *xy_def12 = "\nXY defines: PASS_SEC\n";
#endif

/* Using shadow passwds for acp and/or native regimes
 */
#ifdef NATIVESHADOW
static char *xy_def13 = "\nXY defines: NATIVESHADOW\n";
#endif
#ifdef USESHADOW
static char *xy_def14 = "\nXY defines: USESHADOW\n";
#endif

#ifdef NET_ENIGMA_ACP
static char *xy_def15 = "\nXY defines: NET_ENIGMA_ACP\n";
#endif

#define END_OF_FILE	        1001
#define IS_ANNEX	        1002
#define IS_ANNEX_NOT	        1003
#define IS_HOST		        1004
#define IS_ENV_STRING		1005
#define IS_ENV_STRING_NOT 	1006
#define IS_ENV_STRING_ERR	1007
#define SIZE_INET	64
#define TOKEN_SIZE      256                 /*uniform token size used by different parsers*/
#define EXCLUDE_LIST	1
#define INCLUDE_LIST	2
#define ACCESS_RESTRICTED	0
#define ACCESS_UNRESTRICTED	1

/* Defining an enum for the various code paths chosen */

#define PORT_TO_ANNEX 0
#define IPX_VALIDATE 1
#define PPP_VALIDATE 2
#define NET_TO_PORT 3

/*   Function declarations   */
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

#ifdef USESHADOW
int     warn_user();
#endif

int	setacpdialup(), endacpdialup();
int	acp_validate();
int     acp_kerberos_validate();
int     acp_native_validate();

int     acp_acknowledge();
void    log_message();
void    terminate_session();
int     return_dialup_address();
int     return_max_logon_tcp();
int     dialup_address_authorize();
int     return_user_index();
int     return_log();
int     return_serial_validate();
int     ppp_security_authorize();
int     return_port_to_annex();
int     promptstring_wt();
int     promptstring();
int     outputstring();
int     port_to_annex_authorize();
int     return_annex_to_net();
int     inet_name();
int     available();
int     annex_to_net_authorize();
int     return_net_to_port();
int     net_to_port_authorize();
int     return_appletalk_profile();
int     return_hook_callback();
int     return_max_links();
int     create_group_list();
int	acp_netsafeword_validate();
int	acp_auth_resp();
int	write_audit_log();
int     get_string();
int     wild_match();
int     inet_match();
int     get_token();
int     acp_request_dialout_tcp();
int     acp_request_dialout_udp();
char	*crypt();
int	get_user_profile_entry();
void	release_uprof();

void	acp_special();
int	acp_getusr();
char    *test_password(), *change_password();
static UINT32 dialup_address_validate();
static int acp_securid_authenticate();
static int acp_securid_validate();
static void acp_safeword_printmsg();
static  void process_error();
static  void unlock_database();
void	inet_number();
UINT32	inet_address(), hash();
int	check_port_pool();
void	check_dialback();
void	ipx_check_dialback();
void	dialback_log();
int	access_code_validate();
int	findacpdialup();
int     hook_callback();
int     hook_callback_string();
int     user_index_authorize();
void    release_env();
void    racp_destroy_strlist_chain();
UINT32  get_chap_secret();
static int generic_authenticate_user _((ACP *, UINT32 logid, char *Name,
                                        char *Pass, int prompt,
                                        int max_retries, char *Message,
					ARQ_PROFILE *opt_info));

#ifdef _WIN32
int syslog( int pri, const char *format, ...);
int NTValidate();
/* in ntsupport.c */
extern char *PrependDomainNameAndFix(char *src, char *dest);
#endif

/************************************************************************
 * MACRO DEFINITIONS PRIVATE TO THIS MODULE
 */
/* Return values for get_host_and_ports()
 *  	FOUND_HOST - contained host entry but no port specification
 *	FOUND_HOST_PORTS - contained both host entry and port specification
 *	FOUND_HOST_ERROR - syntax error in token
 */
#define FOUND_HOST 		1
#define FOUND_HOST_PORTS 	2
#define FOUND_HOST_ERROR	3
#define HOST_PORT_BEGIN_SEPCH	'['
#define HOST_PORT_END_SEPCH	']'

/*   Global data declarations   */

extern char group_file[];
struct  gr_file fileinfo={group_file, DEFAULT_GROUP,0};
                                         /* used to pass group file info. where inaccessible
					  * due to modularity issues. Used for  userinfo
					  * lookups primarily.
					  */

/*
 * Un-comment this line to get debugging
 * information about dialup slip and ppp.
 */
/* #define DEBUG_DIALUP */

/* print debug statements for dialup */
int	debug_dialup =
#ifdef DEBUG_DIALUP
	1;
#else
	0;
#endif

INT32	daysleft;	                 /* Used to print password & account warnings */

/* External data */

extern int	debug;
#ifndef FREEBSD
#ifndef BSDI
#ifndef LINUX
#ifndef _WIN32	/* declared in <stdlib.h> for _WIN32 */
extern char	*sys_errlist[];
#endif
#endif
#endif
#endif

/* Used by the shadow-password-file code for aging passwords. */
static char old_password[LEN_ACCESS_CODE];  /* LEN_ACCESS_CODE == 16 */

/* Used to force a command into a user session for macro-per-user */
static char stuff_command[ACP_LONGSTRING]; /* ACP_LONGSTRING == 80 */
static char syslogbuf[512];

char	unknown[] = "<unknown>";
char    none[]    = "         ";

/*
 *   Define the Annex acp encryption key/password list
 *      (wildcard table and normal table)
 */

typedef	struct	key_list
	{
		UINT32		addr;	/* internet address (number) */
		KEYDATA		*ckey;	/* crypt key and tables */

	}	KEY_LST;

KEY_LST		Wild[MAX_WILD], Tame[MAX_TAME];

int		Nwild = 0, Ntame = 0;	/* number of actual entries */

/*
 *  Keep track of allocated memory to free on SIGHUP signal
 */

char		*Allocated[MAX_KEYS];	/* list of addresses to free */
int		Nmalloced = 0;		/* number of allocated KEYDATA's */

#if defined(ENIGMA_SAFEWORD) && !defined(_WIN32)
static struct pblk pblock;
static char savdyn[LEN_ACCESS_CODE]; /* LEN_ACCESS_CODE == 16 */
static char savcha[ACP_MAXSTRING];   /* ACP_MAXSTRING == 32 */

#ifdef USE_SYSLOG

extern char	*service_name[NSERVICES];

#endif /* USE_SYSLOG */
#endif /* defined(ENIGMA_SAFEWORD) && !defined(_WIN32) */


#define LINE \
	puts("\n-----------------------------------------------------------------------");


/************************************************************************
 * FUNCTIONS KNOWN TO BE PRIVATE TO THIS MODULE
 */

/************************************************************************
 * get_host_and_ports
 * Separate a host token into hostname and port parts
 * IN  token_p		host token
 * OUT host_pp		address of start of host part
 * OUT ports_pp		address of start of ports part
 * Results:
 *  	FOUND_HOST - contained host entry but no port specification
 *	FOUND_HOST_PORTS - contained both host entry and port specification
 *	FOUND_HOST_ERROR - syntax error in token
 */
static int get_host_and_ports(token_p, host_pp, ports_pp)
char *token_p;
char **host_pp;
char **ports_pp;
{
	char *temp_p;

	/* First, set the host part equal to the beginning of
	 * the string.
	 */
	*host_pp = token_p;

	/* Next, look and see if there is a beginning port separator
	 * character.  If not, we return that we saw only the host
	 * part, after setting the port pointer to NULL.
	 */
	if((*ports_pp = strchr(token_p, HOST_PORT_BEGIN_SEPCH))
		== (char *) 0)
		return(FOUND_HOST);

	/* If we got here, we're pointing at the opening bracket.
	 * First, we replace it with a NULL and move the ports
	 * pointer forward to point at the beginning of the
	 * ports expression.
	 */
	*(*ports_pp)++ = '\0';	/* separates host from ports */

	/* Now we need to determine whether the syntax is correct.
	 * This can be quickly deduced as follows:
	 * - The string is scanned for the ending separator character.
	 *	This must occur once and only once, and at the end.
	 * - The resulting string must contain only digits, commas,
	 *	and dashes.
	 * - Dashes or commas cannot appear at the beginning or the
	 * 	end of the string ("-90", "90-", "90,", etc., are not
	 *	valid).
	 */

	/* Find the separator.  It must be there, and at the end. */
	if(((temp_p = strchr(*ports_pp, HOST_PORT_END_SEPCH)) ==
		(char *) 0) || (strlen(temp_p) > 1))
		return(FOUND_HOST_ERROR);
	else
		*temp_p = '\0';	/* Get rid of it */

	/* Look for stray characters */
	for(temp_p = *ports_pp; *temp_p; temp_p++)
		if(!isdigit(*temp_p) && !isspace(*temp_p) &&
		   (*temp_p != ',') && (*temp_p != '-'))
			break;

	/* Make sure that we got all the way through, and that there
	 * are digits on both ends.
	 */
	if((*temp_p != '\0') || !isdigit(*(temp_p - 1)) ||
		!isdigit(**ports_pp))
		return(FOUND_HOST_ERROR);

	/* We have both a host and a ports specification. */
	return(FOUND_HOST_PORTS);

} /* get_host_and_ports */

/************************************************************************
 * match_host_ports
 * Attempt to find a match between a specified port and list of ports
 * IN  port		port to match
 * IN  portlist_p	list of ports to match against
 * Results:  TRUE if portlist_p == NULL or port in portlist_p,
 *		FALSE otherwise.
 */
static int match_host_ports(port, portlist_p)
int port;
char *portlist_p;
{
	char *temp_p,
	     *walk_p;
	int  saveport = -1;	/* Save start of range */
	char savech;

	/* First check and see if we even have to bother.  If there's
	 * no ports list, it matches by definition.
	 */
	if(portlist_p == (char *) 0)
		return(TRUE);

	/* Walk through the list, searching out valid ports one
	 * at a time.
	 */
	temp_p = walk_p = portlist_p;

	while(*temp_p) {
		/* temp_p points to beginning of next token.
		 * scan ahead until we find next non-digit.
		 */
		while(isdigit(*walk_p))
			walk_p++;

		/* Save the character and NULL it out temporarily
		 * to get the string port value.
		 */
		savech = *walk_p;
		*walk_p = '\0';

		/* If we get a range delimiter, we need to
		 * save this number and get the rest of it
		 * before we can match.
		 */
		if(savech == '-') {
			saveport = atoi(temp_p);

			/* Skip ahead */
			*walk_p = savech;
			temp_p = ++walk_p;

			/* And around we go again */
			continue;
		}

		/* If it's any other character we need to check
		 * and see if we got a range.
		 */
		if(saveport != -1) {
			/* Check to see if it's within the range.
			 * Be pessimistic about a user's entry -
			 * they might have said hi-lo, as opposed
			 * to lo-hi.
			 */
			if((saveport < atoi(temp_p)) &&
			   (port >= saveport) &&
			   (port <= atoi(temp_p))) {
					/* Found it */
					*walk_p = savech;
					return(TRUE);
			} else if((saveport >= atoi(temp_p)) &&
			          (port >= atoi(temp_p)) &&
				  (port <= saveport)) {
					/* Found it */
					*walk_p = savech;
					return(TRUE);
			} else {
				/* No match here */
				saveport = -1;

				/* Skip ahead */
				*walk_p = savech;
				temp_p = ++walk_p;

				/* And go around again */
				continue;
			}
		} else if(atoi(temp_p) == port) {
			/* Not a range.  Try matching it as
			 * a simple port number.
			 */
			*walk_p = savech;
			return(TRUE);
		}

		/* If we get here we've got no match.  Figure
		 * out if there's any more ports or not.
		 */

		if(savech == '\0') {
			/* Last one - no luck. */
			return(FALSE);
		}

		/* Move beyond these and try again */
		*walk_p = savech;
		temp_p = ++walk_p;
	}

	/* We should never get here, but just in case...*/
	return(FALSE);

} /* match_host_ports */

/*
 *	Annex Security Policy Procedures
 *
 *	global_init()		Annex boot, or security system restart
 *
 *	ppp_security()		Grant or deny access to Annex PPP or SLIP port
 *
 *	dialup_address()	Grant or deny access to Annex dialup user.
 *
 *	port_to_annex()		Grant or deny access to Annex CLI
 *	port_to_annex_logout()	Log message when CLI is terminated
 *
 *	annex_to_net()		Allow connection from Annex to a Host
 *	annex_to_net_logout()	Log message when connection is closed
 *
 *	annex_to_lat()		Log LAT connection attempt
 *
 *	net_to_port()		Grant or deny access to a port via port server
 *	net_to_port_logout()	Log message when connection is broken
 *
 *	appletalk_profile()	Return per user AppleTalk information
 *
 *	user_index()		Return password based on username.
 *
 *	up_secret()		Return secret based on username
 *
 *	Refer to ./policy.doc for information on customizing a security policy
 *	See Chapter 8 of the Annex Network Administrator's Guide (Security)
 *
 *	FILES:
 *
 *	In the examples below, INSTALL_DIR is selected by the install-annex
 *	script, and supplied to the erpcd makefile
 *
 *	INSTALL_DIR/acp_keys	    Annex encryption keys, see ENCRYPTION
 *	INSTALL_DIR/acp_passwd	    Annex password file, like /etc/passwd
 *	INSTALL_DIR/acp_restrict    Connectivity restrictions for annex_to_net
 *	INSTALL_DIR/acp_dialup	    Annex dialup addresses file
 *	INSTALL_DIR/acp_logfile	    Security Event Logging File
 *	INSTALL_DIR/acp_user	    Per User Configuration File
 *
 *	ENCRYPTION:
 *
 *	Messages between the security server and the Annex are encrypted if
 *	the Annex NA parameter acp_key is set, and the Annex is subsequently
 *	booted, given the NA "reset annex security" command, or CLI superuser
 *	"passwd" command.  Encryption keys for the server are stored in the
 *	acp_keys file.  Annexes with no entries are assumed to have no key
 *	set.  Since wildcards can be used, it might be necessary to include
 *	an entry in this file by explicitly declaring "no key", for example:
 *
 *	annex01, annex02:	seKret2
 *	#  131.21 net Annexes have same key except for 3 Annexes
 *	131.21.*:		Gub-Net
 *	131.21.1.1:		SpeciaL
 *	131.21.2.1, 131.21.2.2:
 *
 *	Keys on the original Annex are limited to 7 characters, on the Annex II
 *	15 characters.  Any alphanumeric character and most special characters
 *	may be included in a key.
 */


/*
 *	global_init()
 *
 *	This interface is called when the Annex boots, and security is enabled
 *	or if security is enabled for the first time by setting enable_security
 *	to Y (with NA) followed by a "reset annex security" or CLI passwd
 *	command.  In the first case, the Message is the boot image; in the
 *	latter case, the Message is "(restart)".
 */

void global_init(Acp, logid, inet, Message)

ACP		*Acp;		/* Handle to pass back to library calls */
UINT32		logid,		       /* Log sequence number (initial) */
		inet;		              /* Annex Internet address */
char		*Message;	        /* image booted, or "(restart)" */
{
	/*  Acknowledge call with a generic return message  */
	(void)acp_acknowledge(Acp);

	/*  Log a message with initial sequence number and image name  */

	if(ISUDP(Acp->state))
	  log_message(inet, logid, 0, 0, SERVICE_SECURITY, EVENT_BOOT, Message);

	/*  Exit this session  */

	terminate_session();

	/*  Return - unlikely since terminate_session() exit()s  */

	return;		/*  void  */
}

/*
 * 	dialup_address
 *
 *	This interface is called whenever a user must secure a port for
 *	dialup access.
 */

void dialup_address(Acp, logid, inet, port, ptype, sf, sr, Name, loc, rem,
		    node, get_filters, get_routes)

ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid,				/* Log sequence number */
		inet;			     /* Annex Internet address */
int		port,		       /* physical/virtual port number */
                sf,                     /* protocol service user is on */
		sr;      	   	      /* Expect SERVICE_DIALUP */
ACP_USTRING	Name;					   /* Username */
UINT32		loc,rem;		 /* local and remote addresses */
unsigned char *node;
int get_filters, get_routes;
int ptype;
{
  int net_type;
  STR_LIST *filters, *routes;
  STR_LIST **fp, **rp;
  UINT32 dialup_flags;

  fp = rp = NULL;
  filters = routes = NULL;
  if (!(ISUDP(Acp->state))) {   /* if UDP, there's can't be filters/routes */
    if (get_filters)
      fp = &filters;
    if (get_routes)
      rp = &routes;
  }
  if (debug)
    printf("dialup_address:  %swant filters, %swant routes\n",
	   fp ? "" : "do not ", rp ? "" : "do not ");
  /* Setup port type based on service */
  if (sr == SERVICE_DIALUP) {
	  net_type = IP_ADDRT;
  }
  else if (sr == SERVICE_DIALUP_IPX) {
	  net_type = IPX_ADDRT;
  }

  /* Send the local and remote addresses as a hint.  We may or
	   may not get the same addresses back. */

	(void)return_dialup_address(Acp, REQ_PENDING, net_type, loc, rem,
				    node, filters, routes);

  if(dialup_address_validate(Name, inet, net_type, &loc, &rem, node, port,
				   ptype, fp, rp, sf, &dialup_flags))
	{
	  (void)dialup_address_authorize(Acp, dialup_flags, net_type, loc, rem,
					 node, filters, routes);
	  if(ISUDP(Acp->state))
	    log_message(inet, logid, port, ptype, sr, EVENT_PROVIDE, Name);
	}
	else {
	  (void)dialup_address_authorize(Acp, dialup_flags, net_type, loc, rem,
					 node, NULL, NULL);
	  if(ISUDP(Acp->state))
	    log_message(inet, logid, port, ptype, sr, EVENT_NOPROVIDE, Name);
	}
	return;
}

/*
 *      user_index
 *
 *      This interface is called whenever a password or CHAP secret
 *	needs to be determined based on a username.
 */

void user_index(Acp, logid, inet, port, ptype, service, Name, endpoint)

ACP             *Acp;           /* Handle to pass to library functions */
UINT32          logid,                          /* Log sequence number */
                inet;                        /* Annex Internet address */
int             port,                  /* physical/virtual port number */
                ptype,                                    /* port type */
                service;                         /* Expect SERVICE_DOS */
ACP_USTRING      Name;                                      /* Username */
EndpDesc        *endpoint;                /* MP Endpoint Discriminator */
{
   /*
    * Adding the per-user code to this interface. This code will
    * create a user's environment and search the database using
    * this environment.
    */

    Uprof           up; 		       /* storage for userinfo database */
                                                                          /* entries. */
    int             error, n;                    /* returned error codes from user*/
                                                                     /* -info search. */
    UINT32          ret_err_code= REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
                                                     /* codes identifying regime and  */
                                                         /* reasons used for logging. */
    struct          environment_spec env, *env_p = &env;
    char            upfield[ACP_MAXSTRING];             /* message for authorization. */
#ifndef _WIN32
    struct radius_attribute attrib;
#endif /* not _WIN32 */

    if(debug)
      puts("policy: user_index");

    /*
     * If deny_all_user == TRUE, it means that
     * userinfo database doesn't exist due to a corrupt acp_userinfo file.
     * This is a security breach and all users must be denied access
     * and event logged.
     */
    if(deny_all_users)
    {
      syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
all users. Check acp_userinfo file!\n");
      (void)user_index_authorize(Acp, REQ_DENIED, upfield);
      if (ISUDP(Acp->state))
	log_message(inet, logid, port,ptype, service, EVENT_NOPROVIDE, Name);
      return;
    }

    /*
     * The switch, user_index_pend will cause one of two things to happen.
     *
     * Currently, this routine will not send a PEND back to the Annex, it
     * simply gets the user-specific information and sends the response
     * back to the Annex.  If user_index_pend is #define'ed, then the Annex
     * will immediately send a PEND back to the Annex, get the user's
     * information and make the call to the Annex.
     *
     * If obtaining the user-specific information becomes too time-consuming,
     * the user_index_pend switch may be used to use the PEND mechanism instead.
     *
     */
#ifdef user_index_pend
    (void) bzero((char*)&up, sizeof(Uprof));
    if (service == SERVICE_SECRET)
        (void)return_user_index(Acp, REQ_PENDING,up.up_secret);
    else if (service == SERVICE_MP)
        (void)return_max_links(Acp, REQ_PENDING, up.up_mp_max_links);
    else
        (void)return_user_index(Acp, REQ_PENDING, up.user_index);
#endif

    env.annex = inet; /* ip addr. of annex requesting authentication*/
    env.port = port;  /* port no. where request is generated from   */
    env.ptype = ptype;
    env.protocol = service;                      /* cli, slip, ppp ?? */
    env.regime = (struct security_regime *)NULL; /* what regime used */
    env.group_list = (struct group_entry *)NULL; /* groups for user */

    if (endpoint && endpoint->valid)
    {
        env.endpoint.class = endpoint->class;
        env.endpoint.length = endpoint->length;
        env.endpoint.valid = endpoint->valid;
        bcopy ((char*)endpoint->address,(char*)env.endpoint.address,
               endpoint->length);
    }
    else
        env.endpoint.valid = 0;

    /* Get the time-stamp for this action */
    if (get_time_stamp(&(env.time)) == FALSE)
        syslog(LOG_ERR,"Failed to retrieve system time");

    /* save the user's name */
    strncpy(env.username, Name, LEN_USERNAME -1);
    env.username[LEN_USERNAME -1]= '\0';

#ifndef _WIN32
    /* if we got max_links from radius, send it back */
    Acp->env = &env;
    if (service == SERVICE_MP) {
        int rc = 0;
        int offset = 0;

        bzero((char*)&attrib, sizeof(struct radius_attribute));
        attrib.type = PW_PORT_LIMIT;
        rc = ses_get_attribute(Acp->env, &attrib, &offset);
        if (rc > 0) /* found */
            return_max_links(Acp, REQ_GRANTED, attrib.lvalue);
        else if (rc < 0) /* not found */
            return_max_links(Acp, REQ_GRANTED, 1);
        if (rc != 0) /* radius user */
            return;
    }
#endif  /* _WIN32 */

    /* get user's entry from the userinfo database */
    /* Initialize the various uprof structs */
#ifndef user_index_pend
    (void) bzero((char*)&up, sizeof(Uprof));
#endif    
    error = get_user_profile_entry(&up, env.username, &env_p, &fileinfo);	    

    /* If user has a deny entry in userinfo entry, deny access. */
    if(up.up_deny)
    {
        ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
        (void)return_user_index(Acp, ret_err_code, upfield);
        if (ISUDP(Acp->state))
            log_message(inet, logid, port,ptype, service, ret_err_code, Name);
        release_env(env_p);
	release_uprof(&up);
        return;
    }

    if (service == SERVICE_MP) {
        if (error == ACPU_ESUCCESS && up.up_mp_max_links)
            return_max_links(Acp, REQ_GRANTED, up.up_mp_max_links);
        else /* default to 1 */
            return_max_links(Acp, REQ_GRANTED, 1);
	release_uprof(&up);
        return;
    }

    if (service == SERVICE_SECRET)
        bcopy(up.up_secret,upfield,sizeof(up.up_secret));
    else
        bcopy(up.user_index,upfield,sizeof(up.user_index));

    n = strlen(upfield);

    /*
     * if Dyndial_passwd/chap secret exists for the user
     * , annex is informed about it.
     */
#ifdef user_index_pend
    if ((error == ACPU_ESUCCESS) && (n > 0))
    {
        (void)user_index_authorize(Acp, REQ_GRANTED, upfield);
        if(ISUDP(Acp->state))
            log_message(inet, logid, port,ptype, service, EVENT_PROVIDE,
                        Name);
    }
    else if ((error != ACPU_ESUCCESS) || (service != SERVICE_MP))
    {
        (void)user_index_authorize(Acp, REQ_DENIED, upfield);
        if (ISUDP(Acp->state))
            log_message(inet, logid, port,ptype, service,
                        EVENT_NOPROVIDE , Name);
    }
#else
    if ((error == ACPU_ESUCCESS) && (n > 0))
    {
        (void)return_user_index(Acp, REQ_GRANTED, upfield);
	if (ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_PROVIDE, Name);
    }
    else
    {
        (void)return_user_index(Acp, ret_err_code, upfield);
	if (ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, ret_err_code, Name);
    }
#endif
    release_uprof(&up);
    return;
}


/*
 *	ppp_security
 *
 *	This interface is called whenever an Annex user logs in on a
 *	PPP port, and the the NA parameters enable_security and
 *	cli_security are Y and the security type for that port is PAP.
 *	On virtual CLI's, cli_security (a per-port parameter) is
 *	assumed to be Y.
 */
void ppp_security(Acp, logid, inet, port, ptype, service, direction, Name, Pass, opt_info)

ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid,				/* Log sequence number */
		inet;			     /* Annex Internet address */
int		port,		       /* physical/virtual port number */
		service;	          /* Expect SERVICE_{PPP,SLIP} */
int		direction;		       /* direction of service */
ACP_USTRING	Name;		      /* Username and password */
ACP_STRING	Pass;		      /* Username and password */
int ptype;
ARQ_PROFILE	*opt_info;
{
    int valid = 0;
    int error;
    int regimes_passed = 0, regimes_tried = 0;

    /* vars for per-user security */
    struct environment_spec env, *P_env = &env;
    Uprof  up;			/* storage for userinfo database entries */

    char String[TOKEN_SIZE];    /* Any token of size 256 or less */

    /*  Zero out the Uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);

    /*  supply return to procedure call so Annex does not timeout  */
    (void)return_serial_validate(Acp, REQ_PENDING);

    /*
     * userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and event
     * logged.
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "ppp_security: userinfo database is corrupted, denying access to all users. Check acp_userinfo file!\n");
        (void)ppp_security_authorize(Acp,REQ_DENIED);
        if(ISUDP(Acp->state))
	    log_message(inet, logid, port, ptype, service, EVENT_REJECT, String);
        terminate_session();
        return;
    }

    /*
     * If you return REQ_GRANTED here, then all connections are allowed
     * You can use this feature to bypass security for a group of ports
     */
    if (Pass[0]=='\0' && Name[0]=='\0')
    {
        (void)ppp_security_authorize(Acp,REQ_DENIED);
	terminate_session();
	return;
    }

    String[0] = '\0';
    strcat(String,Name);

    /*
     * generic_authenticate_user authenticates the user and returns a value
     * based on the authentication results.
     */
    Acp->env = &env;
    bzero((char*)&env, sizeof(struct environment_spec));
    strncpy(env.username, Name, LEN_USERNAME - 1);
    Name[LEN_USERNAME - 1] = '\0';
    env.annex = inet;
    env.port = port;
    env.ptype = ptype;
    env.protocol = service;
    Acp->auth.blacklisted = FALSE;
    Acp->chap = NULL;

    valid = generic_authenticate_user(Acp, logid, Name, Pass, FALSE, 1,
                                      String, opt_info);

    if(valid > 0)
    {
        /*
         * This call looks up userinfo database and chooses
         * the first entry that it finds and returns a pointer to the
         * entry. If the search fails, ie nothing for this user is found,
         * pointer points to an emtpy Uprof struct.
         */
       error = get_user_profile_entry(&up, Name, &P_env, &fileinfo);
       if (debug && error)
	 printf("user valid, but profile fetch failed:  %d\n",error);
    }

    /* user has passed authentication & no deny in the userinfo entry. */
    if ((valid > 0) && (error == ACPU_ESUCCESS || error == ACPU_ENOUSER) 
        && (!up.up_deny))
    {
        (void)ppp_security_authorize(Acp, REQ_GRANTED);
        if (ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Name);
    }
    else /*user failed authentication or has been denied access in userinfo  */
    {

        /* if deny in userinfo, use the error code for log in acp_logfile */
        if (up.up_deny)
            Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_DENYUSER);


	/* deny user with the appropriate error code */
        (void)ppp_security_authorize(Acp, Acp->auth.ret_err_code);
        if (ISUDP(Acp->state))
            log_message(inet, logid, port,ptype, service,
                        Acp->auth.ret_err_code, String);


	/*user black listed but not denied in userinfo.*/
        if (Acp->auth.blacklisted && (!up.up_deny)) 
            log_message(inet, logid, port, ptype, service, EVENT_BLACKLIST,
                        Name);

    }

    if (Acp->auth.hmask)
        acp_timer_enabled = 0;
    else if (ISTCP(Acp->state))
        terminate_session();

    release_uprof(&up);
}



/*
 *	ipx_validate
 *
 *	This interface is called whenever an Annex user logs in on a
 *	IPX port.
 */
void ipx_validate(Acp, logid, inet, port, ptype, service,
			Name, Pass, Phone, Netnum, opt_info)

ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid,				/* Log sequence number */
		inet;			     /* Annex Internet address */
int		port,		       /* physical/virtual port number */
		service;	        	 /* Expect SERVICE_IPX */
ACP_USTRING	Name;
ACP_STRING	Pass,
		Phone;
int		Netnum;
int ptype;
ARQ_PROFILE	*opt_info;
{
    char   Message[TOKEN_SIZE];            /* error message to be logged. */
    int    blacklisted = FALSE;
    int    valid = 0;                            /* user passed/faild authentication */
    int    error;                             /* success/failure for userinfo search */
    int    regimes_passed = 0, regimes_tried = 0;
                            /* codes identifying regime and reason, used for logging */

    /* vars for per-user security */
    struct environment_spec env, *P_env = &env;
    struct env_gr_info envinfo;             /* user's environment & group filenames  */
    Uprof  up;				    /* storage for userinfo database entries */

    Message[0] = '\0';

    /*  Zero out the Uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
    /*
     * userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and event
     * logged.
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "ipx_validate: userinfo database is corrupted, denying access to all users. Check acp_userinfo file!\n");
        (void)return_serial_validate(Acp, REQ_DENIED);
        if(ISUDP(Acp->state))
            log_message(inet, logid, port, ptype, service, EVENT_REJECT,
                        Message);
	if (Acp->auth.hmask)
            acp_timer_enabled = 0;
        else
            terminate_session();

        return;
    }

    /*
     * generic_authenticate_user authenticates the user and returns a value
     * based on the authentication results.
     */
    Acp->env = &env;
    bzero((char*)&env, sizeof(struct environment_spec));
    strncpy(env.username, Name, LEN_USERNAME - 1);
    Name[LEN_USERNAME - 1] = '\0';
    env.annex = inet;
    env.port = port;
    env.ptype = ptype;
    env.protocol = service;
    Acp->auth.blacklisted = FALSE;
    Acp->chap = NULL;

    valid = generic_authenticate_user(Acp, logid, Name, Pass, FALSE, 1,
                                      Message, opt_info);

    /*user's environment and group file info is saved. */
    envinfo.env     = &P_env;
    envinfo.gr_info = &fileinfo;

    /*
     * This call looks up userinfo database and chooses
     * the first entry that it finds and returns a pointer to the
     * entry. If the search fails, ie nothing for this user is found,
     * pointer points to an emtpy Uprof struct.
     */
    error = get_user_profile_entry(&up, Name, &P_env, &fileinfo);

    /* Users has passed authentication and is not denied in userinfo */
    if ((valid > 0) && (error == ACPU_ESUCCESS || error == ACPU_ENOUSER) 
        && (!up.up_deny))
    {
#if (DEFAULT_NO_USERINFO > 0)
        Access	ac_info;

	/*
	 * Whether accesscode is defined in the userinfo
	 * for this user.
	 */
        error = get_user_access(Name, "ipx", &ac_info, &envinfo);

#endif
	/*
	 * This if block checks whether this this is a
	 * dialback request. "check_port_pool" checks
	 * if this port is specified in the userinfo
	 * database's port pool with the annex (inet).
	 */
        if ( (service == SERVICE_IPX_DIALBACK) ||
#if (DEFAULT_NO_USERINFO > 0)
	   (error == ACPU_ENOUSER || error == ACPU_ENOACC) ||
#endif
	   (check_port_pool(inet,port,ptype,(caddr_t)0) != DIAL_SUCC))
	{
	    (void)return_serial_validate(Acp, REQ_GRANTED);
	    if (ISUDP(Acp->state))
	        log_message(inet, logid, port, ptype, service, EVENT_LOGIN, Name);
	}
        else
	{
            /* this is a dialback request */
	    ipx_check_dialback(Acp, logid, inet, port,ptype, service,
				Name, Netnum, Phone);
	}
    }
    else     /* user is to be denied access */
    {
        /* if there is a deny in user's userinfo entry */
        if (up.up_deny)
            Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_DENYUSER);

        /* log appropriate message */
        (void)return_serial_validate(Acp, Acp->auth.ret_err_code);
	if (Message[0])
	{
	    strcat(Message, ", ");
	    if (Acp->auth.blacklisted)
	        log_message(inet, logid, port,ptype, service, EVENT_BLACKLIST, Name);

        }
	strcat(Message, Name);
	if (ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, Acp->auth.ret_err_code,
                    Message);
    }

    /*  terminate (exit()) this session  */
    if (Acp->auth.hmask)
       acp_timer_enabled = 0;
    else
       terminate_session();

    release_uprof(&up);

    return;
}


/*
 *	port_to_annex()
 *
 *	This interface is called whenever a user starts an Annex CLI, and
 *	the NA parameters enable_security and cli_security are both Y.  On
 *	virtual CLI's, cli_security (a per-port parameter) is assumed to be Y.
 */

void port_to_annex(Acp, logid, inet, port,port_type, service, opt_info)

ACP		   *Acp;		    /* Handle to pass to library functions */
UINT32		    logid,		                    /* Log sequence number */
		    inet;		                 /* Annex Internet address */
int		    port,		           /* physical/virtual port number */
		    service,		             /* Expect SERVICE_CLI{,_HOOK} */
                    port_type;                       /* port type virtual physical */
ARQ_PROFILE		*opt_info;
{
    ACP_USTRING	    Name;
#ifndef _WIN32
    ACP_LSTRING     Pass;
#else   /* defined _WIN32 */
	ACP_STRING     Pass;
#endif   /* defined _WIN32 */

    char            Message[TOKEN_SIZE];   /* error message to be logged. */
    int		    passed = NOT_VALIDATED;
    char	    nullstr[1];
    Uprof           up;
    int             error;
    char	   *userprompt = ACP_USERPROMPT,
                   *incorrect  = ACP_INCORRECT,
                   *permdenied = ACP_PERMDENIED;

    UINT32	    mask       = CLI_MASK,
                    rcode      = REQ_DENIED;

    char	    password_security = 0;
    int		    use_securid       = 0,
                    use_safeword       = 0,
                    s_passed          = 0,
                    p_passed          = 0;

    int             regimes_passed    = 0,
                    done              = FALSE,
                    regimes_tried     = 0;

    struct         environment_spec env, *P_env = &env;
    struct         env_gr_info     envinfo;  /* user's environment & group filenames  */

    if(debug)
        puts("policy: port_to_annex");

    nullstr[0] = '\0';

    /* Initialize the various uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    Acp->auth.blacklisted = FALSE;
    Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
    /*  supply return to procedure call so Annex does not timeout  */
    (void)return_port_to_annex(Acp,REQ_PENDING,mask,nullstr);

    /*
     * userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and event
     * logged.
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "port_to_annex: userinfo database is corrupted, denying access to all users. Check acp_userinfo file!\n");
        (void)port_to_annex_authorize(Acp,rcode,mask, "userinfo-corrupt", 0);
        if(ISUDP(Acp->state))
            log_message(inet, logid, port,port_type, service, EVENT_REJECT, Name);
        terminate_session();
        return;
    }

    Message[0] = '\0';

    /*
     * generic_authenticate_user authenticates the user and returns a value
     * based on the authentication results. If USER_VALIDATION !=1, then
     * user is not authenticated, however, this fxn. gives us the user's
     * environment which can be used to get cli commands.
     */
    Acp->env = &env;
    bzero((char*)&env, sizeof(struct environment_spec));
    env.annex = inet;
    env.port = port;
    env.ptype = port_type;
    env.protocol = service;
    Acp->auth.blacklisted = FALSE;
    Acp->chap = NULL;

    passed = generic_authenticate_user(Acp, logid, Name, Pass, TRUE, 3,
                                       Message, opt_info);

    /* user's environment and group file info is saved. */
    envinfo.gr_info = &fileinfo;
    envinfo.env     = &P_env;

    /*
     * This call looks up userinfo database and chooses
     * the first entry that it finds and returns a pointer to the
     * entry. If the search fails, ie nothing for this user is found,
     * pointer points to an emtpy Uprof struct.
     */
    error = get_user_profile_entry(&up, Name, &P_env, &fileinfo);

#if	(USER_VALIDATION)
    /*
     * User has passed authentication. Now we'll
     * see if this is a dialback request, if not
     * we get user's environment from userinfo database
     */

    if (passed > NOT_VALIDATED) /* authorize use of CLI */
    {

#if (DEFAULT_NO_USERINFO > 0)
        Access	ac_info;
	int		ret_user_access;
#endif
	if ( (service == SERVICE_DIALBACK) ||
#if (DEFAULT_NO_USERINFO > 0)
	    /*
	     * lookup userinfo database for the user's entry
	     * with accesscode information for dialback
	     */
	    ((ret_user_access = get_user_access(Name, 0, &ac_info, &envinfo))
	     == ACPU_ENOUSER) ||
	    (ret_user_access == ACPU_ENOACC) ||
#endif
	    /*
	     * check the port pool in userinfo database only
	     * when the port is "serial" since that's only
	     * when dialback is allowed; ie. dialback is not
	     * allowed for vcli connections.
	     */
	    ((port_type != DEV_SERIAL && port_type != DEV_V120) ||
	    ((check_port_pool(inet, port,port_type, (caddr_t)0)) != DIAL_SUCC)))

    {
	    /* If user has a deny entry in userinfo entry, deny access. */
	    if(up.up_deny)
	    {
	        Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
	        (void)port_to_annex_authorize(Acp, Acp->auth.ret_err_code,mask,
                                          Name, 0);
	        if (ISUDP(Acp->state))
                    log_message(inet, logid, port, port_type, service,
                                Acp->auth.ret_err_code, Name);
    		release_uprof(&up);
	        return;
	    }

	    /* save climasks specified in userinfo entry, */
	    if (error == ACPU_ESUCCESS && up.up_climask != 0)
	        mask = up.up_climask;

	    /*
	     * cli commands are specified in the user's userinfo
	     * entry; save 'em and set rcode such that annex
	     * expects cli commands with the authorization packet.
	     */
#ifndef _WIN32
        if (Acp->env->regime->regime_mask == RADIUS_MASK) {
            if (Acp->auth.cmd_list != NULL) {
                Acp->auth.hmask =
                    (CHOOK_PROMPTING | CHOOK_BADCMND | CHOOK_GOODCMND);
                rcode = REQ_GRANT_HOOK;
            }
            else
                rcode = REQ_GRANTED;
        }
        else if (up.up_cmd_list && (service == SERVICE_CLI_HOOK ||
                                     service == SERVICE_DIALBACK))
#else   /* defined _WIN32 */
        if (up.up_cmd_list && (service == SERVICE_CLI_HOOK ||
                                service == SERVICE_DIALBACK))
#endif   /* defined _WIN32 */
        {
            Acp->auth.hmask =
                (CHOOK_PROMPTING | CHOOK_BADCMND | CHOOK_GOODCMND);
            Acp->auth.cmd_list = up.up_cmd_list;
            rcode = REQ_GRANT_HOOK;
        }
        else
            rcode = REQ_GRANTED;

	    /* log the successful log-in */
        if (error == ACPU_ESUCCESS && ISUDP(Acp->state))
            log_message(inet, logid, port, port_type, service, EVENT_LOGIN,
                        Name);

    }
	else
	{
	    /* this is a dialback request */
	    check_dialback(Acp, logid, inet, port,port_type, service, Name);
	}

	/*
	 * Sending "permission granted" to the annex.
	 * tcp code does away with "to" arguement but udp
	 * still uses it. Garbage value leaves the vcli
	 * connection hanging with R10.1 boot image
	 */
        if(rcode == REQ_GRANTED || rcode == REQ_GRANT_HOOK)
	    outputstring(Acp, ACP_PERMGRANTD);

	if (debug)
	    fprintf(stderr,"acp_policy.c: rcode = %d hmask = %d service = %d\n",
                rcode, Acp->auth.hmask, service);
	error = port_to_annex_authorize(Acp,rcode,mask,Name,Acp->auth.hmask);
	if (debug)
	    fprintf(stderr,"acp_policy.c: called port_to_annex_authorize;\
                                           returned value error = %d\n",error);
    }
    else
    {
	/* else reject and log */
       	(void) port_to_annex_authorize(Acp, Acp->auth.ret_err_code, mask,
                                       Message,0);
	if (ISUDP(Acp->state))
            log_message(inet, logid, port,port_type, service,
                        Acp->auth.ret_err_code, Message);
        if (Acp->auth.blacklisted)
	   log_message(inet, logid, port,port_type, service, EVENT_BLACKLIST, Name);
    } /* user is denied access. */

#else /* !USER_VALIDATION */

    /*  with user validation disabled, return CLI mask, and log */

    /*
     * cli commands are specified in the user's userinfo
     * entry; save 'em and set rcode such that annex
     * expects cli commands with the authorization packet.
     */
    if (service == SERVICE_CLI_HOOK && up.up_cmd_list)
    {
        Acp->auth.hmask = (CHOOK_PROMPTING | CHOOK_BADCMND | CHOOK_GOODCMND);
        Acp->auth.cmd_list = up->up_cmd_list;
        rcode = REQ_GRANT_HOOK;
    }

    /* a generic authorize. */
    else
        rcode = REQ_GRANTED;

    /* sending the authorize packet. */
    (void)port_to_annex_authorize(Acp,rcode,mask,unknown,Acp->auth.hmask);

    /* log the event */
    if (ISUDP(Acp->state))
        log_message(inet, logid, port,port_type, service, EVENT_LOGIN, unknown);

#endif /* USER_VALIDATION */

    /*  terminate (exit()) session  */
    if (Acp->auth.hmask)
        acp_timer_enabled = 0;
    else
        terminate_session();

    release_uprof(&up);
    return;
}


/*
 *	annex_to_net()
 *
 *	This interface is called whenever a CLI user attempts to connect to
 *	a machine with a call, rlogin, or telnet command; OR when a port
 *	configured for dedicated mode attempts to connect to its dedicated
 *	host.  Enable_security and connect_security must be set to Y.
 *
 *	The default policy is to scan the acp_restrict file for entries
 *	which explicitly allow or disallow connection from the given
 *	Annex to the given remote host.  The file is searched sequentially.
 *	If no entry is found which matches both the Annex and remote host,
 *	either by name, Internet address, or wildcard, then permission is
 *	granted.  For example:
 *
 *	*:		snowwhite
 *	annex01:	harp, knight
 *	annex02:	harp, knight
 *	130.12.*~	131.12.*, annex01, annex02
 *	130.12.*:	*
 *
 *	: means restricted host, ~ means unrestricted host.  No Annex may
 *	connect to snowwhite; annex01 and annex02 may not connect to harp or
 *	knight; Annexes on network 130.12 may only connect to other Annexes
 *	on the same network, or to annex01 or annex02.
 */

void annex_to_net(Acp, logid, linet, port,ptype, service, rinet, Username, tcp_port_req)

ACP		*Acp;			/* Handle to pass to library calls */
UINT32		logid,			       /* log file sequence number */
		linet,			  /* Internet address of the Annex */
		rinet;			/* Internet address of target host */
int		port,			/* physical or virtual port number */
		service,		  /* SERVICE_{CALL,RLOGIN, TELNET} */
		tcp_port_req;		                /* tcp port number */
char		*Username;		   /* Username associated with CLI */
int ptype;
{
    char	String[TOKEN_SIZE];   /* Any token of size 256 or less */
    char	Hostname[ACP_MAX_HOSTNAME_LEN]; /* ACP_MAX_HOSTNAME_LEN == 32 */

#ifndef _WIN32

    struct environment_spec *env_p;     /* storage for user's environment. */
    struct security_regime *regime;  /* storage for regime and passwd file */

#endif

    if(debug)
       	puts("policy: annex_to_net");

    /*
     * userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and
     * event logged
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
all users. Check acp_userinfo file!\n");
        goto error;

    }

    /*  Inform Annex that policy decision is pending  */
    (void)return_annex_to_net(Acp, REQ_PENDING);

    /*  Translate Remote Internet address for log message  */
    inet_name(Hostname, rinet);

    /*  If USER_VALIDATION, include username in log message  */
#if  (USER_VALIDATION)

    /* include port in the message */
    if (tcp_port_req < 0)
        (void)sprintf(String, "%s:%s", Hostname, Username);
    else
        (void)sprintf(String, "%s:%d:%s", Hostname, tcp_port_req, Username);
#else
    /* no user validation, hence no username */
    if (tcp_port_req < 0)
        (void)strncpy(String, Hostname, ACP_MAX_HOSTNAME_LEN);
    else
        (void)sprintf(String, "%s:%d", Hostname, tcp_port_req);

#endif

#ifndef _WIN32

    /*
     * create user's environment. get time-stamp, and check
     * for restriction to be applied in acp_restrict
     * file (by calling available())
     */
    if((env_p = create_env())==NULL)
    {
       	/* Log this event */
        if (strlen(String))
        {
            strcat(String, ",");
        }
        syslog(LOG_ERR,"Failed to allocate memory");

        /* send reject authorization */
        goto error;

    } /* Unable to allocate memory for environment. */

    /*
     * No problem with memory allocation. We can proceed.
     * Set the annex address , port and service (cli/ppp/slip)
     */
    env_p->annex    = linet;
    env_p->port     = port;
    env_p->ptype = ptype;
    env_p->protocol = service;

    /* Get the timestamp for this action */
    if (get_time_stamp(&(env_p->time)) == FALSE)
    {
        /* Log this event */
        if (strlen(String))
        {
            strcat(String, ",");
        }
        syslog(LOG_ERR,"Failed to retrieve system time");
        goto error;

    }

    strcpy(env_p->username,Username);
    if (create_group_list(&(env_p->group_list),env_p->username) == FALSE){
       goto error;
    }

    /*
     * Check if the host requested for connection is
     * restricted for connection or not. Also
     * if the request is to start ppp or slip
     * connection (from a cli prompt), this
     * call will generate automatic filters for
     * the restrictions specified in the acp_restrict
     * file.
     */
    if(available(env_p, rinet, tcp_port_req,DEV_ETHERNET, FALSE, NULL))
    {
        /* if OK, authorize and log */
        (void)annex_to_net_authorize(Acp, REQ_GRANTED);
        if(ISUDP(Acp->state))
            log_message(linet, logid, port,ptype, service, EVENT_LOGIN, String);
        release_env(env_p);
        goto exit;
    }
    else
        goto error;
        /* reject and log  */
    /* free the allocated memory for environment */

#else /* _WIN32 */
    /* if OK, authorize and log */
    (void)annex_to_net_authorize(Acp, REQ_GRANTED);
    if(ISUDP(Acp->state))
        log_message(linet, logid, port,ptype, service, EVENT_LOGIN, String);
    goto exit;
#endif /* _WIN32 */

error:
        /* reject and log  */
    (void)annex_to_net_authorize(Acp, REQ_DENIED);
	if(ISUDP(Acp->state))
	    log_message(linet, logid, port,ptype, service, EVENT_REJECT, String);
#ifndef _WIN32
    release_env(env_p);
#endif  /* _WIN32 */
	goto exit;
exit:
    /* terminate (exit()) this session */
    terminate_session();

    /* dummy return which might never happen */
    return;
}


/*
 *	annex_to_lat()
 *
 *	This interface is called whenever a CLI user attempts to
 *	connect to a machine with a LAT connect command.
 *	Enable_security and connect_security must be set to Y.
 *
 *	The connection attempts are only logged.
 */


void annex_to_lat(Acp, logid, linet, port,ptype, service, Username, Service_name)

ACP		*Acp;		             /* Handle to pass to library calls */
UINT32		logid,		                    /* log file sequence number */
		linet;		               /* Internet address of the Annex */
int		port,		             /* physical or virtual port number */
		service;	                             /* SERVICE_CONNECT */
char		*Username,	                /* Username associated with CLI */
		*Service_name;	                            /* LAT service name */
int ptype;
{
    char	String[TOKEN_SIZE];      /* Any token of size 256 or less */

    if(debug)
	puts("policy: annex_to_net");

    /*  Inform Annex that policy decision is pending  */
    (void)return_annex_to_net(Acp, REQ_PENDING);
    (void)annex_to_net_authorize(Acp, REQ_GRANTED);

    (void)sprintf(String, "%s:%s", Service_name, Username);

    if(ISUDP(Acp->state))
      log_message(linet, logid, port,ptype, service, EVENT_LOGIN, String);

    /*  terminate (exit()) this session  */
    terminate_session();

    /*  dummy return which might never happen  */
    return;
}


/*
 *	net_to_port()
 *
 *	Interface used by conversational port server when enable_security
 *	and port_server_security are set to Y.  In this case, the remote
 *	host is the host from which the Annex was connected via telnet.
 *
 *	Similar to the CLI security policy.  If user's name/password is
 *	not correct, the Annex will redisplay any rotary names, and will
 *	continue with the port/rotary selection prompt.
 */

void net_to_port(Acp, logid, linet, port,ptype, service, rinet, opt_info)

ACP		*Acp;			/* Handle to pass to library calls */
UINT32		logid,			       /* log file sequence number */
		linet,			  /* Internet address of the Annex */
		rinet;			/* Internet address of remote host */
int		port,			/* physical or virtual port number */
		service;		/* service expected: SERVICE_PORTS */
int ptype;
ARQ_PROFILE	*opt_info;
{
    char	    String[TOKEN_SIZE];  /* Any token of size 256 or less */
    char	    Hostname[ACP_MAX_HOSTNAME_LEN];/* ACP_MAX_HOSTNAME_LEN == 32*/
    ACP_USTRING	    Name;
#ifndef _WIN32
    ACP_LSTRING     Pass;
#else   /* defined _WIN32 */
	ACP_STRING     Pass;
#endif   /* defined _WIN32 */
    char	    *userprompt = ACP_USERPROMPT,
                    *passprompt = ACP_PASSPROMPT,
		    *permgrant = ACP_PERMGRANTD,
		    *permdenied = ACP_PERMDENIED;
    char            password_security = 0;
    int             use_securid = 0,
                    use_safeword= 0,
                    s_valid = 0,
                    p_valid = 0,
		    error;
    /* declarations for per-user environment.*/
    struct          environment_spec env, *P_env = &env;
                                           /*storage for user's environment*/
    int             passed = NOT_VALIDATED;
    char            Message[TOKEN_SIZE];
    Uprof           up;
    /* storage for userinfo entries */

    /*  Zero out the Uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    Acp->auth.blacklisted = FALSE;
    Acp->auth.ret_err_code= REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
                          /* codes for regimes and reasons used for logging*/

#ifdef PASS_SEC
    password_security = 1;
#endif

    if(debug)
        puts("policy: net_to_port");

    /*  Notify Annex of pending security decision  */
    (void)return_net_to_port(Acp, REQ_PENDING);

    /*  Translate remote host's address for logging purposes  */
    inet_name(Hostname, rinet);

#if	(USER_VALIDATION)

    String[0] = '\0';

    /*
     * Userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and
     * event logged
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
all users. Check acp_userinfo file!\n");
        (void)outputstring(Acp, permdenied);
        (void)net_to_port_authorize(Acp, REQ_DENIED, Name);
        if(ISUDP(Acp->state))
	    log_message(linet, logid, port,ptype, service, EVENT_REJECT, String);
        if (Acp->auth.hmask)
	    acp_timer_enabled = 0;
        else
	    terminate_session();
        return;
    }

    Message[0]= '\0';

    /*
     * generic_authenticate_user authenticates the user and returns a value
     * based on the authentication results.
     */
#ifdef PSERV_ONLY_USER
    if (acp_getusr(Name))
        passed = VALIDATED;
    else
        passed = NOT_VALIDATED;
#else
    Acp->env = &env;
    bzero((char*)&env, sizeof(struct environment_spec));
    env.annex = linet;
    env.port = port;
    env.ptype = ptype;
    env.protocol = service;
    Acp->auth.blacklisted = FALSE;
    Acp->chap = NULL;

    passed = generic_authenticate_user(Acp, logid, Name, Pass, TRUE, 1,
                                      Message, opt_info);

#endif

    if(passed) {

        /*
         * This call looks up userinfo database and chooses
         * the first entry that it finds and returns a pointer to the
         * entry. If the search fails, ie nothing for this user is found,
         * pointer points to an emtpy Uprof struct.
         */
        error = get_user_profile_entry(&up, Name, &P_env, &fileinfo);
    }

    /*
     * If user has passed authentication and there is no deny specified
     * in the user's userinfo entry, send authorize packet to
     * annex. Else, deny access and log.
     */
    if ((passed > NOT_VALIDATED) && (error == ACPU_ESUCCESS || 
                                     error == ACPU_ENOUSER) && (!up.up_deny)) 
    {
        (void)sprintf(String, "%s:%s", Hostname, Name);
	(void)outputstring(Acp, permgrant);
	(void)net_to_port_authorize(Acp, REQ_GRANTED, Name);
	if(ISUDP(Acp->state))
	    log_message(linet, logid, port,ptype, service, EVENT_LOGIN, String);
    }
    else
    {
        (void)sprintf(String, "%s:%s", Hostname, Name);
	if (up.up_deny)
	    Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_DENYUSER);
	(void)outputstring(Acp, permdenied);
	(void)net_to_port_authorize(Acp, Acp->auth.ret_err_code, Name);
	if(ISUDP(Acp->state))
	    log_message(linet, logid, port,ptype, service, Acp->auth.ret_err_code,
                    String);

	/* If user is black-listed, log in acp_logfile. */
	if (Acp->auth.blacklisted &&(!up.up_deny))
	    log_message(linet, logid, port,ptype, service, EVENT_BLACKLIST,
			Name);
    }


#else

    /*
     *  If no user name/password validation is desired,
     *  authorize unconditionally and log a message
     */

    (void)sprintf(String, "%s:%s", Hostname, unknown);
    (void)net_to_port_authorize(Acp, REQ_GRANTED, unknown);
    if(ISUDP(Acp->state))
        log_message(linet, logid, port,ptype, service, EVENT_LOGIN, String);

#endif

    if (Acp->auth.hmask)
        acp_timer_enabled = 0;
    else
        terminate_session();

    release_uprof(&up);
    return;
}


/*
 *	port_to_annex_logout()
 *
 *	This function is called remotely by the Annex when the CLI terminates.
 *	Only if cli_security and enable_security were set to Y when CLI began.
 */

void port_to_annex_logout(Acp, logid, inet, port,ptype, service, Username)

ACP		*Acp;			/* Handle for various ACP calls */
UINT32		logid,			    /* Log file sequence number */
		inet;			      /* Annex Internet address */
int		port,			/* physical/virtual port number */
		service;		 /* service, expect SERVICE_CLI */
char		*Username;		   /* user associated with port */
int ptype;
{
    /*  generic acknowledge - return to remote caller  */
    (void)acp_acknowledge(Acp);


    /*  log a message for accounting/security purposes  */
#if	(USER_VALIDATION)

    if(ISUDP(Acp->state))
        log_message(inet, logid, port,ptype, service, EVENT_LOGOUT, Username);

#else

    if(ISUDP(Acp->state))
        log_message(inet, logid, port,ptype, service, EVENT_LOGOUT, unknown);

#endif

    /*  terminate this session, which exit()s  */
    /* terminate_session() is now in acp_logout_ppp_slip() in acp_rpc.c */

    /*  dummy return  */
    return;
}


/*
 *	annex_to_net_logout()
 *
 *	This function is called when a session of a CLI or dedicated port
 *	ends for whatever reason. (reset, inactivity, hangup, kill, logout)
 */

void annex_to_net_logout(Acp, logid, linet, port, ptype,service, rinet, Username)

ACP		*Acp;			/* Handle for ACP communication */
UINT32		logid,			 /* sequence number for logging */
		linet,			      /* Annex Internet address */
		rinet;			/* Internet addr of remote host */
int		port,				   /* Annex port number */
		service;		/* SERVICE_{RLOGIN,CALL,TELNET} */
char		*Username;		   /* user associated with port */
int ptype;
{
    char	String[TOKEN_SIZE];   /* Any token of size 256 or less */
    char	Hostname[ACP_MAX_HOSTNAME_LEN]; /* ACP_MAX_HOSTNAME_LEN==32 */

    /*  generic acknowledge - return to remote caller  */
    (void)acp_acknowledge(Acp);

    /*  log a message for accounting/security purposes  */
    inet_name(Hostname, rinet);

    /*  If USER_VALIDATION, include username in log message  */
#if	(USER_VALIDATION)

    (void)sprintf(String, "%s:%s", Hostname, Username);

#else

    (void)strncpy(String, Hostname, ACP_MAX_HOSTNAME_LEN);

#endif
    if(ISUDP(Acp->state))
        log_message(linet, logid, port,ptype, service, EVENT_LOGOUT, String);

    /*  terminate this session, which exit()s  */
    terminate_session();

    /*  dummy return  */
    return;
}


/*
 *	annex_to_lat_logout()
 *
 *	This function is called when a session of a LAT connect
 *	ends for whatever reason.
 */

void annex_to_lat_logout(Acp, logid, linet, port,ptype, service, Username, Service_name)

ACP		*Acp;		/* Handle for ACP communication */
UINT32		logid,		 /* sequence number for logging */
		linet;		      /* Annex Internet address */
int		port,ptype,	           /* Annex port number */
		service;	             /* SERVICE_CONNECT */
char		*Username,	   /* user associated with port */
		*Service_name;	            /* LAT service name */
{
    char	String[TOKEN_SIZE];   /* Any token of size 256 or less */

    /*  generic acknowledge - return to remote caller  */
    (void)acp_acknowledge(Acp);

    /*  log a message for accounting/security purposes  */
    (void)sprintf(String, "%s:%s", Service_name, Username);

    if(ISUDP(Acp->state))
      log_message(linet, logid, port,ptype, service, EVENT_LOGOUT, String);

    /*  terminate this session, which exit()s  */
    terminate_session();

    /*  dummy return  */
    return;
}


/*
 *	net_to_port_logout()
 *
 *	Called when Annex closes a previously secured port server connection.
 */

void net_to_port_logout(Acp, logid, linet, port,ptype, service, rinet, Username)

ACP		*Acp;			/* Handle for ACP library */
UINT32		logid,			   /* log sequence number */
		linet,			/* Annex Internet address */
		rinet;			/* remote host's Internet */
int		port,ptype,		 /* physical/virtual port */
		service;		 /* service SERVICE_PORTS */
char		*Username;		/* user associated w/port */
{
    char	String[TOKEN_SIZE];   /* Any token of size 256 or less */
    char	Hostname[ACP_MAX_HOSTNAME_LEN]; /*  ACP_MAX_HOSTNAME_LEN==32 */

    /*  generic acknowledge - return to remote caller  */
    (void)acp_acknowledge(Acp);

    /*  log a message for accounting/security purposes  */
    inet_name(Hostname, rinet);

#if	(USER_VALIDATION)

    (void)sprintf(String, "%s:%s", Hostname, Username);

#else

    (void)sprintf(String, "%s:%s", Hostname, unknown);

#endif

    if(ISUDP(Acp->state))
        log_message(linet, logid, port,ptype, service, EVENT_LOGOUT, String);

    /*  terminate this session, which exit()s  */
    /* terminate_session() is now in acp_logout_ppp_slip() in acp_rpc.c */

    /*  dummy return  */
    return;
}


/*
 * 	appletalk_profile
 *
 *	This function is called by the annex when a user starts an
 * 	ARAP or ATCP/PPP session on the annex.
 */

void appletalk_profile(Acp, logid, inet, port,ptype, service, Name, nve)

ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid,				/* Log sequence number */
		inet;			     /* Annex Internet address */
int		port,ptype,	       /* physical/virtual port number */
		nve,			        /* tell me nve details */
		service;	   	      /* Expect SERVICE_DIALUP */
ACP_USTRING	Name;					   /* Username */
{

    Uprof     up;
    int       error;             /* error values returned from userinfo search */
    int       guest;
    struct    environment_spec *env_p;                   /* user's environment */
    UINT32    ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
                         /* error codes for regime and reason, used for logging*/

    if(debug)
        puts("policy: appletalk_profile");

    /* Initialize the various uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    /*
     * Userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and
     * event logged
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
all users. Check acp_userinfo file!\n");
        return_appletalk_profile(Acp,REQ_DENIED, 0, 0, 0, 0, 0, 0,0,0,0 );
        if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_NOPROVIDE, Name);
        return;
    }

    /*
     * create user's environment by allocating storage,
     * get time-stamp, lookup userinfo database for user's
     * entry (if any) and check for deny keyword in the user's
     * entry.
     */
    if((env_p = create_env()) == NULL)
    {
        /* do not proceed with the connection and log the instance. */
        return_appletalk_profile(Acp,REQ_DENIED, 0, 0, 0, 0, 0, 0,0,0,0 );
        if(ISUDP(Acp->state))
            log_message(inet, logid, port,ptype, service, EVENT_NOPROVIDE, Name);
        syslog(LOG_ERR, "appletalk_profile: failed to allocate environment for the user; acces denied. \n");
	return;
    } /* failed to allocate storage for the user's environment. */

    /*
     * set the annex's (which made the authentication request)
     * internet address, port no., service (cli/ppp/slip),
     * intialize storage for regime name & password file
     * and group list (link list of groups in which this user
     * belongs).
     */
    env_p->annex    = inet;
    env_p->port     = port;
    env_p->ptype = ptype;
    env_p->protocol = service;
    env_p->regime = (struct security_regime *)NULL;
    env_p->group_list = (struct group_entry *)NULL;

    /* Get the timestamp for this action */
    if (get_time_stamp(&(env_p->time)) == FALSE)
        syslog(LOG_ERR,"Failed to retrieve system time");  /* Log this event */

    strncpy(env_p->username, Name, LEN_USERNAME -1);
    env_p->username[LEN_USERNAME -1]= '\0';

    /* get user's entry from the userinfo database */
    error = get_user_profile_entry(&up,env_p->username,&env_p,&fileinfo);

    /*
     * If user has a deny entry in userinfo entry, deny access
     * and log the event
     */
    if(up.up_deny)
    {
        ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
	return_appletalk_profile(Acp,ret_err_code, 0, 0, 0, 0, 0, 0,0,0,0 );
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, ret_err_code, Name);
	release_env(env_p);
	release_uprof(&up);
	return;
    }

    /* set guest to true if a guest connection request. */
    guest = !(strcmp("<Guest>",Name));

    /*
     * if an entry is found in the userinfo database check
     * to see if any apple talk info. is specified, for
     * instance at_passwd, zonelist, nve filters etc.
     * If yes, proceed else do not proceed.
     *
     * If no entry is found and user is logging in as a
     * guest, proceed , else do not proceed.
     */
    if (error == ACPU_ESUCCESS)
    {
        if (	(up.up_at.at_zone_combined != 0)	||
	        (up.up_at.at_zones != 0)		||
	        (strlen(up.up_at.at_zonelist) != 0)	||
	        (strlen(up.up_at.at_passwd) != 0)	||
	        (up.up_at.at_connect_time != 0)	||
	        (up.up_at.at_nve_exclude != 0)		||
	        (strlen(up.up_at.at_nve) != 0)	)
	{

	    return_appletalk_profile(Acp,REQ_GRANTED, 
			           up.up_at.at_zone_combined, 
			           up.up_at.at_zones, 
				   up.up_at.at_zonelist, 
                                   up.up_at.at_passwd, 
                                   up.up_at.at_connect_time, 
				   up.up_at.at_nve_exclude, 
                                   (nve ? up.up_at.at_nve : 0),
				   (nve ? up.up_at.at_nve_combined : 0),
				   (nve ? (up.up_at.at_nves / 3) : 0));


	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Name);
	}
	else
	{
	    return_appletalk_profile(Acp,REQ_DENIED, 0,0,0,0,0,0,0,
				     0,0);
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype,service,EVENT_NOPROVIDE,Name);
	}

    }
    else if (error == ACPU_ENOUSER && guest)
    {
        return_appletalk_profile(Acp,REQ_GRANTED, 0, 0, 0, 0, 0,0,0,0,0);
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Name);
    }
    else
    {
        return_appletalk_profile(Acp,REQ_DENIED, 0, 0, 0, 0, 0, 0,0,0,0 );
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_NOPROVIDE, Name);
    }

    /* free the allocated memory for the user's environment. */
    release_env(env_p);
    release_uprof(&up);
    return;
}


/*
 *      max_logon_val
 *
 *      This function is called by the annex when a port is started
 */

void max_logon_val(Acp, logid, inet, port, service, Name, to)

     ACP             *Acp;           /* Handle to pass to library functions */
     UINT32          logid,                          /* Log sequence number */
       inet;                        /* Annex Internet address */
     int             port,                  /* physical/virtual port number */
       service;                      /* Expect SERVICE_DIALUP */
     ACP_USTRING      Name;                                      /* Username */
     struct sockaddr_in *to;     /* who sent the message we will respond to */
{


    char            Message[TOKEN_SIZE];
  Uprof           up;
  int             error;
  struct environment_spec *env_p;

  UINT32          ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
#ifndef _WIN32
  struct radius_attribute attrib;
  int rc, offset;
#endif /* not _WIN32 */

  if(debug)
    puts("policy: max_logon_val");

  Message[0] = '\0';

     /* Initialize the various uprof structs */
     (void) bzero(&up, sizeof(Uprof));

     /*
      * userinfo database doesn't exist due to a corrupt acp_userinfo file,
      * this is a security breach and all users must be denied access
      */

     if (debug)
       printf("the value of \"deny_all_user\" is %d \n", deny_all_users);
     if(deny_all_users)
       {
         syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
                   all users. Check acp_userinfo file!\n");
         return_max_logon_tcp(Acp,REQ_DENIED, 0);
         if(ISUDP(Acp->state)) {
           if (debug)
             puts("error1");
           log_message(inet, logid, port, service, EVENT_NOPROVIDE, Name);
         }
         return;
       }

     env_p = create_env();
     if (env_p)
       {
         env_p->annex    = inet;
         env_p->port     = port;
         env_p->protocol = service;
         env_p->regime = (struct security_regime *)NULL;
         env_p->group_list = (struct group_entry *)NULL;


         /* Get the timestamp for this action */
         if (get_time_stamp(&(env_p->time)) == FALSE)
           {
             /* Log this event */
             syslog(LOG_ERR, "Failed to retrieve system time");
           }

         strncpy(env_p->username, Name, LEN_USERNAME -1);
         env_p->username[LEN_USERNAME -1]= '\0';

         /* MAKING TWO CALLS INSTEAD OF ONE. */
         /* FIRST CALL SEARCHES THE DATABASE */
         /* FOR PRE PER-USER ENTRIES AND THE */
         /* 2ND CALL LOOKS FOR ENTRIES WITH  */
         /* THE PER-USER ENV-STRING. WHATEVER*/
         /* IS THE FIRST MATCH IS USED. M_ALI*/
         /*check for ACPU_ESUCCESS =0& ACPU_ENOUSER =4*/

/* new style*/
#ifndef _WIN32
         Acp->env = env_p;
         rc = offset = 0;
         bzero((char*)&attrib, sizeof(struct radius_attribute));
         attrib.type = PW_SESSION_TIMEOUT;
         rc = ses_get_attribute(Acp->env, &attrib, &offset);
         if (rc > 0 && attrib.lvalue > 0) /* found */
             return_max_logon_tcp(Acp, REQ_GRANTED,
                                  1 + ((attrib.lvalue - 1) / 60));
         else if (rc != 0) /* not found */
             return_max_logon_tcp(Acp, REQ_DENIED, 0);
         if (rc != 0) /* radius user */
             return;
#endif  /* _WIN32 */

         error = get_user_profile_entry(&up, env_p->username, &env_p, &fileinfo);

         /* If user has a deny entry in userinfo entry, deny access. */
         if(up.up_deny)
           {
             ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
             return_max_logon_tcp(Acp,ret_err_code, 0);
             if(ISUDP(Acp->state)) {
               if (debug)
                 puts("error2");
               log_message(inet, logid, port, service, ret_err_code, Name);
             }
	     release_uprof(&up);
             return;
           }

       /* value of 0 is invalid. Value of -1 means immediate logout of user */
       /* The code that looks up the acp_userinfo database returns a 0 if the
          max_logon parameter is not specified. */

         if ((error == ACPU_ESUCCESS) && (up.up_max_logon != 0)) {
           return_max_logon_tcp(Acp, REQ_GRANTED, up.up_max_logon);
             if (ISUDP(Acp->state)) {
               if (debug)
                 printf("udp error\n");
               log_message(inet, logid, port, service, EVENT_LOGIN, Name);
             }
         }
         else {
           return_max_logon_tcp(Acp, REQ_DENIED, 0);
           if (ISUDP(Acp->state)) {
             if (debug)
               printf("udp error\n");
             log_message(inet, logid, port, service, EVENT_NOPROVIDE, Name);
           }
         }

         /* free the allocated memory for the user's environment. */
         release_env(env_p);
       } /* if env_p exists */
     else
       {  /* impose no time restriction */
         return_max_logon_tcp(Acp, REQ_DENIED, 0);
         if(ISUDP(Acp->state)) {
           if (debug)
             puts("error4");
           log_message(inet, logid, port, service, EVENT_NOPROVIDE, Name);
         }
         syslog(LOG_ERR, "max_logon_val: failed to allocate environment for\
                 the user; acces denied. \n");
       }/* failed to allocate storage for the user's environment. */

     release_uprof(&up);
     return;
}


int
hook_callback(Acp,logid,code,cmnd)
ACP *Acp;		/* Handle to pass to library functions */
int code;
char *cmnd;
{
    int rcode = HCB_RETURN;

    /*
     * This call permits ACP to print back to the user.  The "pending" code
     * tells the Annex to wait for hook_callback_string instead, and to
     * process any outputstring or promptstring requests in the meantime.
     */
    return_hook_callback(Acp,HCB_PENDING,NULL);

    /*
     * Return the possibly modified command to the CLI.  This call frees up
     * the CLI and restarts execution on the Annex.
     */
    if (code == HCB_BAD_COMMAND) {	/* a parsing error occurred */
	sprintf(syslogbuf, "bad clicmd \"%s\" in acp_userinfo\n", cmnd);
	syslog(LOG_ERR, syslogbuf);

        if (Acp->auth.cmd_list != NULL)	/* was it a clicmd? */
	    rcode = HCB_LAST_CMND;	/* yes, kill the CLI */
	else				/* no, this should never happen */
	    rcode = HCB_TERMINATE;	/* so terminate the RACP session */
    }
    cmnd = "";
    if (code == HCB_BEFORE_PROMPT)	/* the CLI wants to print a prompt */
	if (Acp->auth.cmd_list == NULL)	/* have we any clicmds to send? */
	    rcode = HCB_TERMINATE;	/* no, terminate the RACP session */
	else
	{				/* yes */
	    if (debug)
		printf("acp_policy.c: clicmd \"%s\"\n", Acp->auth.cmd_list->clicmd);
	    if (*Acp->auth.cmd_list->clicmd == '\0')
	    {
		rcode = HCB_TERMINATE;
		Acp->auth.cmd_list = NULL;
	    }
	    else
	    {
		cmnd = Acp->auth.cmd_list->clicmd;
		if ((Acp->auth.cmd_list = Acp->auth.cmd_list->next) == NULL)
		    rcode = HCB_LAST_CMND;
		else
		    rcode = HCB_RETURN;
	    }
	}
    return(hook_callback_string(Acp,rcode,cmnd));
}


/*
 *	dialup_address_validate()
 *
 *	Look up username in (INSTALL_DIR/acp_dialup) file.
 *	Return local and remote addresses associated with first
 *	instance of this username and Annex.
 *
 */
static UINT32
dialup_address_validate(User, inet_addr, type, loc, rem, node, port, port_type,
                        filters, routes, service, dialup_flags)
char	*User;
UINT32	inet_addr, *loc, *rem;
int type;
int port, port_type;
u_char *node;
STR_LIST **filters, **routes;
int service;
UINT32 *dialup_flags;
{
    char	*name ;
    int error;
    UINT32  inet, local=0, remote=0;
    int	found_match = 0;
    int	errorcode,i = 0;
    struct environment_spec env, *env_p = &env;
    Uprof up;
    STR_LIST *strlist, *slp;
    struct cli_cmd_list *clist;
    int radius_user = 0;

#ifdef _WIN32
    char user_and_domain[64];
    char *ptr_user_name;
#else
    struct radius_attribute attrib;
    int offset = 0;
#endif

    if (filters) *filters = NULL;
    if (routes) *routes = NULL;

    *dialup_flags = REQ_GRANTED;       /* assuming everything will be OK */
    bzero((char*)&up, sizeof(Uprof));
    env.annex    = inet_addr;
    env.port     = port;
    env.ptype = port_type;
    env.protocol = service;
    env.regime = (struct security_regime *)NULL;
    env.group_list = (struct group_entry *)NULL;
    /* Get the timestamp for this action */
    get_time_stamp(&(env.time));
    strncpy(env.username, User, MAX_ENV_USERNAME_SIZE);

#ifndef _WIN32
    radius_user = ses_lookup(&env, NULL, SDB_FINDACTIVEUSER);
#endif

    /*
     * This call looks up userinfo database and chooses
     * the first entry that it finds and returns a pointer to the
     * entry. If the search fails, ie nothing for this user is found,
     * pointer points to an emtpy Uprof struct.
     */
    error = get_user_profile_entry(&up, env.username, &env_p, &fileinfo);

    if (filters && (error == ACPU_ESUCCESS) && up.up_filter_list) 
    {

      if (debug)
        printf("dialup_address_validate:  fetched filters.\n");
        strlist = racp_create_strlist(up.up_filter_list->clicmd,
                                      strlen(up.up_filter_list->clicmd));
        for(slp = strlist, clist=up.up_filter_list->next; clist && slp; 
            clist=clist->next, slp=slp->next)
            slp->next = racp_create_strlist(clist->clicmd,
                                            strlen(clist->clicmd));
	    *filters = strlist;
    }

    if (filters) {
        create_group_list(&(env_p->group_list),env_p->username);
        if (available(env_p, 0, 0,0, TRUE, filters) == ACCESS_RESTRICTED)
	{
	    /* error messages and syslogs come from available() */
	    if (*filters)
	    {
	      if (debug)
		printf("dialup_address_validate:  discarding filters.\n");
	        racp_destroy_strlist_chain(*filters);
		*filters = NULL;
	    }
	    *dialup_flags = REQ_DENIED;    /* failed to get filters. */
	    release_uprof(&up);
	    return(0);
	}
    }
    if (routes) {
#ifndef _WIN32
        if (radius_user) {
            bzero((char*)&attrib, sizeof(struct radius_attribute));
            attrib.type = PW_FRAMED_ROUTE;
            strlist = slp = NULL;
            offset = 0;

            if (ses_get_attribute(&env, &attrib, &offset) > 0) {
                if (debug_dialup)
                    printf("dialup_address_validate:  fetched routes; \"%s\"\n",
                           attrib.strvalp);
                slp = strlist = xlate_route_attrib(&attrib);
                free(attrib.strvalp);
                bzero((char*)&attrib, sizeof(struct radius_attribute));
                attrib.type = PW_FRAMED_ROUTE;
                while(ses_get_attribute(&env, &attrib, &offset) > 0) {
                    if (debug_dialup)
                        printf("\t\"%s\"\n", attrib.strvalp);
                    if (slp != NULL)
                        slp->next = xlate_route_attrib(&attrib);
                    else
                        slp = strlist = xlate_route_attrib(&attrib);
                    if (slp != NULL && slp->next != NULL)
                        slp = slp->next;
                    free(attrib.strvalp);
                    bzero((char*)&attrib, sizeof(struct radius_attribute));
                    attrib.type = PW_FRAMED_ROUTE;
                }
            }

            /* Construct from Framed-Netmask */
            offset = 0;
            bzero((char*)&attrib, sizeof(struct radius_attribute));
            attrib.type = PW_FRAMED_NETMASK;
            if (ses_get_attribute(&env, &attrib, &offset) > 0) {
                UINT32 netmask = attrib.lvalue;

                offset = 0;
                bzero((char*)&attrib, sizeof(struct radius_attribute));
                attrib.type = PW_FRAMED_ADDRESS;
                if (ses_get_attribute(&env, &attrib, &offset) > 0) {

                    if (strlist == NULL)
                        strlist = netmask_to_route(netmask, attrib.lvalue);
                    else {
                        if (slp == NULL) { /* find the end again */
                            for(slp = strlist; slp->next != NULL;
                                slp = slp->next);
                        }
                        slp->next = netmask_to_route(netmask, attrib.lvalue);
                    }
                }
            }
            *routes = strlist;
        }
        else if (up.up_route_list)
#else   /* defined _WIN32 */
        if (up.up_route_list)
#endif  /* defined _WIN32 */
	    {
            if (debug_dialup)
                printf("dialup_address_validate:  fetched routes; \"%s\"\n",
                       up.up_route_list->clicmd);
            strlist = racp_create_strlist(up.up_route_list->clicmd,
                                          strlen(up.up_route_list->clicmd));
            for(slp = strlist, clist=up.up_route_list->next; clist; 
                clist=clist->next, slp=slp->next) {
                if (debug_dialup)
                    printf("\t\"%s\"\n", clist->clicmd);
                slp->next = racp_create_strlist(clist->clicmd,
                                                strlen(clist->clicmd));
            }
            *routes = strlist;
        }
    }

#ifndef _WIN32
    if (radius_user) {
        bzero((char*)&attrib, sizeof(struct radius_attribute));
        if (type == IPX_ADDRT)
            attrib.type = PW_FRAMED_IPXNET;
        else
            attrib.type = PW_FRAMED_ADDRESS;
        offset = 0;

        if ((found_match = ses_get_attribute(&env, &attrib, &offset)) > 0) {
            switch(attrib.lvalue) {
            case 0xfffffffe: /* RADIUS let NAS choose */
                found_match = FALSE;
                break;

            case 0xffffffff: /* RADIUS let user choose for IP, unsupported */
                if (type == IP_ADDRT) /* fall back to let NAS choose */
                    found_match = FALSE;
                break;

            default:
                break;
            }

            *rem = remote = attrib.lvalue;
            *loc = inet_addr;
        }
        if (found_match < 0)
            found_match = FALSE;
    }
#else   /* defined _WIN32 */
    if ( 0 )    /* dummy if to match following else */
    {
        ;
    }
#endif  /* defined _WIN32 */
    else {

        if (setacpdialup() < 0)
            goto goback;


        if (debug_dialup)
        {
            LINE;
            printf("Data from Annex:\nname: %-10s   inet: %8x    port: %d\n",
                   User, inet_addr,port);
            LINE;
            printf("Data from acp_dialup file:\n");
            fflush(stdout);
        }

        errorcode = findacpdialup(&name, &inet, type, &local, &remote, node,
			       port, port_type, User, inet_addr, dialup_flags);

        if (errorcode == -1)
        {
            if (debug_dialup)
            {
                printf("-----  Reached end of acp_dialup file.  -----\n");
                LINE;
            }
            goto goback;
        }

        /*
         * If we got a valid entry from getacpdialup() and
         * the username and inet addresses match, then
         * give the corresponding local and remote addresses
         * and return.
         */

        if (errorcode == 1)
        {
            if (debug_dialup)
            {
                struct in_addr in;

                in.s_addr = inet;
                printf("\nname: %-10s  inet: %s  ",name,inet_ntoa(in));
                if (type == IPX_ADDRT)
                    printf("net: %8x node: %02x-%02x-%02x-%02x-%02x-%02x",
                           remote,node[0],node[1],node[2],node[3],node[4],
                           node[5]);
                else {
                    in.s_addr = local;
                    printf("loc: %s  ",inet_ntoa(in));
                    in.s_addr = remote;
                    printf("rem: %s",inet_ntoa(in));
                }
                LINE;
                fflush(stdout);
            }
#ifdef _WIN32
            ptr_user_name = PrependDomainNameAndFix(User, user_and_domain);
            if (found_match =  (!_strnicmp(ptr_user_name, name, ACP_MAXUSTRING)
                                && ( inet == 0 || inet == inet_addr)))
            {
                *loc = local == 0 ? inet_addr : local;
                *rem = remote;
            }
#else
            if (found_match =  (!strncmp(User, name, ACP_MAXUSTRING)  &&
                                ( inet == 0 || inet == inet_addr)))
            {
                *loc = local == 0 ? inet_addr : local;
                *rem = remote;
            }
#endif
        }
goback:
        endacpdialup();
    }

    release_uprof(&up);

    if (filters || routes || found_match)
    {
        return 1;
    }
    else
    {
        *dialup_flags = REQ_DENIED;
        return 0;
    }
}
/*
 * NTValidate(char *User, char *Password)
 * This routine is used for authenticating users when he security server
 * is running on an NT host.
 * IN  User        Username
 * IN  Password    Password entered by the user
 * Returns:
 *      found_match - True/False. found user&password in the database.
 */
#ifdef _WIN32
int NTValidate(char *User, char *Password)
{
    int	found_match = 0;
    HANDLE hUserToken;
	char *Domain, *UserName;
	char buf[ACP_MAXUSTRING];
	char pass_buf[ACP_MAXSTRING];
    int i;

	strncpy(buf, User, ACP_MAXUSTRING-1);
    buf[ACP_MAXUSTRING-1] = '\0';
	strncpy(pass_buf, Password, ACP_MAXSTRING-1);
    pass_buf[ACP_MAXSTRING-1] = '\0';
    Domain = szDefaultDomain;
	UserName = buf;

    if (debug)
        printf("User=<%s>, Pass=<%s>\n", User, Password);

    /* parse for domain and user name */
    for (i=0; buf[i]; i++)
        if (buf[i] == '\\')
		{
		    buf[i]=0;
		    Domain = &buf[0];
		    UserName = &buf[i+1];
		    break;
		}

	/* search the NT database for the username and password specified */
	found_match = LogonUser(UserName,
				    Domain,
				    pass_buf,
				    LOGON32_LOGON_INTERACTIVE,
				    LOGON32_PROVIDER_DEFAULT,
				    &hUserToken);

    /* results of the search */
    if (debug)
        printf("__found_match=%d_______User=<%s>, Pass=<%s>_____%s;%s\n", found_match, User, Password, Domain, UserName);

  	if (found_match && ErpcdOpt->UseGroupAuthentication)
	{
	    if (debug)
		    printf("-------------------------UseGroupAuthentication\n");

		found_match = xyRasValidate(Domain, UserName);
	}

    if(found_match)
        CloseHandle(hUserToken);

    return found_match;
}
#endif  /* _WIN32 */

/*
 *	acp_validate()
 *
 *	Look up name and password combination in an /etc/passwd compatible
 *	password file (INSTALL_DIR/acp_passwd.  If several passwords exist
 *	for the same username, any valid password is accepted.  Null entries
 *	and "*" entries (disabled) for passwords are not considered valid.
 *
 *	Additionally, for systems using a shadow file (/etc/shadow or
 *	INSTALL_DIR/acp_shadow), this file is checked for a valid password
 *	and the appropriate aging is performed if at least one password entry
 *	in the /etc/passwd file is "x".
 *
 *      IN   User        username
 *      IN   Password    User's password.
 *      IN   Passwd      password file path.
 *      OUT  blacklist   blacklist this user; depends on how blacklisting
 *                       parameters are set.
 *
 *	Return codes:
 *		0 - invalid username/password (or account expired)
 *		1 - valid username/password
 *		2 - valid username/password, but password to expire soon
 *		3 - valid username/password, but password has expired
 *		4 - valid username/password, but account to expire soon
 *
 *	In cases 2 and 4, the global variable "daysleft" is set to the number of
 *	days left until this event.
 */

int
acp_validate(User, Password, blacklist, Passwd)
char	*User, *Password;
int     *blacklist;
char *Passwd;
{
#ifdef _WIN32
    return NTValidate(User, Password);
#else
    char str[ACP_LONGSTRING];              /* ACP_LONGSTRING == 80 */
    int rv=0, user_found = FALSE;

    struct	passwd *pwd;
    char	*pw;
    int	found_match = 0;

#ifdef USESHADOW
    struct	spwd *spwd;
    int	found_x = 0;
    INT32	today,expire;
#endif
    if(setacppw(Passwd) == -1)
        return 0;  /* the password file is invalid */

    /*
     * Look in the password file until an entry with the "User" name
     * is found. Once the right entry is found, encrypt the user's
     * password and  match with the entry found.
     */
    while ((pwd = getacppw()) != NULL)
    {
	if(debug)
	   fprintf(stderr, "checking user %s...\n", pwd->pw_name);
	if (pwd->pw_passwd[0] == '\0')
	    continue;	/* Disallow null passwords */

	/*find the password file entry with the user*/
	if (strncmp(pwd->pw_name, User, ACP_MAXUSTRING) != 0)
	    continue;
	else
	    user_found = TRUE;

#ifdef USESHADOW
	if(debug)
	    fprintf(stderr, "found user, now check for x\n");
	if (strcmp("x",pwd->pw_passwd) == 0)
	{
	    found_x = 1;
	    if (debug)
	      fprintf(stderr, "found_x is true\n");
	    break;
	}
#endif
	/* encrypt user's password and match with the file's entry */
	pw = crypt(Password, pwd->pw_passwd);
	if (strcmp(pw, pwd->pw_passwd) == 0)
	{
	    found_match = 1;
	    break;
	}
    }
    /* close the file pointer. */
    endacppw();

#ifdef USESHADOW
    /* Currently will use the default acp_shadow */

    if (found_match)
        return 1;
    if (!found_x)
        return 0;
    today = DAY_NOW;

    /* open the shadow file for reading */
    setacpsp();

    /* read the shadow file until the user's entry is found. */
    while ((spwd = getacpsp()) != NULL)
    {
        /* Disallow null passwords */
        if (spwd->sp_pwdp[0] == '\0')
	    continue;

	if (strncmp(spwd->sp_namp, User, ACP_MAXUSTRING) != 0)
	    continue;
	else
	    user_found = TRUE;

	pw = crypt(Password, spwd->sp_pwdp);
	if (strncmp(pw, spwd->sp_pwdp, ACP_MAXSTRING) != 0)
	    continue;


	/* Check for an expired account */
#ifndef SCO
	if (spwd->sp_expire > 0 && today > spwd->sp_expire)
	    break;
#endif
	/*
	 * We're not implementing sp_inact here to check for inactive accounts.
	 * To do this, the time/date stamp in /usr/adm/wtmp should be checked
	 * and validated.  This would probably also require writing to this
	 * file to update this stamp after the user logs into the Annex.
	 */

	/* Calculate password expiration date */
	if (spwd->sp_lstchg > 0 && spwd->sp_max > 0)
	    expire = spwd->sp_lstchg+spwd->sp_max;
	else
	    expire = 0;

	/* Check for an expired password */
	if (today < spwd->sp_lstchg ||
            (expire > 0 && today > expire) ||
            (spwd->sp_lstchg == 0))
	{
	    strncpy(old_password,spwd->sp_pwdp,
		    sizeof(old_password));
	    found_match = 3;

	/* Check for an account that is soon to expire */
#ifndef SCO
	}
	else if (spwd->sp_expire > 0 && today >= spwd->sp_expire-spwd->sp_warn)
	{
	    found_match = 4;
	    daysleft = spwd->sp_expire-today;

	    /* Check for a password that is soon to expire */
	}
	else if (expire > 0 && today >= expire-spwd->sp_warn)
	{
	    found_match = 2;
	    daysleft = expire-today;
#endif
	}
	else
	    found_match = 1;
	break;
    }
    /* close the shadow file */
    endacpsp();
#endif

#ifdef USE_NDBM
    /* Search acp_dbm for this user to verify that he is not blacklisted. */
    if(user_found == TRUE)
    {
        DBM *dbm;
	rv = erpcd_lock_acp_dbm();

	if(rv == 0)
	{
	    sprintf(str, "%s/", install_dir);
            strcat(str, ACP_DBM_FILE);
            dbm = dbm_open(str, (O_CREAT | O_RDWR), 0600);

	    /* successfully openend database. */
	    if(dbm != NULL)
	    {

	        if(found_match != 0)
		{
		    /*
		     * check whether user is blacklisted and then record
		     * the login success
		     */
		    rv = dbm_verify_login_success(dbm, User);
		    if((rv != TRUE && errno != ENOENT) || rv == FALSE) {
		      if (debug)
			printf("user blacklisted!\n");
		      found_match = 0;
		    }
		    if(rv < 0 && errno != ENOENT)
		        process_error(User, rv);
		}
		else
		{
		    if( maxcon != -1 || maxtotal != -1)
		    {
		        /* record login failure and determine whether to blacklist user */
		        rv = dbm_record_login_failure(dbm, User, maxcon, maxtotal, period);
		    }

		    if(rv < 0 )
		    {
		        process_error(User, rv);
		    }
                    else if ((rv == RVBLACKLIST_MAXTRIES) || (rv == RVBLACKLIST_OVERTME)) {
		        (void)erpcd_suspectAttackTrap (User, rv);
		        if (blacklist != NULL)
		            *blacklist = TRUE;
		     }
		}
		unlock_database(dbm);
	    }
            else
	    {
                syslog(LOG_CRIT, "%m");
		if (debug)
		  printf("Can't open dbm file\n");
                found_match = 0;
                dbm_unlock_acp_dbm();
            }
        }
        else
	{
	  if (debug)
	    printf("Can't lock dbm file\n");
            found_match = 0;
            dbm_unlock_acp_dbm();
        }
	user_found = FALSE;
    }
#endif /* USE_NDBM */

    if (debug > 1)
      printf("acp_validate returning %d\n",found_match);
	return found_match;

#endif /* _WIN32 */
}

/*
 *	acp_kerberos_validate()
 *
 *	Look up name and password combination in an /etc/passwd compatible
 *	password file (INSTALL_DIR/acp_passwd).  If several passwords exist
 *	for the same username, any valid password is accepted.  Null entries
 *	and "*" entries (disabled) for passwords are not considered valid.
 *
 *	Additionally, for systems using a shadow file (/etc/shadow or
 *	INSTALL_DIR/acp_shadow), this file is checked for a valid password
 *	and the appropriate aging is performed if at least one password entry
 *	in the /etc/passwd file is "x".
 *
 *      IN  User      username
 *      IN  Password  password provided by "User".
 *      IN  Passwd    passwd/ticket directory.
 *	Return codes:
 *             -1 - regime is unavailable
 *		0 - invalid username/password (or account expired)
 *		1 - valid username/password
 *		2 - valid username/password, but password to expire soon
 *		3 - valid username/password, but password has expired
 *		4 - valid username/password, but account to expire soon
 *
 *	In cases 2 and 4, the global variable "daysleft" is set to the number of
 *	days left until this event.
 */

int
acp_kerberos_validate(User, Password, Passwd)
char	*User, *Password, *Passwd;
{
#ifdef KERBEROS
    char tktfile[MAXPATHLEN];
    char krbrlm[REALM_SZ], uname[ANAME_SZ];
    int krbval, rv;               /* resuts for calls to kerberos std api */

    /* Whether kerberos is available */
    if ((rv=krb_get_lrealm(krbrlm, 1)) == UNAVAILABLE)
	return (UNAVAILABLE);
    else if (rv != KSUCCESS)
    {
        (void)strncpy(krbrlm, KRB_REALM, sizeof(krbrlm));
    }

    /*
     * Use our pid for the ticket file name; it goes
     * away immediately, anyway
     */
    (void)sprintf(tktfile,"%s%d", KRB_TK_DIR, getpid());
    krb_set_tkt_string(tktfile);

    strcpy(uname, User);

    krbval = krb_get_pw_in_tkt(uname, "", krbrlm, "krbtgt",
				krbrlm, DEFAULT_TKT_LIFE, Password);
    bzero((char*)Password, strlen(Password));
    dest_tkt();

    switch(krbval)
    {
	case INTK_OK:
      	    if (debug)
	      	printf("Krb-auth worked for user %s\n", User);
	    return(1);
	default:
	    if (debug)
        	printf("Krb-auth FAILED for user %s (%s)\n", User,
		       		krb_err_txt[krbval]);
    }
#endif /* KERBEROS */

    return(0);
}


/*
 *	acp_native_validate()
 *
 *	Look up name and password combination in an /etc/passwd compatible
 *	password file (INSTALL_DIR/acp_passwd).  If several passwords exist
 *	for the same username, any valid password is accepted.  Null entries
 *	and "*" entries (disabled) for passwords are not considered valid.
 *
 *	Additionally, for systems using a shadow file (/etc/shadow or
 *	INSTALL_DIR/acp_shadow), this file is checked for a valid password
 *	and the appropriate aging is performed if at least one password entry
 *	in the /etc/passwd file is "x".
 *
 *      IN   User      username supplied by the user
 *      IN   Password  User's password
 *
 *	Return codes:
 *		0 - invalid username/password (or account expired)
 *		1 - valid username/password
 *		2 - valid username/password, but password to expire soon
 *		3 - valid username/password, but password has expired
 *		4 - valid username/password, but account to expire soon
 *
 *	In cases 2 and 4, the global variable "daysleft" is set to the number of
 *	days left until this event.
 */

int
acp_native_validate(User, Password)
char	*User, *Password;
{

#ifdef _WIN32
    return NTValidate(User, Password);
#else
    struct	passwd *pwd;     /* storage for password entries in the password file*/
    char	*pw, str[ACP_LONGSTRING];  /* ACP_LONGSTRING == 80 */
    int	found_match = 0;         /* found the entry for this user. */
#ifdef USENATIVESHADOW
    struct	spwd *spwd;
    int	found_x = 0;
    INT32	today,expire;
#endif

    /* rewind the password file pointer (/etc/passwd) for reads */
    setpwent();

    /*
     * get the password records from /etc/passwd and
     * keep them in the password struct. Read till
     * end of file. Find the match and close file
     */
    while ((pwd = getpwent()) != NULL)
    {
        if (pwd->pw_passwd[0] == '\0')
	    continue;	/* Disallow null passwords */
	if (strncmp(pwd->pw_name, User, ACP_MAXUSTRING) != 0)
	    continue;
#ifdef USENATIVESHADOW
	if (strcmp("x",pwd->pw_passwd) == 0)
	{
	    found_x = 1;
	    break;
	}
#endif
	/* encrypt the user provided password and match*/
	pw = crypt(Password, pwd->pw_passwd);
	if (strncmp(pw, pwd->pw_passwd, ACP_MAXSTRING) == 0)
	{
	    found_match = 1;
	    break;
	}
    }
    /* close file */
    endpwent();

#ifdef USENATIVESHADOW
    if (found_match)
        return 1;

    if (!found_x)
        return 0;
    today = DAY_NOW;

    /* We are unable to use setspent(), getspent() and          */
    /* endspent() here because they are unreliable on           */
    /* all platforms (escpecially SCO).  The setacpsp(),        */
    /* getacpsp(), and endacpsp() functions do the correct      */
    /* thing as long as the shadow_name is set to "/etc/shadow" */
    setacpsp();

    /* read till end of file */
    while ((spwd = getacpsp()) != NULL)
    {
        if (spwd->sp_pwdp[0] == '\0')
	    continue;	/* Disallow null passwords */
	/* find the user */
	if (strncmp(spwd->sp_namp, User, ACP_MAXUSTRING) != 0)
	    continue;
	/* encrypt password and match */
	pw = crypt(Password, spwd->sp_pwdp);

	if (strncmp(pw, spwd->sp_pwdp, ACP_MAXSTRING) != 0)
	    continue;

	/* Check for an expired account */
#ifndef SCO
	if (spwd->sp_expire > 0 && today > spwd->sp_expire)
	    break;
#endif
	/*
	 * We're not implementing sp_inact here to check for inactive accounts.
	 * To do this, the time/date stamp in /usr/adm/wtmp should be checked
	 * and validated.  This would probably also require writing to this
	 * file to update this stamp after the user logs into the Annex.
	 */

	/* Calculate password expiration date */
	if (spwd->sp_lstchg > 0 && spwd->sp_max > 0)
	    expire = spwd->sp_lstchg+spwd->sp_max;

	else
	    expire = 0;
	/* Check for an expired password */
	if (today < spwd->sp_lstchg ||
	    (expire > 0 && today > expire) ||
	    (spwd->sp_lstchg == 0)) 
	{
	    strncpy(old_password,spwd->sp_pwdp, sizeof(old_password));
	    found_match = 3;
	    /* Check for an account that is soon to expire */
#ifndef SCO
	}
	else if (spwd->sp_expire > 0 &&
		    today >= spwd->sp_expire-spwd->sp_warn)
	{
	    found_match = 4;
	    daysleft = spwd->sp_expire-today;
    	    /* Check for a password that is soon to expire */

	}

	/* expires today ? */
	else if (expire > 0 &&
		    today >= expire-spwd->sp_warn)
	{
	    found_match = 2;
	    daysleft = expire-today;
#endif
	}
	else
	    found_match = 1;
	break;
    }

    /* close file */
    endacpsp();

#endif
    return found_match;
#endif /* _WIN32 */
}


/*
 *	acp_port_password_authenticate()
 *
 *      This routine checks the user for port_password if the
 *      annex has port_password options set, with the annex ip addr.
 *      in the password file.
 *
 *      Returns:
 *           VALIDATED - If user supplied port password matches.
 *           NOT_VALIDATED - If user supplied password doesn't match.
 */

acp_port_password_authenticate(Acp,logid,inet,port,ptype,service,tries)

ACP		*Acp;		  /* Handle to pass to library functions */
UINT32		logid,		                  /* Log sequence number */
		inet;		               /* Annex Internet address */
int		port,ptype,	                   /* serial port number */
		service;	           /* Expect SERVICE_CLI{,_HOOK} */
int tries;                                     /* number of times to try */
{
    /*
     *	Prompt for optional port password
     */
    char portstring[ACP_MAX_HOSTNAME_LEN]; /* ACP_MAX_HOSTNAME_LEN == 32 */
#ifndef _WIN32
    ACP_LSTRING     Pass;
#else   /* defined _WIN32 */
	ACP_STRING     Pass;
#endif   /* defined _WIN32 */

    int  got_str = 1;
    int  passed = TRUE;
    int  blacklist = FALSE;
    int i;

    /*
     * look for the port-password for this port (and annex) in the
     * acp_passwd file. First call to acp_special converts, inet and
     * port to a special string and second looks for an entry in
     * the password file. If entry is present, prompt user for
     * port password and match.
     */
    acp_special(portstring, inet, port,ptype);
    if (acp_getusr(portstring))
    {
        passed = NOT_VALIDATED;       /* NOT_VALIDATED == 0 */
	for (i = 0; i < tries; i++)
	{
	    /* prompt user for port password. */
	    got_str = promptstring(Acp, Pass,	ACP_PORTPROMPT, 0,
			     INPUT_TIMEOUT);

	    if (got_str <= 0)
	    {
	        passed = NOT_VALIDATED;
		break;
	    }
	    else
	      /* match the provided password with the one listed */
	      passed = acp_validate(portstring, Pass, &blacklist, NULL);

	    if (passed != NOT_VALIDATED)
	      break;
	}

	/* return appropriate value depending on pass/fail */
	if (passed)
	    return(VALIDATED);
	else if (got_str <= 0)
	    return(VALIDATION_TIMED_OUT);
	else
	    return(NOT_VALIDATED);
    }
    else
        /* no entry in the file, no port password security required. */
        return(VALIDATED);

}


/*
 * This is called by routines that use acp_validate.  It takes appropriate
 * actions based on the returned code.
 */

int
warn_user(Acp,validp,user)
ACP *Acp;		    /* Handle to pass to library functions */
int *validp;                                     /* warning codes. */
char *user;                                           /* user name */
{

#if defined(USESHADOW) || defined(USENATIVESHADOW)

    ACP_USTRING temp,temp2;
    char *cp, str[ACP_LONGSTRING];   /* ACP_LONGSTRING == 80 */
    int i,vcount, rv;

#ifdef USE_NDBM
   DBM *dbm;
#endif

    switch (*validp)
    {
      	/* Password aging warning */
        case 2:
	    if (daysleft <= 0)
	        strcpy(temp,ACP_WARNINGT);
	    else if (daysleft == 1)
	        strcpy(temp,ACP_WARNINGM);
	    else
	    sprintf(temp,ACP_WARNING,daysleft);
	break; /* 2 */

	/* Password has expired -- prompt for new one */
        case 3:
	    /* assume that this won't work */
	    *validp = 0;
	    if (user == NULL || user[0] == '\0')
	        return -1;
            /*
	     * "vcount" allows user to enter "illegal"
	     * passwords if he's persistent.
	     */
	    vcount = 0;
	    if ((i = outputstring(Acp, ACP_EXPIRED)) != 0)
	        return i;

	    for (vcount = 0; vcount < 3; vcount++)
            {
	        if (promptstring(Acp,temp,ACP_NEWPASS,0,INPUT_TIMEOUT) <= 0)
		    return -1;
		if (temp[0] == '\0')
		    return -1;
		if ((cp = test_password(temp)) != NULL)
		{
		    if ((i = outputstring(Acp, cp)) != 0)
		        return i;
		    continue;
		}
#if USE_NDBM
                if(!strcmp( old_password, temp) ||
		   (rv = matches_old_password(user, temp)) == TRUE)
#else
		    if (!strcmp(old_password, temp))
#endif
		    {
		        if((i=outputstring(Acp, ACP_MATCH_FOUND)) != 0)
			    return i;
			else
			    continue;
		    }
#if USE_NDBM
                else if(rv < 0)
		    return 0;
#endif

		if (promptstring(Acp,temp2,ACP_NEWPASS2,0,INPUT_TIMEOUT) <= 0)
		    return -1;
		if (strcmp(temp,temp2) != 0)
		{
		    if ((i = outputstring(Acp, ACP_PASSMATCH)) != 0)
		        return i;
		}
		else
		    break;
            }

	    /* user is a moron -- kick him out */
	    if(vcount == 3)
	    {
	        if ((i = outputstring(Acp, ACP_PASS_UNCHANGED)) != 0)
		    return i;
		return 0;
	    }

	    bzero((char*)temp2,sizeof(temp2));
	    cp = change_password(user,old_password,temp);
	    if (cp != NULL)
	    {
	        if (*cp == ' ')
		    strcpy(temp,cp+1);
		else
		    sprintf(temp,"%s: %s.\n",cp,sys_errlist[errno]);
		break;
	    }
	    *validp = 1;

#ifdef USE_NDBM
            rv = erpcd_lock_acp_dbm();
            if (rv == 0)
	    {
                sprintf(str, "%s/", install_dir);
                strcat(str, ACP_DBM_FILE);
                dbm = dbm_open(str, (O_CREAT | O_RDWR), 0600);
                if(dbm!=NULL)
	        {
	            rv = dbm_store_old_pwd(dbm, user, old_password);
		    if (rv != 0)
		        process_error(user, rv);
		    dbm_close(dbm);
	        }
	    }
	    dbm_unlock_acp_dbm();
#endif
	    return 0;

	/* Account aging warning */
        case 4:
	    if (daysleft <= 0)
	        strcpy(temp,ACP_AWARNINGT);
	    else if (daysleft == 1)
	        strcpy(temp,ACP_AWARNINGM);
	    else
	    sprintf(temp,ACP_AWARNING,daysleft);
	break; /* 3, 4 */

	default:
	    return 0;
    }
    return outputstring(Acp, temp);
#endif
    return 0;
}



/*
 *	acp_securid_authenticate()
 *
 *	Prompt for password and call acp_securid_validate() to validate the
 *      username and password.
 *      Returns:
 *          VALIDATED,
 *          NOT_VALIDATED,
 *          UNAVAILABLE   - user's entry not available.
 */
static int
acp_securid_authenticate(Acp, logid, inet, port,ptype, service, Name, tries,
                         passcode)

ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid,				/* Log sequence number */
		inet;			     /* Annex Internet address */
int		port,ptype,	       /* physical/virtual port number */
		service;		 /* Expect SERVICE_CLI{,_HOOK} */
ACP_USTRING      Name;
int             tries;
char            *passcode; /* User's passcode, NULL to prompt */
{
    static int	got_str = 0;
#ifndef _WIN32
    ACP_LSTRING     Pass;
#else   /* defined _WIN32 */
	ACP_STRING     Pass;
#endif   /* defined _WIN32 */
    int		passed = NOT_VALIDATED;
    char		*usermsg = (char *)NULL;

    if (debug)
        fprintf(stderr,"acp_securid_authenticate: user %s\n",Name);


    /*  prompt for Name and Password until valid or too many tries  */
    if (passcode == NULL && tries < RETRIES_MAX)
    {
        got_str = promptstring(Acp,
			       Pass,
			       SID_PASSPROMPT,
			       0,
			       INPUT_TIMEOUT);
	if (got_str > 0)
        {
	    /* validate user supplied password */
	    passed = acp_securid_validate(Name, Pass, Acp, TRUE);
	    if (passed == UNAVAILABLE)
	        return UNAVAILABLE;
	    if(passed == USER_ABORT)
	      return USER_ABORT;
	    if (passed == VALIDATED)
	    {
	        /* Display appropriate permissions */
	        usermsg = SID_PERMGRANTD;
	    }
	    else
	    {
	        /* Display error message */
	        usermsg = SID_INCORRECT;
	    }
	}

    }
    else if (passcode == NULL)
    {
        /* Display the appropriate error message */
        if(got_str)
	{
	    usermsg = SID_PERMDENIED; /* Attempts failed */
	}
	else
	{
	    usermsg = ACP_TIMEDOUT; /* Never reviced anything */
	}
    }
    else /* framed user, no prompting/displaying can be done, just validate */
        return(acp_securid_validate(Name, passcode, Acp, FALSE));

    /* prompt user for appropriate message. */
    if (usermsg)
        outputstring(Acp, usermsg);
    /* return the pass/fail/unavailable */
    return(passed);

} /* end of acp_securid_authenticate() */



/*
 *	acp_securid_validate()
 *
 *	Look up name and password combination by calling the Security
 *	Dynamics Ace/Server utility.
 */
static int
acp_securid_validate(User, Password, Acp, prompt)

char	*User, *Password;
ACP	*Acp;			        /* Handle to pass to library calls */
int prompt; /* TRUE if we have user prompting capability */
{
    int	found_match = NOT_VALIDATED;
#ifdef SECURID_CARD
#ifdef _WIN32
    static FARPROC sd_init;
    static FARPROC sd_check;
    static FARPROC sd_pin;
    static FARPROC sd_next;
    static FARPROC sd_close;
    static HANDLE hDllACECLNT;
#endif /* _WIN32 */
    int	got_str = 0, i;
#ifndef _WIN32
    ACP_LSTRING nextcode, newpin, pinprompt;
#else   /* defined _WIN32 */
	ACP_USTRING nextcode, newpin, pinprompt;    
#endif   /* defined _WIN32 */

    char	*s;
    char	*pintype, pinsize[20];
    short	flag;
    struct 	SD_CLIENT sd_dat, *sd;

    if (debug)
        printf ("acp_securid_validate\n");

#ifdef _WIN32
    /* First time, load DLL */
    if (hDllACECLNT == NULL) {
	hDllACECLNT = LoadLibrary("aceclnt.dll");	/* load DLL */
	if (hDllACECLNT == NULL) {
	    syslog (LOG_EMERG, "Error: can't load \"aceclnt.dll\"\n");
	    if(debug)
		printf ("Error: can't load \"aceclnt.dll\"\n");
	    return found_match;
	    }
        sd_init = GetProcAddress(hDllACECLNT, "sd_init");
        sd_check = GetProcAddress(hDllACECLNT, "sd_check");
        sd_pin = GetProcAddress(hDllACECLNT, "sd_pin");
        sd_next = GetProcAddress(hDllACECLNT, "sd_next");
        sd_close = GetProcAddress(hDllACECLNT, "sd_close");

        if (!sd_init || !sd_check || !sd_pin || !sd_next || !sd_close) {
	    syslog (LOG_EMERG,
		"can't load function(s) from \"aceclnt.dll\"\n");
	    if(debug)
		printf ("can't load function(s) from \"aceclnt.dll\"\n");
	    FreeLibrary(hDllACECLNT);
	    hDllACECLNT = NULL;
	    return found_match;
	    }
	if(debug)
	    printf ("Functions retrieved from \"aceclnt.dll\"\n");
	}
#endif /* _WIN32 */
    sd = &sd_dat;
    memset(sd, 0, sizeof(*sd));
    nextcode[0] = newpin[0] = '\0';

#ifdef ACE1_2
    creadcfg();
#endif /* ACE1_2 */

#if defined(ACE2_0) && !defined(_WIN32)
        if(creadcfg()){
          if(debug)
             printf("error reading sdconf.rec.\n");
          return found_match;
        }
#endif /* defined(ACE2_0) && !defined(_WIN32) */

#if defined(ACE1_2) || defined(ACE2_0)
    if ((i=sd_init(sd)) == UNAVAILABLE)
        return UNAVAILABLE;
    else if (i)
    {
        if (debug) {
	    printf ("failed to init client-server communications\n");
	    printf ("sd_init return code %d\n", i);
	    }
#ifdef _WIN32
	syslog (LOG_CRIT, "%s%s%d\n",
		"failed to init client-server communications\n",
		"sd_init return code ", i);
#endif /* _WIN32 */
	return found_match;
    }
#endif /* defined(ACE1_2) || defined(ACE2_0) */


    if (prompt == FALSE) { /* prompting not available, short and sweet */
        if (sd_check(Password, User, sd) == ACM_OK)
            found_match = VALIDATED;
#ifdef ACE2_0
        sd_close();
#endif
        return found_match;
    }

    switch (sd_check (Password, User, sd))
    {
        case ACM_OK:
             found_match = VALIDATED;
	break; /* ACM_OK */

       	case ACM_NEXT_CODE_REQUIRED:
	    got_str = promptstring(Acp, nextcode, SID_NEXTCODEPROMPT, 0,
				 INPUT_TIMEOUT + 60);
	    if (got_str < 0)
	    {
		break;
	    }

	    switch (sd_next(nextcode, sd))
	    {
	        case ACM_OK:
	            found_match = VALIDATED;
	        break;

	        case ACM_ACCESS_DENIED:
	        case ACM_NEXT_CODE_BAD:
	        default:
	        break;
	    }
        break; /* ACP_NEXT_CODE_REQUIRED */

        case ACM_NEW_PIN_REQUIRED:
            pintype = (sd->alphanumeric) ? SID_PINCHAR : SID_PINDIGIT;

            if (sd->min_pin_len == sd->max_pin_len)
	        sprintf (pinsize, SID_PINSIZE, sd->min_pin_len);
	    else
		sprintf (pinsize, SID_PINSZRANGE, sd->min_pin_len,
				sd->max_pin_len);
#ifndef ACE2_0
	    if (sd->user_selectable)
            {
		 sprintf (pinprompt, SID_NEWPINPROMPT, pinsize, pintype);
		 outputstring (Acp, pinprompt);
		 outputstring (Acp, SID_OR);
	    }

            outputstring (Acp, SID_NEWPIN_2);
	    outputstring (Acp, SID_OR);
	    outputstring (Acp, SID_NEWPIN_3);
#else  /* 2.0 has new meanings for user_selectable */
                sprintf(pinprompt, SID_NEWPINPROMPT, pinsize, pintype);

                switch(sd->user_selectable){
                case CANNOT_CHOOSE_PIN: outputstring(Acp, SID_NEWPIN_2);
                                        break;

                case MUST_CHOOSE_PIN:   outputstring(Acp, pinprompt);
                                        break;

                case USER_SELECTABLE:   outputstring(Acp, pinprompt);
                                        outputstring(Acp, SID_OR);
                                        outputstring(Acp, SID_NEWPIN_2);
                                        break;
                default:
                        break;
                }

                outputstring(Acp, SID_OR);/*or leave it in new pin mode*/
                outputstring (Acp, SID_NEWPIN_3);

#endif /*ACE2_0*/

            /* include terminator in input string */
	    /* in order to distinguish between a  */
	    /* timeout and a <return>.            */
	    flag = GET_TERMINATOR;
	    got_str = promptstring_wt(Acp, newpin, " ", 0, INPUT_TIMEOUT, &flag);
	    if (got_str < 0)
	        /* timeout */
	        break;
	    /* delete terminator from string (unless old annex)*/
	    if (flag == GET_TERMINATOR)
	    {
	        if (got_str == 0)
		{
		    /* timeout */
		    break;
	        }
		newpin[strlen(newpin) -  1] = '\0';
	    }

	    if (debug)
	    {
	        s = &newpin[0];
		printf ("---- securid_validate ---- newpin: %s\n", newpin);
		for (i = 0; i < (int)strlen(newpin) + 1; i++)
		{
		    printf ("%02x ", s[i]);
		    if (( (i + 1) % 16) == 0)
		        printf ("\n");
		}
		printf ("\n");
	    }

	    if (newpin[0] == 0x04)
	    {
	        /* got a control-D */
	        sd_pin ("", CANCELLED, sd);
		found_match = USER_ABORT;
	        break;
	    }
	    else if (strlen(newpin) == 0)
	    {
	        /* got a <return> */
#ifdef ACE2_0
	      /* User cannot ask for a system generated pin */
	      if(sd->user_selectable == MUST_CHOOSE_PIN)
		break;
#endif /* ACE2_0 */
	        sprintf (pinprompt, SID_SYSGENPIN, sd->system_pin);
		outputstring(Acp, pinprompt);
		if (sd_pin(sd->system_pin, 0, sd) != ACM_NEW_PIN_ACCEPTED)
		{
		    break;
		}
	    }
#ifndef ACE2_0
		else if (sd->user_selectable)
#else /*ACE2_0*/
                else if (sd->user_selectable != CANNOT_CHOOSE_PIN)
#endif /*ACE2_0*/
	        {
	        /* got a new pin */
	        strcpy (sd->system_pin, newpin);
		newpin[0] = '\0';
#ifndef _WIN32
		bzero(newpin, ACP_MAXLSTRING);
#else   /* defined _WIN32 */
		bzero(newpin, ACP_MAXUSTRING);
#endif   /* defined _WIN32 */
		got_str = promptstring(Acp, newpin, SID_PINREENTRY, 0,
				INPUT_TIMEOUT);
		if(strcmp (sd->system_pin,newpin) != 0)
		{
		    sd_pin ("", CANCELLED, sd);
		    break;
		}
		if (sd_pin(sd->system_pin, 0, sd) != ACM_NEW_PIN_ACCEPTED)
		{
		    break;
		}
	    }
#ifdef ACE2_0
                /* user wrongly entered a newpin instead of hitting return */
                else
                  break;
#endif /*ACE2_0*/

	    outputstring(Acp, SID_LOGNEWPIN_1);
	    outputstring(Acp, SID_LOGNEWPIN_2);
	    nextcode[0] = '\0';
	    got_str = promptstring(Acp, nextcode, SID_PASSPROMPT, 0,
             		INPUT_TIMEOUT + 60);
	    if (got_str < 0)
	        break;
	    if (sd_check (nextcode, User, sd) == ACM_OK)
	        found_match = VALIDATED;
	break; /* ACP_NEW_PIN_REQUIRED */

	default:
            case ACM_ACCESS_DENIED:
        break;

    }
#endif /* SECURID_CARD */

#ifdef ACE2_0
        sd_close();
#endif /* ACE2_0 */
    return found_match;
} /* end of acp_securid_validate() */



#if defined(ENIGMA_SAFEWORD) && !defined(_WIN32)
/*
 * acp_safeword_printmsg()
 * This function prints out any messages that the SafeWord
 * Authentication Server wants displayed to the user.
 *
 */
static void
acp_safeword_printmsg(pb, Acp)
struct pblk *pb;
ACP *Acp;
{
    char instr[ACP_LONGSTRING]; /* ACP_LONGSTRING == 80 */

    if (pb->msg1[0])
    {
        sprintf(instr, "\nSafeWord: %s\n", pb->msg1);
        outputstring(Acp, instr);
        pb->msg1[0] = '\0';
    }
    if (pb->msg2[0])
    {
        sprintf(instr, "\nSafeWord: %s\n", pb->msg2);
        outputstring(Acp, instr);
        pb->msg2[0] = '\0';
    }
}
#endif /* defined(ENIGMA_SAFEWORD) && !defined(_WIN32) */

#ifdef ENIGMA_SAFEWORD
/*
 * acp_strip_hyphens()
 * This function strips out hyphens from a string.
 *
 */
void acp_strip_hyphens(str)
char *str;
{
    char *sp = str;

    do
    {
        while (*sp == '-')
        {
            sp++;
        }
    } while ( (*str++ = *sp++) != '\0');
}
#endif /* ENIGMA_SAFEWORD */

#if defined(ENIGMA_SAFEWORD) && !defined(_WIN32)
#ifndef NET_ENIGMA_ACP
/* acp_safeword_updlogs()
 * Updates Safeword logs
 */
void
acp_safeword_updlogs(pb, Acp)
struct pblk *pb;
ACP *Acp;
{
    if (pb->dynpwd[0] == '\0')
    {
        strncpy(pb->dynpwd, savdyn, sizeof(pb->dynpwd));
        strncpy(pb->chal, savcha, sizeof(pb->chal));
    }
    pb->mode = UPDATE_LOGS;
    if(debug)
        (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_updlogs\n");

    pbmain(pb);
    acp_safeword_printmsg(pb, Acp);
}
#endif /* not NET_ENIGMA_ACP */


/* acp_safeword_savdata()
 * Saves data for logging
 */
void
acp_safeword_savdata(pb)
struct pblk *pb;
{
    if (pb->dynpwd[0])
    {
        strcpy(savdyn, pb->dynpwd);
	savdyn[sizeof(pb->dynpwd) - 1] = '\0';
        strcpy(savcha, pb->chal);
	savcha[sizeof(pb->chal) - 1] = '\0';
    }
}
/*
 * acp_safeword_getfixed()
 * This function retrieves a fixed password, in addition to
 * retrieving a new fixed password if the user whants to change.
 * It puts the fixed password and the new fixed password into
 * the proper fields in the pb structure.  It returns the return
 * value from the function promptstring()
 *
 */
int
acp_safeword_getfixed(pb, Acp)
struct pblk *pb;
ACP *Acp;
{
#ifndef _WIN32
    ACP_LSTRING     Pass;
#else   /* defined _WIN32 */
	ACP_STRING     Pass;
#endif   /* defined _WIN32 */
    char fp[ACP_MAXSTRING], fpv[ACP_MAXSTRING];  /* ACP_MAXSTRING == 32 */
    char inistr[80];
    int got_str, i;

    outputstring(Acp, EAS_ENTERESC);
    got_str = promptstring(Acp, Pass, EAS_FIXPASS, (pb->echofix == ENABLED),
			   INPUT_TIMEOUT);
    if (got_str <= 0)
        return(got_str);

    strncpy(pb->fixpwd, Pass, sizeof(pb->fixpwd));

    if (pb->fixpwd[0] == ESC)
    {
        got_str = promptstring(Acp, Pass, EAS_OLDFIXPASS,
			       (pb->echofix == ENABLED), INPUT_TIMEOUT);
        if (got_str <= 0)
	    return(got_str);

	strncpy(pb->fixpwd, Pass, sizeof(pb->fixpwd));
	got_str = promptstring(Acp, Pass, EAS_NEWFIXPASS,
			       (pb->echofix == ENABLED), INPUT_TIMEOUT);
	if (got_str <= 0)
	    return(got_str);

	strncpy(fp, Pass, sizeof(fp));
	if (fp[0])
        {
            if (pb->echofix == DISABLED)
            {
                got_str = promptstring(Acp, Pass, EAS_REPFIXPASS, 0,
				       INPUT_TIMEOUT);
		if (got_str <= 0)
		    return(got_str);
		strncpy(fpv, Pass, sizeof(fpv));
            }
	    else
	        strncpy(fpv, fp, sizeof(fpv));

	    for (i=0;i<RETRIES_MAX_SAFEWORD;i++)
            {
                if (strcmp(fp, fpv) == 0 && strlen(fp) >= pb->fixmin &&
		            strcmp(fp, pb->fixpwd) != 0)
		    break;

		if (strcmp(fp, pb->fixpwd) == 0)
		    outputstring(Acp, EAS_MUSTDIFF);
		else
                {
                    if (strlen(fp) < pb->fixmin)
                    {
                        sprintf(inistr, EAS_PASSMIN, pb->fixmin);
                        outputstring(Acp, inistr);
                    }
		    else
                        outputstring(Acp, EAS_VERIFYERR);
		}

		got_str = promptstring(Acp, Pass, EAS_NEWFIXPASS,
				       (pb->echofix == ENABLED), INPUT_TIMEOUT);
		if (got_str <= 0)
		    return(got_str);
		strncpy(fp, Pass, sizeof(fp));

		if (pb->echofix == DISABLED)
                {
                    got_str = promptstring(Acp, Pass, EAS_REPFIXPASS, 0,
					   INPUT_TIMEOUT);
		    if (got_str <= 0)
		        return(got_str);
		    strncpy(fpv, Pass, sizeof(fpv));
                }
		else
		    strncpy(fpv, fp, sizeof(fpv));

	    }
	    if (i != 3)
	        strncpy(pb->nfixpwd, fp, sizeof(pb->nfixpwd));
	    else
	        outputstring(Acp, EAS_FIXNOCHANGE);
	}
    }
    return(got_str);

}
#endif /* defined(ENIGMA_SAFEWORD) && !defined(_WIN32) */
#ifdef ENIGMA_SAFEWORD
/*
 * acp_safeword_validate()
 * This function authenticates a user with the SafeWord Authentication
 * Server.  This function takes care of all prompting.  It returns a 1
 * if the user passed authentication, 0 if the user faild authentication.
 *
 */
int
acp_safeword_validate(Acp, logid, inet, port,ptype, service, got_str_p, User)

ACP	*Acp;			/* Handle to pass to library calls */
UINT32 logid,				/* Log sequence number */
		   inet;			     /* Annex Internet address */
int	port,ptype,	       /* physical/virtual port number */
	service;			 /* Expect SERVICE_CLI{,_HOOK} */
int *got_str_p;
char *User;
{
#ifdef NET_ENIGMA_ACP
  return acp_netsafeword_validate(Acp, logid, inet, port, service,
						got_str_p, User);
#else
#ifndef _WIN32
    ACP_LSTRING     Password;
#else   /* defined _WIN32 */
	ACP_STRING     Password;
#endif   /* defined _WIN32 */
    struct pblk *pb;
    char instr[ACP_MAXUSTRING];  /* ACP_MAXLSTRING == 128 */
    int i, index;
    char Inum[ACP_MAX_HOSTNAME_LEN], *aname; /*ACP_MAX_HOSTNAME_LEN==32*/
    struct hostent *hp;
    FILE *fp;

    pb = &pblock;
    bzero((char*)pb, sizeof(struct pblk));
    *savdyn = *savcha = '\0';
    pb->mode = CHALLENGE;

    *got_str_p = User && strlen(User);
    if (*got_str_p <= 0)
        goto notvalid;

    strncpy(pb->id, User, sizeof(pb->id));
    if (!pb->id[0])
        goto notvalid;

    if(debug)
        (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate\n");

    pbmain(pb);

    if(pb->pbresrv3 == UNAVAILABLE)
        return UNAVAILABLE;

    acp_safeword_printmsg(pb, Acp);

    /*
     * Pretend we are a valid user
     * because we don't want to give away
     * the fact that the username tried
     * is not in the database.
     */
    if (pb->status == BAD_USER)
        outputstring(Acp, EAS_HIDEBAD);

    if (pb->status == PASS || pb->status == PASS_PIN)
        return(VALIDATED);

    if (pb->status != GOOD_USER && pb->status != BAD_USER)
        goto notvalid;

range:

    if (pb->dynpwdf == ENABLED)
    {
        if (pb->chal[0])
        {
            sprintf(instr, EAS_CHALLENGE, pb->chal);
            outputstring(Acp, instr);
        }

	*got_str_p = promptstring(Acp, Password, EAS_DYNPASS,
				  (pb->echodyn == ENABLED), INPUT_TIMEOUT);
	if (*got_str_p <= 0)
	    return(*got_str_p);

	acp_strip_hyphens(Password);
	strncpy(pb->dynpwd, Password, sizeof(pb->dynpwd));
	if (pb->dynpwd[0] == ESC)
	    pb->dynpwd[0] = '\0';
	if (pb->fixpwdf == ENABLED && pb->dynpwd[0])
	    *got_str_p = acp_safeword_getfixed(pb, Acp);
    }

    /* mask bad user as someone who needs a fixed password */
    else if (pb->fixpwdf == ENABLED || pb->status == BAD_USER)
        *got_str_p = acp_safeword_getfixed(pb, Acp);

    pb->mode = EVALUATE_ALL;
    pb->msg1[0] = '\0';
    pb->msg2[0] = '\0';
    acp_safeword_savdata(pb); /* save for logging */
    if(debug)
        (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate(2)\n");

    pbmain(pb);
    acp_safeword_printmsg(pb, Acp);

    /* What's going here is the user has just passed authentication and is
    using a token with a SOFT PIN.  A SOFT PIN is a PIN that is appended
    to the challenge when calculating passwords.  So we first ask if he
    wants to change his pin.  But we don't want this info (the PIN) to go
    over the wire, so we give the challenge, and the user calculates his
    dynamic password with the new pin.  The server then back-calculates the
    new pin from the dynamic password given and the challenge. */
    /* Note that since the user has passed authentication, all retunrs return
    VALIDATED, even if the user failed to change his PIN */

    if (pb->status == PASS_PIN)
    {
        *got_str_p = promptstring(Acp, Password, EAS_CHANGEPIN, 1, INPUT_TIMEOUT);
	if (*got_str_p <= 0 || (Password[0] != 'Y' && Password[0] != 'y'))
	    goto valid;
	acp_strip_hyphens(Password);

	pb->mode = CHANGE_PIN;
	pb->dynpwd[0] = 0;
	pb->msg1[0] = '\0';
	pb->msg2[0] = '\0';
	if(debug)
	    (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate(3)\n");

	pbmain(pb);
	acp_safeword_printmsg(pb, Acp);
	if (pb->chal[0])
	{
	    sprintf(instr, EAS_CHALLENGE, pb->chal);
	    outputstring(Acp, instr);
	}
	index = 0;
	*got_str_p = promptstring(Acp, Password, EAS_DYNPASS,
				  (pb->echodyn == ENABLED), INPUT_TIMEOUT);
	if (*got_str_p <= 0)
        {
            outputstring(Acp, EAS_NOTCHANGED);
	    goto valid;
	}
	acp_strip_hyphens(Password);
	strncpy(pb->dynpwd, Password, sizeof(pb->dynpwd));
	if (pb->dynpwd[index] == ESC || pb->dynpwd[index] == 0 )
        {
            outputstring(Acp, EAS_NOTCHANGED);
	    goto valid;
        }

	/* this section of code is needed because, for some users, they
        only have to enter in a certain number of characters for the
        dynamic password.  For example, the card/token may generate an
        eight digit password, but the user only has to enter in the
        first four.  However, if only four characters of the dynamic
        password are entered here, it may not be enough to back-calculate
        the new SOFT PIN.  Therefore, we ask for the dynamic password
        again and again until the whole password has been entered */

	index = strlen(pb->dynpwd);
	for (i=0;i<RETRIES_MAX_SAFEWORD;i++)
        {
            pb->msg1[0] = '\0';
	    pb->msg2[0] = '\0';
	    if(debug)
	        (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate(4)\n");

	    pbmain(pb);
	    acp_safeword_printmsg(pb, Acp);

	    if (pb->status == PIN_VERIFIED)
            {
                outputstring(Acp, EAS_PINCHANGED);
		goto valid;
	    }
	    if (pb->status == PIN_NOT_VERIFIED)
            {
                outputstring(Acp, EAS_NOTCHANGED);
		goto valid;
	    }
	    if (pb->status == PIN_FOUND || pb->status == PIN_NOT_FOUND)
	        break;
	    *got_str_p = promptstring(Acp, Password, EAS_RESTDYNPASS,
				      (pb->echodyn == ENABLED), INPUT_TIMEOUT);
	    if (*got_str_p <= 0)
            {
                outputstring(Acp, EAS_NOTCHANGED);
		goto valid;
            }
	    acp_strip_hyphens(Password);
	    strcat(pb->dynpwd, Password);
	    if (pb->dynpwd[index] == ESC || pb->dynpwd[index] == 0 )
	    {
                outputstring(Acp, EAS_NOTCHANGED);
		goto valid;
            }
	    index = strlen(pb->dynpwd);
	}

	if (i == RETRIES_MAX_SAFEWORD)
        {
            outputstring(Acp, EAS_NOTCHANGED);
	    goto valid;
        }

	pb->mode = VERIFY_PIN;
	pb->msg1[0] = '\0';
	pb->msg2[0] = '\0';

	if(debug)
       	    (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_updlogs(5)\n");

	pbmain(pb);
	acp_safeword_printmsg(pb, Acp);

	if (pb->status == FAIL)
        {
            outputstring(Acp, EAS_NOTCHANGED);
	    goto valid;
        }

	if (pb->chal[0])
        {
            sprintf(instr, "\nChallenge: %s", pb->chal);
	    outputstring(Acp, instr);
        }
	*got_str_p = promptstring(Acp, Password, EAS_DYNPASS,
				  (pb->echodyn == ENABLED), INPUT_TIMEOUT);
	if (*got_str_p <= 0)
        {
            outputstring(Acp, EAS_NOTCHANGED);
	    goto valid;
        }
	acp_strip_hyphens(Password);
	strncpy(pb->dynpwd, Password, sizeof(pb->dynpwd));
	if (pb->dynpwd[0] == ESC || pb->dynpwd[0] == 0 )
        {
            outputstring(Acp, EAS_NOTCHANGED);
	    goto valid;
        }

	pb->mode = VERIFY_PIN;
	pb->msg1[0] = '\0';
	pb->msg2[0] = '\0';
	if(debug)
	    (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate(6)\n");

	pbmain(pb);
	acp_safeword_printmsg(pb, Acp);
	if (pb->status == PIN_VERIFIED)
        {
            outputstring(Acp, EAS_PINCHANGED);
	    goto valid;
        }
	outputstring(Acp, EAS_NOTCHANGED);
	goto valid;

    }

    if (pb->status == PASS)
        goto valid;

    /* RANGE error:  the SafeWord host knows the next n dynamic passwords.
       If it detects a password entered that is more than n removed then
       it yields the RANGE error.  The user is asked to enter his password
       again, and if it is the next one in the sequence, it lets him in */

    if (pb->errcode == RANGE)
        goto range;

    acp_safeword_updlogs(pb, Acp);
    goto notvalid;

valid:
    acp_safeword_updlogs(pb, Acp);
    return(VALIDATED);

notvalid:
    if(ISUDP(Acp->state))
        log_message(inet, logid, port,ptype, service, EVENT_REJECT, "");
    if (pb->errcode)
    {
        sprintf(instr, "%s:SafeWord error #%d", pb->id, pb->errcode);
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, instr);
    }

#ifdef USE_SYSLOG
    if (ErpcdOpt->UseSyslog)
    {
#ifdef USE_ANAME
        if (ErpcdOpt->UseHostName && (hp = gethostbyaddr(&inet, sizeof(inet), AF_INET)) != NULL &&
	    hp->h_name != NULL && hp->h_name[0] != '\0')
	    aname = hp->h_name;
	else
#endif
	{
	    inet_number(Inum, inet);
	    aname = Inum;
	}
    } /* UseSyslog */
#endif /*USE_SYSLOG */
    if (pb->msg1[0])
    {
#ifdef USE_SYSLOG
        if (ErpcdOpt->UseSyslog && (pb->errcode == 6 || pb->errcode == 10 || pb->errcode == 12 ||
				    pb->errcode == 13 || pb->errcode ==14 || pb->errcode == 19)) {
	    sprintf(syslogbuf, "%s:%s:[%s/%d]:%s:%s", "reject",
		   service_name[service], aname, port,ptype, pb->id, pb->msg1);
	    syslog(LOG_WARNING, syslogbuf);
	} else
#endif /*USE_SYSLOG */
        {
            sprintf(instr, "%s:%s", pb->id, pb->msg1);
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, instr);
        }
    }
    if (pb->msg2[0])
    {
#ifdef USE_SYSLOG
        if (ErpcdOpt->UseSyslog && (pb->errcode == 6 || pb->errcode == 10 || pb->errcode == 12 ||
				    pb->errcode == 13 || pb->errcode ==14 || pb->errcode == 19)) {
	    sprintf(syslogbuf, "%s:%s:[%s/%d]:%s:%s", "reject",
		   service_name[service], aname, port,ptype, pb->id, pb->msg2);
	    syslog(LOG_WARNING, syslogbuf);
	} else
#endif
        {
            sprintf(instr, "%s:%s", pb->id, pb->msg2);
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, instr);
        }
    }

    return(NOT_VALIDATED);
#endif /* not NET_ENIGMA_ACP */
}
#endif /* ENIGMA_SAFEWORD */

#if defined(ENIGMA_SAFEWORD) && !defined(_WIN32)
#ifndef NET_ENIGMA_ACP
/*
 * acp_safeword_validate_ipx()
 * This function authenticates a user with the SafeWord Authentication
 * Server.  Note that a username and password already needs to be set.
 * It returns a 1 if the user passed authentication, 0 if the user
 * failed authentication.  Note that authentication will fail if more
 * than one password is required.  Authentication will also fail if a
 * challenge is involved.
 *
 */

int
acp_safeword_validate_ipx(User, Password, Acp, logid, inet, port,ptype, service)

char *User, *Password;
ACP *Acp;
UINT32 logid,				/* Log sequence number */
inet;			             /* Annex Internet address */
int port,ptype,		       /* physical/virtual port number */
service;			 /* Expect SERVICE_CLI{,_HOOK} */
{
    struct pblk *pb;
    char instr[ACP_LONGSTRING];   /* ACP_LONGSTRING == 80 */
    int i, index;
    char Inum[ACP_MAX_HOSTNAME_LEN], *aname; /* ACP_MAX_HOSTNAME_LEN == 32 */
    struct hostent *hp;

    pb = &pblock;
    bzero((char*)pb, sizeof(struct pblk));
    pb->mode = CHALLENGE;

    strncpy(pb->id, User, sizeof(pb->id));
    if (!pb->id[0])
        goto notvalid;

    if(debug)
        (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate_ipx\n");

    pbmain(pb);

    if (pb->status == PASS)
        return(VALIDATED);

    if (pb->status != GOOD_USER && pb->status != BAD_USER)
        goto notvalid;

    /* can't support two passwords */
    if (pb->dynpwdf == ENABLED && pb->fixpwdf == ENABLED)
        goto notvalid;

    if (pb->dynpwdf == ENABLED)
    {
        acp_strip_hyphens(Password);
	strncpy(pb->dynpwd, Password, sizeof(pb->dynpwd));
    }
    else if (pb->fixpwdf == ENABLED)
        strncpy(pb->fixpwd, Password, sizeof(pb->fixpwd));

    pb->mode = EVALUATE_ALL;
    pb->msg1[0] = '\0';
    pb->msg2[0] = '\0';
    if(debug)
        (void) fprintf(stderr, "*** Calling pbmain() from acp_safeword_validate_ipx(2)\n");

    pbmain(pb);

    if (pb->status == PASS)
        return(VALIDATED);

notvalid:
    if (pb->errcode)
    {
        sprintf(instr, "SafeWord error #%d", pb->errcode);
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, instr);
    }
#ifdef USE_SYSLOG
    if (ErpcdOpt->UseSyslog)
    {
#ifdef USE_ANAME
        if (ErpcdOpt->UseHostName && (hp = gethostbyaddr(&inet, sizeof(inet), AF_INET)) != NULL
	                                && hp->h_name != NULL && hp->h_name[0] != '\0')
            aname = hp->h_name;
	else
#endif
	{
	    inet_number(Inum, inet);
	    aname = Inum;
	}
    }  /* UseSyslog */
#endif
    if (pb->msg1[0])
    {
#ifdef USE_SYSLOG
        if (ErpcdOpt->UseSyslog && (pb->errcode == 6 || pb->errcode == 10 || pb->errcode == 12
				|| pb->errcode == 13 || pb->errcode ==14 || pb->errcode == 19)) {
            sprintf(syslogbuf, "%s:%s:[%s/%d]:%s:%s", "reject",
		   service_name[service], aname, port,ptype, pb->id, pb->msg1);
	    syslog(LOG_WARNING, syslogbuf);
	} else
#endif
        {
            sprintf(instr, "%s:%s", pb->id, pb->msg1);
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, instr);
	}
    }
    if (pb->msg2[0])
    {
#ifdef USE_SYSLOG
        if (ErpcdOpt->UseSyslog && (pb->errcode == 6 || pb->errcode == 10 || pb->errcode == 12
			       || pb->errcode == 13 || pb->errcode ==14 || pb->errcode == 19)) {
	    sprintf(syslogbuf, "%s:%s:[%s/%d]:%s:%s", "reject",
		   service_name[service], aname, port,ptype, pb->id, pb->msg1);
	    syslog(LOG_WARNING, syslogbuf);
	} else
#endif
        {
            sprintf(instr, "%s:%s", pb->id, pb->msg2);
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, instr);
        }
    }

    return(NOT_VALIDATED);
}
#endif /* not NET_ENIGMA_ACP */
#endif /* defined(ENIGMA_SAFEWORD) && !defined(_WIN32) */


/*
 * This function is called by available() to generate an address to
 * include in a filter.  A NULL return indicates an error.
 * IN  token   ip address with wild cards or just host name.
 * Returns:
 *     IP   - address (with 0's in place of asterisks) or the host name.
 *     NULL - if "token" is erroneous.
 */

/* #define DEBUG_GFA 1 */

static char *
get_filter_addr(token)
char *token;
{
    static char addrbuf[20];

    /* If token contain an ip addr. */
    if (isdigit(*token))
    {
        register char *tp, *ap;
	int mask = 0, dot = 0;
       	char mflag = FALSE;

#ifdef DEBUG_GFA
	if (debug)
	    fprintf(stderr, "get_filter_addr: address token \"%s\"\n",token);
#endif

	/* Go through the token and save the values in addrbuf */
	for (tp = token, ap = addrbuf; *tp; tp++, ap++)
	{
	    switch (*tp)
            {
	        /*
		 * for digits and '.' of an ip addr just copy to
		 * addrbuf and continue.
		 */
	        case '.':
	            dot++;
		    if (!mflag)
		        mask += 8;
		    *ap = *tp;
		    continue;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
	        case '8':
		case '9':
		    if (mflag)
		    {
#ifdef DEBUG_GFA
		        if (debug)
			    fprintf(stderr, "get_filter_addr: found '%c' after wildcard\n", *tp);
#endif
			goto addr_err;
		    }
		    *ap = *tp;
		    continue;

		/*
		 * wild card specified in the ip addr.
		 * if an erroneous element return eror
		 * otherwise put a '0' in place of the
		 * asterisk.
		 */
		case '*':
		    if ((*(tp+1) != '.') && (*(tp+1) != '\0'))
		    {
#ifdef DEBUG_GFA
		        if (debug)
			    fprintf(stderr, "get_filter_addr: found '%c' after '*'\n", *tp);
#endif
			/* erroneous entry, return failure */
			goto addr_err;
		    }
		    mflag = TRUE;
		    /* complete the rest of the ip address */
		    strcpy(ap,"0");
		    ap = addrbuf + strlen(addrbuf);
		    while (dot < 3) {
		      strcpy(ap,".0");
		      ap = addrbuf + strlen(addrbuf);
		      dot++;
		    }
		    continue;
		default:
addr_err:
		/* return failure */
	        if (debug)
		    (void)fprintf(stderr, "get_filter_addr: bad IP addr \"%s\"\n", token);
		sprintf(syslogbuf, "bad IP address \"%s\" in acp_restrict\n", token);
		syslog(LOG_ERR, syslogbuf);
		return(NULL);
            }
        }

	/* erroneous presence of dots in the incoming entry */
        if (dot != 3)
        {
#ifdef DEBUG_GFA
	    if (debug)
	        fprintf(stderr, "get_filter_addr: found %d dots\n", dot);
#endif
	    goto addr_err;
        }
	/* end of addr, save the mask in addrbuf */
	*ap = '\0';
	ap = addrbuf + strlen(addrbuf);
	if (mflag)
	{
	    sprintf(ap, "/%d", mask);
	}
#ifdef DEBUG_GFA
	if (debug)
	  printf("get_filter_addr: %s\n", addrbuf);
#endif
    }/* if (isdigit(*token)) */

    else if (*token == '*') {
      /* include/exclude all addresses */
      sprintf(addrbuf, "*");
    }

    /* token is a host name eg. vulcan */
    else
    {
        UINT32 addr;
	register unsigned char *ap = (unsigned char *)(&addr);
	struct hostent *hent;       /* storage for host info from /etc/hosts */
#ifdef h_addr
	struct in_addr *iaddr;
#endif

#ifdef DEBUG_GFA
	if (debug)
	    fprintf(stderr, "get_filter_addr: hostname token \"%s\"\n", token);
#endif

	/* read /etc/hosts till host is found or EOF */
	if ((hent = gethostbyname(token)) == NULL)
       	{
	    if (debug)
	        (void)fprintf(stderr, "get_filter_addr: bad hostname \"%s\"\n", token);
	    sprintf(syslogbuf, "could not resolve hostname \"%s\" in acp_restrict\n",
		   token);
	    syslog(LOG_ERR, syslogbuf);
	    return(NULL);
	}

	/* save the ip address. */
#ifdef h_addr
	iaddr = (struct in_addr *)(*hent->h_addr_list);
	addr = iaddr->s_addr;
#else
	addr = hent->h_addr->s_addr;
#endif
	sprintf(addrbuf, "%u.%u.%u.%u", *ap, *(ap+1), *(ap+2), *(ap+3));
    }

#ifdef DEBUG_GFA
    if (debug)
        fprintf(stderr, "get_filter_addr: returning \"%s\"\n", addrbuf);
#endif
    return(addrbuf);
}

/*********************************************************************
 * available
 * Process restriction information on available ports
 * IN  env_p		pointer to environment structure
 * IN  rinet		internet address of remote host
 * IN  port		destination port
 * IN  do_filters	TRUE to construct filters, FALSE otherwise
 * OUT filter_pp	address of filter_list pointer
 * Results: Access status (ACCESS_RESTRICTED or ACCESS_UNRESTRICTED)
 */
available(env_p, rinet, port,ptype, do_filters, filter_pp)
struct environment_spec *env_p;
UINT32 rinet;
int port,ptype;
int do_filters;
STR_LIST **filter_pp;

{
    int	done = 0;
    int	got_annex = 0;
    int	filter_dflt = 0;
    int	status;
    char	token[TOKEN_SIZE];         /*using the same length as in */
                                           /*acp_regime parser. A larger */
                                           /*array is required since     */
                                           /*profile criteria gets       */
                                           /*chopped with SIZE_INET      */
    char    *host_p = NULL;
    char    *ports_p = NULL;
    struct  environment_values tmp_val;

    /*
     * Scan file until EOF, or until a match is encountered.  In the
     * event of no match (EOF), take default action - allow access.
     */

    while(!done)
    {
        status = get_string(token);

	/*
	 * Print a debug message saying what token we got.  The
	 * switch statement will contain another printf() telling
	 * the status in a printable form.
	 */
	if(debug)
	    (void) fprintf(stderr,
			   "available: get_string returns token %s, status: ",
			   token);

	switch(status)
	{
	    case END_OF_FILE:
	        /* Print status if in debug mode */
	        if(debug)
		    (void) fprintf(stderr, "EOF\n");

		done = -1;
	    break; /* END_OF_FILE */

	    case IS_ANNEX:
		/* Print status if in debug mode */
		if(debug)
		    (void) fprintf(stderr, "IS_ANNEX\n");

		/* Clear out the environment structure */
		(void) bzero((char*)&tmp_val, sizeof(struct environment_values));

		/* Stick the token into the environment values struct */
		(void) strcpy(tmp_val.annex, token);

		if(match_env_options(env_p, &tmp_val))
		{
		    got_annex = EXCLUDE_LIST;
		    if(debug)
		        (void) fprintf(stderr, "MATCH(exclude)!\n");
		}
		else
		{
		    got_annex = 0;
		    if(debug)
		        (void) fprintf(stderr, "No match (exclude)\n");
		}
	    break; /* IS_ANNEX */

	    case IS_ANNEX_NOT:
		/* Print status if in debug mode */
		if(debug)
		    (void) fprintf(stderr, "IS_ANNEX_NOT\n");

		/* Clear out the environment structure */
		(void) bzero((char*)&tmp_val, sizeof(struct environment_values));

		/* Stick the token into the environment values struct */
		(void) strcpy(tmp_val.annex, token);

		if(match_env_options(env_p, &tmp_val))
		{
		    got_annex = INCLUDE_LIST;
		    if(debug)
		        (void) fprintf(stderr, "MATCH(include)!\n");
		}
		else
		{
		    got_annex = 0;
		    if(debug)
		        (void) fprintf(stderr, "No match (include)\n");
		}
	    break; /*  IS_ANNEX_NOT */

	    case IS_ENV_STRING:
		/* Print status if in debug mode */
		if(debug)
		    (void) fprintf(stderr, "IS_ENV_STRING\n");

		/* Clear out the environment structure */
		(void) bzero((char*)&tmp_val, sizeof(struct environment_values));

		/*
		 * Try and parse the environment.  If that works,
		 * see if we get a match.
		 */
		if(env_keyword_routine(token, &tmp_val) >= 0)
		{
		    if(match_env_options(env_p, &tmp_val))
		        got_annex = EXCLUDE_LIST;
		    else
		        got_annex = 0;
		}
		else
		{
		    syslog(LOG_ERR, "available: environment string parse failed.\n");
		    return(ACCESS_RESTRICTED);
		}
	    break; /*  IS_ENV_STRING */

	    case IS_ENV_STRING_NOT:
		/* Print status if in debug mode */
		if(debug)
		    (void) fprintf(stderr, "IS_ENV_STRING_NOT\n");

		/* Clear out the environment structure */
		(void) bzero((char*)&tmp_val, sizeof(struct environment_values));

		/*
		 * Try and parse the environment.  If that works,
		 * see if we get a match.
		 */
		if(env_keyword_routine(token, &tmp_val) >=0 )
		{
		    if(match_env_options(env_p, &tmp_val))
		        got_annex = INCLUDE_LIST;
		    else
			got_annex = 0;
		}
		else
		{
		    syslog(LOG_ERR, "available: environment string parse failed.\n");
		    return(ACCESS_RESTRICTED);
		}
	    break; /* IS_ENV_STRING_NOT */

	    case IS_HOST:
		/* Print status if in debug mode */
		if(debug)
		    (void) fprintf(stderr, "IS_HOST\n");

		/*
		 * Only bother parsing this if we've got an annex
		 * or environment string we've matched already.
		 */
		if(got_annex)
		{
		    /*
		     * Parse the host/ports specification and find
		     * out whether we got a host only, a host and
		     * port description, or an error.
		     */
		    if(get_host_and_ports(token, &host_p, &ports_p)
		                             == FOUND_HOST_ERROR)
		    {
		        syslog(LOG_ERR, "available: get_host_and_ports failed.\n");
			if(debug)
			    (void) fprintf(stderr,
					"available: get_host_and_ports failed.\n");
			return(ACCESS_RESTRICTED);
		    }

		    if(debug)
		        (void) fprintf(stderr,
				     "available: host: %s, ports: %s\n",
				       (host_p == NULL)?"NULL":host_p,
				       (ports_p == NULL)?"NULL":ports_p);

		    /*
		     * Filter construction algorithm (simple version; could be smarter)
		     *
		     * If this is a restrict (:) entry, then we want to build incl filters;
		     * if we're already building excl filters, that's an error.
		     *
		     * If this is an allow (~) entry, then we want to build excl filters
		     * (which presumes the default is deny because the filters make it so);
		     * if we're already building incl filters, that's an error.
		     *
		     * NOTE: this doesn't handle ports because we'd need a seperate
		     * filter for each port.  We need to make the filter command
		     * smarter to do this correctly.
		     */
		    if (do_filters)
		    {
		        char *addrp;
			char	*iep, *oep, *pp;
			char	buffi[60], buffo[60];
			STR_LIST *slp;

			/* if a range of ports is specified, deny access */
			if (ports_p)
			{
			    if (index(ports_p, '-') != NULL)
			    {
			        if (debug)
				    (void)fprintf(stderr,
					"available: port range on filters\n");
                syslog(LOG_ERR,
				    "cannot generate filters for port ranges");
				return(ACCESS_RESTRICTED);
			    }
			    if ((pp = index(ports_p, ',')) != NULL)
			        *pp++ = '\0';
			} /* if (ports_p) */
			else
			    pp = NULL;

			if (got_annex == EXCLUDE_LIST)
			{
			    if (filter_dflt == EXCLUDE_LIST)
			    {
			        if (debug)
				    (void)fprintf(stderr,
						  "available: incl/excl mismatch\n");
				syslog(LOG_ERR,
				       "acp_restrict incl/excl mismatch\n");
				return(ACCESS_RESTRICTED);
			    }
			    filter_dflt = INCLUDE_LIST;
			    if ((addrp = get_filter_addr(host_p)) == NULL)
			          return(ACCESS_RESTRICTED);
			    sprintf(buffi, "input include ip addr %s *", addrp);
			    sprintf(buffo, "output include ip addr %s *", addrp);
			} /* if (got_annex == EXCLUDE_LIST) */
			else
			{
			    if (filter_dflt == INCLUDE_LIST)
			    {
			        if (debug)
				  (void)fprintf(stderr,
						"available: excl/incl mismatch\n");
				syslog(LOG_ERR,
				       "acp_restrict excl/incl mismatch\n");
				return(ACCESS_RESTRICTED);
			    }
			    filter_dflt = EXCLUDE_LIST;
			    if ((addrp = get_filter_addr(host_p)) == NULL)
				  return(ACCESS_RESTRICTED);
			    sprintf(buffi, "input exclude ip addr %s *", addrp);
			    sprintf(buffo, "output exclude ip addr %s *", addrp);
			}/* else, if (got_annex == EXCLUDE_LIST) */
			iep = buffi + strlen(buffi);
			oep = buffo + strlen(buffo);
filter_next_port:
			if (ports_p)
			{
			    char buffp[20];
			    sprintf(buffp, " port %s * disc", ports_p);
			    strcat(buffi, buffp);
			    strcat(buffo, buffp);
			}
			else
			{
			    strcat(buffi, " disc");
			    strcat(buffo, " disc");
			}

			if (debug)
			    (void)fprintf(stderr,
					    "available: generated \"%s\"\n",buffi);
			/* do the output filter */
			slp = racp_create_strlist(buffo, strlen(buffo));
			if (slp == NULL)
			{
			    if (debug)
			        (void)fprintf(stderr,
					      "available: cannot create SRT_LIST\n");
			    syslog(LOG_ERR,
				   "could not generate output filter entry");
			    return(ACCESS_RESTRICTED);
			}
			slp->next = *filter_pp;
			*filter_pp = slp;
			/* do the input filter */
			slp = racp_create_strlist(buffi, strlen(buffi));
			if (slp == NULL)
			{
			    if (debug)
			        (void)fprintf(stderr,
					      "available: cannot create SRT_LIST\n");
			    syslog(LOG_ERR,
				   "could not generate input filter entry");
			    return(ACCESS_RESTRICTED);
			}
			slp->next = *filter_pp;
			*filter_pp = slp;

			if ((ports_p = pp) != NULL)
			{
			    if ((pp = index(pp, ',')) != NULL)
			        *pp++ = '\0';
			    *iep = '\0';
			    *oep = '\0';
			    goto filter_next_port;
			}
		    }/* if (do_filters) */
		    else
		    {
		        /* Match against the host and ports - return
			 * the access restriction if we win!
			 */
		        if(wild_match(token, rinet) &&
			   match_host_ports(port, ports_p))
			{
			    /* if debug, report that we succeeded */
			  if (debug)
         		      (void)fprintf(stderr,
					    "available: MATCH! Access is %s\n",
					    (got_annex == EXCLUDE_LIST) ?
					    "RESTRICTED" : "UNRESTRICTED");

			  return((got_annex == EXCLUDE_LIST) ?
				 ACCESS_RESTRICTED : ACCESS_UNRESTRICTED);
			}
		    } /*else , if (do_filters) */
		}/* if (got_annex) */
	    break; /* IS_HOST */

	    case IS_ENV_STRING_ERR:
		if(debug)
		    (void) fprintf(stderr, "IS_ENV_STRING_ERR\n");
		syslog(LOG_ERR, "available: environment string parse failed. \n");
		   return ACCESS_RESTRICTED;
	    default:
		if(debug)
		    (void) fprintf(stderr, "*** UNRECOGNIZED TOKEN ***\n");

	    break;
	}/* switch (status) */
    }/* while (!done) */

    /* End of file - no explicit restriction found - include me */
    if(debug)
        (void) fprintf(stderr, "available: No match - unrestricted.\n");

    return(ACCESS_UNRESTRICTED);
}

/*
 *	get_string()	- low level parser for acp_restrict file
 *      OUT  String   profile criteria or the annex for which the following
 *                    annex/host is restricted or allowed.
 *      Returns:
 *          END_OF_FILE
 *          IS_ENV_STRING      - this env_string restricts the following annex/host.
 *          IS_ENV_STRING_NOT  - this env_string does not restrict the following annex/host.
 *          IS_ANNEX           - this annex/host restricts the following annex/host.
 *          IS_ANNEX_NOT       - this annex/host does not restricts the following annex/host.
 */

get_string(String)

char	*String;
{
    static	int	start_file = -1, end_file = 0, incomment;
    static	FILE	*rfile;

    char		restrict_pth[PATHSZ];
    int		slen = 0, quotes_count=0,
    value;

    int	is_env_string = 0, inquotes = 0;	/* Set if we have an env str */
    int	can_contain_whitespace = 0;	/* true if whitespace OK */
    int	can_contain_comma = 0;	/*
				 * Set if parsing an expression that
				 * can contain a comma, such as:
				 * 	host[24,45]
				 */
    int can_contain_colon = 0;  /* Time specifications can contain colon */

    /* macro saves the acp_restrict filepath. */
    ACP_RESTRICT(restrict_pth);

    /* read file */
    if(start_file)
        if(!(rfile = fopen(restrict_pth, "r")))
	    return END_OF_FILE;

    start_file = 0;
    incomment = 0;

    while(!end_file)
    {
        value = getc(rfile);

	/*
	 * fall through for the white space and save the token
	 * in the String array. If a colon (:) or tilde (~) is hit,
	 * return restrict and not-restrict respectively.
	 */
	switch(value)
	{
	    case EOF:

	        end_file = -1;
		/*
		 * Check and see if this token we're processing
		 * can contain whitespace.  If it can, just add
		 * the character to the buffer, and go around for the
		 * the next.
		 *
		 * The default action is to drop through and use
		 * the whitespace as a delimiter to signify the
		 * end of the token.
		 */
		if(can_contain_whitespace && (slen < (TOKEN_SIZE - 1)))
		{
		    String[slen++] = value;
		    break;
		}
		/* FALL THROUGH - if whitespace not allowed */

	    case '\r':
	    case '\n':
	    case '\f':
	    case '\0':
		incomment = 0;

	    case ' ':
	    case '\t':
	    case ',':
		/*
		 * Check and see if this token we're processing
		 * can contain commas.  If it can, just add
		 * the character to the buffer, and go around for the
		 * the next.
		 *
		 * The default action is to drop through and use
		 * the comma as a delimiter to signify the
		 * end of the token.
		 */
		if(can_contain_comma && (slen < (TOKEN_SIZE - 1)))
		{
		    String[slen++] = value;
		    break;
		}
		/* FALL THROUGH - if comma not allowed */

	    case '\\':

		if(slen)
		{
		    String[slen] = '\0';
		    return IS_HOST;
		}
	    break;  /* '\\', ',', '\t', ' ' , '\0', '\f', '\n', '\r', EOF */

	    case '#':
		incomment = 1;
	    break;  /* # */

	    case '"':
		if (!incomment) { /* if we're in a comment, who cares what we find! */
		    inquotes = !inquotes;
		    quotes_count++;
		    if(quotes_count > 2) /*this should be changed if other
				           security profiles allow quotes */
		        return IS_ENV_STRING_ERR;
		}
		if(!incomment && slen){
		    String[slen++] = value;
		   if(inquotes)
		      can_contain_colon = 1;
	       	   else
		      can_contain_colon = 0;
		}
		break;
	    case ':':
		if(!can_contain_colon){
		   if(!incomment && slen)
		   {
		      String[slen] = '\0';
		      /* This might be an environment string or
		       * a host specification.
		       */
		      if(is_env_string)
		        return IS_ENV_STRING;
		      else
		        return IS_ANNEX;
		   }
		}
		else
		   String[slen++] = value;
	    	break; /* ':' */

	    case '~':

		if(!incomment && slen)
		{
		    String[slen] = '\0';
		    /* This might be an environment string or
		     * a host specification.
		     */
		    if(is_env_string)
		        return IS_ENV_STRING_NOT;
		    else
		        return IS_ANNEX_NOT;
		}
	    break; /* '~' */


	    case '=':
		/*
		 * If we see an equal sign, we're parsing an
		 * an environment string.  We need to set a flag
		 * to indicate this, and we also need to say that
		 * commas/whitespace can be included in the specification
		 * (as opposed to functioning as a delimiter).
		 */
		is_env_string = 1;
		can_contain_comma = 1;
		can_contain_whitespace = 1;
		/*
		 * FALL THROUGH - we need to put the equal
		 * sign into the parsed token.
		 */

	    case '[':
	    case ']':
		/*
		 * For the braces, we need to turn on or off the
		 * appropriate indicators to say if whitespace/commas
		 * are allowed or not.
		 *
		 * In either case, fall through and add the characters
		 * to the result string.
		 *
		 * Perhaps it would be better do duplicate the code
		 * that puts them in the buffer.
		 */
		if(value == '[')
		{
		    can_contain_comma = 1;
		    can_contain_whitespace = 1;
		}
		else if(value == ']')
		{
		    can_contain_comma = 0;
		    can_contain_whitespace = 0;
		}
		/* FALL THROUGH */

	    default:
		/* Add the character to the string */
		if(!incomment && slen < (TOKEN_SIZE - 1))
		    String[slen++] = value;
	 }
    }
    (void)fclose(rfile);
    return END_OF_FILE;
}


/*
 *  secure_cache()
 *
 *  Create internal tables for annex encryption keys.
 *  A separate table is created for wildcard entries.
 *  Bytes containing nulls match corresponding byte of internet address.
 *
 *  This routine is invoked at initialization time, or by a SIGHUP.
 */

#define GOT_END		1001
#define GOT_ANNEX	1002
#define LAST_ANNEX	1003
#define GOT_PASSWORD	1004
#define SIZE_TOKEN	64
#define ANNEX_LIST	2501
#define	ANNEX_PASSWORD	2502

void secure_cache()
{
	int		done = 0;		/* set on end of file */
	int		status;			/* return from get_token() */
	int		wildcard;		/* is token a wildcard? */
	int		i;			/* use me for loops */
	int		wildmark = 0;		/* mark wildcard cache */
	int		tamemark = 0;		/* mark regular cache */
	int		quest;			/* which token is expected? */
	UINT32		address;		/* internet address */
	KEYDATA		*key;			/* pointer to crypt table */
	char		token[SIZE_TOKEN + 1];	/* token from get_token() */
	FILE 		*sfile;			/* file pointer */
	char		keypath[PATHSZ];

	/*
	 *  Free any previously allocated KEYDATA tables, since this
	 *  routine is also called on a SIGHUP and tables are replaced
	 */

	for(i = 0; i < Nmalloced; i++)
	    free(Allocated[i]);

	Nwild = Ntame = Nmalloced = 0;

	ACP_KEYS(keypath);
	sfile = fopen(keypath, "r");

	if(!sfile)
	    done = -1;

	quest = ANNEX_LIST;

	while(!done)
	{
	    status = get_token(sfile, quest, token, &wildcard);

	    switch(status)
	    {
		case LAST_ANNEX:

		    quest = ANNEX_PASSWORD;

		case GOT_ANNEX:

		    if(!strlen(token))
			address = 0;
		    else
		        address = inet_address(token);

		    if(wildcard)
		    {
			if(Nwild < MAX_WILD)
			    Wild[Nwild++].addr = address;
		    }
		    else if(address)
		    {
			if(Ntame < MAX_TAME)
			    Tame[Ntame++].addr = address;
		    }
		    break;

		case GOT_END:

		    done = -1;

		case GOT_PASSWORD:

		    token[KEYSZ - 1] = '\0';  /* limit size */

		    if(Nmalloced < MAX_KEYS)
		    {
			key = make_table(token, (KEYDATA *)0);

			Allocated[Nmalloced++] = (char *)key;

			while(wildmark < Nwild)
			    Wild[wildmark++].ckey = key;

			while(tamemark < Ntame)
			    Tame[tamemark++].ckey = key;
		    }
		    quest = ANNEX_LIST;
		    break;

		default:

		    break;
	    }
	}

	if(debug)
	{
		printf("Wild entries:\n");
		    for(i = 0; i < Nwild; i++)
			printf("Address %8.8x, key <%s>\n",
			    Wild[i].addr, Wild[i].ckey->password);

		printf("Tame entries:\n");
		for(i = 0; i < Ntame; i++)
		    printf("Address %8.8x, key <%s>\n",
			    Tame[i].addr, Tame[i].ckey->password);
	}
	if(sfile)
	    (void)fclose(sfile);
	return;
}


/*
 *	get_token()	- low level parser for acp_keys file
 *      Returns:
 *        GOT_PASSWORD
 *        GOT_ANNEX
 *        LAST_ANNEX
 *        GOT_END
 *        ANNEX_PASSWORD
 */

get_token(file, quest, String, wild)

FILE	*file;		/* file pointer for ACP_KEYS file */
int	quest;		/* quest is for an Annex address or a password? */
char	*String;	/* token - Annex identifier or password */
int	*wild;		/* is this token a wildcard entry? */
{
	int		slen = 0,	/* length of current token */
			endoffile = 0,	/* reached end of file */
			value;		/* returned character or EOF */

    *wild = 0;
    String[0] = '\0';

    while(!endoffile)
    {
        value = getc(file);

	switch(value)
	{
	    case EOF:

		String[slen] = '\0';		/* can be null */
	        endoffile = -1;

	    case ' ':
	    case '\t':

	    break;/* skip white space */

	    case '\\':

		value = getc(file);

		if(value == EOF)		/* cant escape EOF */
		    endoffile = -1;
		else if(value == '\n')		/* ignore newlines */
		    break;
		else goto data;			/* else it is data */

	    case '#':

		/* skip from # to end of line */

		while((value = getc(file)) != '\n' && value != EOF)
		  ;

	    case '\n':

		String[slen] = '\0';		/* can be null */
		    return GOT_PASSWORD;	/* got the password */

	    case ':':

		if(quest == ANNEX_PASSWORD)
		    goto data;

		String[slen] = '\0';	       /* null terminate */
		    return LAST_ANNEX;	       /* end of list */

	    case ',':
	    case ';':

		if(quest == ANNEX_PASSWORD)    /* can be in passwd */
		    goto data;

		String[slen] = '\0';	       /* null terminate */
		    return GOT_ANNEX;	       /* got an Annex */

	    case '*':

		*wild = -1;		       /* got a wildcard */
		value = '0';		       /* treat as zero */

data:
	    default:

		if(slen < (SIZE_TOKEN - 1))    /* token character */
		    String[slen++] = value;
	}/* switch(value) */
    }/* while (!endoffile) */
    return GOT_END;
}


/*
 *  annex_key()
 *
 *  Retrieve key from internal address/key cache.
 *  This information is derived from ACP_KEYS file, at start or SIGHUP.
 */

KEYDATA *
annex_key(iaddr)

UINT32		iaddr;		 /* internet address of an Annex */
{
    int		i, j;		            /* indices for loops */
    char       *x, y[4];	/* point to entry, copy of iaddr */


    /* search exact match table first, then search wildcard table */
    for(i = 0; i < Ntame; i++)	/* straight comparison */
    {
        if(Tame[i].addr == iaddr)
	    return Tame[i].ckey;
    }
    for(i = 0; i < Nwild; i++)	/* wildcard comparison */
    {
        x = (char *)&Wild[i].addr;
	bcopy((char *)&iaddr, y, sizeof(iaddr));
	for(j = 0; j < sizeof(iaddr); j++)
	    if(x[j] == '\0')
	        y[j] = '\0';

	if(Wild[i].addr == *(UINT32	 *)y)
	    return Wild[i].ckey;
    }
    return (KEYDATA *)0;
}

/*
 * Look for a special port password for this port.
 * These are stored in the acp_passwd file as inetaddr.port, i.e.,:
 * for milo (132.245.1.200) port 13:
 *	132.245.1.200.13:xxxxxxxxxxxxx:
 */
void
acp_special(Special, inet, port,ptype)

char		*Special;
UINT32		inet;
int		port,ptype;
{
    unsigned char	*Pinet = (unsigned char *)&inet;

    /*
     *  Convert internet address and port number to special string
     */

    (void)sprintf(Special, "%u.%u.%u.%u.%u",
		  Pinet[0], Pinet[1], Pinet[2], Pinet[3], port);
    return;
}

/*
 * This fxn looks for a user's entry in the acp_passwd file.
 * Returns:
 *     1/0 - based on the success of failure of the search.
 */
acp_getusr(Name)

char	*Name;            /* username */
{
#ifndef _WIN32
    struct	passwd *pwd;

    /*
     *  Check password file for an entry
     */
    setacppw(NULL);     /*6131*/
    while(pwd = getacppw())
    {
        if(!strcmp(pwd->pw_name, Name))
	    return 1;
    }
    endacppw();
#endif
    return 0;	/* no entry found */
}

/*
 * check_port_pool() returns TRUE if the port/Annex pair belongs to
 * "pool_name" as defined in the file acp_userinfo.
 * When no "pool_name" is specified all pools are checked.
 * returns DIAL_SUCC if pool entry was found.
 */
int
check_port_pool(annex, port,ptype, pool_name)
UINT32		annex;
int		port,ptype;
char		*pool_name;
{
    int 	error;  /* returns the results of the search */

    if(debug)
    {
        if(pool_name != 0)
	    printf("annex=0x%x, port=%d, pool_name=%s.\n",annex, port, pool_name);
	else
	    printf("annex=0x%x, port=%d, pool_name=0.\n",annex, port);
    }

    /* check pool/ports database for this annex and port */
    error = get_pool_entry_by_addr(pool_name, annex, port,ptype);

if(debug)
    printf("check_port_pool: error=%d\n",error);
    /* return the results found */
    return(error);
}


/*
 * access_code_validate() scans the userinfo database for
 * "Name" and then "Access_code". Once match is found, it fills in
 * the user profile arguments: the telephone number, the port mask,
 * the inbound and the outbound modem pool names.
 * returns TRUE if username/accesscode was found, FALSE otherwise.
 * IN    Name
 * IN    Access_code  provided by the user (in check_dialback()).
 * OUT   Job          clicommand specified with accesscode info
 *                           block in userinfo.
 * OUT   In_pool      port&annex pool for inbound requests.
 * OUT   Out_pool     port&annex pool for outbout requests.
 * OUT   Phone        phone numbers found from the userinfo entry.
 * Return:
 *    TRUE/FALSE - depending on the results of the search.
 */
int
access_code_validate(Name, Access_code, Phone, Job,In_pool, Out_pool, ipx_phone, envinfo)
char	           *Name;
char	           *Access_code;
char	           *Phone;
char	           *Job;
char	           *In_pool;
char	           *Out_pool;
char	           *ipx_phone;
struct env_gr_info *envinfo;              /*
					   * user's environemnt and group file info
					   * required since now we support profile
					   * criteria in acp_userinfo file
					   */
{
int	error;
Access	ac_info;
int	len, index, phone_index;
char	*phone_str = "";
struct  _phone *_phone_ptr = (struct _phone *)NULL;

    *Phone = '\0';

    if (debug)
    {
	printf("access_code_validate: name=%s acc=%s\n",
	       Name, Access_code);
	if (ipx_phone)
	{
	    printf(" ipx_phone = %s", ipx_phone);
	}
	printf("\n");
    }

    /*
     * search the database for username (Name)
     * and Access_code,if match found keep the
     * info. in ac_info struct. The new arg. "envinfo"
     * contains the user's environment and group file
     * info which is required for profile criteria
     * matching.
     */
    error = get_user_access(Name, Access_code, &ac_info, envinfo);

    /*
     * If debug mode is on and search is successful , print
     * found info on the debug output .
     */
    if (debug)
    {
       	printf("get_user_access ret %d\n",error);
	/* found match , print info */
	if (error == DIAL_SUCC)
	{
	    int i = 1;
	    printf("... code:\t%s.\n",ac_info.ac_code);
	    printf("... phone #'s:");
	    for (_phone_ptr = ac_info.ac_phone_list;
		 _phone_ptr; _phone_ptr = _phone_ptr->next,i++)
	    {
	        if (((i % 3) == 1) && (i != 1))
		    printf("\n\t");
		printf("\t\"%s\"  ", _phone_ptr->ac_phone);
	    }
	    printf("\n");
	    printf("... inpool:\t%s.\n",ac_info.ac_inpool);
	    printf("... outpool:\t%s.\n",ac_info.ac_outpool);
	    printf("... job:\t%s.\n",ac_info.ac_job.j_string);
	}
    }

    /* no match found, return false. */
    if (error != DIAL_SUCC)
        return (FALSE);

    /* for ipx request. */
    if (ipx_phone)
    {

        /*
	 * This is for IPX.
	 */
        int i;
	len = strlen(ipx_phone);
	if (index = ((len <= 2) ? 1 : 0))
	    phone_index = atoi(ipx_phone);

	if (debug)
	    printf("ipx_phone = %s    index = %d\n",
		              ipx_phone, index);
	/*save the phone values that match in phone_str */
	for (i = 0, _phone_ptr = ac_info.ac_phone_list;
		(!*phone_str) && _phone_ptr;
		_phone_ptr = _phone_ptr->next)
	{

	    if (index)
	    {
	        if (++i == phone_index)
		{
		    phone_str = _phone_ptr->ac_phone;
		}
		continue;
	    }

	    if (!(strcmp(_phone_ptr->ac_phone,
			IPX_CHARGE_BACK_TOK)))
	    {
	        phone_str = ipx_phone;
		continue;
	    }
	    else if (!strncmp(ipx_phone, _phone_ptr->ac_phone,
			strlen(_phone_ptr->ac_phone)))
	    {
	        phone_str = _phone_ptr->ac_phone;
	    }
	}
    }
    else
    {

	/*
	 * This is for CLI.
	 */

        if (ac_info.ac_phone_list)
	    phone_str = ac_info.ac_phone_list->ac_phone;
    }

    /*
     * IPX accesscode entries must have a phone number.
     */
    if (ipx_phone && !*phone_str)
    {
        return (FALSE);
    }

    if (debug)
	printf("access_code_validate: obtained phone=%s\n",
		phone_str);

    /* save the info. found from the userinfo entry */
    (void)strcpy(Phone, phone_str);
    (void)strcpy(Job, ac_info.ac_job.j_string);
    (void)strcpy(In_pool, ac_info.ac_inpool);
    (void)strcpy(Out_pool,ac_info.ac_outpool);

    return(TRUE);
}

/*
 * check_dialback() is called by port_to_annex() on the host to
 * determine if this is a valid dialback request, in which case
 * the user is prompted for the access code and (if all goes
 * well) the dialback request is started.
 *
 * This is what we are trying to do:
 *
 *
 *	go through the username and password authentication
 *	if (this Annex port number not included in any pool)
 *		{
 *		this is a direct connect
 *		}
 *	else
 *		{
 *		prompt for Access_Code
 *		if (bad access code)
 *			goto reject_request
 *		else if (port not member if inbound pool)
 *			goto reject_request
 *		else if (outbound pool name not specified)
 *			this is a direct connect
 *		else if (telephone number not specified)
 *			prompt user for telephone number
 *		if (telephone number not given)
 *			goto reject_request
 *		else
 *			dial back
 *		}
 *
 */
void
check_dialback(Acp, logid, inet, port,ptype, service,Name)

ACP		*Acp;		    /* Handle to pass to library functions */
UINT32		logid,				    /* Log sequence number */
		inet;			         /* Annex Internet address */
int		port,ptype,	           /* physical/virtual port number */
		service;		       	     /* Expect SERVICE_CLI */
char		*Name;
{
#ifndef _WIN32
    ACP_LSTRING Access_code,Phone;
#else   /* defined _WIN32 */
	ACP_STRING Access_code,Phone;
#endif   /* defined _WIN32 */

    char	Job[LEN_JOB], Port_mask[LEN_PORT_MASK];
    char	In_pool[ACP_LONGSTRING], Out_pool[ACP_LONGSTRING];
    char	Message[TOKEN_SIZE];
    int	retries, passed;
    int	got_str;
    UINT32	target_inet, ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
    UINT32	mask	= CLI_MASK,
		rcode	= REQ_DENIED;

    int dialb_port=port;
    int dialb_ptype = ptype;
    PoolEntry       pool_info;
    int	error;
    Uprof	up;
    struct         environment_spec *env_p;
    struct         env_gr_info  envinfo;
    Message[0] = 0; /* empty string */

    /* Initialize the various uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    /* creating the user environment. */
    if((env_p = create_env()) == NULL)
    {
        /* failed to create environment for the user; deny access */
        port_to_annex_authorize(Acp, REQ_DENIED, 0xffffffff, Name,0);
	syslog(LOG_ERR, "Failed to allocate memory");
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	if (debug)
	{
	    printf("check_dialback log: %s.\n",Message);
	    fflush(stdout);
	}
	return;
    }/* failed to create env */

    env_p->annex    = inet;         /* ip addr. of annex requesting authentication*/
    env_p->port     = port;         /* port no. where request is generated from   */
    env_p->ptype = ptype;
    env_p->protocol = service;                               /* cli, slip, ppp ?? */
    env_p->regime = (struct security_regime *)NULL; /* what regime used for authe.*/
    env_p->group_list = (struct group_entry *)NULL; /* groups that user belogns to*/

    /* Get the timestamp for this action */
    if (get_time_stamp(&(env_p->time)) == FALSE)
    {
        /* Log this event */
        syslog(LOG_ERR,"Failed to retrieve system time");
    }

    /* save username in the environment. */
    strncpy(env_p->username, Name, LEN_USERNAME -1);
    env_p->username[LEN_USERNAME -1]='\0';

    /*
     * userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and
     * event logged.
     */

    if(deny_all_users)
    {
        syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
all users. Check acp_userinfo file!\n");
	(void)outputstring(Acp, ACP_PERMDENIED);
	port_to_annex_authorize(Acp, REQ_DENIED, 0xffffffff, Name, 0);
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port, ptype,service, EVENT_REJECT, Message);
	return;
    }

    /* user's environment and group file info is saved. */
    envinfo.gr_info = &fileinfo;
    envinfo.env     = &env_p;

    /*
     * get access code from the user. Once the access code
     * is received , call access_code_validate() which
     * searches for that access code definition in the user's
     * userinfo entry. If the access code is matched,
     * "Phone", "Job", " In_pool " and " Out_pool " information
     * is saved. This is repeated until a workible "Access_code"
     * is provided by the user and found in userinfo database
     * or "retries < 3"
     */
    for (retries = 0; retries < RETRIES_MAX; retries++)
    {
        passed = FALSE;
	got_str = promptstring(Acp, Access_code, ACP_ACCESSCODEPROMPT, 0,
			       INPUT_TIMEOUT);
	if (got_str < 0)
	    continue;
	if (!got_str)
	{
	    passed = FALSE;
	    break;
	}
	else
	{
	    passed = access_code_validate(Name, Access_code, Phone,
					Job, In_pool, Out_pool, 0, &envinfo);
	}

	if (passed)
	    break;
    }

    /*
     * If no access code is provided or no match is found
     * in the userinfo database, deny this user.
     */
    if  ( ! passed )
    {
        (void)outputstring(Acp, ACP_PERMDENIED);
	port_to_annex_authorize(Acp, REQ_DENIED, 0xffffffff, Name, 0);
	(void) strcat ( Message, (char *)Name ) ;
	(void) strcat ( Message, ",bad access code" );
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	if (debug)
	{
	    printf("check_dialback log: %s.\n",Message);
	    fflush(stdout);
	}
    }
    else	/*match found, proceed. */
    {
        /* check if port belongs to inbound pool */
        if (check_port_pool(inet, port,ptype, In_pool) != DIAL_SUCC)
	{
	    /* request came from non authorized port: reject it */
	    (void)outputstring(Acp, ACP_PERMDENIED);
	    port_to_annex_authorize(Acp, REQ_DENIED, 0xffffffff, Name, 0);
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",bad inbound port");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	    if (debug)
	    {
	        printf("check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	    goto finished;
	}
	else if (strlen(Out_pool) == 0)
	{
	    /* outbound poolname undefined: this is a direct connect */
	    (void)outputstring(Acp, ACP_PERMGRANTD);

	    /*
	     * This call looks up userinfo database and chooses
	     * the first entry that it finds and returns a pointer to the
	     * entry. If the search fails, ie nothing for this user is found,
	     * pointer points to an emtpy Uprof struct.
	     */
	    error = get_user_profile_entry(&up, Name, &env_p, &fileinfo);

	    /* If user has a deny entry in userinfo entry, deny access. */
	    if(up.up_deny)
	    {
	        /* set the appropriate error code for logging */
	        ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
		(void)outputstring(Acp, ACP_PERMDENIED);

		/* send the authorize packet packet and log */
		port_to_annex_authorize(Acp, ret_err_code, 0xffffffff, Name, 0);
		if(ISUDP(Acp->state))
		    log_message(inet, logid, port,ptype, service, ret_err_code, Message);
		release_env(env_p);
    		release_uprof(&up);
		return;
	    }

	    /* save climasks specified in userinfo entry, */
	    if (error == ACPU_ESUCCESS && up.up_climask != 0)
	        mask = up.up_climask;

	    if (service == SERVICE_CLI_HOOK && up.up_cmd_list)
	    {
	        Acp->auth.hmask = (CHOOK_PROMPTING | CHOOK_BADCMND |
                               CHOOK_GOODCMND);
            Acp->auth.cmd_list = up.up_cmd_list;
		rcode = REQ_GRANT_HOOK;
	    }
	    else
	        rcode = REQ_GRANTED;

#ifdef DIALUP_SLIP
	    set_dialup_slip(Acp, inet, port,ptype, Name);
#endif
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Name);
	    if (debug)
	    {
	        printf("check_dialback log: %s.\n",Name);
		fflush(stdout);
	    }

	    error = port_to_annex_authorize(Acp,rcode,mask,Name,Acp->auth.hmask);
	    if (debug)
	        fprintf(stderr,"acp_policy.c: called port_to_annex_authorize;\
returned value error = %d\n",error);

	    goto finished;
	}
	/* port not a member of outbound pool */
	else if (get_port_pool(Out_pool, &pool_info) != ACPU_ESUCCESS)
	{
	    /* Unable to read pool information: probably an invalid */
	    /* pool name, or data base problem: reject request      */
	    (void)outputstring(Acp, ACP_PERMDENIED);
	    port_to_annex_authorize(Acp, REQ_DENIED, 0xffffffff, Name,0);
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",bad outbound poolname");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	    if (debug)
	    {
	        printf("check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	    goto finished;
	}
	/* telephone number not specified */
	else if (strlen(Phone) == 0)
	{
	    /* prompt user for telephone number */
	    got_str = promptstring(Acp, Phone, ACP_PHONEPROMPT, 1,
				   INPUT_TIMEOUT);
	    if (debug)
	    {
	        printf("check_dialback: got_str=%d, phone=%s.\n",
		       got_str,Phone);
		fflush(stdout);
	    }
	}
	/* telephone number not provided. */
	if (strlen(Phone) == 0)
	{
	    /* error: don't have the phone number */
	    (void)outputstring(Acp, ACP_PERMDENIED);
	    port_to_annex_authorize(Acp, REQ_DENIED, 0xffffffff, Name,0);
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",no phone number");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	    if (debug)
	    {
	        printf("check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	}
	else
	{
	    /* everything looks good */
	    (void)outputstring(Acp, ACP_DIALBACKGRANTD);

	    bzero((char*)&up, sizeof(Uprof));

	    /*
	     * This call looks up userinfo database and chooses
	     * the first entry that it finds and returns a pointer to the
	     * entry. If the search fails, ie nothing for this user is found,
	     * pointer points to an emtpy Uprof struct.
	     */
	    error = get_user_profile_entry(&up, Name, &env_p, &fileinfo);

	    /* If user has a deny entry in userinfo entry, deny access. */
	    if(up.up_deny)
	    {
	        /* set the appropriate error code for logging. */
	        ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
		/* print perm. denied message for the user. */
		(void)outputstring(Acp, ACP_PERMDENIED);
		/* set the authorize packet. and log */
		port_to_annex_authorize(Acp, ret_err_code, 0xffffffff, Name,0);
		if(ISUDP(Acp->state))
		    log_message(inet, logid, port,ptype, service, ret_err_code, Message);
		release_env(env_p);
    		release_uprof(&up);
		return;
	    }

	    /* send "granted" packet to annex with appropriate climasks */
	    if ((error != ACPU_ESUCCESS) || (up.up_climask == 0))
	        port_to_annex_authorize(Acp, REQ_DIALB_GRANT, CLI_MASK,Name,0);
	    else
	        port_to_annex_authorize(Acp, REQ_DIALB_GRANT,
						up.up_climask,Name,0);

	    if (debug)
	    {
	        printf("check_dialback: calling acp_request_dialout\n");
		fflush(stdout);
	    }

	    /* log this dialbakc request . */
	    Message[0] = 0;
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",dialback request");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Message);
	    if (debug)
	    {
	        printf("check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }

	    errno = -1;

	    /*
	     * give the requesting annex time to disconnect
	     * and release the port. This is necessary in case
	     * both the dial in and the dial out go through
	     * the same annex port: if we don't sleep the
	     * dialout process will find the port is busy
	     * disconnecting. Wait a few seconds.
	     */
	    (void)sleep(DIALBACK_DELAY * ONE_SECOND);

          /* try the pools for dialback. */
	    do
	    {
	        int errno2;

		/* get Annex addr.and port set from pool member */
		(void) bcopy(pool_info.pe_ports[dialb_ptype],Port_mask,
			     LEN_PORT_MASK);
		target_inet = pool_info.pe_hostaddr;

		/* send request to appropriate annex */
		errno = acp_request_dialout_tcp(target_inet, Name, Access_code,
					    Phone, Job, Port_mask, 
					    &dialb_port,&dialb_ptype,
					    service, 0);

		if(debug)
		{
		    printf("acp_request_dialout_tcp returned errno=%d\n",
			   errno);
		    fflush(stdout);
		}

                /* If we were unable to connect via TCP, then the annex
                   may  be old (R10.0) and only do erpcd over UDP, so
                   fallback and try UDP */

                if (errno == DIAL_REJ) {
                  errno = acp_request_dialout_udp(target_inet, Name,
                                                  Access_code, Phone, Job,
                                                  Port_mask, &dialb_port,
                                                  &dialb_ptype, service,
                                                  0);
                  if(debug) {
                    printf("acp_request_dialout_udp returned errno=%d\n",
                           errno);
                    fflush(stdout);
                  }
                }

		if (errno == DIAL_SUCC)
		    break;

		/* dialback request failed: try next pool member */
		errno2 = get_next_pool_entry(&pool_info);
		if (errno2 == ACPU_ESUCCESS)
		    errno = errno2;
		if (debug)
		{
		    printf("get_next_pool_entry ret %d\n",errno2);
		    fflush(stdout);
		}
	    } while (errno == ACPU_ESUCCESS);

	    /* log dialback success */
	    if(ISUDP(Acp->state))
	        dialback_log(inet, port,ptype, Name, Phone, target_inet, logid,
			     dialb_port,dialb_ptype, service, Message);

	    if (debug)
	    {
	        printf("check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	}
    } /* else,for if(!passed) */
finished:
    /* release the environment */
    release_env(env_p);
    release_uprof(&up);
    return;
}

/*
 * ipx_check_dialback() is called by ipx_validate() on the host to
 * determine if this is a valid dialback request, in which case
 * the user is prompted for the access code and (if all goes
 * well) the dialback request is started.
 *
 * This is what we are trying to do:
 *
 *
 *	go through the username and password authentication
 *	if (this Annex port number not included in any pool)
 *		{
 *		this is a direct connect
 *		}
 *	else
 *		{
 *		prompt for Access_Code
 *		if (bad access code)
 *			goto reject_request
 *              else if (charge back with out a phone number)
 *                     goto reject_request
 *		else if (port not member if inbound pool)
 *			goto reject_request
 *		else if (outbound pool name not specified)
 *			this is a direct connect
 *		else if (telephone number not specified)
 *			prompt user for telephone number
 *		if (telephone number not given)
 *			goto reject_request
 *		else
 *			dial back
 *		}
 *
 */
void
ipx_check_dialback(Acp, logid, inet, port,ptype, service, Name, Netnum, ipx_phone)

ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid,				/* Log sequence number */
		inet;			     /* Annex Internet address */
int		port,ptype,	       /* physical/virtual port number */
		service;			 /* Expect SERVICE_CLI */
ACP_USTRING	Name;
int		Netnum;			      /* IPX Network Number    */
char		*ipx_phone;		   /* Phone number to match on */
{
    char	Access_code[ACP_MAXSTRING], Phone[LEN_PHONE];
    char	Job[LEN_JOB], Port_mask[LEN_PORT_MASK];
    char	In_pool[ACP_LONGSTRING], Out_pool[ACP_LONGSTRING];
    char	Message[TOKEN_SIZE];
    int	passed;
    int	got_str;
    UINT32 target_inet, ret_err_code = REJECT_CODE(CODE_UNKNOWN, REJ_ERPCDDENY);
    int dialb_port=port;
    int dialb_ptype = ptype;
    PoolEntry	pool_info;
    int             error;                 /* returned values from userinfo search */
    Uprof           up;		           /* storage for userinfo entries. */
    struct         environment_spec *env_p;      /* storage for user's environment */
    struct         env_gr_info  envinfo;/* user's environment and group filenames. */
    Message[0] = 0; /* empty string */

    /* Initialize the various uprof structs */
    (void) bzero((char*)&up, sizeof(Uprof));

    /*
     * userinfo database doesn't exist due to a corrupt acp_userinfo file,
     * this is a security breach and all users must be denied access and event
     * logged.
     */
    if(deny_all_users)
    {
        syslog(LOG_ERR, "userinfo database is corrupted, denying access to\
all users. Check acp_userinfo file!\n");
	return_serial_validate(Acp, REQ_DENIED);
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	return;
    }

    /*
     * Create user's environment, get a userinfo entry based on the
     * access code, check the dial-back pool and commence dial-back.
     * If any one of them fail, reject the request.
     */
    if((env_p = create_env())==NULL)
    {
        /* deny request. */
        return_serial_validate(Acp, REQ_DENIED);
	syslog(LOG_ERR,"Failed to allocate memory");
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	return;
    }

    env_p->annex    = inet;         /* ip addr. of annex requesting authentication*/
    env_p->port     = port;         /* port no. where request is generated from   */
    env_p->ptype = ptype;
    env_p->protocol = service;                               /* cli, slip, ppp ?? */
    env_p->regime = (struct security_regime *)NULL; /* what regime used for authe.*/
    env_p->group_list = (struct group_entry *)NULL; /* groups that user belogns to*/

    /* Get the timestamp for this action */
    if (get_time_stamp(&(env_p->time)) == FALSE)
    {
        /* Log this event */
        syslog(LOG_ERR,"Failed to retrieve system time");
    }
    strcpy(env_p->username, (char *)Name);

    /* use a keyword for the accesscode search in userinfo database */
    strcpy(Access_code, IPX_ACCESS_CODE_TOK);
    bzero(Phone, LEN_PHONE);

    /* save the user's environment and group file info */
    envinfo.gr_info = &fileinfo;
    envinfo.env     = &env_p;

    /*
     * Look in the userinfo database and find an entry with username
     * "Name" and provided accesscode "Access_code". If such an
     * entry is found, get the other info. phonenumbers, job,
     * and pools (in/out)
     */
    passed = access_code_validate(Name, Access_code, Phone,
				  Job, In_pool, Out_pool, ipx_phone, &envinfo);

    /* If failed to find an entry, log and deny service */
    if  ( ! passed )
    {
        /* send a permission denied packet */
        return_serial_validate(Acp, REQ_DENIED);
	(void) strcat ( Message, (char *)Name ) ;
	(void) strcat ( Message, ",bad access code" );
	/* log this event */
	if(ISUDP(Acp->state))
	    log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	if (debug)
	{
	    printf("ipx_check_dialback log: %s.\n",Message);
	    fflush(stdout);
	}
    } /* if (!passed) */
    else
    {
        /* check if we were trying to do chargeback without a phone no. */
        if (!strcmp(Phone,"unknown"))
	{
	    (void)return_serial_validate(Acp, REQ_GRANTED);
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Name);
	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Name);
		fflush(stdout);
	    }
	    goto finished;
	}/* if (!strcmp(Phone,"unknown")) */

	/* check if port belongs to inbound pool */
	if (check_port_pool(inet, port,ptype, In_pool) != DIAL_SUCC)
	{
	    /* request came from non authorized port: reject it */
	    return_serial_validate(Acp, REQ_DENIED);
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",bad inbound port");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	    goto finished;
	} /* if (check_port_pool(inet, port,ptype, In_pool) != DIAL_SUCC) */
	else if (strlen(Out_pool) == 0)
	{
	    /*
	     * This call looks up userinfo database and chooses
	     * the first entry that it finds and returns a pointer to the
	     * entry. If the search fails, ie nothing for this user is found,
	     * pointer points to an emtpy Uprof struct.
	     */
	    error = get_user_profile_entry(&up, Name, &env_p, &fileinfo);

	    /* deny found in userinfo entry */
	    if(up.up_deny)
	    {
	        /* set appropriate error message and reject request. */
	        ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
		return_serial_validate(Acp, ret_err_code);
		/* log the reject */
		if(ISUDP(Acp->state))
		    log_message(inet, logid, port,ptype, service, ret_err_code, Message);
		release_env(env_p);
    		release_uprof(&up);
		return;
	    }

	    /* send the validation with appropriate climasks */
	    if ((error != ACPU_ESUCCESS) || (up.up_climask == 0)) 
	        (void)return_serial_validate(Acp, REQ_GRANTED);
	    /* TODO: this else is missing cli_masks */
	    else
	        (void)return_serial_validate(Acp, REQ_GRANTED);

	    /* log the log-in */
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Name);
	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Name);
		fflush(stdout);
	    }
	    goto finished;
	}/* else if (strlen(Out_pool) == 0) */
	else if (get_port_pool(Out_pool, &pool_info) != ACPU_ESUCCESS)
	{
	    /* Unable to read pool information: probably an invalid */
	    /* pool name, or data base problem: reject request      */
	    return_serial_validate(Acp, REQ_DENIED);
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",bad outbound poolname");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	    goto finished;
	}/* else if (get_port_pool(Out_pool, &pool_info) != ACPU_ESUCCESS) */
	else if (strlen(Phone) == 0)
	{
	    /* prompt user for telephone number */
	    got_str = promptstring(Acp, Phone, ACP_PHONEPROMPT, 1,
				   INPUT_TIMEOUT);
	    if (debug)
	    {
	        printf("ipx_check_dialback: got_str=%d, phone=%s.\n",
		       got_str,Phone);
		fflush(stdout);
	    }
	}/* else if (strlen(Phone) == 0) */
	if (strlen(Phone) == 0)
	{
	    /* error: don't have the phone number */
	    return_serial_validate(Acp, REQ_DENIED);
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",no phone number");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_REJECT, Message);
	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	}/* if (strlen(Phone) == 0) */
	else
	{
	    /*
	     * This call looks up userinfo database and chooses
	     * the first entry that it finds and returns a pointer to the
	     * entry. If the search fails, ie nothing for this user is found,
	     * pointer points to an emtpy Uprof struct.
	     */
	    errno = get_user_profile_entry(&up, Name, &env_p, &fileinfo);	
	    /* deny found in userinfo entry */
	    if(up.up_deny)
	    {
	        /* set appropriate error code */
	        ret_err_code = REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER);
		/* deny user and log */
		return_serial_validate(Acp, REQ_DENIED);
		if(ISUDP(Acp->state))
		    log_message(inet, logid, port,ptype, service, ret_err_code, Message);
		release_env(env_p);
    		release_uprof(&up);
		return;
	    }

	    /* grant dialback */
	    (void)return_serial_validate(Acp, REQ_DIALB_GRANT);

	    if (debug)
	    {
	        printf("ipx_check_dialback: calling acp_request_dialout\n");
		fflush(stdout);
	    }

	    Message[0] = 0;
	    (void) strcat ( Message, (char *)Name ) ;
	    (void) strcat ( Message, ",dialback request");
	    if(ISUDP(Acp->state))
	        log_message(inet, logid, port,ptype, service, EVENT_LOGIN, Message);
	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	    errno = -1;

	    /*
	     * give the requesting annex time to disconnect
	     * and release the port. This is necessary in case
	     * both the dial in and the dial out go through
	     * the same annex port: if we don't sleep the
	     * dialout process will find the port is busy
	     * disconnecting. Wait a few seconds.
	     */
	    (void)sleep(6 * ONE_SECOND);

	    do /* try the pools for dialback. */
	    {
	        int errno2;

		/* get Annex addr.and port set from pool member */
		(void) bcopy(pool_info.pe_ports[dialb_ptype], Port_mask,
			     LEN_PORT_MASK);
		target_inet = pool_info.pe_hostaddr;

		/* send request to appropriate annex */

		errno = acp_request_dialout_tcp(target_inet, Name, Access_code,
						Phone, Job, Port_mask, 
						&dialb_port,&dialb_ptype,
						service, Netnum);

		if(debug)
		{
		  printf("acp_request_dialout_tcp returned errno=%d\n",errno);
		  fflush(stdout);
		}
		/* If we were unable to connect via TCP, then the annex
		   may  be old (R10.0) and only do erpcd over UDP, so
		   fallback and try UDP */
		if (errno == DIAL_REJ) {
		  errno = acp_request_dialout_udp(target_inet, Name,
						  Access_code,
						  Phone, Job, Port_mask,
						  &dialb_port,
						  &dialb_ptype, service,
						  Netnum);
		  if(debug)
			  {
			  printf("acp_request_dialout_udp returned errno=%d\n",
                                 errno);
                          fflush(stdout);
                        }
		}

		if (errno == DIAL_SUCC)
		    break;

		/* dialback request failed: try next pool member */
		errno2 = get_next_pool_entry(&pool_info);
		if (errno2 == ACPU_ESUCCESS)
		    errno = errno2;
		if (debug)
		{
		    printf("get_next_pool_entry ret %d\n",errno2);
		    fflush(stdout);
		}
	    } while (errno == ACPU_ESUCCESS);

	    if (ISUDP(Acp->state))
	        dialback_log(inet, port,ptype, Name, Phone, target_inet,
			     logid, dialb_port,dialb_ptype, service, Message);

	    if (debug)
	    {
	        printf("ipx_check_dialback log: %s.\n",Message);
		fflush(stdout);
	    }
	}/*else, for  if (strlen(Phone) == 0) */
    }/*else ,for if(!passed ) */
finished:
    /* free the alloc'ed memory */
    release_env(env_p);
    release_uprof(&up);
    return;
}


void
dialback_log(inet, port,ptype, Name, Phone, target_inet, logid,
		dialb_port,dialb_ptype, service, Message)
UINT32 inet;
char	*Name, *Phone;
UINT32 target_inet;
UINT32 logid;
int dialb_port,service;
char    *Message;
int port,ptype,dialb_ptype;
{
    /* do message logging */
    Message[0] = 0;
    switch(errno)
    {
	case DIAL_SUCC:
            (void) sprintf(Message,"%s, tel:%s", Name, Phone);
	    log_message(target_inet, logid, dialb_port,dialb_ptype,
			service, EVENT_DIAL, Message);
	break;

	case DIAL_EBUSY:
	    (void) sprintf(Message,"%s, ports busy", Name);
	    log_message(inet, logid, port,ptype, service, EVENT_DIAL, Message);
	break;

	case DIAL_ETIMEDOUT:
	    (void) sprintf(Message,"%s, timed out", Name);
	    log_message(inet, logid, dialb_port,dialb_ptype,
			service, EVENT_DIAL, Message);
	break;

	case DIAL_TIME:
	    (void) sprintf(Message,"%s, srpc timed out", Name);
	    log_message(inet, logid, port,ptype,
			service, EVENT_DIAL, Message);
	break;

        case DIAL_EINVAL:
	    (void) sprintf(Message,"%s, unknown modem", Name);
	    log_message(inet, logid, dialb_port,dialb_ptype,
			service, EVENT_DIAL, Message);
	break;

	case DIAL_EIO:
	    (void) sprintf(Message,"%s, I/O error", Name);
	    log_message(inet, logid, dialb_port,dialb_ptype, service,
			EVENT_DIAL, Message);
	break;

	default:
	    (void) sprintf(Message,"%s, failed", Name);
	    log_message(inet, logid, port,ptype, service, EVENT_DIAL, Message);
        break;
    }
  return;
}

#ifdef USE_NDBM
/* Waits to use the database and then breaks the lock on it after a period of
   5 seconds*/

int erpcd_lock_acp_dbm()
{
    struct stat *stats;
    char str[ACP_LONGSTRING];
    int i, rv=0;
    u_short set_lock_flag = FALSE;

    if((stats = (struct stat *)malloc(sizeof(struct stat))) == NULL)
    {
        errno = ENOMEM;
	process_error(NULL, -1);
	return -1;
    }

    /* check the permissions& modes for acp_dbm.db and acp_dbm.pag. */
    ACP_DBM_DIR(str);
    if (stat(str, stats) == -1)
    {
        if (errno != ENOENT)
	{
	    syslog(LOG_CRIT, "Error reading from acp_dbm\n");
	    free(stats);
	    return -1;
	}
    }
    else if(stats->st_mode != ROOT_RDWR)
    {
        sprintf(syslogbuf, "Wrong permissions on file: %s\n", str);
	syslog(LOG_CRIT, syslogbuf);
	free(stats);
        erpcd_dbmErrorTrap (ERPCD_TRAP_PROTECT);
	return -1;
    }

    ACP_DBM_PAGE(str);
    if (stat(str, stats) == -1)
    {
        if (errno != ENOENT)
	{
	    syslog(LOG_CRIT, "Error reading from acp_dbm\n");
	    free(stats);
	    return -1;
	}
    }
    else if(stats->st_mode != ROOT_RDWR)
    {
        sprintf(syslogbuf, "Wrong permissions on file: %s\n", str);
	syslog(LOG_CRIT, syslogbuf);
	free(stats);
        erpcd_dbmErrorTrap (ERPCD_TRAP_PROTECT);
	return -1;
    }
    free(stats);

    /* acp_dbm exists, try locking */
    for( i=0; i<5; i++)
    {
        rv = dbm_lock_acp_dbm();
	if(rv == -2)
	{
	    rv = -1;
	    syslog(LOG_CRIT, "Error in locking acp_dbm\n");
	    break;
	}
	if(rv == -1)
	    sleep(1);
	else
	{
	    set_lock_flag = TRUE;
	    break;
	}
    }

    if((set_lock_flag==FALSE) && (dbm_lock_acp_dbm() == -1))
    {
        dbm_unlock_acp_dbm();
	rv = dbm_lock_acp_dbm();
	if(rv == -2)
	{
	    rv=-1;
	    syslog(LOG_CRIT, "Error in locking acp_dbm\n");
	}
    }
    return rv;
}

/* Matches users entered password with the previous history of passwords*/

int matches_old_password(user, new)
     char *user;
     char *new;
{

    int erpcd_lock_acp_dbm();

    DBM *dbm;
    int rv, i;
    char *pw, old_password[MAX_STORED_PASS][HASHLEN + 1], str[ACP_LONGSTRING];


    if(erpcd_lock_acp_dbm()==-1)
        return -1;

    sprintf(str, "%s/", install_dir);
    strcat(str, ACP_DBM_FILE);
    dbm = dbm_open(str, (O_CREAT | O_RDWR), 0600);

    if(dbm != NULL)
    {
        bzero(old_password, MAX_STORED_PASS * (HASHLEN + 1));
	rv=dbm_get_old_pwds(dbm, user, old_password);
	unlock_database(dbm);
	if(rv == 0)
	{
	    for(i=0; i<STORED_PASS && old_password[i][0] != '\0'; i++)
	    {
	        pw = crypt(new, old_password[i]);
		if((strncmp(pw, old_password[i], 13))==0)
		    return TRUE;
	    }
	}
	else
	{
	    if(errno != ENOENT)
	    {
	        process_error(user, rv);
		unlock_database(dbm);
		return -1;
	    }
	}
    }
    return FALSE;
}

/* Closes the database and then breaks the lock*/
static
void unlock_database(dbm)
     DBM *dbm;
{

    dbm_close(dbm);
    dbm_unlock_acp_dbm();
}


/* Handles the various errors that occur with the database*/
static
void process_error(user, rv)
     char *user;
     int rv;
{

  if((rv == -1) && errno == EIO)
  {
	  sprintf(syslogbuf, "erpcd:Error reading from %s\n", ACP_DBM_FILE);
	  syslog(LOG_CRIT, syslogbuf);
  }

  if((rv == -1) && errno == ENOENT)
  {
	  sprintf(syslogbuf, "No such user name found in the acp_dbm database: \"%s\"\n", user);
	  syslog(LOG_CRIT, syslogbuf);
  }

  if((rv == -1) && errno == ENOMEM)
	  syslog(LOG_CRIT, "Could not allocate dynamic memory from the heap\n");

  if(rv == -2)
  {
	  sprintf(syslogbuf, "erpcd:Error writing to %s\n", ACP_DBM_FILE);
	  syslog(LOG_CRIT, syslogbuf);
  }

  if (rv == -1)
     erpcd_dbmErrorTrap (ERPCD_TRAP_READ);
  else if (rv == -2)
     erpcd_dbmErrorTrap (ERPCD_TRAP_WRITE);
  else
     erpcd_dbmErrorTrap (ERPCD_TRAP_PROTECT);

}
#endif /* USE_NDBM */

/*
 * Fxn. generic_authenticate_user() authenticates the user based on the
 * regime (specified in acp_regime file) and the code_path that this
 * request has come from. Different code_paths (could) warrant a different
 * response from the user (for the same regime) and  could use different
 * authentication routines.
 * Returns:
 *     passed - VALIDATED/NOT_VALIDATED. depending on the outcome
 *                 of the authentications.
 */

static int
generic_authenticate_user(Acp, logid, Name, Pass, prompt, max_retries,
                          Message, opt_info)
ACP		*Acp;		/* Handle to pass to library functions */
UINT32		logid;				/* Log sequence number */
char *Name;
char *Pass;
int prompt; /* TRUE prompt user for info */
int max_retries; /* retries if prompt */
char *Message;
ARQ_PROFILE *opt_info;
{
    char	   *userprompt = ACP_USERPROMPT ;
#ifndef _WIN32
    struct         security_regime  *regime;
#endif
    int tries, done =FALSE, regimes_passed = 0, regimes_tried =0;
    int got_str =1, passed = NOT_VALIDATED;
    int regime_used=0;
    struct environment_spec *env_p = Acp->env;
    CHAP_REQ *chap = Acp->chap;
    SECPORT secport;

    secport.unit = env_p->port;
    secport.type = env_p->ptype;

#define MULTIPLE_REGIMES
#undef MULTIPLE_REGIMES

    Message[0] = '\0';

    /* Get the timestamp for this action */
    if (get_time_stamp(&(env_p->time)) == FALSE)
    {
        /* Log this event */
        syslog(LOG_ERR, "Failed to retrieve the system time");
    }

    /*  prompt for Name and Password until valid or too many tries  */

    /*
     * Get the user's name. Call get_security_regime() which
     * reads acp_regime file and gets regime and password info.
     * for user's authentication.
     */
    for (tries = 0; tries < max_retries && done == FALSE; tries++) {
        regimes_passed = 0;
        regimes_tried = 0;

        /* Prompt for the users name */
        if(prompt)
            got_str = promptstring(Acp, Name, userprompt, 1, INPUT_TIMEOUT);

        /* if username provided. */
        if (got_str > 0) {
            /* save the username */
            strncpy(env_p->username, Name, LEN_USERNAME -1);
            env_p->username[LEN_USERNAME -1] = '\0';
            env_p->regime = (struct security_regime *)NULL;

#if (USER_VALIDATION == 1)
            /*
	     * for ipx_validate and ppp_security, fall through.
	     * If (USER_VALIDATE !=1), just fall through. We only
	     * need the user's environment which can be used
	     * by the calling fxn. to get the cli commands (if
	     * specified) for this user.
	     */
            if ((Pass[0] == '\0') && !prompt)
                passed = VALIDATED;

#ifdef _WIN32
            else if ( chap && !ErpcdOpt->RadiusAuthentication )
			{
                /* this section does chap via acp_userinfo */
                /* radius is done in acp_radius_validate() */

                int valid = 0;
                ACP_STRING secret;

                Acp->auth.ret_err_code = get_chap_secret(env_p, secret);

                switch(Acp->auth.ret_err_code) {
                case EVENT_PROVIDE:
                    valid = verify_chap(chap, secret);
                    valid = record_login(valid, &Acp->auth.blacklisted, Name);
                    if (valid)
                        passed = VALIDATED;
                    else
                        passed = NOT_VALIDATED;
                    break;

                case EVENT_NOPROVIDE:
                default:
                    passed = NOT_VALIDATED;
                    break;
                }
            }
            else {
                /* (note: got_str is >0 here) */
                if(prompt && !ErpcdOpt->SecuridAuthentication
				&& !ErpcdOpt->SafewordAuthentication)
                    got_str = promptstring(Acp, Pass, ACP_PASSPROMPT, 0,
                                           INPUT_TIMEOUT);
                if (got_str > 0) {
		    if (debug)
			{
                        printf("Using RadiusAuthentication: %s\n",
				ErpcdOpt->RadiusAuthentication
				? "TRUE" : "FALSE");
			if(ErpcdOpt->SecuridAuthentication)
			    printf("Using SecurID Authentication\n");
			if(ErpcdOpt->SafewordAuthentication)
			    {
#ifndef BAY_ALPHA
			    SwecVersionRec swecVersionInfo;
			    swecVersion(&swecVersionInfo);
			    printf("Using SafeWord Authentication: %s\n",
				swecVersionInfo.description ?
				swecVersionInfo.description : "<null>");
#endif
			    }
                        }
                    if ( ErpcdOpt->RadiusAuthentication )
		    {
                passed = acp_radius_validate(Acp, prompt, Name, Pass, &secport, opt_info);
		    }
                    else if ( ErpcdOpt->SecuridAuthentication )
		    {
			if (prompt == FALSE) {
                            passed = acp_securid_authenticate(Acp, logid, Acp->inet,
                                                         secport.unit,
                                                         secport.type,
                                                         Acp->env->protocol,
                                                         Name, tries, Pass);
			}
			else {
                            passed = acp_securid_authenticate(Acp, logid, Acp->inet,
                                                         secport.unit,
                                                         secport.type,
                                                         Acp->env->protocol,
                                                         Name, tries, NULL);
			}

		    }
		    else if ( ErpcdOpt->SafewordAuthentication )
		    {
#ifdef ENIGMA_SAFEWORD
                        passed = acp_safeword_validate(Acp, logid, Acp->inet,
                                                       secport.unit,
						       secport.type,
						       Acp->env->protocol,
                                                       &got_str, Name);
                        if (passed == VALIDATED)
                            outputstring(Acp, EAS_PERMGRANTD);
                        else
                            outputstring(Acp, EAS_INCORRECT);

                        if (got_str <= 0 || passed <= 0)
                            passed = NOT_VALIDATED;
                        else
                            passed = VALIDATED;
#else /* not ENIGMA_SAFEWORD */
                        passed = NOT_VALIDATED;
#endif /* not ENIGMA_SAFEWORD */
		    }
                    else
		    {
                    	passed = NTValidate(Name, Pass);
		    }
                    done = passed;
                    if(!passed) {
                        if (strlen(Message)) {
                            strcat(Message, ",");
                        }
                        strcat(Message, Name);

                        if(prompt && tries < (max_retries -1))
                            outputstring(Acp, ACP_INCORRECT);
                        else if (prompt)
                            outputstring(Acp, ACP_PERMDENIED);
                    }

                }
                else if (!got_str && prompt){
                    Acp->auth.ret_err_code = EVENT_TIMEOUT;
                    outputstring(Acp, ACP_TIMEDOUT);
		    }

            }
#else /* not _WIN32 */

            /*
             * get the user's regime && password/ticket-dir
             * for authentication
             */
            else if (get_security_regime(env_p)) {

	        /* use the acquired regime. */
                regime = env_p->regime;

                if (debug)
                    fprintf(stderr,
                            "acp_policy.c: the regime_mask is %d \n",
                            regime->regime_mask);
                /*
                 * use the regime specified in the user's
                 * environment.
                 */
                if (chap && regime->regime_mask != RADIUS_MASK) {
                    /* this section does chap via acp_userinfo */
                    /* radius is done in acp_radius_validate() */

                    int valid = 0;
                    ACP_STRING secret;

                    Acp->auth.ret_err_code = get_chap_secret(env_p, secret);

                    switch(Acp->auth.ret_err_code) {
                    case EVENT_PROVIDE:
                        valid = verify_chap(chap, secret);
                        valid = record_login(valid, &Acp->auth.blacklisted,
                                             Name);
                        if (valid)
                            passed = VALIDATED;
                        else
                            passed = NOT_VALIDATED;
                        break;

                    case EVENT_NOPROVIDE:
                    default:
                        passed = NOT_VALIDATED;
                        break;
                    }
                }
                else {

                    switch(regime->regime_mask) {
                    case KERBEROS_MASK:
                    case NATIVE_MASK:
                    case ACP_MASK:
                    case RADIUS_MASK:
                        passed = NOT_VALIDATED;
                        if (prompt) {

                            if ((got_str = promptstring(Acp, Pass,
                                                        ACP_PASSPROMPT, 0,
                                                        INPUT_TIMEOUT)) <= 0)
                                if(!got_str && prompt){
                                    Acp->auth.ret_err_code = EVENT_TIMEOUT;
                                    outputstring(Acp, ACP_TIMEDOUT);
                                }
                        }

                        switch(regime->regime_mask) {
                        case KERBEROS_MASK:
                            passed = acp_kerberos_validate(Name, Pass);
                            break;

                        case NATIVE_MASK:
                            passed = acp_native_validate(Name, Pass);
                            break;

                        case ACP_MASK:
                            passed =
                                acp_validate(Name,Pass,&Acp->auth.blacklisted,
                                     regime->regime_supplement.password_file);
                            break;
                        case RADIUS_MASK:
                            passed = acp_radius_validate(Acp, prompt, Name,
                                                         Pass, &secport, opt_info);
                            break;
                        } /* switch */

                        if (prompt) {
                            if (passed > 0){
#ifdef USESHADOW
                                warn_user(Acp, &passed, Name);
#endif
			    }
                            else if (tries < (max_retries - 1))
                                outputstring(Acp, ACP_INCORRECT);
                            else
                                outputstring(Acp, ACP_PERMDENIED);
                        }
                        if (passed > 0)
                           passed = VALIDATED;
                        break;

                        /* for securid */
                    case SECURID_MASK:

                        if (prompt == FALSE) {
                            passed =
                                acp_securid_authenticate(Acp, logid, Acp->inet,
                                                         secport.unit,
                                                         secport.type,
                                                         Acp->env->protocol,
                                                         Name, tries, Pass);
                        }
                        else {
                            passed =
                                acp_securid_authenticate(Acp, logid, Acp->inet,
                                                         secport.unit,
                                                         secport.type,
                                                         Acp->env->protocol,
                                                         Name, tries, NULL);
#ifdef PASS_SEC
                            if (passed > 0){
                            	if ((got_str = promptstring(Acp, Pass,
                                                        ACP_PASSPROMPT, 0,
                                                        INPUT_TIMEOUT)) <= 0)
                                	if(!got_str){
                                    		Acp->auth.ret_err_code = EVENT_TIMEOUT;
                                    		outputstring(Acp, ACP_TIMEDOUT);
						passed = NOT_VALIDATED;
						done = TRUE;
						break;
                                }
#ifdef NATIVEPASSWD

                                passed = acp_native_validate(Name, Pass);
#else
                                passed =
                                acp_validate(Name,Pass,&Acp->auth.blacklisted,
                                     NULL);
#endif
                                if (passed > 0){
#ifdef USESHADOW
                                    warn_user(Acp, &passed, Name);
#endif
                                }
                            }
#endif
                        }
                        if(passed == USER_ABORT)
                            done=TRUE;
                        break; /* SECURID_MASK */

                        /* for enigma-safeword */
                    case SAFEWORD_MASK:

#ifdef ENIGMA_SAFEWORD
                        passed = acp_safeword_validate(Acp, logid, Acp->inet,
                                                       secport.unit,
                                                       secport.type,
                                                       Acp->env->protocol,
                                                       &got_str, Name);
                        if (passed == VALIDATED)
                            outputstring(Acp, EAS_PERMGRANTD);
                        else
                            outputstring(Acp, EAS_INCORRECT);

                        if (got_str <= 0 || passed <= 0)
                            passed = NOT_VALIDATED;
                        else
                            passed = VALIDATED;

#else
                        passed = NOT_VALIDATED;
#endif
                        break; /* SAFEWORD_MASK */

                        /* for deny, undocumented regime */
                    case DENY_MASK:

                        passed = NOT_VALIDATED;
                        break;

		    case NONE_MASK:
			passed = VALIDATED;
			done = TRUE;
			break;

		    case NO_REGIME_MASK:
		    default:
			passed = NOT_VALIDATED;
			break;
                    }/* End regime switch */
                } /* if chap... */

                if (passed != VALIDATED) {

                    /* Log the failed user */
                    regime_used = map_mask_to_code(regime->regime_mask);
                    if(passed == UNAVAILABLE)
                        Acp->auth.ret_err_code = REJECT_CODE(regime_used,
                                                             REJ_REGNOTAVAIL);
                    else
                        Acp->auth.ret_err_code = REJECT_CODE(regime_used,
                                                             REJ_REGDENY);

                    if (strlen(Message))
                        strcat(Message, ",");
                    strcat(Message, Name);
                } /* else ,for, if(passed == VALIDATED) */

                /* Now have we passed all the specified regimes */
                if (passed == VALIDATED) {
                    done = TRUE;
                }
            } /* else if (get_security_regime(env_p)) */

            /*
             * No security regime found. denying
             * acces.
             */
            else {

                /* Log this event */
                Acp->auth.ret_err_code = REJECT_CODE(CODE_UNKNOWN,
                                                     REJ_ERPCDDENY);

                if (strlen(Message))
                    strcat(Message, ",");
                strcat(Message, Name);

                /* adding fake prompting here */
                if(prompt)
                    got_str = promptstring(Acp, Pass, ACP_PASSPROMPT, 0,
                                           INPUT_TIMEOUT);

                /*
		 * put the thread to sleep for 2 seconds
		 * to avoid a rapid-fire condition.
		 */
                sleep(2);
            }/* If there is a regime */
#endif /* not _WIN32 [from before if (get_security_regime...)] */

#else /* (USER_VALIDATION) */
    /*
     * just fall through, we got what we need
     * - user's environment.
     */
    done = TRUE;
    passed = VALIDATED;

#endif /* (USER_VALIDATION) */
        }/* if got_str gets a username */
        else
        {
            done = TRUE;
	    if(!got_str && prompt){
	      Acp->auth.ret_err_code = EVENT_TIMEOUT;
	      outputstring(Acp, ACP_TIMEDOUT);
	    }

        }
    }/* End retries - for loop for regimes. */

#ifndef _WIN32
#ifdef PORT_PASSWORD
    if ((secport.type == DEV_SERIAL || secport.type == DEV_V120) &&
	(passed > NOT_VALIDATED) && prompt)
        passed = acp_port_password_authenticate(Acp, logid, Acp->inet,
                                                secport.unit, secport.type,
                                                Acp->env->protocol,
                                                max_retries);
#endif
#endif

    return passed;

}

/*
 * Map regime masks to regime codes.
 * Returns:
 *     regime code.
 */
static int map_mask_to_code(regime_mask)
	int regime_mask;
{

    switch(regime_mask)
    {

        case ACP_MASK:
            regime_mask = CODE_ACP ;
	break;

        case SAFEWORD_MASK:
	    regime_mask = CODE_SAFEWORD;
	break;

	case KERBEROS_MASK:
	    regime_mask = CODE_KERBEROS;
	break;

	case NATIVE_MASK:
	    regime_mask = CODE_NATIVE;
	break;

        case SECURID_MASK:
	    regime_mask =  CODE_SECURID;
        break;

        case DENY_MASK:
	    regime_mask =  CODE_DENY;
	break;

	case NONE_MASK:
	    regime_mask =  CODE_NONE;
	break;

        default:
	    regime_mask =  CODE_UNKNOWN;
        break;
    }
    return(regime_mask);
}

/*****************************************************************************
 *
 * NAME: UINT32 get_chap_secret()
 *
 * DESCRIPTION: Retrieves the chap secret from the userinfo database
 *
 * ARGUMENTS:
 * struct environment_spec *env - INPUT Security Profile for this request
 * char *secret - OUTPUT Retrieved chap secret
 *
 * RETURN VALUE:
 * EVENT_PROVIDE - an entry was found
 * REJ_NOUSERINFO - user was not found
 * REJ_NOPWDINFO - chap secret not found
 * other - error code indicating why entry was not retrieved
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

UINT32 get_chap_secret(env, secret)
struct environment_spec *env;
char *secret;
{

    Uprof           up;
    int             error;
    UINT32          status;
    
    (void) bzero((char*)&up, sizeof(Uprof));
    error = get_user_profile_entry(&up, env->username, &env, &fileinfo);
    
    /* If user has a deny entry in userinfo entry, deny access. */
    if(up.up_deny)
        status = (REJECT_CODE(CODE_UNKNOWN,REJ_DENYUSER));
    else if (up.up_de.de_key[0] == 0)
	status = (REJECT_CODE(CODE_UNKNOWN,REJ_NOUSERINFO));
    else
        bcopy(up.up_secret,secret,sizeof(up.up_secret));

    if (strlen(secret))
        status = (EVENT_PROVIDE);
    else
        status = (REJECT_CODE(CODE_UNKNOWN,REJ_NOPWDINFO));

    release_uprof(&up);
    return (status);
}

/*****************************************************************************
 *
 * NAME: UINT32 verify_chap()
 *
 * DESCRIPTION: Verifies the chap response from the remote peer
 *
 * ARGUMENTS:
 * CHAP_REQ *chap - INPUT chap info
 * char *secret - INPUT chap secret
 *
 * RETURN VALUE: TRUE - response is good
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

int verify_chap(chap, secret)
CHAP_REQ *chap;
char *secret;
{
    u_char cat[MAX_MD5];
    u_char result[CHAP_RESP_LEN];
    int valid;

    bzero((char*)cat, MAX_MD5);
    cat[0] = chap->id;
    strcpy((char *)cat+1, secret);
    bcopy((char*)chap->challenge, (char*)&cat[1 + strlen(secret)],
          CHAP_CHAL_LEN);
    cat[1 + strlen(secret) + CHAP_CHAL_LEN] = '\0';
    MDString(cat, (1 + strlen(secret) + CHAP_CHAL_LEN), result);
    valid = (memcmp(chap->response, result, CHAP_RESP_LEN) == 0);
    return(valid);
}


/*****************************************************************************
 *
 * NAME: void chap_authenticate()
 *
 * DESCRIPTION: Authenticates a chap session (TCP only)
 *
 * ARGUMENTS:
 * ACP *acp - INPUT acp for this connection
 * SECPORT *port - INPUT port over which the ppp connection is authenticated
 * char *user - INPUT username being authenticated
 *
 * RETURN VALUE: None
 *   Calls acp_auth_resp() to send back authentication status to RA
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

void chap_authenticate(acp, port, user, opt_info)
ACP *acp;
SECPORT *port;
char *user;
ARQ_PROFILE *opt_info;
{
    int valid = 0;
    struct environment_spec env;
    char String[TOKEN_SIZE];      /* Any token of size 256 or less */
    ACP_STRING pwd;

    acp->auth.blacklisted = FALSE;
    acp->auth.ret_err_code = EVENT_PROVIDE;

    if(deny_all_users) {
        syslog(LOG_ERR, "chap_authenticate: userinfo database is corrupted, denying access to all users. Check acp_userinfo file!\n");
        acp_auth_resp(acp, REQ_DENIED, NULL, NULL, NULL);
        terminate_session();
        return;
    }

    acp->env = &env;
    bzero((char*)acp->env, sizeof(struct environment_spec));
    strncpy(env.username, user, MAX_OPTION - 1);
    user[MAX_OPTION - 1] = '\0';
    env.annex = acp->inet;
    env.port = port->unit;
    env.ptype = port->type;
    env.protocol = SERVICE_PPP;
    acp->auth.blacklisted = FALSE;

    strcpy(pwd, "kludge");
    valid = generic_authenticate_user(acp, 0, user, pwd, FALSE, 1, String, opt_info);

    switch(acp->auth.ret_err_code) {
    case EVENT_PROVIDE:

        if (valid)
            acp_auth_resp(acp, REQ_GRANTED, NULL, NULL, NULL);
        else
            acp_auth_resp(acp, REQ_DENIED, NULL, NULL, NULL);
        if (acp->auth.blacklisted)
            write_audit_log(acp->inet, 0, port, SERVICE_PPP, EVENT_BLACKLIST,
                            0, NULL, NULL, user, NULL);
        break;

    case EVENT_NOPROVIDE:
    default:
        acp_auth_resp(acp, acp->auth.ret_err_code, NULL, NULL, NULL);
        break;
    }

    terminate_session();
}

/*****************************************************************************
 *
 * NAME: int record_login()
 *
 * DESCRIPTION: Records a login attempt for blacklisting
 *
 * ARGUMENTS:
 * int success - INPUT TRUE if login attempt was successful
 * int *blacklist - OUTPUT points to a TRUE value if the user is blacklisted
 * char *user - INPUT username used for login attempt
 *
 * RETURN VALUE: TRUE if the user should be accepted, FALSE denied
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

int record_login(success, blacklist, user)
int success;
int *blacklist;
char *user;
{
#ifdef USE_NDBM
    int rv = 0;
    DBM *dbm;
    char str[PATHSZ];      /* for pathnames/filenames. */

    rv = erpcd_lock_acp_dbm();
    if(rv == 0){
        sprintf(str, "%s/", install_dir);
        strcat(str, ACP_DBM_FILE);
        dbm = dbm_open(str, (O_CREAT | O_RDWR), 0600);
        if(dbm != NULL){
            if(success){
                rv = dbm_verify_login_success(dbm, user);
                if((rv != TRUE && errno != ENOENT) || rv == FALSE)
                    success = FALSE;
                if(rv < 0 && errno != ENOENT)
                      print_error(user, rv);
            }
            else{
                if( maxcon != -1 || maxtotal != -1){
                    rv = dbm_record_login_failure(dbm, user, maxcon, maxtotal, period);
                }
                if(rv < 0 )
                  print_error(user, rv);
                else if (blacklist != NULL && rv == 1)
                    *blacklist = TRUE;
            }
            unlock_database(dbm);
        }
        else{
            syslog(LOG_CRIT, "%m");
            success = FALSE;
            dbm_unlock_acp_dbm();
        }
    }
    else {
        success = FALSE;
        dbm_unlock_acp_dbm();
    }
#endif
    return(success);
}
