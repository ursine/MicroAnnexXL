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

#ifndef ACP_POLICY_H
#define ACP_POLICY_H

#include "../inc/port/port.h"
#include "../libannex/srpc.h"
#include "../inc/erpc/acp_const.h"
#include <time.h>
#include <stdio.h>

/* to define a cross platform (compatible) definition of PATHSZ */
#ifndef _WIN32
#if defined (LINUX)
#include <linux/limits.h>
#elif defined (IUNIX)
#include <sys/limits.h>
#else
#include <sys/param.h>
#endif /* LINUX, etc */
#endif	/* not defined _WIN32 */
/* select user name/password validation	*/
#define	USER_VALIDATION	1

/* Defines used by all ACP validation routIne */
#define NOT_VALIDATED        0
#define VALIDATED            1
#define VALIDATION_TIMED_OUT 2

#define NO_REGIME_MASK                  0
#define ACP_MASK                        0x01
#define SAFEWORD_MASK                   0x02
#define KERBEROS_MASK                   0x04
#define NATIVE_MASK                     0x08
#define SECURID_MASK                    0x10
#define DENY_MASK                       0x20
#define NONE_MASK                       0x40
#define RADIUS_MASK			0x80

#ifndef ESUCCESS
#define ESUCCESS 0
#endif

/*
 * Uncomment this line to compile a "fast-retry" version of the security
 * code.  This option requires that all served Annexes are running R6.2
 * or later of the operational image.  Otherwise, duplicate prompts may
 * result.
 */
#define FASTRETRY 1

/*
 * Uncomment this line to compile in the shadow password file option.
 * (This enables password aging and protection of encrypted passwords.)
 *
 * This feature, when enabled, will use either the Annex acp_shadow
 * file that resides in the annex install directory or the standard system
 * shadow file usually found in the /etc directory.
 * See shadow/passwd file selection below.
 *
 * If you wish to later disable the feature, comment the line and recompile.
 * It is not recommended that you change the value.
 */

/* #define USESHADOW 1 */
#define ACP_AVAILABLE	   ACP_MASK 

/* The following variable is used to turn on the -p switch for acp_dbm.  
 * This switch allows the system administrator to look at the encrypted 
 * passwords of all users upto the maximum stored.
*/
/*#define DEBUG_P 1*/ 

#define USE_NDBM 1

/* These should not be here.  Remove me! */
#ifdef UNIXWARE
#undef USE_NDBM
#endif
#ifdef _WIN32
#undef USE_NDBM
#endif
#ifdef LINUX
#undef USE_NDBM
#endif

/* The following variable is used to define the number of passwords that 
 * need to be stored for checking with the old passwords.  This will force
 * the user to choose a password that is not in the currently stored limit
 */
#ifdef USESHADOW
#define STORED_PASS 6
#else
#define STORED_PASS 0
#endif

/* The following variable defines the ultimate maximum for the number of old
 * user passwords stored for prevention of re-use.  If you change this variable,
 * you will cause compatability problems with the old acp_dbm.pag/acp_dbm.dir 
 * files.  To avoid this problem, delete acp_dbm.pag and acp_dbm.dir every time
 * you change this variable and recompile erpcd, ch_passwd or acp_dbm.
 */
#ifndef  MAX_STORED_PASS
#define MAX_STORED_PASS 12
#endif

/* The following variable defines the ultimate maximum for the number of login
 * failures (on a per-user basis) that are stored.  If you change this variable,
 * you will cause compatability problems with the old acp_dbm.pag/acp_dbm.dir 
 * files.  To avoid this problem, delete acp_dbm.pag and acp_dbm.dir every time
 * you change this variable and recompile erpcd, ch_passwd or acp_dbm.
 */

#ifndef MAX_FAILURES
#define MAX_FAILURES 20
#endif

/* The following variable defines the default number of allowed consecutive
 * login failures before blacklisting a user.  If not defined, the default is
 * to never blacklist based on consecutive login failures.  This value may be 
 * over-ridden in erpcd with the -b command-line option
 */
/* #ifndef MAX_BL_CON   */
/* #define MAX_BL_CON 5 */
/* #endif               */

/* The following variable defines the default number of allowed nonconsecutive
 * login failures before blacklisting a user.  If not defined, the default is
 * to never blacklist based on nonconsecutive login failures.  This value may 
 * be over-ridden in erpcd with the -x command-line option
 */
/* #ifndef MAX_BL_NONCON    */
/* #define MAX_BL_NONCON 10 */
/* #endif                   */

/* The following variable defines the default time period (in weeks) over which
 * to apply MAX_BL_NONCON (above).  That is, login failures that occurred more
 * than MAX_BL_NONCON weeks ago are not counted.
 */
#ifndef MAX_BL_PERIOD
#define MAX_BL_PERIOD 26
#endif

/* ACP Enhancement functions */
extern int erpcd_lock_acp_dbm();
extern int matches_old_password();

extern UINT32 get_chap_secret();
int verify_chap();
void chap_authenticate();
int record_login();
KEYDATA *annex_key();

extern int maxcon, maxtotal;
extern time_t period;

/*
 * Uncomment these lines to compile with the normal /etc/passwd
 * searching routines, rather than the default acp_passwd routines.
 * (This will link acp into NIS (erstwhile YP) on those systems that
 * support it.)
 *
 * If you wish to later disable the feature, comment the lines and recompile.
 * It is not recommended that you change the value.
 *
 * PASSWD/SHADOW MATRIX:
 *
 * ann = The Annex install directory
 * 0 = leaving the macro undefined
 *
 * USESHADOW         NATIVESHADOW            DIR/FILES
 *       NATIVEPASSWD                        
 * 0         0            0  No Shadow       ann/acp_passwd
 * 0         0            1  Bad Config
 * 0         1            0  No shadow       etc/passwd      
 * 0         1            1  Bad Config
 * 1         0            0  Shadow Enabled  ann/acp_passwd ann/acp_shadow
 * 1         0            1  Shadow enabled  ann/acp_passwd etc/shadow
 * 1         1            0  Shadow enabled  etc/passwd ann/acp_shadow
 * 1         1            1  Shadow enabled  etc/passwd etc/shadow
 * 
 */
/* #define NATIVEPASSWD 1 */
/* #define NATIVESHADOW 1 */

#ifdef NATIVEPASSWD

/* Use Unix shadow passwd processing */
/* #define USENATIVESHADOW 1 */ 

#define NATIVE_AVAILABLE   NATIVE_MASK


#else

#define NATIVE_AVAILABLE   NO_REGIME_MASK

#endif


#ifdef KERBEROS

#define KERBEROS_AVAILABLE KERBEROS_MASK

#else

#define KERBEROS_AVAILABLE NO_REGIME_MASK

#endif


/*
 * Uncomment this line to substitute seconds-since-1970 (raw time
 * format) in place of year/month/day/hour/minute/second in the log
 * file.  This form is more amenable to automatic parsing.
 */
/* #define USE_SECONDS 1 */

/*
 * Uncomment this line to select the use of the standard syslog(3)
 * facility in addition to or in place of the logfile -- the value of
 * "USE_SYSLOG" is used to identify the daemon.  (Comment the second
 * line out to disable the normal acp log file.)
 *
 * NOTE: The following two lines will affect acp logging only. Normal
 * syslogging will remain unaffected.
 */
/* #define USE_SYSLOG "annex" */ 
#define USE_LOGFILE 1

/*
 * Uncomment this line to select the F_LOCK method to lock the acp_logfile
 * for updating.
 *
 * A file must be locked for update in order to block other processes from
 * writing to it simultaneously.
 *
 * F_LOCK - Passing the F_LOCK as the cmd value when making system lockf call
 * is the most efficient and preferred maner to lock a file for exclusive write  * access. In this scenario a process is put to sleep until the resource is
 * available. Once available the process is preempted owning the resource.
 * available. Once available the process is preempted owning the resource.
 *
 * T_LOCK - When the T_LOCK cmd argument is passed, the process must
 * repeatedly send the lockf call the until the resource is available.
 * Once available the system call returns a success and the resource is
 * acquired.
 *
 * The F_LOCK cmd has been determined to be faulty on many hosts. Failures
 * can not be narrowed down to any particular hardware manufacturer or UNIX
 * system. There are to many OS revs and varables to sense the correct lockf
 * method to use at installation time. The default, T_LOCK was chosen simply
 * because it has been proven reliable. SEE 'log_message()'
 */
/* #define USE_F_LOCK 1 */

/*
 * Uncomment this line to use decoded Annex peer names, rather than
 * numeric IP addresses, in the log file and in syslogging.
 */
/* #define USE_ANAME 1 */

#ifdef SECURID_CARD

/*
 * This macro can be changed to select the ports on which the SecurID
 * system is used.  For example, using this definition will enable
 * SecurID on ports 2 and 3, and other ACP security on the other ports:
 *	#define USE_SECURID_CHECK (port == 2 || port == 3)
 * As defined below (just a '1'), all ports get SecurID security.
 */
#define USE_SECURID_CHECK 1
#define SECURID_AVAILABLE  SECURID_MASK

#else

#define SECURID_AVAILABLE  NO_REGIME_MASK

#endif /* !SECURID_CARD */

#ifdef ENIGMA_SAFEWORD

/*
 * This macro can be changed to select the ports on which the Safeword
 * system is used.  For example, using this definition will enable
 * Safeword on ports 2 and 3, and other ACP security on the other ports:
 *	#define USE_SAFEWORD_CHECK (port == 2 || port == 3)
 * As defined below (just a '1'), all ports get Safeword security.
 */
#define USE_SAFEWORD_CHECK 1
#define SAFEWORD_AVAILABLE   SAFEWORD_MASK
#define ESC 0x1b
#define RETRIES_MAX_SAFEWORD 3

#else

#define SAFEWORD_AVAILABLE   NO_REGIME_MASK

#endif /* ENIGMA_SAFEEWORD */



/* enable "Port Password:" feature */
#define	PORT_PASSWORD 1

/*
 * PATHSZ is defined as MAXPATHLEN (of size 1024).
 * Most platforms support this definition for use
 * with filename etc. Alternate but same size 
 * definitions are used for systems that don't 
 * define MAXPATHLEN. LINUX and IUNIX define a 
 * different macro of same length called PATH_MAX.
 * SCO defines PATHSIZE of same length.
 */

/* what goes for sco, goes for sco5 */
#if defined (SCO5)
#define SCO
#endif

#if defined (LINUX) || defined (IUNIX)
#define	PATHSZ	PATH_MAX		/* Max size of path name == 1024*/
#elif defined (SCO)
#define	PATHSZ	PATHSIZE                /* 1024 */
#elif defined (_WIN32)
#define PATHSZ 256                      /* Old value, only for NT hosts. */
#else  
#define PATHSZ MAXPATHLEN               /* 1024 */
#endif /* LINUX ,etc. */

/*	Define pathnames password and shadow files	*/
/* These are in erpcd.c */
#ifdef _WIN32
	extern char *root_dir,*install_dir;
#else
	extern char root_dir[],install_dir[]; 
#endif /*  _WIN32 */

/* Define for NATIVE password authentication            */
#define ACP_NATIVEPASSWD(str)	strcpy(str,"/etc/passwd")
#define ACP_NATIVEPTMP(str)	strcpy(str,"/etc/passwd.tmp")
#define ACP_NATIVESHADOW(str)	strcpy(str,"/etc/shadow")
#define ACP_NATIVESTMP(str)	strcpy(str,"/etc/shadow.tmp")
#define ACP_NATIVELOCKFILE(str) strcpy(str,"/etc/.pwd.lock")


/* Define for ACP password authentication               */
#define ACP_PASSWD(str)	sprintf(str,"%s/acp_passwd",install_dir)
#define ACP_PTMP(str)	sprintf(str,"%s/acp_ptmp",install_dir)
#define ACP_SHADOW(str)	sprintf(str,"%s/acp_shadow",install_dir)
#define ACP_STMP(str)	sprintf(str,"%s/acp_stmp",install_dir)
#define ACP_LOCKFILE(str) sprintf(str,"%s/.pwd.lock",install_dir)



/*	define pathname of accounting file		*/
#define ACP_LOGFILE(str) \
	sprintf(str,"%s/acp_logfile",install_dir)

/*	define pathname for restrictions file		*/
#define ACP_RESTRICT(str) \
	sprintf(str,"%s/acp_restrict",install_dir)

/*	define pathanme for annex acp_keys file 	*/
#define	ACP_KEYS(str) \
	sprintf(str,"%s/acp_keys",install_dir)

/*	define pathanme for annex dialup addresses file */
#define ACP_DIALUP(str) \
	sprintf(str,"%s/acp_dialup",install_dir)

/*	define pathname for user profile file 		*/
#define ACP_USERINFO(str) \
	sprintf(str,"%s/acp_userinfo",install_dir)

#define ACP_ESERVICES(str) \
	sprintf(str,"%s/eservices",install_dir)

/*      define pathname for Enigma Net API config file  */
#define NETAPI_CONFIGFILE(str) \
        sprintf(str,"%s/safeword.cfg",install_dir)
#define ACP_REGIME(str) \
        sprintf(str,"%s/acp_regime",install_dir) 

#define ACP_GROUP(str) \
	sprintf(str,"%s/acp_group",install_dir)

/*	define pathname for erpcd.conf file (to hold trap info) */        
#define ACP_CONFIG(str) \
	sprintf(str,"%s/erpcd.conf",install_dir)
        
#define DEFAULT_GROUP "/etc/group"

#define ACP_MATCH_FOUND "You cannot use a recently used password--try again.\n"

#define ACP_PASS_UNCHANGED "Password not changed.\n"

 /*      define pathname for acp_dbm.dir file            */
#if (defined (BSDI) || defined (FREEBSD) || defined (LINUX)) 
#define ACP_DBM_DIR(str) \
        sprintf(str,"%s/acp_dbm.db",install_dir)
#else
#define ACP_DBM_DIR(str) \
        sprintf(str, "%s/acp_dbm.dir", install_dir)             
#endif

/*      define pathname for acp_dbm.pag file            */
#if (defined (BSDI) || defined (FREEBSD) || defined (LINUX))
#define ACP_DBM_PAGE(str) \
        sprintf(str,"%s/acp_dbm.db",install_dir)
#else
#define ACP_DBM_PAGE(str) \
        sprintf(str,"%s/acp_dbm.pag",install_dir)
#endif

/*      define pathname for acp_dbm.lck file            */
#define ACP_DBM_LOCK(str) \
        sprintf(str,"%s/acp_dbm.lck",install_dir)

/*	define sizes of internal encryption tables	*/

#define MAX_WILD	32
#define	MAX_TAME	96
#define MAX_KEYS	128

/*	define messages used by default application	*/

#define ACP_USERPROMPT	"Annex username: "
#define ACP_PASSPROMPT	"Annex password: "
#define ACP_PERMGRANTD	"\nPermission granted\n"
#define ACP_PERMDENIED	"\007\nPermission denied\n"
#define ACP_ADMINDENIED	"\007\nPermission denied by administrator\n"
#define ACP_INCORRECT	"\nUsername/Password Incorrect\n"
#define BOTH_INCORRECT	"\nUsername/Password/PASSCODE Incorrect\n"
#define BOTH_PERMGRANTD "\nPassword and PASSCODE accepted\n"
#define SID_USERPROMPT	"Username: "
#define SID_PASSPROMPT	"Enter PASSCODE: "
#define SID_PERMGRANTD	"\nPASSCODE accepted\n"
#define SID_PERMDENIED	"\007\nAccess Denied\n"
#define SID_INCORRECT	"\nUsername/PASSCODE Incorrect\n"
#define SID_LOGNEWPIN_1 "\nWait for the code on your card to change,\n"
#define SID_LOGNEWPIN_2 "then enter PASSCODE including the new PIN.\n"
#define EAS_USERPROMPT	"ID: "
#define EAS_CHALLENGE   "\nChallenge: %s\n"
#define EAS_DYNPASS	    "Dynamic PassWord: "
#define EAS_RESTDYNPASS "Enter Rest of Dynamic PassWord: "
#define EAS_FIXPASS	    "Fixed PassWord: "
#define EAS_OLDFIXPASS	"Old Fixed PassWord: "
#define EAS_NEWFIXPASS	"New Fixed PassWord: "
#define EAS_REPFIXPASS	"Repeat New Fixed PassWord: "
#define EAS_PERMGRANTD	"\nPermission granted\n"
#define EAS_PERMDENIED	"\007\nAccess Denied\n"
#define EAS_INCORRECT	  "\nLogin Incorrect\n"
#define EAS_CHANGEPIN   "Do you want to change your PIN? (Y/N): "
#define EAS_ENTERESC    "\n(Enter [Esc] if you wish to change your password)\n"
#define EAS_MUSTDIFF    "\nYour new password must be different from your old one\n"
#define EAS_PASSMIN     "\nFixed passwords must have %d or more characters\n"
#define EAS_VERIFYERR   "\nVerify error\n"
#define EAS_PINCHANGED  "\nPIN changed\n"
#define EAS_NOTCHANGED  "\nPIN not changed\n"
#define EAS_FIXNOCHANGE "\nGiving up trying to change fixed password\n"
#define EAS_HIDEBAD     "\nSafeWord: Your password will expire in 1 day(s)\n"

#define ACP_TIMEDOUT	"\007\nLogin Timed Out\n"
#define ACP_WARNING	"\007\nYour password will expire in %ld days unless changed.\n"
#define ACP_WARNINGM	"\007\nYour password expires after tomorrow unless changed.\n"
#define ACP_WARNINGT	"\007\nYour password expires after today unless changed.\n"
#define ACP_AWARNING	"\007\nYour account will expire in %ld days.\n"
#define ACP_AWARNINGM	"\007\nYour account expires after tomorrow.\n"
#define ACP_AWARNINGT	"\007\nYour account expires after today.\n"
#define ACP_EXPIRED	"Your password has expired.\n"
#define ACP_NEWPASS	"Enter a new password:  "
#define ACP_NEWPASS2	"Re-enter new password:  "
#define ACP_PASSMATCH	"Entered passwords do not match.  Try again.\n"
#define ACP_MATCH_FOUND "You cannot use a recently used password--try again.\n"
#define ACP_PASS_UNCHANGED "Password not changed.\n"
#define ACP_ACCESSCODEPROMPT	"Access Code: "
#define ACP_PHONEPROMPT		"Telephone Number: "
#define ACP_DIALBACKGRANTD	"\nRequest accepted, dialback in progress...\n"
#define ACP_CLINODIALBACK	"\nPermission granted, no dialback\n"
#define ERPCD_RANGE "Warning: option %s ignored because out of range (%s)\n"

/* 	define messages used by Securid Card application	*/

#define SID_NEXTCODEPROMPT      "Enter next card code: "
#define SID_PINCHAR     "characters"
#define SID_PINDIGIT    "digits"
#define SID_PINSIZE     "%d"
#define SID_PINSZRANGE  "%d to %d"
#define SID_NEWPINPROMPT        "Enter your new PIN containing %s %s,\n"
#define SID_OR          "\t\tor\n"
#define SID_NEWPIN_2    "Press <Return> to generate new PIN and display it\n"
#define SID_NEWPIN_3    "      <Ctrl d> <Return> to leave your card in New-PIN mode.\n"
#define SID_SYSGENPIN   "\t\t%s\n"
#define SID_PINREENTRY  "Please re-enter PIN: "

/* only used if PORT_PASSWORD set and a port password exists in acp_passwd */
#define ACP_PORTPROMPT	"Port password: "

/*
 *    MAXLOGACK - defines the maximum number of log messages ERPCD will get
 *    from an annex before it sends back an ACK.  Note that is does not
 *    affect the maximum time between ACKs.
 */
#define MAXLOGACK 10

/*
 *    DIALBACK DELAY - When a user requests a valid dialback connection,
 *    ACP checks authentication, then instructs the Annex to
 *    issue the dialout. This delay is the number of seconds ACP waits prior
 *    to sending the acp_request_dialout back to the Annex. The delay is
 *    required for the case where the Annex dial in and dial out ports
 *    are configured to be the same. It gives the target Annex time to
 *    disconnect from the port before starting the dialout. If enough time
 *    is not allotted, the dialout process will find that the port is busy.
 *    Set this parameter to a higher value if a dialback attempt causes a
 *    "port is busy" message in the acp_logfile.
 */
#define DIALBACK_DELAY 45

/*	miscellaneous defines for default application	*/

#define INPUT_TIMEOUT		60
#define INPUT_POLL_TIMEOUT	3
#define RETRIES_MAX		3

/* md5 */
#define MAX_MD5 (ACP_MAXSTRING + CHAP_CHAL_LEN + 2)

/*	define bit to disable each maskable CLI command	*/

#define MASK_BG		0x00000001
#define MASK_CALL	0x00000002
#define MASK_FG		0x00000004
#define MASK_HANGUP	0x00000008
#define MASK_HELP	0x00000010
#define MASK_HOSTS	0x00000020
#define MASK_JOBS	0x00000040
#define MASK_KILL	0x00000080
#define MASK_NETSTAT	0x00000100
#define MASK_RLOGIN	0x00000200
#define MASK_STATS	0x00000400
#define MASK_STTY	0x00000800
#define MASK_TELNET	0x00001000
#define MASK_WHO	0x00002000
#define MASK_LOCK	0x00004000
#define MASK_SU		0x00008000
#define MASK_SLIP	0x00010000
#define MASK_CONNECT	0x00020000
#define MASK_SERVICES	0x00040000
#define MASK_PPP	0x00080000
#define MASK_ARAP	0x00100000
#define MASK_IPX	0x00200000
#define MASK_NONE	0x80000000

/*	define cli command mask		*/

#define CLI_MASK	(UINT32)0

/* Port type defines for dialup addressing */
#define PORT_ASYNC  0
#define PORT_SYNC   1

#define ACP_LOG_MASK	0640	/*  umask when creating ACP_LOGFILE  */

#define IPX_CHARGE_BACK_TOK     "charge_back"
#define IPX_ACCESS_CODE_TOK     "ipx"

/* Just in case ... */
#ifdef NOT_ANSI_LIB
# define LOG_FORMAT_S    "%s:%8.8x:%s:%10.10d:%s:%s%s%s%s%s%s%s%s%s\n"
# define LOG_FORMAT    "%s:%8.8x:%s:%2.2d%2.2d%2.2d:%2.2d%2.2d%2.2d:%s:%s%s%s%s%s%s%s%s%s\n"
#else /* !NOT_ANSI_LIB */
# define LOG_FORMAT_S    "%s:%8.8lx:%s:%10.10ld:%s:%s%s%s%s%s%s%s%s%s\n"
# define LOG_FORMAT    "%s:%8.8lx:%s:%2.2d%2.2d%2.2d:%2.2d%2.2d%2.2d:%s:%s%s%s%s%s%s%s%s%s\n"
#endif /* NOT_ANSI_LIB */

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

/* Xylogics builtin passwd functions */
int setacppw();
void endacppw();
struct passwd *getacppw();

/* Xylogics builtin shadow passwd functions */
int setacpsp();
void endacpsp();
struct spwd *getacpsp();
int lckacpf(),ulckacpf();

#ifndef _WIN32
/* These are in getacppw.c */
extern char passwd_name[],ptmp_name[];
extern char shadow_name[],stmp_name[];
extern char lock_name[];

/* This is in acp_trap.c */
extern char config_file[];
#endif



/*
 * When DEFAULT_NO_USERINFO is set to 1, a user is allowed to dial in into
 *					 the Annex even if the user does not
 *					 have an entry in the acp_userinfo file.
 *					 An access_code does not need to be
 *					 assigned to all users. Notice that
 *					 users requesting dialback must have
 *					 a valid entry in acp_userinfo.
 *
 * When DEFAULT_NO_USERINFO is set to 0, all users are required to have an
 *					 access_code defined in acp_userinfo
 *					 for increased security. All users
 *					 will be prompted for the access code
 *					 during authentication.
 */
#define	DEFAULT_NO_USERINFO	1

int acp_safeword_validate_ipx();
int wild_match();
KEYDATA *annex_key();

#ifdef _WIN32
struct passwd {
    char *pw_name;
    char *pw_passwd;
    int pw_uid;
    int pw_gid;
    char *pw_age;
    char *pw_comment;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
};
#define ONE_SECOND 1000
#else
#define ONE_SECOND 1
#endif

#endif /* ACP_POLICY_H */
