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
 * Module Function:
 *
 *    ERPC listener process
 *
 * Original Author: Jonathan Taylor    Created on: 84/08/07
 *
 *****************************************************************************
 */


/*
 *    Include Files
 */
#include "../inc/port/install_dir.h"
#include "../inc/vers.h"

#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include "../libannex/api_if.h"
#include <sys/stat.h>
#include <fcntl.h>

#ifndef _WIN32
#include <sys/param.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sgtty.h>
#include <netdb.h>
#else
#include <time.h>
#include <process.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "../libannex/srpc.h"

#include "../inc/courier/courier.h"
#include "../inc/erpc/erpc.h"
#include "../inc/erpc/nerpcd.h"
#include "acp_policy.h"
#include "getacpuser.h"

#ifndef _WIN32
#define USE_CLIENT_REC
#include "acp.h"
#include "acp_group.h"
#include "acp_lib.h"
#include "environment.h"
#include "time_parser.h"
#endif

#include "acp_regime.h"


#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#endif /* _WIN32 */


/*
 *    External Data Declarations
 */

char group_file[PATHSZ];
char regime_file[PATHSZ];

int    deny_all_users = TRUE;	/* If TRUE, deny access to all users.
				 * when acp_userinfo is parsed successfully,
				 * this is reset to FALSE.
				 */

#ifdef DEBUG_TO_FILE
FILE *dbgout = NULL;
#endif

/*
 *    Defines and Macros
 */

#define STDIN    0
#define STDOUT    1
#define STDERR    2

#define BUFFSIZE    2048

#define ERPC_CHILD_MAX    25    /* maximum number of forked processes */
#define SESNUMANNEX_DEFAULT 250	/* number of annexes supported by radius */
#define COURRPN_ACP    3

#define LISTEN_BACKLOG 5 /* maximum for tcp listen queue */

#define DEF_LINGER_TIME 120

#ifndef _WIN32
#ifndef SIGCHLD
#ifndef SIGCLD
error: no SIGCLD/SIGCHLD !
#else
#define SIGCHLD SIGCLD
#endif
#endif
#endif

#ifndef _WIN32
struct clientrec clientrec[ERPC_CHILD_MAX];
#endif

#ifndef BFS
#define BFS "/usr/spool/erpcd/bfs"
#endif
#ifndef INSTALL_DIR
#define INSTALL_DIR "/etc"
#endif

/*      ACP Enhancements */

#ifdef MAX_BL_CON
int maxcon = MAX_BL_CON;
#else
int maxcon = -1;
#endif

#ifdef MAX_BL_NONCON
int maxtotal = MAX_BL_NONCON;
#else
int maxtotal = -1;
#endif

#ifdef MAX_BL_PERIOD
time_t period = (time_t)(7 * 60 * 60 * MAX_BL_PERIOD);
#else
time_t period = 0;
#endif

#ifndef MAX_FAILURES
#define MAX_FAILURES 20
#endif


/*
 *    Structure Definitions
 */

struct eservent {
    u_short    es_rpnum;
    u_short es_verlo, es_verhi;
    char *es_name;
  };

/*
 *    Forward Routine Declarations
 */
StructErpcdOption *ErpcdOpt;
char command_line[256];

#ifdef ORACLE
extern char ora_user[ACP_MAXLSTRING];
#endif

#ifdef _WIN32
char szDefaultDomain[20];
char InstallDirBuf[256], RootDirBuf[256];
extern StructRadiusOption *RadiusOpt;
extern int radius_server_count;

int pcount;
HANDLE hEventSIGCHLD;
HANDLE hEventSIGHUP;
HANDLE hEventSIGPWR;
HANDLE hEventContinue;
HANDLE hEventStop;
HANDLE hEventOKToExitUDP;
HANDLE hEventOKToExitTCP;
HANDLE hSemaphoreChildCount;
HANDLE hMapStructErpcdOption;
HANDLE hMapStructRadiusOption;

HANDLE hThreadSIGHUP;
HANDLE hThreadSIGPWR;
HANDLE hThreadUpdate;
HANDLE hThreadServiceStop;

DWORD dwThreadID;
BOOL Inherit;

void ServiceControlStop(void *);
void UpdateErpcdOpt(void *);
void ReadRegistryParam();
void sdump();
int  syslog( int pri, const char *format, ...);
BOOL InitAlarmThread(void);
BOOL GetPrimaryDomainName(int);
void random_seed(char *seed);
void clear_user_profile(void);
void hangup(void *), leave_erpcd(void *);

#else /* _WIN32 */

StructErpcdOption StructErpcdOptionBlock;
void reaper();
void re_acpuser();
void koolaidfest();
void  acpuser();
int suicide();
void hangup(), leave_erpcd();
#endif	/* _WIN32 */

struct eservent *geteservent(), *geteservbynum();
int erpcd_kid();
int open_user_profile_file();
int close_user_profile_file();
int initialize_user_profile_file();
int api_open();
int api_bind();
int api_connect();
int api_recv();
int api_recvmsg();
int api_sendmsg ();
int api_send();
int api_rcvud();
int api_sndud();
int api_release();
int api_close();
int api_opt();
int bfs();
int acp();
void erpc_reject();
void secure_cache();
void seteservent();
void acp_tcp();
int api_listen();
int api_accept();
void display();
void acpuser ();

UINT32 get_long();
void erpcd_init();
void endeservent();
static void udp_accept();
static void tcp_accept();

/*
 *    Global Data Declarations
 */
#define ERPCD	1	/* Needed for xyreg.c.  This files
					 * need to know if they are running as part of the
					 * erpcd daemon or standalone in install.dll.  If this
					 * constant is undefined, then it will define its own
					 * version of the next variable "debug".  If this 
					 * constant is defined it will look externally for
					 * "debug". Externally meaning in this file.
					 */
int debug = 0;        /* 1 iff called with -d; 0 otherwise */
struct in_addr myipaddr;
time_t erpcd_boottime;

/* Ensure long-word alignment for ICL SPARC machines. */
INT32 cbuff[(BUFFSIZE+sizeof(INT32)-1)/sizeof(INT32)];

Radius_server *default_servers = NULL; /* acp_regime.h */
#ifndef _WIN32
Radius_serverinfo *radius_head = NULL; /* acp_regime.h */
int raddb_numannex = SESNUMANNEX_DEFAULT;
int raddb_up = FALSE;
extern int ses_open_db();
#else	/* WIN32 */
/* ----------------------------------------------
	This variable must only be changed under
	control of UseCriticalSection()
 */
CRITICAL_SECTION	GlobalCriticalSection;
Radius_serverinfo *radius_head = NULL;
/* ---------------------------------------------- */
#endif /* WIN32 */

char eservices_name[256], userinfo_name[256];

#ifdef _WIN32
	char *install_dir = INSTALL_DIR;
	char *root_dir = BFS;
#else
	char install_dir[256];
	char root_dir[256];
#endif /*  _WIN32 */

/*
 *    Static Declarations
 */

/* current number and max number of forked processes,
   used in main() and reaper() */
int child_count = 0;			/* made global for version request */
int child_max = ERPC_CHILD_MAX;		/* ibid */
int child_rejects = 0;			/* number of rejects due to max */

static int use_udp = TRUE;
static int use_tcp = TRUE;
static struct sockaddr_in tcpaddr, udpaddr, from;
static int api_options = 0;
int tcpsock, udpsock;
static int showpid = 0;
char *myname = NULL;
int udp_child = FALSE;

static void
usage()
{
#ifdef ORACLE
    fprintf(stdout,"Usage:\
\n\terpcd [-f<filedir>] [-s<securitydir>] [-d[<portnum/name>]] [-D[#]]\
\n\t\t[-c<maxchild>] [-u [filename]] [-b<max con>] [-x<max total>] \
\n\t\t[-g<period>] [-[l,L]] [-[a,A]] [-n] [-[t,T]] [-v] [-R<max annexes>] \
\n\t\t[-O <user/password>] \
\n");


    fprintf(stdout,"Where:\
\n\t-f\tBoot file directory.\n\t-s\tSecurity directory.\
\n\t-d\tPort number or name.\n\t-D\tDebug mode with level.\
\n\t-c\tMaximum number of child processes.\
\n\t-u\tVerify user profile (acp_userinfo) syntax.\
\n\t-b\tMaximum consecutive login failures before blacklisting.\
\n\t-x\tMaximum nonconsecutive login failures before blacklisting.\
\n\t-g\tTime period for nonconsecutive login failures.\
\n\t-lL\tACP logfile information directed to syslog. \n\t\t-l turns it off, -L turns it on.\
\n\t-aA\tACP logfile, -a turns it off, -A turns it on.\
\n\t-n\tUse host name instead of IP Address in logfile.\
\n\t-O\tUsername and Password for database access.\
\n\t-tT\tACP log information stamped with date/second, \n\t\t-t use seconds, -T use standard time format.\
\n\t-v\tDisplay software version number.\
\n\t-R\tMaximum number of Annexes in RADIUS table.\n");
    ErpcdExit(1);
#endif

#ifndef _WIN32
    fprintf(stdout,"Usage:\
\n\terpcd [-f<filedir>] [-s<securitydir>] [-d[<portnum/name>]] [-D[#]]\
\n\t\t[-c<maxchild>] [-u [filename]] [-b<max con>] [-x<max total>] \
\n\t\t[-g<period>] [-[l,L]] [-[a,A]] [-n] [-[t,T]] [-v] [-R<max annexes>] \
\n");


    fprintf(stdout,"Where:\
\n\t-f\tBoot file directory.\n\t-s\tSecurity directory.\
\n\t-d\tPort number or name.\n\t-D\tDebug mode with level.\
\n\t-c\tMaximum number of child processes.\
\n\t-u\tVerify user profile (acp_userinfo) syntax.\
\n\t-b\tMaximum consecutive login failures before blacklisting.\
\n\t-x\tMaximum nonconsecutive login failures before blacklisting.\
\n\t-g\tTime period for nonconsecutive login failures.\
\n\t-lL\tACP logfile information directed to syslog. \n\t\t-l turns it off, -L turns it on.\
\n\t-aA\tACP logfile, -a turns it off, -A turns it on.\
\n\t-n\tUse host name instead of IP Address in logfile.\
\n\t-tT\tACP log information stamped with date/second, \n\t\t-t use seconds, -T use standard time format.\
\n\t-v\tDisplay software version number.\
\n\t-R\tMaximum number of Annexes in RADIUS table.\n");

#else

    fprintf(stdout,"Usage:\
\n\terpcd [-d[<portnum/name>]] [-D[#]] [-c<maxchild>] [-u [filename]] \n");

    fprintf(stdout,"Where:\
\n\t-d\tPort number or name.\
\n\t-D\tDebug mode with level.\
\n\t-c\tMaximum number of children.\
\n\t-u\tVerify user profile (acp_userinfo) syntax.\n");
#endif


    ErpcdExit(1);
}

#define DO_EXTRA_PARM(FUNC)                    \
    if (cp[1] == '\0') {                    \
        if (--argc <= 0 || (cp = *++argv) == NULL)    \
            FUNC;                    \
    } else                            \
        cp++

#define OPTIONAL_EXTRA_PARM DO_EXTRA_PARM(break)
#define EXTRA_OR_NULL DO_EXTRA_PARM(cp = NULL)
#define EXTRA_PARM DO_EXTRA_PARM(goto show_usage)



static void
handle_arguments(argc,argv)
int argc;
char **argv;
{
    char *cp;
#ifndef _WIN32	/* not used in win32 */
    char rangebuf[20];
    int buf;
#endif
	int	i;
    char *portname = "erpc";
    struct stat sbuf;
    struct servent *sp;
    unsigned mode = M_LINT;

    bzero(&tcpaddr, sizeof(struct sockaddr_in));
    bzero(&udpaddr, sizeof(struct sockaddr_in));

#ifndef _WIN32
    bzero(install_dir, sizeof(install_dir));
    bcopy (INSTALL_DIR, install_dir, strlen(INSTALL_DIR));
    bzero(root_dir, sizeof(root_dir));
    bcopy (BFS, root_dir, strlen(BFS));
#endif /*  _WIN32 */

    /* get command line */
    command_line[0]=0;
    for (i=0; i<argc; i++)
    {
#ifdef _WIN32
        if (argv[i][1]=='#')
            continue;
#endif
        if (argv[i][1]=='1')  /* use udp */
            continue;
        if (argv[i][1]=='2')  /* use tcp */
            continue;
        strcat(command_line, argv[i]);
        strcat(command_line, " ");
    }
	use_udp = TRUE;
	use_tcp = TRUE;
#ifdef _WIN32
    pcount = 0;
#else


#ifndef _WIN32

#ifdef USE_SYSLOG
    ErpcdOpt->UseSyslog = TRUE;
#else
    ErpcdOpt->UseSyslog = FALSE;
#endif /* USE_SYSLOG */

#ifdef USE_LOGFILE
    ErpcdOpt->UseLogfile = TRUE;
#else
    ErpcdOpt->UseLogfile = FALSE;
#endif /* USE_LOGFILE */

#else
    ErpcdOpt->UseSyslog = FALSE;
    ErpcdOpt->UseLogfile = TRUE;

#endif /* Win32 */

    ErpcdOpt->UseHostName = FALSE; /* default use IP address in logfile */
    ErpcdOpt->UseSeconds = FALSE; /* default use seconds format in ACP log */
    ErpcdOpt->UseGroupAuthentication = FALSE; /* default use seconds format in ACP log */
#endif

    while (--argc > 0 && (cp = *++argv) != NULL) {
        if (cp[0] == '-' && cp[1] != '\0')
            switch (*++cp) {
#ifdef _WIN32
            case '#':    /* ERPCD process count */
                pcount = atoi(cp+1);
                break;
#endif
#ifdef USE_NDBM
			/* ACP Enhancements */
		    case 'b':
				maxcon = atoi(cp+1);
				if(maxcon < 0){
				  maxcon = -1;
				  fprintf(stdout, ERPCD_RANGE, "-b", "0+");
				}
				break;

			case 'x':
				maxtotal = atoi(cp + 1);
				if(maxtotal < 0 || 
				   (maxtotal > MAX_FAILURES)){
				  sprintf(rangebuf, "0-%d", MAX_FAILURES);
				  fprintf(stdout, ERPCD_RANGE, "-x", 
					  rangebuf);
				  maxtotal = -1;
				}
				break;

		    case 'g':
				buf = atoi(cp + 1);
				period = (time_t)7 * 3600 * buf;
				if(buf <=0){
				  fprintf(stdout, ERPCD_RANGE, "-g", "0+");
				  period = 0;
				}
				break;
#endif
			case '1':    /* Turn off use_udp */
                use_udp = FALSE;
                break;
            case '2':    /* Turn off use_tcp */
                use_tcp = FALSE;
                break;
#ifndef _WIN32
            case 'a':    /* Turn off acp_logfile */
                ErpcdOpt->UseLogfile = FALSE;
                break;
            case 'A':    /* Turn on acp_logfile */
                ErpcdOpt->UseLogfile = TRUE;
                break;
            case 'l':    /* Turn off syslog */
                ErpcdOpt->UseSyslog = FALSE;
                break;
            case 'L':    /* Turn on syslog */
                ErpcdOpt->UseSyslog = TRUE;
                break;
            case 'n':    /* Use host name */
                ErpcdOpt->UseHostName = TRUE;
                break;
            case 't':    /* Use seconds */
                ErpcdOpt->UseSeconds = TRUE;
                break;
            case 'T':    /* Use standard time format */
                ErpcdOpt->UseSeconds = FALSE;
		break;
            case 'f':    /* File (BFS) directory */
                EXTRA_PARM;
                if (stat(cp,&sbuf) < 0)
                    perror(cp);
                else if ((sbuf.st_mode&S_IFMT)!=S_IFDIR)
                    fprintf(stdout,
                        "Bad file mode: %s:  %o.\n",
                        cp,sbuf.st_mode);
                else {
                    bzero(root_dir, sizeof(root_dir));
                    bcopy(cp, root_dir, strlen(cp));
                    break;
                }
                ErpcdExit(1);
            case 's':    /* Security (ACP) directory */
                EXTRA_PARM;
                if (stat(cp,&sbuf) < 0)
                    perror(cp);
                else if ((sbuf.st_mode&S_IFMT)!=S_IFDIR)
                    fprintf(stdout,
                        "Bad file mode: %s:  %o.\n",
                        cp,sbuf.st_mode);
                else {
                    bzero(install_dir, sizeof(install_dir));
                    bcopy( cp, install_dir, strlen(cp));
                    break;
                }
                ErpcdExit(1);
            case 'R':	/* RADIUS Session records */
		raddb_numannex = atoi(cp+1);
                if (raddb_numannex < 8)
			raddb_numannex = SESNUMANNEX_DEFAULT;
                break;
#endif /* WIN32 */
            case 'd':    /* API debug & ERPC port */
                api_options |= API_TO_DEBUG;
                OPTIONAL_EXTRA_PARM;
                portname = cp;
                break;
            case 'D':    /* ERPCD debug level */
                debug = atoi(cp+1);
                if (debug <= 0)
                    debug = 1;
                fprintf(stdout,
                    "erpcd: debug level %d\n",
                    debug);
                break;
            case 'p':
                showpid = 1;
                break;
	    case 'U':	/* Syntax check for ERPCD developers (undocumented) */
		mode |= M_DEBUG;
            case 'u':	/* Syntax check */
                EXTRA_OR_NULL;
                if (cp == NULL || stat(cp, &sbuf) == 0) {
		    open_user_profile_file(cp);
		    initialize_user_profile_file(mode);
		    close_user_profile_file();
#ifndef _WIN32
		    ACP_REGIME(regime_file);
		    if (validate_acp_regime_file() == FALSE) {
            fprintf(stdout,
				"erpcd: regime_file %s failed validation\n",
				regime_file);
			ErpcdExit(1);
		    }
#endif
	        }
                else
                    perror(cp);
                ErpcdExit(0);
	    case 'v':
		printf("erpcd host tool version %s, released %s\n",
		       VERSION,RELDATE);
		ErpcdExit(0);
            case 'c':
                EXTRA_PARM;
                child_max = atoi(cp);
                if (child_max <= 0)
                    child_max = ERPC_CHILD_MAX;
                break;
#ifdef ORACLE
	    case 'O':
		EXTRA_PARM;
		strcpy (ora_user, cp);
		break;
#endif 
            default:
                fprintf(stdout,"Unknown switch:  -%c\n",
                    *cp);
show_usage:
                usage();
            }
        else {
            if (strcmp(cp,"help") != 0)
                fprintf(stdout,
                    "Illegal argument:  \"%s\"\n",
                    cp);
            usage();
        }
    }

    if (period <= 0) /* if no period, then disable bl on total failures */
       maxtotal = -1;
    sp = getservbyname(portname,"udp");
    if (sp != NULL)
      udpaddr.sin_port = sp->s_port;
    else if (isdigit(*portname)) {
        int portnum;
        portnum = atoi(portname);
        if (portnum <= 0 || portnum > 65535) {
            fprintf(stdout,
                "erpcd:  Illegal port number -- \"%s\"\n",
                portname);
            ErpcdExit(1);
        }
        udpaddr.sin_port = htons((u_short)portnum);
    } else {
        fprintf(stdout,
            "erpcd: Warning: unknown service udp/%s\n",
            portname);
        udpaddr.sin_port = htons((u_short)121);
    }

    sp = getservbyname(portname,"tcp");
    if (sp != NULL)
      tcpaddr.sin_port = sp->s_port;
    else
      tcpaddr.sin_port = udpaddr.sin_port;

}

void declare_self(newsock)
int newsock;
{
    char *bp;
    PROBE response;
    int length, rv;

    bzero(&response, sizeof(PROBE));
    response.head.pid = 0; /* htonl(getpid()); */
    response.head.client = htons(PET_AREPLY);
    response.head.devclass = htons(DC_LOGHOST | DC_AUTHHOST | DC_BOOTHOST);
    response.head.pcode = htonl(PC_HOST);
    response.version[0] = 100;
    response.version[1] = 0;
    response.version[2] = 5;
    response.af = htons(AF_INET);
    bcopy(&myipaddr, response.addr, sizeof(struct in_addr));

    length = sizeof(PROBE);
    bp = (char*)&response;
    display(bp, length);
    while(length) {
        if ((rv = api_send(newsock, bp, length, 0, "eprcd", TRUE)) < 0)
            return;
        length -= rv;
        bp -= rv;
    }

    api_release(newsock);
    api_close(newsock);
}

static void
udp_thread(ccount, rpnum, mainsock)
int ccount, rpnum, mainsock;
{
    int newsock;
    struct sockaddr_in sin;
    PROBE *local_probe = (PROBE*)cbuff;
    char *app_nam = "erpcd:spawn_child";

#ifdef _WIN32
    (void)api_close(mainsock);
#else
    int pid;

#ifdef SPT_TYPE
    setproctitle("%s", "udp");
#endif
    /*
     * instance of erpcd just forked
     * setup socket for communicating with client and exec()
     * to service requested
     */

#ifdef SYS_V
    (void)signal(SIGCLD, SIG_DFL);
    (void)signal(SIGHUP, SIG_DFL);
#endif

    /* close master socket */
    (void)api_close(mainsock);

    display(local_probe, sizeof(PROBE));

#endif /* _WIN32 */

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = 0;

    if (debug > 1)
        fprintf(stdout,
            "erpcd: connecting to %s port %d\n",
            inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    if ((newsock = api_open(IPPROTO_UDP, &sin, app_nam, TRUE)) < 0)
        ErpcdExit(1);

    switch (api_bind(newsock, NULL, &sin, app_nam, TRUE)) {
      case 1:
        ErpcdExit(-1);
      case 2:
        ErpcdExit(1);
      case 0:
      default:
        break;
    }
#ifdef EXOS
    from.sin_family = AF_INET;              /* EXOS bug */
#endif
    switch (api_connect(newsock,&from,IPPROTO_UDP,app_nam,TRUE)) {
    case 0:
        break;
    case 1:
        ErpcdExit(1);
    case 2:
        ErpcdExit(-1);
    default:
        break;
    }

    if (local_probe->head.client == PET_AFIND) {
        declare_self(newsock);
        ErpcdExit(0);
    }
    else {
        switch (rpnum) {
          case COURRPN_BFS:
            bfs(newsock,(char *)cbuff, ccount);
            break;

          case COURRPN_ACP:
#ifdef DEBUG_TO_FILE
            pid = sizeof(sin);
            getsockname(newsock,&sin,&pid);
            fprintf(dbgout,
                    "%d:  Spawned ACP child, sock %d, lport %d, fport %d.\n",
                    getpid(),newsock,ntohs(sin.sin_port),
                    ntohs(from.sin_port));
#endif
            acp(newsock,(char *)cbuff,ccount,from.sin_addr.s_addr);

#ifdef DEBUG_TO_FILE
            fprintf(dbgout,"%d:  ACP returned?\n",getpid());
#endif
            break;

          default:
            fprintf(stdout, "erpcd: Unknown remote program %d\n",
                    rpnum);
            ErpcdExit(-1);
        }
        ErpcdExit(0);
    }
}

spawn_child(useudp)
int useudp;
{
#ifdef _WIN32
#define MAX_PATH          260
int i;
    char szTemp[MAX_PATH];
    PROCESS_INFORMATION exec_Info;
    STARTUPINFO StartInfo;

	sprintf(szTemp, "%s\\erpcd.exe", ErpcdOpt->htc.szAppPath);

    StartInfo.cb = sizeof (STARTUPINFO);
    StartInfo.lpReserved = NULL;
    StartInfo.lpDesktop = NULL;
    StartInfo.lpTitle = NULL;
    StartInfo.dwXCountChars = 80;
    StartInfo.dwYCountChars = 1180;
    StartInfo.dwFlags = STARTF_USECOUNTCHARS | STARTF_USESTDHANDLES;
    StartInfo.cbReserved2 = 0;
    StartInfo.lpReserved2 = NULL;
    StartInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    StartInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    StartInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    {
		LONG dw;
		char newcommand[256];
		sprintf(newcommand, "%s -#%d -%d", command_line, pcount+1, (useudp)?2:1);
        if ( !ResetEvent(useudp ? hEventOKToExitUDP : hEventOKToExitTCP) )  /* don't exit until child is ready.*/
        {
            syslog(LOG_WARNING, "ResetEvent failed, %s, %d",
                    (useudp ? "OKToExitUDP" : "OKToExitTCP"), GetLastError());
        }
		for (i=0; i<20; i++)
			if (!CreateProcess(szTemp,newcommand,NULL,NULL,TRUE,
				NORMAL_PRIORITY_CLASS,NULL,NULL,&StartInfo, &exec_Info))
/*	        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,NULL,NULL,&StartInfo, &exec_Info))	   */
			{
				DWORD dwErr = GetLastError();
				syslog(LOG_ERR, "%d=Error 0x%lx: %d, not able to create process %d, szTemp=%s, command=%s\n"
					,i, dwErr, dwErr, pcount+1, szTemp, newcommand);
				Sleep(3000 + i*1000);
		    }
			else
				return 0;
        if ( !ReleaseSemaphore(hSemaphoreChildCount, 1, &dw) )
            syslog(LOG_ERR, "ReleaseSemaphore failed for hSemaphoreChildCount %s", strerror( errno ));
		return -1;
    }

#else
    int pid;

    pid = fork();

    if (pid < 0) {
        perror("fork");
        return pid;
    }
    if (pid > 0) {
        clientrec[child_count].pid = pid;
        if (debug)
            fprintf(stdout, "erpcd: forked, new pid=%d\n", pid);
        child_count++;
        return pid;
    }

#endif
    random_seed("");
    return(0);
}


static void
spawn_child_udp(ccount, rpnum, mainsock)
int ccount, rpnum, mainsock;
{
#ifdef _WIN32
	spawn_child(1);
#else
    clientrec[child_count].host = from.sin_addr;
    clientrec[child_count].port = ntohs(from.sin_port);
    clientrec[child_count].tcpflag = 0;
    if (spawn_child(1) == 0)
#endif
        udp_thread(ccount, rpnum, mainsock);
}

static void tcp_thread(mainsock, newsock)
int mainsock, newsock;
{
#ifndef _WIN32
    int pid;
#endif
    char *app_nam = "erpcd:spawn_child_tcp";

#ifdef SPT_TYPE
    setproctitle("%s", "tcp");
#endif

    /*
     * instance of erpcd just forked
     * setup socket for communicating with client and exec()
     * to service requested
     */

#ifdef SYS_V
    (void)signal(SIGCLD, SIG_DFL);
    (void)signal(SIGHUP, SIG_DFL);
#endif

    /* close master socket */
    (void)api_close(mainsock);


    acp_tcp(newsock, from.sin_addr.s_addr);

    ErpcdExit(0);
}

static void spawn_child_tcp(mainsock, newsock)
     int mainsock, newsock;
{
    char *app_nam = "erpcd:spawn_child_tcp";

#ifdef _WIN32
	spawn_child(0);	   /* in NT parent do the work other than child in UNIX */
#else
    clientrec[child_count].host = from.sin_addr;
    clientrec[child_count].port = ntohs(from.sin_port);
    clientrec[child_count].tcpflag = 1;
    if (spawn_child(0) == 0)
#endif
        tcp_thread(mainsock, newsock);
}

#ifdef DEBUG_TO_FILE
static void
show_exit()
{
    fprintf(dbgout,"%d: Exiting.\n",getpid());
}
#endif


static int start_socket(pd, addr)
     int pd;
     struct sockaddr_in *addr;
{
  int socket;
  char *app_nam = "erpcd:start_socket";

  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = INADDR_ANY;

#ifdef _WIN32
    if (debug)
        fprintf(stdout,"%d---Inherit = %d\n", pcount, Inherit);
    if (Inherit)
    {
		socket = (int)((pd == IPPROTO_TCP) ? ErpcdOpt->hMainTCPSocket : ErpcdOpt->hMainUDPSocket);
        SetEvent(pd == IPPROTO_TCP ? hEventOKToExitTCP : hEventOKToExitUDP);  /* the parent is ok to exit.    */
    }
    else
    {
#endif /* _WIN32 */

  if ((socket = api_open(pd, addr, app_nam, TRUE)) < 0)
    ErpcdExit(1);

  if ((api_options & API_TO_DEBUG) == API_TO_DEBUG)
    if (api_opt(socket, API_TO_DEBUG, TRUE, app_nam) < 0)
      ErpcdExit(-1);

  if (pd == IPPROTO_TCP) {
    api_opt(socket, API_TO_REUSE, TRUE, app_nam);
    api_opt(socket, API_TO_OOB, TRUE, app_nam);
    api_opt(socket, API_TO_LINGER, TRUE, app_nam);
  }

  switch (api_bind(socket, NULL, addr, app_nam, TRUE)) {
  case 1:
    ErpcdExit(-1);
    break;
  case 2:
    ErpcdExit(1);
    break;
  case 0:
  default:
    break;
  }

if (pd == IPPROTO_TCP)
	api_listen(socket, LISTEN_BACKLOG, app_nam, TRUE);

#ifdef _WIN32
		if (pd == IPPROTO_TCP)
			ErpcdOpt->hMainTCPSocket = (HANDLE) socket;
		else
			ErpcdOpt->hMainUDPSocket = (HANDLE) socket;
    }
#endif /* _WIN32 */

  return(socket);
}

static void udp_accept(socket)
int socket;
{
#ifdef _WIN32
    DWORD   result;
#endif
    /*
     * main loop
     * listens for ERPC service requests on reserved UDP port
     * forks appropriate server when properly identified request received
     */
        for (;;)
		{
        UINT32 rpnum, pid;
        int rpver;
        int        received;
        u_short                  verlo,
                     verhi;
        int len, cc;
        char *app_nam = "erpcd:udp_accept";
        struct eservent *esp;
        register struct chdr     *ch = (struct chdr *)cbuff;
        int bad_format;

        /*
         * Wait for a remote procedure call message from anyone
         */
        len = sizeof(from);

        /* Receive datagram from given source */
        cc = sizeof(cbuff);
        if (debug)
            printf("UDP ready and waiting...\n");

#ifdef SPT_TYPE
	setproctitle("%s", "udp: listening");
#endif

        received = api_rcvud(&cc, &len, socket, NULL, (char *)cbuff, app_nam,
                             TRUE, &from);
#ifdef _WIN32
        if ( WAIT_FAILED == WaitForSingleObject(hEventContinue, INFINITE) )
            syslog(LOG_ERR, "WaitForSingleObject failed, %d, %s, %d",
                        GetLastError(), __FILE__, __LINE__);
#endif
        switch(received) {
        case 1:
            ErpcdExit(1);
        case 2:
            ErpcdExit(-1);
        case 3:
            continue;
        default:
            break;
        }

        if (debug)
        fprintf(stdout,
            "erpcd: received %d errno %d from %s[%d] port %d\n",
            cc, errno,
            inet_ntoa(from.sin_addr), len, ntohs(from.sin_port));

         if (cc <= 0)
            continue;

        display(cbuff, cc);
        /*
         * check format
         */
        bad_format = TRUE;
        switch(ntohs(ch->ch_client)) {
          case PET_ERPC:
            if (cc >= CHDRSIZE && ntohs(ch->ch_type) == C_CALL
                && ch->ch_tid == 0)
                bad_format = FALSE;
            break;

          case PET_AFIND:
            bad_format = FALSE;
            break;

          default:
            break;
        }

        if (bad_format) {
            if (debug) {
                fprintf(stdout, "erpcd: bad erpc header\n");
                fprintf(stdout, "cc (%d) < (%d) CHDRSIZE\n",
                        cc, CHDRSIZE);
                fprintf(stdout, "ch_client (%d) != (%d) PET_ERPC\n",
                        ntohs(ch->ch_client), PET_ERPC);
                fprintf(stdout, "ch_type (%d) != (%d) C_CALL\n",
                        ntohs(ch->ch_type), C_CALL);
                fprintf(stdout, "ch_tid (%d) != 0\n",
                        ch->ch_tid);
            }
            continue;
        }

        pid = get_long(ch->ch_id);

        if (ntohs(ch->ch_client) == PET_AFIND) {
            PROBEHEAD *local_probehead = (PROBEHEAD*)cbuff;
            struct in_addr hostaddr, highaddr;
            char *addrlist;
            u_short host;
            int include, exclude;

            host = (DC_AUTHHOST | DC_BOOTHOST | DC_LOGHOST);
            if ( !(ntohs(local_probehead->devclass) & host) ||
                 !(ntohs((u_short)local_probehead->pcode) & PC_HOST) )
                continue;

            addrlist = (char*)(local_probehead + 1);
            include = exclude = FALSE;
            while(!include && !exclude && *addrlist) {
                switch(addrlist[0]) {
                  case ADDR_EXCL:
                    addrlist++;
                    bcopy(addrlist, (char*)&hostaddr, sizeof(struct in_addr));
                    addrlist += sizeof(struct in_addr);
                    if (hostaddr.s_addr == myipaddr.s_addr) {
                        exclude = TRUE;
                        continue;
                    }
                    break;

                  case ADDR_INCL:
                    addrlist++;
                    bcopy(addrlist, (char*)&hostaddr, sizeof(struct in_addr));
                    addrlist += sizeof(struct in_addr);
                    if (hostaddr.s_addr == myipaddr.s_addr) {
                        include = TRUE;
                        continue;
                    }
                    break;

                  case ADDR_RANGE_EXCL:
                    addrlist++;
                    bcopy(addrlist, (char*)&hostaddr, sizeof(struct in_addr));
                    addrlist += sizeof(struct in_addr);
                    bcopy(addrlist, (char*)&highaddr, sizeof(struct in_addr));
                    addrlist += sizeof(struct in_addr);
                    if (hostaddr.s_addr > myipaddr.s_addr
                        || highaddr.s_addr < myipaddr.s_addr) {
                        exclude = TRUE;
                        continue;
                    }
                    break;

                  case ADDR_RANGE_INCL:
                    addrlist++;
                    bcopy(addrlist, (char*)&hostaddr, sizeof(struct in_addr));
                    addrlist += sizeof(struct in_addr);
                    bcopy(addrlist, (char*)&highaddr, sizeof(struct in_addr));
                    addrlist += sizeof(struct in_addr);
                    if (hostaddr.s_addr <= myipaddr.s_addr &&
                        highaddr.s_addr >= myipaddr.s_addr) {
                        include = TRUE;
                        continue;
                    }
                    break;

                  case ADDR_END:
                  default:
                    *addrlist = 0;
                    break;

                }
            }

            if (!include)
                continue;
        }
        else {

            /*
             * Find requested remote program.
             */
            seteservent(1);

            rpnum = get_long(ch->ch_rpnum);

            if ((esp = geteservbynum(rpnum)) == NULL) {
		/*
		 * Would like to send a reject if request was not
		 * broadcasted but there is no way to find this
		 * out from here.
		 */
		erpc_reject(socket, &from, pid, CMJ_NOPROG, 0, 0);
                if (debug) {
                    fprintf(stdout,
                      "erpcd: Message rejected: prog %ld is not in %s file\n",
                            rpnum, eservices_name);
                }
                continue;
            }

            rpver = ntohs(ch->ch_rpver);
            verlo = esp->es_verlo; verhi = esp->es_verhi;

            while (   (u_short)rpnum != esp->es_rpnum
                      || (u_short)rpver < esp->es_verlo
                      || (u_short)rpver > esp->es_verhi
                      )
                if ((esp = geteservent()) == NULL)
                    break;

            endeservent();

            if (esp == NULL) {
		/*
		 * Would like to send reject if request not
		 * broadcast but no way to find this out from here.
		 */
		erpc_reject(socket, &from, pid, CMJ_NOVERS, verlo, verhi);
                if (debug) {
                    fprintf(stdout,
                      "Message rejected: prog %ld ver %d excluded by %s\n",
                            rpnum, rpver, eservices_name);
                }
                continue;
            }

        }
        /*
         * Reject the request if current child count is not
         * less than the maximum allowed count
         */
#ifdef _WIN32
        if ( (result=WaitForSingleObject(hSemaphoreChildCount, 0)) == WAIT_TIMEOUT)
#else
        if (child_count >= child_max)
#endif
        {
	  child_rejects++;
	    /*
	     * Would like to send reject if request not broadcast
	     * but no way to find this out from here.
	     */
	    erpc_reject(socket, &from, pid, CMJ_UNSPEC, verlo, verhi);
            if (debug) {
                fprintf(stdout,
                        "Message rejected: exceeded session limit(%d)\n",
                 child_max);
            }
            continue;
        }
#ifdef _WIN32
        else
        {
            if ( result == WAIT_FAILED )
            {
                syslog(LOG_ERR, "WaitForSingleObject failed, %d, %s, %d",
                            GetLastError(), __FILE__, __LINE__);
            }
        }
#endif
        /*
         * Start requested remote program
         */
		spawn_child_udp(cc, (ntohs(ch->ch_client) == PET_AFIND) ? 0 : esp->es_rpnum, socket);
#ifdef _WIN32
		break;
#endif
    }
}

int newtcpsock;
static void tcp_accept(socket)
int socket;
{
  char *app_nam = "erpcd:tcp_accept";
  u_char *netaddr = (u_char*)&from.sin_addr.s_addr;
  int count = 0;

  while(1)
	  {
#ifndef TLI
      struct linger ling;
#endif

#ifdef SPT_TYPE
	setproctitle("%s", "tcp: listening");
#endif

      /* BLOCKS waiting for a connection request */
      if (debug)
          printf("TCP ready and waiting...\n");
      if ((newtcpsock = api_accept(socket, &from, app_nam, TRUE)) < 0) {
          ACP_USTRING buf;

          count++;
          if (count == 1) {
              sprintf(buf, "ACP Error in accept, errno is %d", errno);
              syslog(LOG_ERR, buf);
          }
          else if (count == 100) {
              sprintf(buf,
                     "Fatal ACP Error in accept, errno is %d, erpcd is exiting",
                     errno);
              syslog(LOG_CRIT, buf);
              api_release(socket, 2, app_nam);
              api_close(socket);
#ifndef _WIN32
              koolaidfest(0); /* die a horrible death, exit()s */
#else
	/* Should this shut down the erpc service in NT ? */
    	      ErpcdExit(0);
#endif	/* _WIN32 */
          }
          continue;
      }
      count = 0;
#ifndef TLI
      api_opt(tcpsock, API_TO_REUSE, TRUE, app_nam);
      api_opt(tcpsock, API_TO_OOB, TRUE, app_nam);
      ling.l_onoff = 1;
      ling.l_linger = DEF_LINGER_TIME;
      setsockopt(tcpsock, SOL_SOCKET, SO_LINGER, (char*)&ling, sizeof(ling));
#endif

      if (debug) {
          printf("Accepted connection from %s\n", inet_ntoa(from.sin_addr));
      }
#ifdef _WIN32
	  {
		  /* make new sock non-inheriable */
		  HANDLE hps = GetCurrentProcess();
		  HANDLE noinhsock;

          if ( !DuplicateHandle(hps, (HANDLE)newtcpsock, hps, &noinhsock,
                                0, FALSE, DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS) )
            syslog(LOG_ERR, "DuplicateHandle failed, %d, %s, %d",
                        GetLastError(), __FILE__, __LINE__);

          /* syslog(LOG_INFO, "Process %d, socket handles old(inheritable):%d, new(uninheritable):%d", _getpid(), newtcpsock, noinhsock);*/
		  CloseHandle((HANDLE)newtcpsock);
		  newtcpsock = (int) noinhsock;
	  }
#endif

      spawn_child_tcp(socket, newtcpsock);

      api_close(newtcpsock);
#ifdef _WIN32
	  break;
#endif
  }
}

/*
 * ERPC listener
 */
int
main(argc, argv, envp)
int  argc;
char **argv;
char **envp;
{
    static char *app_nam="erpcd";
    int    error;
    struct hostent *host;
    char hoststring[64];
#ifndef _WIN32
    time_t clock;
    int rc;
#endif

#ifdef LINUX
        struct  sigaction  sigaction_struct;
#endif

#ifdef _WIN32
{
    HANDLE handle;
    DWORD lerr;
    WSADATA WSAData;

    /* put any stderr output into stdout */
    if(0 == _close(_fileno(stderr)))
	_dup (_fileno (stdout));

    if ((error = WSAStartup(MAKEWORD(1,1), &WSAData)) != 0) {
      syslog(LOG_ERR, "WSAStartup Failed: %d\n", GetLastError());
    }

    if ( !InitAlarmThread() )   /* initialize a thread to handle alarm */
    {
        syslog(LOG_ERR, "Fatal Error, InitAlarmThread failed");
    }

	handle = CreateSemaphore(NULL, ERPC_CHILD_MAX, ERPC_CHILD_MAX, "ChildCountSemaphore");
    if ( handle == NULL )
    {
        syslog(LOG_ERR, "Fatal Error, CreateSemaphore ChildCountSemaphore failed: %d", GetLastError());
    }
	/* Initialize the critical section. */

	InitializeCriticalSection(&GlobalCriticalSection);

    /* create all the synch object if they are not exist */
    lerr = GetLastError();
    Inherit = (lerr == ERROR_ALREADY_EXISTS);
    if (debug)
        fprintf(stdout,"%d--===============LastErr = %lx\n", pcount, lerr);

    if ( !GetPrimaryDomainName(sizeof(szDefaultDomain)) )
    {
        syslog(LOG_ERR, "Can not get Primary Domain Name, Erpcd exiting");
        exit(1);
    }

    if (Inherit)
    {

        hSemaphoreChildCount = OpenSemaphore(SEMAPHORE_ALL_ACCESS, FALSE, "ChildCountSemaphore");
        if ( hSemaphoreChildCount == NULL )
        {
            syslog(LOG_ERR, "OpenSemaphore failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }

        hEventOKToExitUDP = OpenEvent(EVENT_ALL_ACCESS, FALSE,"OKToExitUDP");
        if ( hEventOKToExitUDP == NULL )
        {
            syslog(LOG_ERR, "OpenEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventOKToExitTCP = OpenEvent(EVENT_ALL_ACCESS, FALSE,"OKToExitTCP");
        if ( hEventOKToExitTCP == NULL )
        {
            syslog(LOG_ERR, "OpenEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }

        hEventSIGHUP = OpenEvent(EVENT_ALL_ACCESS, FALSE,"SIGHUP");
        if ( hEventSIGHUP == NULL )
        {
            syslog(LOG_ERR, "OpenEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventSIGPWR = OpenEvent(EVENT_ALL_ACCESS, FALSE,"SIGPWR");
        if ( hEventSIGPWR == NULL )
        {
            syslog(LOG_ERR, "OpenEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventContinue = OpenEvent(EVENT_ALL_ACCESS, FALSE,"ServiceControlContinue");
        if ( hEventContinue == NULL )
        {
            syslog(LOG_ERR, "OpenEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventStop = OpenEvent(EVENT_ALL_ACCESS, FALSE,"ErpcdServiceControlStop");
        if ( hEventSIGHUP == NULL )
        {
            syslog(LOG_ERR, "OpenEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }

        /* Open the memory mapped file of Erpcd options */

        hMapStructErpcdOption = OpenFileMapping (FILE_MAP_WRITE,
                                        FALSE,
                                        "StructErpcdOption");
		if ( hMapStructErpcdOption == NULL )
        {
			syslog(LOG_CRIT,
                     "Fatal ACP Error, can't open StructErpcdOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }
        ErpcdOpt = (StructErpcdOption *) MapViewOfFile (hMapStructErpcdOption,
                                           FILE_MAP_WRITE,
                                           0, 0, 0);
        if ( ErpcdOpt == NULL )
        {
			syslog(LOG_CRIT,
                     "Fatal ACP Error, can't MapViewOfFile StructErpcdOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }

	if (debug) {
	  fprintf(stdout,"\tDir Security:  %s, %d\n",
		  ErpcdOpt->htc.szDirSecurity, strlen(ErpcdOpt->htc.szDirSecurity));
	  fprintf(stdout,"\tLoad Dump:  %s, %d\n",
		  ErpcdOpt->htc.szDirLoadDump, strlen(ErpcdOpt->htc.szDirLoadDump));
	}

		install_dir = ErpcdOpt->htc.szDirSecurity;
		root_dir = ErpcdOpt->htc.szDirLoadDump;

        /* Open the memory mapped file of RADIUS options */

        hMapStructRadiusOption = OpenFileMapping (FILE_MAP_WRITE,
                                        FALSE,
                                        "StructRadiusOption");
        if ( hMapStructRadiusOption == NULL )
        {
            syslog(LOG_CRIT,
                     "Fatal ACP Error, can't open StructRadiusOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }
        RadiusOpt = (StructRadiusOption *) MapViewOfFile (hMapStructRadiusOption,
                                           FILE_MAP_WRITE,
                                           0, 0, 0);
        if ( RadiusOpt == NULL )
        {
			syslog(LOG_CRIT,
                     "Fatal ACP Error, can't MapViewOfFile StructRadiusOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }

        /* Copy the Radius server information */

        if ( strcmp(ErpcdOpt->htc.szRadiusAuthenticationServer, "<Local>") == 0 )
            strcpy(RadiusOpt->RadiusAuthenticationServer, "");
        else
            strcpy(RadiusOpt->RadiusAuthenticationServer, ErpcdOpt->htc.szRadiusAuthenticationServer);

        if ( strcmp(ErpcdOpt->htc.szRadiusAccountingServer, "<Local>") == 0 )
            strcpy(RadiusOpt->RadiusAccountingServer, "");
        else if ( strcmp(ErpcdOpt->htc.szRadiusAccountingServer, "<Same as Authentication>") == 0 )
            strcpy(RadiusOpt->RadiusAccountingServer, RadiusOpt->RadiusAuthenticationServer);
        else
            strcpy(RadiusOpt->RadiusAccountingServer, ErpcdOpt->htc.szRadiusAccountingServer);

        memcpy(RadiusOpt->aServer, ErpcdOpt->htc.aServer, sizeof(ErpcdOpt->htc.aServer));
        radius_server_count = ErpcdOpt->htc.SrvrCnt;

    }
    else
    {
        hSemaphoreChildCount = handle;
        hEventSIGHUP = CreateEvent(NULL, FALSE, FALSE, "SIGHUP");
        if ( hEventSIGHUP == NULL )
        {
            syslog(LOG_ERR, "CreateEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventSIGPWR = CreateEvent(NULL, TRUE, FALSE, "SIGPWR");
        if ( hEventSIGPWR == NULL )
        {
            syslog(LOG_ERR, "CreateEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventContinue = CreateEvent(NULL, TRUE, TRUE,"ServiceControlContinue");
        if ( hEventContinue == NULL )
        {
            syslog(LOG_ERR, "CreateEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventStop = CreateEvent(NULL, TRUE, FALSE,"ErpcdServiceControlStop");
        if ( hEventStop == NULL )
        {
            syslog(LOG_ERR, "CreateEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventOKToExitUDP = CreateEvent(NULL, TRUE, TRUE,"OKToExitUDP");
        if ( hEventOKToExitUDP == NULL )
        {
            syslog(LOG_ERR, "CreateEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }
        hEventOKToExitTCP = CreateEvent(NULL, TRUE, TRUE,"OKToExitTCP");
        if ( hEventOKToExitTCP == NULL )
        {
            syslog(LOG_ERR, "CreateEvent failed, %s, Line: %d, Error: %s",
                     __FILE__, __LINE__, strerror( errno ));
            exit(1);
        }

        /* Create a memory mapped file for the Erpcd options */

        hMapStructErpcdOption = CreateFileMapping ((HANDLE) 0xFFFFFFFF,
                                          NULL,
                                          PAGE_READWRITE,
                                          0,
                                          sizeof(StructErpcdOption),
                                          "StructErpcdOption");
		if ( hMapStructErpcdOption == NULL )
        {
            syslog(LOG_CRIT,
                     "Fatal ACP Error, can't create StructErpcdOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }

        ErpcdOpt = (StructErpcdOption *) MapViewOfFile (hMapStructErpcdOption,
                                           FILE_MAP_WRITE,
                                           0, 0, 0);
        if ( ErpcdOpt == NULL )
        {
			syslog(LOG_CRIT,
                     "Fatal ACP Error, can't MapViewOfFile StructErpcdOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }

        /* Create a memory mapped file for the Radius options */

        hMapStructRadiusOption = CreateFileMapping ((HANDLE) 0xFFFFFFFF,
                                          NULL,
                                          PAGE_READWRITE,
                                          0,
                                          sizeof(StructRadiusOption),
                                          "StructRadiusOption");
        if ( hMapStructRadiusOption == NULL )
        {
            syslog(LOG_CRIT,
                     "Fatal ACP Error, can't create StructRadiusOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }

        RadiusOpt = (StructRadiusOption *) MapViewOfFile (hMapStructRadiusOption,
                                           FILE_MAP_WRITE,
                                           0, 0, 0);
        if ( RadiusOpt == NULL )
        {
			syslog(LOG_CRIT,
                     "Fatal ACP Error, can't MapViewOfFile StructErpcdOption filemap. Error: %s",
                            strerror( errno ));
                          exit(1);
        }

        /* Read the Erpcd and RADIUS options into the memory mapped files */
	if (debug) {
	  fprintf(stdout,"\tReadRegistryParamBefore:File file directory:  %s, %d, %s\n",
		  ErpcdOpt->htc.szDirSecurity, strlen(ErpcdOpt->htc.szDirSecurity), install_dir);
	  fprintf(stdout,"\tReadRegistryParam:Security load dump:  %s, %d, %s\n",
		  ErpcdOpt->htc.szDirLoadDump, strlen(ErpcdOpt->htc.szDirLoadDump), root_dir);
	}

        ReadRegistryParam();

	if (debug) {
	  fprintf(stdout,"\tReadRegistryParamAfter:File file directory:  %s, %d, %s\n",
		  ErpcdOpt->htc.szDirSecurity, strlen(ErpcdOpt->htc.szDirSecurity), install_dir);
	  fprintf(stdout,"\tReadRegistryParam:Security load dump:  %s, %d, %s\n",
		  ErpcdOpt->htc.szDirLoadDump, strlen(ErpcdOpt->htc.szDirLoadDump), root_dir);
	}
    }

    if (WaitForSingleObject(hSemaphoreChildCount, 0) != WAIT_TIMEOUT)
    {
        LONG dw;
        ReleaseSemaphore(hSemaphoreChildCount, 1, &dw);
        if (debug)
            printf("Semaphore111 == %d\n", dw);
    }

}
#else  /* not _WIN32 */
    ErpcdOpt = &StructErpcdOptionBlock;
    myname = argv[0];
#endif  /* _WIN32 */

    erpcd_boottime = time((time_t *) 0);

    bzero(&myipaddr, sizeof(struct in_addr));

    if (gethostname(hoststring, 64) == 0)
        if ((host = gethostbyname(hoststring)) != NULL)
            myipaddr.s_addr = *( (UINT32*)host->h_addr_list[0] );

    /* process arguments */
    handle_arguments(argc,argv);

    tzset();
#ifndef _WIN32
#ifndef NATIVEPASSWD
    ACP_PASSWD(passwd_name);
 
    ACP_PTMP(ptmp_name);
 
    ACP_LOCKFILE(lock_name);
#else
    ACP_NATIVEPASSWD(passwd_name);
    ACP_NATIVEPTMP(ptmp_name);
    ACP_NATIVELOCKFILE(lock_name);
#endif /* !NATIVEPASSWD */
 
#ifndef NATIVESHADOW
    ACP_SHADOW(shadow_name);
    ACP_STMP(stmp_name);
#else
    ACP_NATIVESHADOW(shadow_name);
    ACP_NATIVESTMP(stmp_name);
#endif /* !NATIVESHADOW */
 
    ACP_REGIME(regime_file);
    ACP_GROUP(group_file);
    ACP_CONFIG(config_file);
#endif /* !_WIN32 */
    ACP_USERINFO(userinfo_name);
    ACP_ESERVICES(eservices_name);

#ifdef DEBUG_TO_FILE
    unlink("erpcd.dbg");
    if ((dbgout = fopen("erpcd.dbg","w")) == NULL)
        dbgout = stdout;
    else
        setlinebuf(dbgout);
    fprintf(dbgout,"%d: Running erpcd!\n",getpid());
    on_exit(show_exit,NULL);
#endif
#ifdef notdef
    if (getuid()) {
        fprintf(stdout, "erpcd: not super user\n");
        ErpcdExit(1);
      }
#endif

    if (debug) {
        fprintf(stdout,"erpcd: using udp port %d.\n",
            (int)ntohs(udpaddr.sin_port));
        fprintf(stdout,"erpcd: using tcp port %d.\n",
            (int)ntohs(tcpaddr.sin_port));
        fprintf(stdout,"\t----File service directory:  %s\n",
            root_dir);
        fprintf(stdout,"\tSecurity file directory:  %s\n",
            install_dir);
      }
#ifdef _WIN32
		install_dir = ErpcdOpt->htc.szDirSecurity;
		root_dir = ErpcdOpt->htc.szDirLoadDump;	   
    
    if (debug) {
      fprintf(stdout,"erpcd: using udp port %d.\n",
	      (int)ntohs(udpaddr.sin_port));
      fprintf(stdout,"erpcd: using tcp port %d.\n",
	      (int)ntohs(tcpaddr.sin_port));
      fprintf(stdout,"\t----File service directory:  %s\n",
	      root_dir);
      fprintf(stdout,"\tSecurity file directory:  %s\n",
	      install_dir);
    }
    
   /*
	* If RADIUS is the selected security regime,
	* parse the radius parameters read from the registry/memory file
	* into a linked list structure and save the head.
    */
	if ( ErpcdOpt->RadiusAuthentication == TRUE )
	{
    	radius_head = create_radius_configs();
	}
#else /* not WIN32 */

   /*
	* Read the erpcd.conf file to save the serverinfo in a linked list
    * structure and store the head on return
    */
	radius_head = create_radius_configs();

   /*
    * Read erpcd.conf file to save trap host information
    *    WHAT DO I DO WITH ERRORS???
    */
    (void)erpcd_read_config();

#endif

#ifdef SPT_TYPE
    /* Initialize the routine to set the process title */
    initsetproctitle(argc, argv, envp);
#endif

    /*
     * this "mother" UDP socket receives generic ERPC requests
     * instances of a service are handled by a forked instance of the
     * server and use a new socket (eg, not this socket)
     */

    if (use_udp) {
      udpsock = start_socket(IPPROTO_UDP, &udpaddr);
      if (udpsock < 0)
		use_udp = 0; /* slu - no udp socket */
    }
    if (use_tcp) {
      tcpsock = start_socket(IPPROTO_TCP, &tcpaddr);
      if (tcpsock < 0)
		use_tcp = 0; /* slu - no tcp socket */
    }
    if (!use_udp && !use_tcp)
      ErpcdExit(-1);

#ifndef _WIN32
    /* initialize the shared memory db */
    rc = ses_open_db(raddb_numannex, ntohs(tcpaddr.sin_port));	/* initial num records */
    if (rc == 0) {
	raddb_up = TRUE;
    }
    else {
    fprintf(stdout, "erpcd: RADIUS shared mem init failure %i\n",rc);
	syslog(LOG_CRIT, "RADIUS shared memory init failure");
     }
#endif


#ifdef _WIN32
	if (Inherit)	  /* first instance */
		udp_child = use_udp;
	else
	{
		if (use_tcp && use_udp)
		{
			if (spawn_child(0))
				ErpcdExit(1);	/* spawn tcp child failed */
			udp_child = TRUE;
		}
        else if (use_udp)			 /* use only udp */
            udp_child = TRUE;
	}
#else /* not _WIN32 */
    if (!debug) {
        int f;

#ifdef SPT_TYPE
	setproctitle("%s", "parent");
#endif

        if ((f=fork()) > 0)
       {
            if (showpid)
                printf("%d\n",f);
            ErpcdExit(0);
        }

        if (f < 0) {
            perror("fork");
            ErpcdExit(1);
         }
	(void)close(0);
	(void)close(1);
	(void)close(2);
#if defined(SYS_V) || defined(LINUX)
        f = open ("/dev/console", O_RDWR);
        if (f < 0)
            f = open ("/dev/tty", O_RDWR);
        if (f < 0)
            f = open ("/dev/null", O_RDWR);
        (void) dup2(STDIN, STDOUT);
        (void) dup2(STDIN, STDERR);
        (void) setpgrp();
#else
        (void) open("/dev/null", 2);
        (void) dup2(STDIN, STDOUT);
        (void) dup2(STDIN, STDERR);
        f = open("/dev/tty", 2);
        if (f >= 0) {
            ioctl(f, TIOCNOTTY, 0);
            (void) close(f);
        }
	(void) setpgrp(0, getpid());
#endif
		if (use_tcp && use_udp)
		{
            if ((f = fork()) > 0) 	 /* parent */
	    {
                if (showpid)
                    printf("%d\n",f);
            }
            else if (f < 0) 		 /* fork failed */
			{
                perror("fork");
                ErpcdExit(1);
            }
            else
      			 /* child */
                udp_child = TRUE;
        }
        else if (use_udp)			 /* use only udp */
            udp_child = TRUE;
    }
    else { /* debug */
      if (use_tcp && use_udp) {
        int f;

#ifdef SPT_TYPE
	setproctitle("%s", "debug");
#endif

        f = fork();

	if (f == 0) /* child */
	{
#ifdef SPT_TYPE
	  setproctitle("%s", "debug/child");
#endif
          udp_child = TRUE;
        }
        else if (f<0){ /* error */
          perror("fork");
          ErpcdExit(1);
        }
      }
      else if (use_udp)
        udp_child = TRUE;
    }
#endif	/* _WIN32 */

#ifdef USE_SYSLOG
#ifndef _WIN32
    openlog(USE_SYSLOG,LOG_PID|LOG_NDELAY|LOG_NOWAIT,LOG_AUTH);
#endif /* _WIN32 */
#endif /* USE_SYSLOG */

#ifndef _WIN32
#ifdef LINUX
        sigaction_struct.sa_handler = reaper;
        sigaction(SIGCHLD, &sigaction_struct, NULL);
#else
    (void)signal(SIGCHLD, reaper);
#endif
    (void)signal(SIGHUP, hangup);
    (void)signal(SIGUSR1, re_acpuser);
    (void)signal(SIGTERM, koolaidfest);

/* If we've got a power-fail signal, then exit when we hear it. */
#ifdef SIGPWR
    (void)signal(SIGPWR,leave_erpcd);
#endif

#else /* _WIN32 */
    hThreadSIGHUP = (HANDLE)_beginthread (hangup, 0, (void *)NULL);
    if ( hThreadSIGHUP == (HANDLE)0xFFFFFFFF )
    {
        syslog(LOG_ERR, "_beginthread failed, hangup, %s, Line: %d, Error: %s",
                    __FILE__, __LINE__, strerror( errno ));
        exit(1);
    }

    hThreadSIGPWR = (HANDLE)_beginthread (leave_erpcd, 0, (void *)NULL);
    if ( hThreadSIGPWR == (HANDLE)0xFFFFFFFF )
    {
        syslog(LOG_ERR, "_beginthread failed, leave_erpcd, %s, Line: %d, Error: %s",
                    __FILE__, __LINE__, strerror( errno ));
        exit(1);
    }

    hThreadUpdate = (HANDLE)_beginthread (UpdateErpcdOpt, 0, (void *)NULL);
    if ( hThreadUpdate == (HANDLE)0xFFFFFFFF )
    {
        syslog(LOG_ERR, "_beginthread failed, UpdateErpcdOpt, %s, Line: %d, Error: %s",
                    __FILE__, __LINE__, strerror( errno ));
        exit(1);
    }

    hThreadServiceStop = (HANDLE)_beginthread (ServiceControlStop, 0, (void *)NULL);
    if ( hThreadServiceStop == (HANDLE)0xFFFFFFFF )
    {
        syslog(LOG_ERR, "_beginthread failed, ServiceControlStop, %s, Line: %d, Error: %s",
                    __FILE__, __LINE__, strerror( errno ));
        exit(1);
    }

#endif	/* _WIN32 */

    /*
     * read "eservices" and initialize remote programs
     */
    erpcd_init();

      /*
       * read "acp_userinfo" and initialize user profile database.
       */
	acpuser(0);

    if (udp_child)
		udp_accept(udpsock);
	else
		tcp_accept(tcpsock);
#ifdef _WIN32
	return 0;
#endif
}


struct eservent *
geteservbynum(rpnum)
    UINT32 rpnum;
{
    register struct eservent *p;

    seteservent(0);

    while (p = geteservent())
        if (p->es_rpnum == rpnum)
            break;

    endeservent();

    return (p);
}

FILE            *eservf = NULL;
char            line[BUFSIZ+1];
struct eservent eserv;
int             stayopen = 0;

void seteservent(f)
    int f;
{
    if (eservf == NULL)
        eservf = fopen(eservices_name,"r");
    else
        rewind(eservf);

    stayopen |= f;
}    /* seteservent() */

void endeservent()
{
    if (eservf && !stayopen)
        {
        (void)fclose(eservf);
        eservf = NULL;
        }
}    /* endeservent() */

static char *
any(cp, match)
    register char *cp;
    char          *match;
{
    register char *mp, c;

    for (; c = *cp; cp++)
        for (mp = match; *mp; mp++)
            if (*mp == c)
                return (cp);

    return ((char *)0);
}

struct eservent *
geteservent()
{
    register char *p, *cp;

    if (eservf == NULL &&
        (eservf = fopen(eservices_name, "r" )) == NULL)
        return (NULL);

again:
    if ((p = fgets(line, BUFSIZ, eservf)) == NULL)
        return (NULL);

    if (*p == '#')
        goto again;

    cp = any(p, "#\n");

    if (cp == NULL)
        goto again;

    *cp = '\0';
    cp = any(p, " \t");

    if (cp == NULL)
        goto again;

    *cp++ = '\0';
    eserv.es_rpnum = (u_short)atoi(p);

    while (*cp == ' ' || *cp == '\t')
        cp++;

    p = cp;
    cp = any(p, " \t");

    if (cp == NULL)
        goto again;

    *cp++ = '\0';
    eserv.es_verlo = atoi(p);

    while (*cp == ' ' || *cp == '\t')
        cp++;

    p = cp;
    cp = any(p, " \t");

    if (cp == NULL)
        goto again;

    *cp++ = '\0';
    eserv.es_verhi = atoi(p);

    while (*cp == ' ' || *cp == '\t')
        cp++;

    p = cp;
    cp = any(p, " \t");

    if (cp)
        *cp = '\0';

    eserv.es_name = p;
    return (&eserv);
}


#ifdef IUNIX
void
dummy_alarm(dummy)
int dummy;
{
}
#endif

/*
 * Collect status of exitting children.
 */
#ifndef _WIN32
void reaper(arg)
    int arg;
{
    int savederrno = errno;
    int i,j;
#ifdef SYS_V
    int status;
#else
    union wait status;
#endif

#ifdef SYS_V
    /* decrement child_count for each status successfully returned */

#ifdef IUNIX
    int awas;
    void (*swas)();
/*
 * Work-around for a horrible IUNIX 3.2 bug; WNOHANG doesn't mean squat
 * on this machine.  We have to time ourselves out of here!
 */
    swas = signal(SIGALRM,dummy_alarm);
    awas = alarm(2);
#endif

    while ((j=waitpid(-1, &status, WNOHANG)) > 0) {
      for (i = 0; i < child_count; i++)
	if (clientrec[i].pid == j)
	  break;
      for (j = i+1; j < child_count; j++)
	clientrec[j-1] = clientrec[j];
      child_count--;
    }

#ifdef IUNIX
    alarm(awas);
    signal(SIGALRM,swas);
#endif

    signal(SIGCHLD,reaper);
#else
    /* decrement child_count for each status successfully returned */

    signal(SIGCHLD,reaper);
    while ((j=wait3(&status, WNOHANG, (struct rusage *)0)) > 0) {
      for (i = 0; i < child_count; i++)
	if (clientrec[i].pid == j)
	  break;
      for (j = i+1; j < child_count; j++)
	clientrec[j-1] = clientrec[j];
      child_count--;
    }

#endif
    errno = savederrno;
}
#endif

/*
 *  Initialize remote programs on the hangup signal, SIGHUP, a la init
 */
#ifdef _WIN32
void hangup(void *arg)
#else
void hangup(arg)
    int arg;
#endif
{
#ifdef _WIN32
    for(;;)
    {
        if ( WAIT_FAILED == WaitForSingleObject(hEventSIGHUP, INFINITE) )
            syslog(LOG_ERR, "WaitForSingleObject failed, %d, %s, %d",
                        GetLastError(), __FILE__, __LINE__);
        erpcd_init();
    }
#else
    erpcd_init();

#ifdef    SYS_V
    signal(SIGHUP, hangup);
#endif
#endif
}

/*
 *  Initialize acp user profile database
 */
void acpuser (dummy)
int dummy;
{
#ifndef _WIN32
    int  mask;
#endif
    int ret;
    /* char buf[128]; */

    /* Deny access while parsing, and if an error occurs. */
    deny_all_users = TRUE;

#if defined(SYS_V) && !defined(BSDSIG)
    (void) sighold(SIGUSR1);
#elif !defined(_WIN32)
    mask = sigblock(sigmask(SIGUSR1));
#endif /* defined(SYS_V) && !defined(BSDSIG) */

	ret = open_user_profile_file(userinfo_name);
	if (ret == ACPU_ESUCCESS)
	    ret = initialize_user_profile_file(0);

#if defined(SYS_V) && !defined(BSDSIG)
    (void) sigrelse(SIGUSR1);
#elif !defined(_WIN32)
    sigsetmask(mask);
#endif /* defined(SYS_V) && !defined(BSDSIG) */

#ifdef    SYS_V
    signal(SIGUSR1, acpuser);
#endif

    /* acp_userinfo parsed successfully - don't deny access anymore. */
    if(ret == ACPU_ESUCCESS)
     deny_all_users = FALSE;

    return;
}

/*
 * Frees old acp user profile database and initializes a new one.
 * Called on USR1 signal.
 */
void
re_acpuser(dummy)
int    dummy;
{
    close_user_profile_file();
    clear_user_profile_info();
    acpuser(0);
}


#ifdef _WIN32
void leave_erpcd ( void *dummy)
#else
void leave_erpcd (arg)
    int arg;
#endif
{
#ifdef _WIN32
    WaitForSingleObject(hEventSIGHUP, INFINITE);
    if (hEventSIGHUP != NULL)
        CloseHandle(hEventSIGHUP);
#endif

#ifdef DEBUG_TO_FILE
    fprintf(dbgout,"%d:  leave_erpcd called.\n",getpid());
#endif

    ErpcdExit(0);
}

#ifndef _WIN32
void koolaidfest(dummy)
int dummy;
{
    /* Tell all the other processes in my group to exit as well.
     * If I'm running in debug and I type ^C at my terminal, it will
     * send SIGINT to everyone and they'll all go away.  If I send
     * SIGTERM to everyone (including the shell) the shell goes away
     * and the user is logged out.
     */
    if(!debug)
	    kill(0, SIGTERM);

    ErpcdExit(0);
}
#endif

void erpcd_init()
{
    /* initialize secure annex cache for ACP (security) */

    secure_cache();
}
