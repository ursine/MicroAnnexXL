/*****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 *     %$(Description)$%
 *
 * Detailed Design Specification:
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 * Module Reviewers:
 *    %$(reviewers)$%
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *    DESIGN DETAILS
 *   This library contains functions for sending and parsing RACP PDUs
 *
 *    MODULE INITIALIZATION -
 *   All functions require a connected ACP link
 *
 *    PERFORMANCE CRITICAL FACTORS -
 *
 *      RESOURCE USAGE -
 *       Needs to allocate/free large buffers for parsing/building
 *
 *    SIGNAL USAGE -
 *
 *      SPECIAL EXECUTION FLOW -
 *
 *     SPECIAL ALGORITHMS -
 *
 ***************************************************************************
 */


/*
 *    INCLUDE FILES
 */

#ifdef ANNEX
#include "udas.h"

#include "types.h"
#include "externs.h"
#include "param.h"
#include "errno.h"
#include "socket.h"
#include "strings.h"
#include "malloc.h"
#include "syslog.h"
#include "stdio.h"
#include "../netinet/in.h"
#include "../courier/courier.h"
#include "../erpc/erpc.h"
#include "../erpc/erpc_annex.h"
#include "../srpc/srpc.h"
#include "erpc/nerpcd.h"
#include "../acp/acp_types.h"
#include "../acp/acp.h"
#include "asn1.h"

#else /* ANNEX */
#include "../inc/config.h"
#include "../inc/vers.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/time.h>
#else
#include <process.h>
#include "../ntsrc/acplog/acplogmsg.h"
#endif
#include <signal.h>

#include "../libannex/api_if.h"
#include "../inc/erpc/netadmp.h"

#include "../inc/port/install_dir.h"
#include "../inc/erpc/nerpcd.h"
#define USE_CLIENT_REC
#include "acp.h"
#include "acp_policy.h"
#include "errno.h"
#include "../libannex/asn1.h"
#include "getacpuser.h"

#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#endif /* _WIN32 */

extern int debug;
extern StructErpcdOption *ErpcdOpt;

extern int child_count,child_max,child_rejects;
extern int deny_all_users;

#ifndef _WIN32
extern struct clientrec clientrec[];
#endif

#endif /* ANNEX */

/*
 *    CONSTANT AND MACRO DEFINES
 *    - Comment those that are external interfaces
 */

/* #define DEBUG_ACP 1 */

#define MAXPDUHEAD 4

#define USE_HTTP

/*
 *    STRUCTURE AND TYPEDEF DEFINITIONS
 *    - Comment those that are external interfaces
 */

/*
 *    GLOBAL DATA DECLARATIONS
 */

/*
 *    STATIC DATA DECLARATIONS
 */

/*
 *    Forward Function Definitions
 *     - Follow ANSI prototype format for ALL functions.
 */


/*****************************************************************************
 *
 * NAME: racp_create_strlist
 *
 * DESCRIPTION: Creates an RACP string list element
 *
 * ARGUMENTS:
 *   buffer - buffer holding string
 *   length - length of string without termination, 0 means empty string
 *
 * RETURN VALUE: the new strlist element, NULL if error
 *
 * RESOURCE HANDLING:  mallocs a strlist element.  can be freed by
 *                     racp_destroy_strlist
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
STR_LIST *racp_create_strlist(buffer, length)
char *buffer;
u_short length;
{
    STR_LIST *new;
    int size;

    if (buffer == NULL && length != 0)
        return(NULL);

    if (length < 2)
        size = sizeof(STR_LIST);
    else
        size = sizeof(STR_LIST) + length - 1;

    if ((new = (STR_LIST*)malloc(size)) == NULL)
        return(NULL);

    new->next = NULL;
    new->strlen = length;
    if (length == 0)
        bzero(new->str, 2);
    else {
        bcopy(buffer, new->str, length);
        new->str[length] = '\0';
    }

    return(new);
}


/*****************************************************************************
 *
 * NAME: racp_destroy_strlist
 *
 * DESCRIPTION:  Destroys an RACP string list element
 *
 * ARGUMENTS:
 *   strlist - string list element to destroy
 *
 * RETURN VALUE: the next strlist element, NULL if none
 *
 * RESOURCE HANDLING:  frees a strlist element created by racp_create_strlist
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
STR_LIST *racp_destroy_strlist(strlist)
STR_LIST *strlist;
{
    STR_LIST *next = NULL;
    int size;

    if (strlist) {
        next = strlist->next;
        if (strlist->strlen == 0)
            size = sizeof(STR_LIST);
        else
            size = sizeof(STR_LIST) + strlist->strlen - 1;

        RACP_FREE(strlist, size); /* macro def in src/inc/erpc/nerpcd.h */
    }

    return(next);
}


/*****************************************************************************
 *
 * NAME: racp_destroy_strlist_chain
 *
 * DESCRIPTION:  Destroys an RACP string list chain
 *
 * ARGUMENTS:
 *   strlist - string list chain to destroy
 *
 * RETURN VALUE:
 *
 * RESOURCE HANDLING:  frees a strlist chain
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void racp_destroy_strlist_chain(strlist)
STR_LIST *strlist;
{
    STR_LIST *next;

    for (next = strlist; ((next = racp_destroy_strlist(next)) != NULL););

    return;
}

void cipher();
void random_key();

/*
 * write log message to syslog or NT event log  *
 *
 */
void writesyslog(pri, str)
int pri;
char* str;
{
#if defined(USE_SYSLOG) || defined(ANNEX)
#ifndef ANNEX
		if (ErpcdOpt->UseSyslog)
#endif
		{
			syslog(pri, str);
		}
#endif /* USE_SYSLOG */
}

/*****************************************************************************
 *
 * NAME: racp_init_conn
 *
 * DESCRIPTION:
 *  Initiates an RACP connection
 *
 *  This function will be called by:
 *
 * ARGUMENTS:
 *  acp - pointer to ACP_STATE structure for this connection
 *
 * RETURN VALUE: errno_t
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
/ *
 */

errno_t racp_init_conn(acp)
caddr_t acp;
{
    int rcode;
    KEY rand, response;
    u_short options;
    u_char version[2];
    u_short nusage, ncapability, noptions;

    /* Sanity checks */
    if (!acp || !RACP_SOCKET(acp))
        return(EINVAL);

#ifndef ANNEX
    SETNEGO(((ACP*)acp)->state);
#endif
    RACP_USAGE(acp) = NU_SECURITY;
    RACP_CAP(acp) = CAP_GLOBAL;
    RACP_OPTIONS(acp) = NO_DATAENC;
#ifdef ANNEX
    RACP_SHARED_KEY(acp) = keytab[ACP_PROG];
#else
    {
        struct in_addr haddr;
        haddr.s_addr = RACP_PEER_ADDR(acp);
        /*RACP_SHARED_KEY(acp) = annex_key(haddr);*/
        (((ACP*)acp)->key) = annex_key(haddr.s_addr);
    }
#endif
    nusage = htons(NU_SECURITY);
    ncapability = htons(CAP_GLOBAL);

    version[0] = RACP_LO_VER;
    version[1] = RACP_HI_VER;

    /* Send usage code */
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), &nusage,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    /* Send capability mask */
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), &ncapability,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    /* Send low/high version */
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), version, sizeof(u_char) * 2))
        != ESUCCESS)
        return(rcode);

	{
		char syslogbuf[256];
		sprintf(syslogbuf, "RACP Init: Request Usage SECURITY Capability ENIGMA Version %d-%d",
			RACP_LO_VER, RACP_HI_VER);
		writesyslog(LOG_DEBUG, syslogbuf);
	}

#ifndef ANNEX
    if (debug > 1)
#endif
      {
#if defined(DEBUG_ACP) || !defined(ANNEX)
    printf("RACP Init: Request Usage SECURITY Capability ENIGMA Version %d-%d\n",
           RACP_LO_VER, RACP_HI_VER);
#endif
  }

    /* receive random identifier */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), rand, KEYSZ))
        != ESUCCESS)
        return(rcode);

    /* receive new capability mask */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &ncapability,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    RACP_CAP(acp) = ntohs(ncapability);

    if (RACP_SHARED_KEY_SET(acp) && !RACP_CAP(acp)) {

		writesyslog(LOG_ERR,  "RACP Init: Capability request denied by host RACP");

#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Init: Capability request denied by host RACP\n");
#endif
	  }
        return(EACCES);
    }

    /* receive options mask */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &noptions,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    options = ntohs(noptions);
    RACP_OPTIONS(acp) &= options;
    if (RACP_SHARED_KEY_SET(acp)) {
        if (!(RACP_OPTIONS(acp) & NO_DATAENC)) {

			writesyslog(LOG_ERR, "RACP Init: No Remote Encryption.  Connection dropped\n");

#ifndef ANNEX
            if (debug)
#endif
	      {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Init: No Remote Encryption.  Connection dropped\n");
#endif
	  }
            return(EACCES);
        }
    }
    else {
		writesyslog(LOG_DEBUG, "RACP Init: Session not encrypted");
#ifndef ANNEX
        if (debug > 1)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Init: Session not encrypted\n");
#endif
	  }
        RACP_OPTIONS(acp) &= ~NO_DATAENC;
    }

    /* receive version */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &RACP_VERSION(acp),
                               sizeof(u_char))) != ESUCCESS)
        return(rcode);

    /* generate and send encrypted response */
    if (RACP_SHARED_KEY_SET(acp))
        cipher(rand, rand, KEYSZ, RACP_SHARED_KEY(acp));
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), rand, KEYSZ))
        != ESUCCESS)

    random_key(rand);
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), rand, KEYSZ))
        != ESUCCESS)
        return(rcode);

    /* send options */
    noptions = htons(RACP_OPTIONS(acp));
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), &noptions,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    /* receive back encrypted rand */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), response, KEYSZ))
        != ESUCCESS)
        return(rcode);

    if (RACP_SHARED_KEY_SET(acp))
        cipher(response, response, KEYSZ, RACP_SHARED_KEY(acp));
    if (memcmp(response, rand, KEYSZ)) {
			writesyslog(LOG_ERR, "RACP Init: Encryption error.  Connection dropped");
#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Init: Encryption error.  Connection dropped\n");
#endif
	  }
        return(EACCES);
    }

    if (RACP_OPTIONS(acp) & NO_DATAENC) {

        /* generate the new xmit key */
        random_key(rand);
        RACP_MAKE_KEY(rand, RACP_SEND_KEY(acp));
        cipher(rand, rand, KEYSZ, RACP_SHARED_KEY(acp));
        if ((rcode = racp_send_raw(RACP_SOCKET(acp), rand, KEYSZ))
            != ESUCCESS)
            return(rcode);

        /* read and decrypt new receive key */
        if ((rcode = racp_recv_raw(RACP_SOCKET(acp), rand, KEYSZ))
            != ESUCCESS)
            return(rcode);

        cipher(rand, rand, KEYSZ, RACP_SHARED_KEY(acp));
        RACP_MAKE_KEY(rand, RACP_RECV_KEY(acp));

    }
    else {
        RACP_NULL_KEY(RACP_RECV_KEY(acp));
        RACP_NULL_KEY(RACP_SEND_KEY(acp));
    }

#ifndef ANNEX
    CLRNEGO(((ACP*)acp)->state);
    SETCONN(((ACP*)acp)->state);
#endif
	writesyslog(LOG_DEBUG, "RACP Enters data phase");
#ifndef ANNEX
    if (debug > 1)
#endif
      {
#if defined(DEBUG_ACP) || !defined(ANNEX)
        printf("RACP Enters data phase\n");
#endif
      }
    return(ESUCCESS);
}


#ifndef _WIN32
#ifndef ANNEX
#ifdef USE_HTTP
int
run_httpd(sock)
int sock;
{
  FILE *outfp = fdopen(sock,"w");
  FILE *infp = fdopen(sock,"r");
  char buffer[128];
  int i;

  fgets(buffer,sizeof(buffer),infp);
  if (buffer[0] == 'S')
    return 0;
  if (buffer[0] != 'T')
    return 0;
  if (strncmp(buffer+2,"/reread",7) == 0) {
    kill(getppid(),SIGUSR1);
    fprintf(outfp,"HTTP/1.0 204 No Content\n");
    return 0;
  }
  fprintf(outfp,"HTTP/1.0 200 OK\n\
\n\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML//EN//2.0\">\n\
<html><head>\n\
<title>ERPCD</title>\n\
</head><body>\n\
Security/boot server running as pid %d.<br>\n\
Version %s (%s).  Debug level set to %d.<br>\n\
%d child process(es) active out of a maximum of %d.<br>\n\
Security files in %s; file service from %s\n",
	  getppid(),VERSION,RELDATE,debug,child_count,child_max,
	  install_dir,root_dir);
  if (child_rejects > 0)
    fprintf(outfp,"<bold>%d requests denied due to maximum child count.</bold><br>\n",
	    child_rejects);
  fprintf(outfp,"<hr>\n");
  for (i = 0; i < child_count; i++)
    fprintf(outfp,"<a href=\"http://%s/\">host %s port %d</a> - system using %s security; server process ID %d<br>\n",
	    inet_ntoa(clientrec[i].host),
	    inet_ntoa(clientrec[i].host),
	    clientrec[i].port,
	    (clientrec[i].tcpflag ? "RACP" : "ACP"),
	    clientrec[i].pid);
  fprintf(outfp,"<hr><a href=\"reread\">Reload acp_userinfo database.</a><br>");
  if (deny_all_users)
    fprintf(outfp,"<hr><p><center><strong>All users are now being denied access to this system due to configuration errors.</strong></center>");
  fprintf(outfp,"<hr></body></html>\n");
  return 0;
}
#endif
#endif
#endif

/*****************************************************************************
 *
 * NAME: racp_accept_conn
 *
 * DESCRIPTION:
 *  This function negotiates the RACP start-up phase from the target's point
 *  of view
 *
 * ARGUMENTS:
 *  acp - pointer to an allocated ACP for this connection
 *    ERPCD:
 *    acp->s - accept()ed socket for this connection
 *    acp->racp - pointer to an allocated RACP
 *    acp->key - pointer to KEYDATA for acp_key (NULL if no key)
 *    acp->racp->rcv_key - pointer to KEYDATA for receive encryption
 *                         can be NULL if !(acp->racp->options & OPT_ENCRYPT)
 *                         (i.e. not encrypting data)
 *    acp->racp->send_key - pointer to KEYDATA for send encryption
 *                          can be NULL as per rcv_key
 *    acp->racp->capability - encryption capability mask
 *    acp->racp->options - protocol options mask
 *    acp->racp->version - highest version acceptable
 *    ANNEX:
 *    acp->cs - pointer to an allocated CONNECTION_STATE
 *    acp->cs->socket - accept()ed socket for this connection
 *    acp->cs->shared_key - pointer to KEYDATA for acp_key (NULL if no key)
 *    acp->cs->capability - encryption capability mask
 *    acp->cs->options - protocol options mask
 *    acp->cs->version - highest version acceptable
 *  lover - lowest version acceptable
 *
 * RETURN VALUE: errno_t
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

errno_t racp_accept_conn(acp, lover)
caddr_t acp;
u_char lover;
{
    int rcode;
    KEY rand, response;
    u_short usage, capability, options;
    u_char req_low, req_high;

    /* Get Usage code */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &usage, sizeof(u_short)))
        != ESUCCESS) {
	return(rcode);
    }
#ifndef ANNEX
    SETNEGO(((ACP*)acp)->state);
#endif
    usage = ntohs(usage);
#ifndef _WIN32
#ifndef ANNEX
#ifdef USE_HTTP
    if ((usage&0xDFDF) == 0x4745 || (usage&0xDFDF) == 0x504F)
      exit(run_httpd(RACP_SOCKET(acp)));
#endif
#endif
#endif
    if (usage != NU_SECURITY) {
		writesyslog(LOG_ERR, "RACP Accept: Security not requested.  Connection dropped.\n");
#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
        printf("RACP Accept: Security not requested.  Connection dropped.\n");
#endif
      }
	return(EACCES);
    }

    /* Get Capability mask, set it accordingly */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &capability, sizeof(u_short)))
        != ESUCCESS)
        return(rcode);
	{
		char syslogbuf[256];
		sprintf(syslogbuf, "RACP Accept: Received Capability%s%s%s",
			((ntohs(capability) & NC_CRYPT) ? " CRYPT" : ""),
			((ntohs(capability) & NC_DES) ? " DES" : ""),
			((ntohs(capability) & NC_ENIGMA) ? " ENIGMA" : ""));

		writesyslog(LOG_INFO, syslogbuf);
	}

#ifndef ANNEX
    if (debug > 1)
#endif
      {
#if defined(DEBUG_ACP) || !defined(ANNEX)
    printf("RACP Accept: Received Capability%s%s%s\n",
           ((ntohs(capability) & NC_CRYPT) ? " CRYPT" : ""),
           ((ntohs(capability) & NC_DES) ? " DES" : ""),
           ((ntohs(capability) & NC_ENIGMA) ? " ENIGMA" : ""));
#endif
  }

    RACP_CAP(acp) = (ntohs(capability) & RACP_CAP(acp));
    if (RACP_SHARED_KEY_SET(acp) && !RACP_CAP(acp)) {
		writesyslog(LOG_ERR, "RACP Init: No Remote Encryption.  Connection dropped\n");
#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Init: No Remote Encryption.  Connection dropped\n");
#endif
	  }
        return(EACCES); /* reject encryption desired but not negotiated */
    }

    /* Determine version number */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &req_low, sizeof(u_char)))
        != ESUCCESS)
        return(rcode);
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &req_high, sizeof(u_char)))
        != ESUCCESS)
        return(rcode);
    if (req_low > RACP_VERSION(acp) || req_high < lover) {
		{
			char syslogbuf[256];
			sprintf(syslogbuf, "RACP Accept: Version %d-%d rejected.  Need %d-%d",
               req_low, req_high, lover, RACP_VERSION(acp));
			writesyslog(LOG_ERR, syslogbuf);
		}
#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Accept: Version %d-%d rejected.  Need %d-%d\n",
                   req_low, req_high, lover, RACP_VERSION(acp));
#endif
	  }
        return(EACCES);
    }
    if (RACP_VERSION(acp) > req_high)
        RACP_VERSION(acp) = req_high;

    if (!RACP_SHARED_KEY_SET(acp))
        /* do not request encryption without acp_key -- spoofing! */
        RACP_OPTIONS(acp) &= ~NO_DATAENC;

	{
		char syslogbuf[256];
		sprintf(syslogbuf, "RACP Accept: Negotiated Version %d",
			RACP_VERSION(acp));
		writesyslog(LOG_ERR, syslogbuf);
	}
#ifndef ANNEX
    if (debug > 1)
#endif
      {
#if defined(DEBUG_ACP) || !defined(ANNEX)
        printf("RACP Accept: Negotiated Version %d\n", RACP_VERSION(acp));
#endif
      }

    /* generate and send random seed */
    if (RACP_SHARED_KEY_SET(acp)) {
        random_key(rand);
    }
    else
        bzero(rand, KEYSZ);

    if ((rcode = racp_send_raw(RACP_SOCKET(acp), rand, KEYSZ)) != ESUCCESS)
        return(rcode);

    /* send Capability mask */
    capability = htons(RACP_CAP(acp));
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), &capability,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    /* send options mask */
    options = htons(RACP_OPTIONS(acp));
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), &options,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);

    /* send version */
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), &RACP_VERSION(acp),
                               sizeof(u_char))) != ESUCCESS)
        return(rcode);

    /* read, decipher and verify seed response */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), response, KEYSZ))
        != ESUCCESS)
        return(rcode);
    if (RACP_SHARED_KEY_SET(acp)) {
        cipher(response, response, KEYSZ, RACP_SHARED_KEY(acp));
        if (memcmp(response, rand, KEYSZ)) {
			writesyslog(LOG_ERR, "RACP Accept: Encryption error.  Connection dropped");
#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
            printf("RACP Accept: Encryption error.  Connection dropped\n");
#endif
	  }
            return(EACCES); /* reject he does not know acp_key! */
        }
    }

    /* read new random seed */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), rand, KEYSZ)) != ESUCCESS)
        return(rcode);

    /* read negotiated options mask */
    if ((rcode = racp_recv_raw(RACP_SOCKET(acp), &options,
                               sizeof(u_short))) != ESUCCESS)
        return(rcode);
    RACP_OPTIONS(acp) = ntohs(options);
    if (RACP_SHARED_KEY_SET(acp) && !(RACP_OPTIONS(acp) & NO_DATAENC)) {
		writesyslog(LOG_ERR, "RACP Accept: No Remote Encryption.  Connection dropped\n");
#ifndef ANNEX
        if (debug)
#endif
	  {
#if defined(DEBUG_ACP) || !defined(ANNEX)
        printf("RACP Accept: No Remote Encryption.  Connection dropped\n");
#endif
      }
        return(EACCES);
    }

    /* encrypt initiators random seed and send back */
    if (RACP_SHARED_KEY_SET(acp))
        cipher(rand, rand, KEYSZ, RACP_SHARED_KEY(acp));
    if ((rcode = racp_send_raw(RACP_SOCKET(acp), rand, KEYSZ)) != ESUCCESS)
        return(rcode);

    if (RACP_OPTIONS(acp) & NO_DATAENC) {

        /* read and decrypt new receive key */
        if ((rcode = racp_recv_raw(RACP_SOCKET(acp), rand, KEYSZ)) != ESUCCESS)
            return(rcode);
        cipher(rand, rand, KEYSZ, RACP_SHARED_KEY(acp));
        RACP_MAKE_KEY(rand, RACP_RECV_KEY(acp));

        /* generate new send key and send it encrypted to initiator */
        random_key(rand);
        RACP_MAKE_KEY(rand, RACP_SEND_KEY(acp));
        cipher(rand, rand, KEYSZ, RACP_SHARED_KEY(acp));
        if ((rcode = racp_send_raw(RACP_SOCKET(acp), rand, KEYSZ)) != ESUCCESS)
            return(rcode);
    }
    else /* no encryption signified by NULL keys */ {
        RACP_NULL_KEY(RACP_SEND_KEY(acp));
        RACP_NULL_KEY(RACP_RECV_KEY(acp));
    }

    /* We made it this far without bugging out.  Done with set-up phase */
#ifndef ANNEX
    CLRNEGO(((ACP*)acp)->state);
    SETCONN(((ACP*)acp)->state);
#endif
	writesyslog(LOG_ERR, "RACP Enters data phase");
#ifndef ANNEX
    if (debug > 1)
#endif
      {
#if defined(DEBUG_ACP) || !defined(ANNEX)
        printf("RACP Enters data phase\n");
#endif
      }

    return(ESUCCESS);

}


#ifdef ANNEX
/*****************************************************************************
 *
 * NAME: racp_send_auth_req()
 *
 * DESCRIPTION: Sends an RACP authorization-request PDU to remote RACP
 *
 * ARGUMENTS:
 * caddr_t acp - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * u_short service_from - INPUT service user is on
 * u_short service_req - INPUT service user requests
 * SECPORT *port_from - INPUT port user is on
 * SECPORT *port_dest - INPUT user's destination port
 * ARQ_PROFILE *opt_info - Optional INPUT; fill in wanted fields
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_auth_req(acp, data, datalength, service_from, service_req,
                           port_from, port_dest, opt_info)
caddr_t acp;
u_char *data;
int datalength;
int service_from, service_req;
SECPORT *port_from, *port_dest;
ARQ_PROFILE *opt_info;
{
    u_char *pdu;

    /* build packet here */
    if ((pdu = racp_build_auth_req(data, &datalength, RACP_VERSION(acp),
                                   service_from, service_req, port_from,
                                   port_dest, opt_info)) == NULL)
        return(EINVAL);

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
}
#endif /*ANNEX*/


#ifndef ANNEX
/*****************************************************************************
 *
 * NAME: racp_send_auth_resp()
 *
 * DESCRIPTION: Sends an RACP authorization-response to the remote peer
 *
 * ARGUMENTS:
 * caddr_t acp; - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * u_long grant - INPUT status of authorization grant
 * any of the following can be NULL, in which case no segment is built
 * u_long *cli_mask - INPUT pointer to returned CLI command mask
 * u_long *hooks_mask - INPUT pointer to HOOKS mask
 * char *user_name - INPUT username of user
 * void *tms_info - INPUT tunnel info if tunnel user (tms_db_entry)
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_auth_resp(acp, data, datalength, grant, cli_mask, hooks_mask,
                        user_name, domain, tms_info)
caddr_t acp;
u_char *data;
int datalength;
u_long grant;
u_long *cli_mask;
u_long *hooks_mask;
char *user_name;
char *domain;
void *tms_info;
{
    u_char *pdu;

   if ((pdu = racp_build_auth_resp(data, &datalength, RACP_VERSION(acp), grant,
                                   cli_mask, hooks_mask, user_name,
				   domain, tms_info))
       == NULL)
       return(EINVAL);

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
}
#endif /*!ANNEX*/


#if defined(ANNEX) && (NUDAS > 0)
/*****************************************************************************
 *
 * NAME: racp_send_tms_req()
 *
 * DESCRIPTION: Sends an RACP TMS-request to the remote peer
 *
 * ARGUMENTS:
 * caddr_t acp	- INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalen  - INPUT valid size of buffer
 * UINT32 rasid	- INPUT ip address of the box
 * char *domain	- INPUT pointer to domain name
 * char *dnis	- INPUT pointer to dnis
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_tms_req(acp, data, datalen, rasid, domain, dnis)
caddr_t acp;
u_char *data;
int datalen;
UINT32 rasid;
char *domain;
char *dnis;
{
    u_char *pdu;

    if ((pdu = racp_build_tms_req(data, &datalen, RACP_VERSION(acp), rasid,
				  domain, dnis)) == NULL)
	return(EINVAL);

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
}
#endif /*ANNEX*/


/*****************************************************************************
 *
 * NAME: racp_send_info_req()
 *
 * DESCRIPTION: Sends an RACP information-request PDU to remote RACP
 *
 * ARGUMENTS:
 * caddr_t acp - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * u_short sf - INPUT service user is on
 * u_short sr - INPUT service user requests
 * SECPORT *pf - INPUT port user is on
 * SECPORT *pt - INPUT user's destination port
 * IRQ_PROFILE *opt_info - Optional INPUT; fill in wanted fields
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_info_req(acp, data, datalength, sf, sr, pf, pt, opt_info)
caddr_t acp;
u_char *data;
int datalength;
u_short sf, sr; /* sw intf from/requested */
SECPORT *pf, *pt;
IRQ_PROFILE *opt_info;
{
    u_char *pdu;

    if ((pdu = racp_build_info_req(data, &datalength, RACP_VERSION(acp), sf,
                                   sr, pf, pt, opt_info))
        == NULL)
        return(EINVAL);

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
}

/*****************************************************************************
 *
 * NAME: racp_send_info_resp()
 *
 * DESCRIPTION: Sends and RACP information-response PDU
 *
 * ARGUMENTS:
 * ACP *acp; - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * u_long grant - INPUT status of authorization grant
 * IRQ_PROFILE *opt_info - INPUT/OUTPUT - pointer to a structure of optional info
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_info_resp(acp, data, datalength, grant, opt_info)

caddr_t acp;
u_char *data;
int datalength;
u_long grant;
IRQ_PROFILE *opt_info;
{
    u_char *pdu;
    int retv;

    if ((pdu = racp_build_info_resp(data, &datalength, RACP_VERSION(acp),
                                    grant, opt_info)) == NULL) {
        return(EINVAL);
    }

    retv = racp_send_pdu(acp, data, (int)(pdu - data));
    return retv;
}


/*****************************************************************************
 *
 * NAME: racp_send_exec_req()
 *
 * DESCRIPTION: Sends an RACP execution-request PDU to remote RACP
 *
 * ARGUMENTS:
 * caddr_t acp - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * u_short service_from - INPUT service user is on
 * u_short service_req - INPUT service user requests
 * SECPORT *port_from - INPUT port user is on
 * ERQ_PROFILE *opt_info - Optional INPUT; fill in wanted fields
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_exec_req(acp, data, datalength, service_from, service_req,
                           opt_info)
caddr_t acp;
u_char *data;
int datalength, service_from, service_req;
ERQ_PROFILE *opt_info;
{
    u_char *pdu;

    if ((pdu = racp_build_exec_req(data, &datalength, RACP_VERSION(acp),
                                   service_from, service_req, opt_info)) == NULL) {
        return(EINVAL);
    }

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
}


/*****************************************************************************
 *
 * NAME: racp_send_exec_reply()
 *
 * DESCRIPTION: Sends an RACP execution-request PDU to remote RACP
 *
 * ARGUMENTS:
 * caddr_t acp - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * int grant - INPUT status of execution grant
 * SECPORT *port - INPUT port execution performed on
 * int *flags - INPUT pointer to flags mask for execution
 * char *text - INPUT extra information (VisibleString)
 *
 * RETURN VALUE: errno_t
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

errno_t racp_send_exec_reply(acp, data, datalength, grant, port, flags, text,
                             codep)
caddr_t acp;
u_char *data;
int datalength;
int grant;
SECPORT *port;
int *flags;
char *text;
int *codep;
{
    u_char *pdu;

    if ((pdu = racp_build_exec_reply(data, &datalength, RACP_VERSION(acp),
                                     grant, port, flags, text, codep)) == NULL)
        return(EINVAL);

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
}

/*****************************************************************************
 *
 * NAME: racp_send_ack()
 *
 * DESCRIPTION: Sends and RACP audit-log acknowledgement PDU
 *
 * ARGUMENTS:
 * ACP *acp; - INPUT connected acp
 * u_char *data - INPUT buffer to use
 * int datalength - INPUT valid size of buffer
 * u_long sequence - INPUT highest-numbered logid to ACK
 *
 * RETURN VALUE: errno_t
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
errno_t racp_send_ack(acp, data, datalength, sequence)
caddr_t acp;
u_char *data;
int datalength;
u_long sequence;
{
    u_char *pdu;

    if ((pdu = racp_build_ack(data, &datalength, RACP_VERSION(acp), sequence))
        == NULL)
        return(EINVAL);

    return(racp_send_pdu(acp, data, (int)(pdu - data)));
      
}


