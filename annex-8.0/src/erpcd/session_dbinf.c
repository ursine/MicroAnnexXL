/*****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Filename: session_dbinf.c
 *
 * Module Description: RADIUS database interface
 * 	
 * Design Specification: RADIUS Authorization 
 *
 * Author: Dave Mitton
 *
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *	DESIGN DETAILS
 *
 *	MODULE INITIALIZATION - 
 *		Initializes at parent task startup (global_init) or first invocation
 *       
 *	PERFORMANCE CRITICAL FACTORS - 
 *      This module depends on the lower level implementation to optimize
 *		performance.
 *
 *  RESOURCE USAGE - 
 *		This subsystem depends on the platform specific lower layer to implement
 *      the actual memory allocation
 *
 *	SIGNAL USAGE -
 *		none
 *
 *  SPECIAL EXECUTION FLOW - 
 *		Semaphores are used to prevent concurrent access when records are being
 *      added or deleted from the db.
 *
 * 	SPECIAL ALGORITHMS - 
 *		The data layout is designed so that readers will not be affected by a 
 *		concurrent operation.
 *
 ***************************************************************************
 */

/*
 *	INCLUDE FILES
 */

#include "../inc/config.h"
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "acp.h"
#include "../libannex/api_if.h"
#include "../inc/erpc/nerpcd.h"

#include "radius.h"
#include "acp_regime.h"
#include "acp_policy.h"
#include "environment.h"


/* instantiate my interface here */
#define DEFINE_HERE
#include "session_db.h"
#undef DEFINE_HERE

#include "session_db_i.h"

/*
 *	Static definitions
 *	
 */
static char	appname[] = "RADIUS DBinf";		/* component name for error logging	*/

/* Code conditionals */
#define DEBUG_PROTOS 1			/* define debug prototype code */
/*#define SYSDEBUG 1				* define system prototypes */

/* code for setting up debugging prototypes *!* ANSI C only */
#undef _						/* also defined in nerpcd.h */
#if (__STDC__ && DEBUG_PROTOS )
#define _(x)	x
#else
#define _(x)	()
#endif

/* for debugging on systems without system calls prototyped */
#if (__STDC__ && SYSDEBUG)
time_t time(time_t *tloc);
char *inet_ntoa(struct in_addr in);
void bzero(void *b, size_t len);
void bcopy(void *s1, void *s2, size_t len);
void syslog(int prio, char *format, ...);
int printf(char *format, ...);
#endif


/* external erpcd variables */
extern int debug;
extern int errno;
extern int raddb_up;
extern char *service_name[];	/* acp_lib.c */
extern char *event_name[];		/* acp_lib.c */
extern Radius_server *default_servers;	/* radius_config.c */
extern char xa2_service_type[];	/* radius_acct.c */
extern UINT32 nextses;          /* radius_acct.c */
extern int actfailed;           

/* external routines */
extern int get_security_regime _((struct environment_spec *env_p));		/* acp_regime.c */
extern void release_security_regime _((struct security_regime *regimep));
extern int get_time_stamp _((struct tm *intime));                       /* acp_lib.c */
extern char *port_to_name _((SECPORT *portd, char *name));  

extern	void display_mem _((char *buf, int len));	 /* radius_parser.c */


/*****************************************************************************
 *
 * NAME: ses_open_db
 *
 * DESCRIPTION: 
 *	Initialize the RADIUS session database
 *
 * ARGUMENTS:
 *	numrec - number of annexes to support
 *
 * RETURN VALUE:
 *	success/fail
 *
 * RESOURCE HANDLING:
 *	Allocates global system memory, and locking semaphores.
 *
 */
int
ses_open_db(numannex, tcpport) 
int numannex;
u_short tcpport;
{
    return (sesdb_init_db(numannex, tcpport));   /* call platform dependent init */
}

/*****************************************************************************
 *
 * NAME: ses_nas_reboot
 *
 * DESCRIPTION: 
 *	Annex reboot - clear all records for this NAS
 *
 * ARGUMENTS:
 *	nasaddr - address of NAS that rebooted
 *
 * RETURN VALUE:
 *	none
 *
 */
void
ses_nas_reboot(nasaddr) 
UINT32 nasaddr;
{
    if (debug) printf("%s: NAS Reboot %s\n",appname,inet_ntoa(*(struct in_addr *)&nasaddr)); 
    sesdb_nas_reboot(nasaddr);   /* call platform dependent init */
    return;
}

/*
 * NAME: ses_nas_down
 * DESCRIPTION:  indicate offline status of NAS to database
 *
 * ARGUMENTS: 
 *    nasaddr - address of NAS changing
 * RETURN VALUE: none
 * SIDE EFFECTS: 
 * 	Database marks Annex record inactive.
 *	Inactive records are timestamped and made eligible for deallocation
 *	Activity in the database resets the timestamp automatically
 */
void
ses_nas_down(nasaddr)
UINT32 nasaddr;
{
    if (raddb_up) {
        sesdb_connect(nasaddr, SDB_CONNECTION_DOWN);
    }
    return;
}

/*****************************************************************************
 *
 * NAME: ses_new
 *
 * DESCRIPTION: 
 *	save the information from this new authorization
 *
 * ARGUMENTS:
 *  envp - pointer to user environment block, contains all the context info
 *  msgp - pointer to radius message
 *
 * RETURN VALUE:
 *	0 - Success; record created, info added
 *  <1 - Error occured
 *
 * RESOURCE HANDLING:
 *	This function will do the necessary checks on NAS, Port, User before 
 *   creating the new record.
 *  This entails staleing an current active record, and freeing anything older.
 *   
 *  The native db functions are called to do the work.
 *  It's expected that a Logout will free the record.
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *   if database didn't init, fail
 *
 * ASSUMPTIONS:
 *	 
 */

int
ses_new(envp, msgp, opt_infop)
struct environment_spec *envp;
u_char *msgp;
struct arq_profile *opt_infop;
{
    NASPROFILE nprofile;
    SESPROFILE profile;
    struct attrib_handle ahndl;
	struct radius_attribute atrblk;
    u_char *aptr, *sptr;
    u_short alen, slen;

    if (!raddb_up) return -1;

    /* Move data into record format */
    nprofile.nasaddr = envp->annex;
    nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);

    bzero((char *)&profile, sizeof(profile));
    strncpy(profile.username, envp->username, sizeof(profile.username)-1);
    strncpy(profile.caller, opt_infop->calling_number, sizeof(profile.caller) -1);
    strncpy(profile.called, opt_infop->called_number, sizeof(profile.called) -1); 
 
	/* find attributes, and copy values out */
    if (msgp != NULL) {
        sptr = msgp;
        bcopy(sptr + 2, (char *)&slen, 2);
        sptr += AUTH_HDR_LEN;
        slen = ntohs(slen) - AUTH_HDR_LEN;
	    bzero((char *)&atrblk, sizeof(atrblk));

        /* fetch basic authorized attributes for accounting
         *  service-type;
         *      framed-protocol, f-ip-addr, 
         *      login-service, login-ip-host, login-tcp-port, 
         *  class
         */
        aptr = sptr;  alen = slen;
	    atrblk.type = PW_USER_SERVICE_TYPE;
	    if (radius_get_attribute(&aptr, &alen, &atrblk)) 
            profile.aservice = (u_char)atrblk.lvalue;
        aptr = sptr;  alen = slen;
        if (profile.aservice == PW_FRAMED_USER) {
	        atrblk.type = PW_FRAMED_PROTOCOL;
	        if (radius_get_attribute(&aptr, &alen, &atrblk)) 
                profile.aprotocol = (u_char)atrblk.lvalue;
	        atrblk.type = PW_FRAMED_ADDRESS;
	        if (radius_get_attribute(&aptr, &alen, &atrblk)) 
                profile.ataddr = *(struct in_addr *)&atrblk.lvalue;
        }
        else if (profile.aservice == PW_LOGIN_USER) {
	        atrblk.type = PW_LOGIN_SERVICE;
	        if (radius_get_attribute(&aptr, &alen, &atrblk)) {
                profile.aprotocol = (u_char)atrblk.lvalue;
 	            atrblk.type = PW_LOGIN_HOST;
	            if (radius_get_attribute(&aptr, &alen, &atrblk)) 
                    profile.ataddr = *(struct in_addr *)&atrblk.lvalue;
	            atrblk.type = PW_LOGIN_TCP_PORT;
	            if (radius_get_attribute(&aptr, &alen, &atrblk)) 
                    profile.aport = (u_short)atrblk.lvalue;
            }
            else {
                profile.aprotocol = 255;
            }
        }
        aptr = sptr;  alen = slen;
	    atrblk.type = PW_CLASS;
	    if (radius_get_attribute(&aptr, &alen, &atrblk)) {
            if(atrblk.length < (SDB_RADIUS_CLASS_SZ -1)){
                profile.class[0] = (u_char)atrblk.length;
                memcpy(profile.class + 1, atrblk.strvalp, atrblk.length);
            }
		    free(atrblk.strvalp);
        }
        if (debug>7) printf("%s: New profile Service=%i, Proto=%i, Addr=%s, Port=%i, Class='%.*s' size = %d\n", appname,
            profile.aservice, profile.aprotocol, inet_ntoa(profile.ataddr), profile.aport, (atrblk.length < (SDB_RADIUS_CLASS_SZ -1))? atrblk.length:SDB_RADIUS_CLASS_SZ -1, profile.class +1, atrblk.length);
    }

    /* create new record (NAS, Port, user) */
    if (sesdb_new_record(&nprofile, &profile, msgp) != SDB_SUCCESS) {
      if (debug >1)
	printf("%s: Create new record failed \n", appname);
      return -1;
    }
    if (debug > 1)
      printf("%s: Create record succeeded\n", appname);

    return 0;
}


/*****************************************************************************
 *
 * NAME: ses_lookup
 *
 * DESCRIPTION: 
 *	Find session record in database
 *
 * ARGUMENTS:
 *	envp = pointer to environment block
 *  sesp = address of a session block to copy data to
 *  flag - lookup modifier; 0=active port only, 1=active user, 2=user match, stale if any
 *
 * RETURN VALUE:
 *	Session match return code {SESDB...}
 *   0= failure, >0 type of record found
 *
 * SIDE EFFECTS:
 *	none
 * 
 * EXCEPTIONS:
 *  errors in data state return NULL
 *
 * ASSUMPTIONS:
 *
 */

int
ses_lookup(envp, sesp, sflag)
struct environment_spec *envp;
struct profileses *sesp;
int sflag;
{
  NASPROFILE nprofile;
  SESPROFILE profile;
  SESPROFILE *rsesp;
  char *rtnattrib;
  SESREC *rtnrecord;
  int rc;
  
  if (!raddb_up) return 0;

  if (debug >1) 
    printf("%s: Lookup [%s] Port %d.%d  '%s'  flag=%d\n", appname, 
	   inet_ntoa(*(struct in_addr *)&envp->annex), envp->ptype, envp->port, envp->username, sflag);
  
  /* Move search data into record format */
  nprofile.nasaddr = envp->annex;
  nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);
  strncpy(profile.username, envp->username, sizeof(profile.username)-1);
  
  /* call db lookup function */
  if (rc = sesdb_find_record(&nprofile, &profile, &rsesp, &rtnattrib, &rtnrecord, sflag)) {
  
      if (sesp != NULL) 
        memcpy(sesp, rsesp, sizeof(struct profileses)); /* copy data back to caller */

      /* release the record lock */
      sesdb_release_record(rtnrecord);
  }

  /* return profile info */
  return (rc); 
}

/*****************************************************************************
 *
 * NAME: ses_update
 *
 * DESCRIPTION: 
 *	Update session record in database
 *
 * ARGUMENTS:
 *	envp = pointer to environment block
 *  sesp = address of a session block to copy data from
 *  flag - lookup modifier; 0=active port only, 1=active user, 2=user match, stale if any
 *  uflag - type of update, as needed
 *
 * RETURN VALUE:
 *	Session match return code {SESDB...}
 *   0= failure, >0 type of record found
 *
 * SIDE EFFECTS:
 *	db record updated
 * 
 * EXCEPTIONS:
 *  errors in data state return NULL
 *
 * ASSUMPTIONS:
 *
 */

int
ses_update(envp, sesp, sflag, uflag)
struct environment_spec *envp;
struct profileses *sesp;
int sflag;
int uflag;
{
  NASPROFILE nprofile;
  SESPROFILE profile;
  SESPROFILE *rsesp;
  char *rtnattrib;
  SESREC *rtnrecord;
  int rc;
  
  if (!raddb_up) return 0;

  if (debug >1) 
    printf("%s: Update [%s] Port %d.%d  '%s'  flag=%d\n", appname, 
	   inet_ntoa(*(struct in_addr *)&envp->annex), envp->ptype, envp->port, envp->username, sflag);
  
  /* Move search data into record format */
  nprofile.nasaddr = envp->annex;
  nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);
  strncpy(profile.username, envp->username, sizeof(profile.username)-1);
  
  /* call db lookup function */
  if (rc = sesdb_find_record(&nprofile, &profile, &rsesp, &rtnattrib, &rtnrecord, sflag)) {
  
      if (sesp != NULL) {
	switch (uflag) {
	
	/* update ppp address */
	case EVENT_NEGO_ADDR:
		if (rsesp->aservice == 0) rsesp->aservice = sesp->aservice;
		rsesp->aprotocol = sesp->aprotocol;
		rsesp->ataddr = sesp->ataddr;
		break;
	}
      }
      /* release the record lock */
      sesdb_release_record(rtnrecord);
  }
  /* return lookup status */
  return (rc); 	
}

/*****************************************************************************
 *
 * NAME: ses_get_attribute
 *
 * DESCRIPTION: 
 *	return RADIUS attribute requested
 *
 * ARGUMENTS:
 *	envp = ptr to environment block
 *  offset = offset in message parsed so far
 *  attrib = ptr to attribute block
 *
 * RETURN VALUE:
 *   0 = User Not found
 *	>0 = Success, Attribute returned
 *  -1 = Attribute Not found
 *
 * RESOURCE HANDLING:
 * SIDE EFFECTS: none
 * EXCEPTIONS: none
 *
 * ASSUMPTIONS:
 *	attributes are in a raw RADIUS packet
 *  VSAs are accessed via additional argument
 *	for packets where multiple occurances are expected, loop until not found
 */
int 
ses_get_attribute(envp, attrib, offset)
struct environment_spec *envp;
struct radius_attribute *attrib;
int *offset;
{
    NASPROFILE nprofile;
    SESPROFILE profile;
    SESPROFILE *rsesp;
    struct sesdb *rtnrecord;
    struct attrib_handle ahndl;
    u_char *msgptr;
    u_short msglen;
    int rc;
    
    if (!raddb_up) return 0;

    /* Move search data into record format */
    nprofile.nasaddr = envp->annex;
    nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);
    strncpy(profile.username, envp->username, sizeof(profile.username)-1);
  
    /* call db lookup function */
    if (rc = sesdb_find_record(&nprofile, &profile, &rsesp, &msgptr, &rtnrecord, SDB_FINDACTIVEUSER) == SDB_NO_MATCH)
          return 0;      /* if not found, bail */

    /* get pointer to attribute list */
    if ((msgptr == NULL) || (msgptr[0] == 0)) {
        rc = -1;
    } 
    else {
        /* fetch up the message length and point to start of attributes */
        ahndl.aptr = msgptr;   
        bcopy(ahndl.aptr + 2, (char*)&msglen, 2);
        ahndl.aptr += AUTH_HDR_LEN;
        msglen = ntohs(msglen);
        ahndl.alen = msglen - AUTH_HDR_LEN;
 
        if (ahndl.alen <3) {
            rc = -1;
        } 
        else {
            /* if we have an offset use it */
            if (*offset >= msglen) /* we've reached the end of the message */
                rc = -1;
            else {
                if ((*offset > 0) && (*offset < msglen)) { 
                    ahndl.aptr = msgptr + *offset;
                    ahndl.alen = msglen - *offset;
                }
        
		if(debug)
                printf("ahndl.aptr = %x, ahndl.alen = %d\n", ahndl.aptr, 
                       ahndl.alen);
                /* parse out attribute value, returning value to user
                   attrib block */
                if (rc = radius_get_attribute(&ahndl.aptr, &ahndl.alen,
                                              attrib))
                    *offset = ahndl.aptr - msgptr; /* return offset */
            }
        }
    }

    sesdb_release_record(rtnrecord);    /* release db */

    return(rc);
}

/* 
 * Check if radius regime user
 *
 * Returns: 1 = Yes
 *          0 = No
 *
 */

int
ses_radius_check(envp)
struct environment_spec *envp;
{
    int rc;
    char *tptr;

if(debug>8) printf("in ses_radius_check\n");

    /* establish that this is a RADIUS user */
    /* Unix: go search profile file */
    /* WIN32, consult registry switch */
    rc = 1;
    if (get_security_regime(envp)) {
        if (envp->regime) {
	        if (debug) {
	            tptr = ((envp->regime->regime_mask == RADIUS_MASK) ? "RADIUS" : "Not RADIUS");
	            printf("%s: got regime %p, mask= %0X: %s\n", 
		        appname, envp->regime, envp->regime->regime_mask, tptr);
	        }
          
	        /* found a regime; if RADIUS - extract server address */
	        if (envp->regime->regime_mask != RADIUS_MASK)  rc = 0;
	
	        release_security_regime(envp->regime);	/* free dynamic structure */
        }
        else {
	        rc = 0;
	        if (debug) 	printf("%s: regime pointer is null!\n", appname);
        }
    }
    else {
        if (debug) 
	        printf("%s: failed to find security regime info for user '%s'\n", appname, envp->username);
        syslog(LOG_WARNING, "%s: failed to find security regime info for user %s", appname, envp->username);
        rc = 0;
    }     
    return rc;
}

/* Initialize login record
 * 
 * Arguments:
 *      sesp = pointer to session buffer to init
 *      envp = pointer to environment spec
 *      logid = session log id number assigned
 * Returns:
 *      0 = success
 *      -1 = error (server lookup)
 */
int
ses_login_rec(sesp, envp, logid)
struct profileses *sesp;
struct environment_spec *envp;
UINT32 logid;
{
if (debug > 8) printf("in ses_login_rec\n");

    /* fill in login record data */
    sesp->sesid = (logid & 0xFFFF0000) | (++nextses & 0x0000FFFF); 
    sesp->starttime = time(NULL);		
	sesp->iservice = envp->protocol;
	sesp->actses = 1;
	sesp->totses = 1;

    /* fetch from default servers definition (read once from erpcd.conf) */
	if (default_servers != NULL) {
		sesp->srvaddr.s_addr = default_servers->acct_server.s_addr;
		if (sesp->srvaddr.s_addr == 0) 
			sesp->srvaddr.s_addr = default_servers->auth_server.s_addr;
	}
	else {
		if (debug) printf("%s: No RADIUS Server defined in erpcd.conf!\n", appname);
		syslog(LOG_CRIT, "%s: No RADIUS Server defined in erpcd.conf", appname);
		actfailed = 1;		/* shut off accounting */
		return -1;
	}
	/* recptr->status |= SDB_ISLOGGEDIN; */
    return 0;
}

/*****************************************************************************
 *
 * NAME: ses_login
 *
 * DESCRIPTION: 
 *	session lookup for login events
 *  Find the record, update the data, make a copy for the user, release
 *
 * ARGUMENTS:
 *  envp - user environment
 *  sesp - pointer to user data copy
 *  logid - acp log sequence number
 *
 * RETURN VALUE:
 *	 0= Success - Do RADIUS thing, record updated, copy of data in sesp 
 *   1= Ignore - RADIUS, but don't do anything else with this event
 *  -1= Not RADIUS (handle by other means if possible)
 *
 * RESOURCE HANDLING:
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *  if user not found, check for if in RADIUS regime, and create temp if so
 *
 * ASSUMPTIONS:
 *
 */
int
ses_login(envp, sesp, logid)
struct environment_spec *envp;
struct profileses *sesp;
UINT32 logid;
{
    NASPROFILE nprofile;
    SESPROFILE profile;
    SESPROFILE *rsesp;
	SESREC *recptr;
	char stype;
    char *msgptr;
    
    /* Move search data into record format */
    nprofile.nasaddr = envp->annex;
    nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);
    strncpy(profile.username, envp->username, sizeof(profile.username)-1);

if (debug>8) printf("in ses_login: user='%s'\n",profile.username);
  
    /* call db lookup function */
    if (sesdb_find_record(&nprofile, &profile, &rsesp, &msgptr, &recptr, SDB_FINDSTALEUSER) == SDB_NO_MATCH) {

    /* check the timestamp on the stale record, may want to use active ?? or otherway around */
    /* only makes sense if using annex timestamps, not local time */
    /* if using local time, always logout oldest user match */
#ifdef ANNEXTIMESTAMPS
        if (sesp != NULL) {
            /* yes, something here */
            /* is it older than now? */
            if (sesp->logintime < envp->time) {
	        /*             yes, ignore it  */
            }
        }
#endif
        /* now look for active */
        if (sesdb_find_record(&nprofile, &profile, &rsesp, &msgptr, &recptr, SDB_FINDACTIVEUSER) == SDB_NO_MATCH) {

	if (debug>8) printf ("ses_login: lookups failed\n");

            /* didn't find anything, check regime */
            if (ses_radius_check(envp)) {
                /* is RADIUS; create temp record */
                if (sesdb_new_record(&nprofile, &profile, NULL) == SDB_FAILED) 
                    return SDB_FAILED;
                if (sesdb_find_record(&nprofile, &profile, &rsesp, &msgptr, &recptr, SDB_FINDACTIVEUSER) == SDB_NO_MATCH)
                    return SDB_FAILED;                   
            }
            else
                return SDB_NOTRADIUS;
        }
    }

	 /* If Login type service, this is nested inside of CLI session for start/stop purposes */
    stype = xa2_service_type[envp->protocol];   /* event service type */
	if (stype == PW_LOGIN_USER) {
        sesdb_release_record(recptr);
		return SDB_IGNORE;
    }

    /* if sescount = 0, init this record */
	if (rsesp->actses == 0) {
        ses_login_rec(rsesp, envp, logid);
	}
	else {
		rsesp->actses++;		/* bump the session count */
        sesdb_release_record(recptr);
		return SDB_IGNORE;
	}

    /* return session data copy to caller */
    memcpy(sesp, rsesp, sizeof(SESPROFILE));

    /* release db record */
    sesdb_release_record(recptr);

    return SDB_SUCCESS;
}

/*****************************************************************************
 *
 * NAME: ses_logout
 *
 * DESCRIPTION: 
 *	session lookup for logouts
 *	called by radius_acct for logout events
 *
 * ARGUMENTS:
 *  envp - user environment
 *  sesp - pointer to structure to receive session data
 *  logid - acp log sequence number
 *
 * RETURN VALUE:
 *	Success - Do RADIUS thing, active record data returned
 *  Ignore - Don't do anything else
 *  Not - Not RADIUS (handle by other means if possible)
 *  Error - something failed
 *
 * RESOURCE HANDLING:
 *	This function does not delete the matched record, that should be done by the
 *  caller afterwards.
 *	This function does delete stale records "below" the matched record on the port.
 *
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *	if session not found: figure out if this is a RADIUS session, and 
 *	   create temp if so.
 *  LOOKOUT for null timestamps (Active not logged in yet)
 *
 * ASSUMPTIONS:
 *	Logouts are serialized by Annex.  
 *	Stale login timestamps should pre-date the active login timestamp
 *	A logout will clear older records (stale or active).
 *	
 *
 */
int 
ses_logout(envp, sesp, event, logid)
struct environment_spec *envp;
struct profileses *sesp;
int event;
UINT32 logid;
{
  NASPROFILE nprofile;
  SESPROFILE profile;
  SESPROFILE *rsesp;
  SESREC *recptr;
  char stype;
  char *tptr;
  int rc;

    
    /* Move search data into record format */
    nprofile.nasaddr = envp->annex;
    nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);
    strncpy(profile.username, envp->username, sizeof(profile.username)-1);
  
     /* look for user match on stale first */ 
    if (sesdb_find_record(&nprofile, &profile, &rsesp, NULL, &recptr, SDB_FINDSTALEUSER) == SDB_NO_MATCH) {

    /* check the timestamp on the stale record, may want to use active ?? or otherway around */
    /* only makes sense if using annex timestamps, not local time */
    /* if using local time, always logout oldest user match */
#ifdef ANNEXTIMESTAMPS
        if (sesp != NULL) {
            /* yes, something here */
            /* is it older than now? */
            if (sesp->logintime < envp->time) {
	        /*             yes, ignore it  */
            }
        }
#endif
        /* now look for active */
        if (sesdb_find_record(&nprofile, &profile, &rsesp, NULL, &recptr, SDB_FINDACTIVEUSER) == SDB_NO_MATCH) {

            /* didn't find anything, check regime */
            if (ses_radius_check(envp)) {
                /* is RADIUS; create temp record */
                if (sesdb_new_record(&nprofile, &profile, NULL) == SDB_FAILED) 
                    return SDB_FAILED;
                if (sesdb_find_record(&nprofile, &profile, &rsesp, NULL, &recptr, SDB_FINDACTIVEUSER) == SDB_NO_MATCH)
                    return SDB_FAILED;                   
                ses_login_rec(rsesp, envp, logid);   /* init the session block */
            }
            else
                return SDB_NOTRADIUS;
        }
    }

    /* now we have a user match (or a temp record) */
    rc = SDB_IGNORE;

	/* If Login/terminal type service, this is nested inside of CLI session for start/stop purposes */
	/* NOTE: This could be fixed by some sort of nested or multisession logging, except that they are 
	 * not guaranteed to be symetric.  That is, a logins don't always get matching logouts.  */

    stype = xa2_service_type[envp->protocol];   /* event service type */
    if (stype == PW_LOGIN_USER) goto logout_release;
    
    /* For RADIUS session stops, In the following cases we use the ACCT event instead of LOGOUT:
	 * not if service_from == SERVICE_PORTS
	 *	yes if port_from_type == DEV_VIRTUAL
	 *		or service_from == {TELNET, RLOGIN, CONNECT}
	 * Indicate to standard logging that this is an ignored but RADIUS event
	 */
	if (event == EVENT_LOGOUT) {
		if (envp->protocol == SERVICE_PORTS) goto logout_release;
		if (!((envp->ptype == DEV_VIRTUAL) ||
			  ((envp->protocol == SERVICE_TELNET) || 
			   (envp->protocol == SERVICE_RLOGIN) || 
			   (envp->protocol == SERVICE_CONNECT)))) goto logout_release;
	}	

	/* if a nested login/logout, ignore this event */
	if (rsesp->actses > 1) {
		rsesp->actses--;
		goto logout_release;
	}

    /* return session data copy to caller */
    memcpy(sesp, rsesp, sizeof(SESPROFILE));
    rc = SDB_SUCCESS;


    /* release the record */
logout_release:
    sesdb_release_record(recptr);

    return rc;
}


/*****************************************************************************
 *
 * NAME: ses_delete
 *
 * DESCRIPTION: 
 *	Delete the session. Called after logout delivered
 *
 * ARGUMENTS:
 *  envp = pointer to session environment block
 *	sesp = pointer to session profile
 *
 * RETURN VALUE:
 *	none
 *
 * RESOURCE HANDLING:
 *	The session record is deallocated.
 *
 * SIDE EFFECTS:
 * EXCEPTIONS:
 * ASSUMPTIONS:
 */

void
ses_delete(envp, sesp)
struct environment_spec *envp;
struct profileses *sesp;
{
  NASPROFILE nprofile;

  nprofile.nasaddr = envp->annex;
  nprofile.nasport = (UINT32)envp->port + ((UINT32)envp->ptype << 16);

  if (sesp != NULL)
    sesdb_del_record(&nprofile, sesp);
  return;
}

/*****************************************************************************
 *
 * NAME: ses_close_db
 *
 * DESCRIPTION: 
 *	Close the database
 *
 * ARGUMENTS:
 *	none
 *
 * RETURN VALUE:
 *	
 *
 * RESOURCE HANDLING:
 *	The session database is removed from the system.
 *
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 * *!* needed?? only for parent?
 */
 
void
ses_close_db() 
{
  /* call the platform function to do this */
  sesdb_close_db();
  return;
}



