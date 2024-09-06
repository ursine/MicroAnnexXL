/*
 *****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed MAterial - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 *	Security Policy - Annex Security Server - SafeWord Net API
 *
 * Original Author: Stan Ryckman	Created on: May 1996
 *
 * Module Reviewers:
 *
 *	?
 *
 * Revision Control Information:
 *
 * ?
 *
 * This file is currently under revision by:
 *
 * ??
 * $Locker:  $
 *
 *****************************************************************************
 */

/* acp_safeword.c -- erpcd functions for the new SafeWord NETWORKAPI. */

#ifdef _WIN32
#ifndef BAY_ALPHA   /* Safeword not supported on DEC Alpha */
#define ENIGMA_SAFEWORD
#define NET_ENIGMA_ACP
#endif
#endif /* _WIN32 */

#ifdef NET_ENIGMA_ACP

/* To have prototypes on or off: */

/* Set PROTOTYPING if user specifies -DPROTO or compiler is __STDC__ */
#if defined(PROTO) || defined(__STDC__) || defined(_WIN32)
/* SafeWord routines have their own idea of what PROTO should be */
#  ifdef PROTO
#      undef PROTO
#  endif
#  define PROTOTYPING 1
#endif

/* This makes prototypes easier to use or not */
#ifndef OF
#  if defined(__STDC__) || defined(PROTOTYPING)
#    define OF(args)  args
#  else
#    define OF(args)  ()
#  endif
#endif /* not OF */

/*********************************************************************/
/* Structure type for which we only need pointers */
	struct sockaddr_in;
/*********************************************************************/
/* Include files */
/*********************************************************************/
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#ifdef _WIN32
#include "../inc/port/port.h"
#include "../inc/rom/syslog.h"
#else /* not _WIN32 */
#include <syslog.h>
#endif /* not _WIN32 */

#include "acp.h"
#include "acp_policy.h"
#ifdef _WIN32
#undef PROTOTYPING	/* (buggy swecapi.h can't handle it) */
#endif /* _WIN32 */
#include "../enigma/swecapi.h"
/*********************************************************************/
/* Global data */
	extern int debug;
#ifdef _WIN32
	extern StructErpcdOption *ErpcdOpt;   /* Defined in erpcd.c
					* Handles logging options for
					* acp logging.
					*/
#endif /* _WIN32 */
/*********************************************************************/
/* These are prototypes for erpcd functions called from herein. */
/*********************************************************************/
	void acp_strip_hyphens	OF(( char *str));

	int promptstring	OF(( ACP *acp,
					char *instr,
					char *outstr,
					int echo,
					int timeout ));

	void outputstring	OF(( ACP *acp,
					const char *s ));

	void log_message	OF(( UINT32 inet,
					UINT32 logid,
					int port,
					int service,
					int type,
					char *Message));
#ifdef _WIN32
	int syslog( int pri, const char *format, ...);
#endif /* _WIN32 */

/*********************************************************************/
/*
 * These declarations should be moved to a header file which will
 * be visible to callers.  That is, if prototypes are to be used.
 * (exception: static functions, which only need to be visible here)
 */
/*********************************************************************/

/* callback function to talk to the users */
static void acp_DialogCallback	OF((
		SwecHdl dialogContext,
		SwecDialogRec *dialogPtr
		));

static int setup_netsafeword_connection	OF((
		ACP *Acp,	/* Handle to pass to library calls */
		UINT32 logid,	/* Log sequence number */
		UINT32 inet,	/* Annex Internet address */
		int port,	/* physical port number */
		int service,	/* Expect SERVICE_CLI{,_HOOK} */
		SwecHdl *appHandle,	/* handle for SafeWord */
		SwecHdl *connectionHandle /* handle for SafeWord */
		));


int acp_netsafeword_validate		OF((
		ACP *Acp,	/* Handle to pass to library calls */
		UINT32 logid,	/* Log sequence number */
		UINT32 inet,	/* Annex Internet address */
		int port,	/* physical port number */
		int service,	/* Expect SERVICE_CLI{,_HOOK} */
		int *got_str_p,
		char *User
		));

int acp_netsafeword_validate_ipx	OF((
		char *User,
		char *Password,
		UINT32 logid,	/* Log sequence number */
		UINT32 inet,	/* Annex Internet address */
		int port,	/* physical port number */
		int service	/* Expect SERVICE_CLI{,_HOOK} */
		));


/*********************************************************************/
/* Static variables, since can't pass directly to acp_DialogCallback */
/*********************************************************************/
	static ACP *save_Acp;

/*********************************************************************/
/* Code begins here. */
/*********************************************************************/
/*
 * The user may or may not have set DIALOG_TIMEOUT in the Makefile
 */
#ifndef DIALOG_TIMEOUT
#define DIALOG_TIMEOUT INPUT_TIMEOUT
#endif

/*
 * setup_netsafeword_connection()
 * This sets up a connection to the SafeWord server.
 * a non-zero return indicates a failure.
 * SafeWord codes are returned for now.
 * The arguments are only used in event of failure.
 * In "real life" want to log failures, not send to user, anyway.
 */

static int
setup_netsafeword_connection( Acp, logid, inet, port, service,
		appHandle, connectionHandle)
	ACP *Acp;		/* Handle to pass to library calls */
	UINT32 logid;		/* Log sequence number */
	UINT32 inet;		/* Annex Internet address */
	int port;		/* physical port number */
	int service;		/* Expect SERVICE_CLI{,_HOOK} */
	SwecHdl *appHandle;	/* valid if SWEC_STATUS_SUCCESS */
	SwecHdl *connectionHandle; /* valid if SWEC_STATUS_SUCCESS */
{
	int rc;
	SwecRegisterRec regRec;
	SwecOpenRec openRec;
	SwecDeregisterRec deregisterRec;	/* ignoring this */
	static char config_path[PATHSZ];
	char msgstr[512];			/* size arbitrary */

	/* make pathname */
	NETAPI_CONFIGFILE( config_path);

	rc = swecInit();
	if( rc != SWEC_STATUS_SUCCESS) {
	    sprintf( msgstr, "swecInit error %d\n", rc);
	    syslog(LOG_ERR, "%s", msgstr);
	    if(debug)
		fprintf(stderr, "%s\n", msgstr);
	    return rc;
	    }

	/* we are letting SWEC take care of the data etc. */
	regRec.statusLogCallback = NULL;
	regRec.statusLogLabel = "erpcd: ";
	regRec.waitCallback = NULL;
	regRec.useSwecDataFileFlag = SWEC_TRUE;
	regRec.useConfigFileFlag = SWEC_TRUE;
	regRec.configFilePath = config_path;

	rc = swecRegister( appHandle, &regRec);
	if( rc != SWEC_STATUS_SUCCESS) {
	    sprintf( msgstr, "swecRegister error %d\n", rc);
	    strcat( msgstr, regRec.statusText);
	    strcat( msgstr, "\n");
	    syslog(LOG_ERR, "%s", msgstr);
	    if(debug)
		fprintf(stderr, "%s\n", msgstr);
	    (void) swecUninit( SWEC_FALSE);
	    return rc;
	    }

	/* pick any available connection */
	/* this is the wait time for the server, not for the user */
#ifdef _WIN32
	openRec.waitTime = atoi(ErpcdOpt->htc.szSWTimeout);
	if(openRec.waitTime < 1)	/* sanity check */
	    openRec.waitTime = 10;
#else /* not _WIN32 */
	openRec.waitTime = 10;
#endif /* not _WIN32 */
	openRec.openAllFlag = SWEC_FALSE;
	openRec.server = NULL;
	openRec.serverNumber = 0;

	rc = swecOpen( *appHandle, connectionHandle, &openRec);
	if( rc != SWEC_STATUS_SUCCESS) {
	    sprintf( msgstr, "swecOpen error %d\n", rc);
	    syslog(LOG_ERR, "%s", msgstr);
	    if(debug)
		fprintf(stderr, "%s\n", msgstr);
	    (void) swecDeregister( *appHandle, &deregisterRec);
	    (void) swecUninit( SWEC_FALSE);
	    return rc;
	    }

	return SWEC_STATUS_SUCCESS;
} /* end of setup_netsafeword_connection() */

/*********************************************************************/
/*
 * acp_DialogCallback()
 * This is the callback function.  Calls to swecAuthen() may call
 * this zero to many times for I/O, depending on what is needed.
 */

static void
acp_DialogCallback( dialogContext, dialogPtr)

SwecHdl dialogContext;		/* not used here */
SwecDialogRec *dialogPtr;

{
	char inbuff [ACP_MAXUSTRING];

	if (dialogPtr->dialogMessage != NULL &&
		dialogPtr->dialogMessage[0] != '\0') {   
	    outputstring( save_Acp, "\n");
	    outputstring( save_Acp, dialogPtr->dialogMessage);
	    if( debug)
		fprintf( stderr, "Message out: %s\n",
			dialogPtr->dialogMessage);
	    }
	if (dialogPtr->dialogType == SWEC_DIALOG_INPUT_ECHO ||
		dialogPtr->dialogType == SWEC_DIALOG_INPUT_NO_ECHO) {
	    outputstring( save_Acp, "\n");
	    outputstring( save_Acp, dialogPtr->dialogInputPrompt);

	    /* dialogPtr->inputBufferLength contains the "safe" size */
	    /* hence we use a known-size buffer as protection */

	    promptstring( save_Acp, inbuff, "",
		(dialogPtr->dialogType == SWEC_DIALOG_INPUT_ECHO),
		DIALOG_TIMEOUT);

	    /* remove any hyphens (the card may display one) */
	    acp_strip_hyphens( inbuff);

	    strncpy( dialogPtr->inputBuffer, inbuff,
			dialogPtr->inputBufferLength);

	    if( debug)
		printf( "Got a string [%s]\n", dialogPtr->inputBuffer);
	    if (dialogPtr->inputBuffer[0] == ESC) {
		dialogPtr->abortFlag = SWEC_TRUE;
		outputstring( save_Acp, 
		"\nApplication detected escape, terminating authentcation");
	    }
	}
	return;
} /* end of acp_DialogCallback() */

/*********************************************************************/
/*
 * acp_netsafeword_validate()
 * This function authenticates a user with the SafeWord Authentication
 * Server, Net API version.  This function takes care of all prompting.
 * It returns VALIDATED (1) if the user passed authentication,
 * NOT_VALIDATED (0) if the user faild authentication.
 *
 */
int
acp_netsafeword_validate( Acp, logid, inet, port, service,
		got_str_p, User)

ACP *Acp;		/* Handle to pass to library calls */
UINT32 logid;		/* Log sequence number */
UINT32 inet;		/* Annex Internet address */
int port;		/* physical port number */
int service;		/* Expect SERVICE_CLI{,_HOOK} */
int *got_str_p;
char *User;

{
	int rc;			/* swec functions return codes */
	int result;		/* this function return code */
	SwecHdl appHandle;	/* handle for SafeWord */
	SwecHdl connectionHandle; /* handle for SafeWord */
	SwecAuthenRec authenRec;	/* authentication struct */
	SwecCloseRec closeRec;
	SwecDeregisterRec deregRec;
	static int first = 1;
	static SwecHdl saveappHandle;
	static SwecHdl saveconnectionHandle;

	if( first) {
	    if(rc = setup_netsafeword_connection( Acp, logid, inet,
			port, service, 
			&appHandle, &connectionHandle)) {
		if( debug)
		    fprintf(stderr,
			"Connect with server failed:errorno %d\n", rc);
		return NOT_VALIDATED;
		}
	    saveappHandle = appHandle;
	    saveconnectionHandle = connectionHandle;
	    first = 0;
	    }
	else {
	    appHandle = saveappHandle;
	    connectionHandle = saveconnectionHandle;
	    }

	if( debug)
	    fprintf(stderr, "Connection established with server\n");

	/* connected -- now try and authenticate */
	authenRec.waitTime = 0;	/* wait for server, not user */
	authenRec.userId = User;	/* username from caller */
	authenRec.password = NULL;	/* unknown yet */
	authenRec.passUserFlag = SWEC_FALSE;
	authenRec.dialogCallback = acp_DialogCallback;
	save_Acp = Acp;

	rc = swecAuthen( appHandle, connectionHandle, &authenRec);
	if( debug)
	    fprintf(stderr, "Returned from swecAuthen, rc = %d\n", rc);
	if( rc != SWEC_STATUS_SUCCESS) {
	    *got_str_p = 0;
	    return NOT_VALIDATED;
	    }

	/* Examine result of authentication. */
	/* Ignoring "action data" for now. */
	if( authenRec.resultCode != SWEC_RESULT_PASSED_CHECK) {
	    if( debug)
		fprintf( stderr, "Authentication failed, result %d\n",
			authenRec.resultCode);
	    *got_str_p = 0;
	    result = NOT_VALIDATED;
	    return result;
	    }

	else {
	    if( debug)
		fprintf( stderr, "Authentication passed.\n");
	    *got_str_p = 1;
	    result = VALIDATED;
	    }
	
	/* Try to clean up.  Just give up on any failure, since*/
	closeRec.closeAllFlag = SWEC_FALSE;
	rc = swecClose( appHandle, connectionHandle, &closeRec);
	if( rc != SWEC_STATUS_SUCCESS) {
	    if(debug)
	       fprintf( stderr, "swecClose error %d\n", rc);
	    syslog(LOG_ERR, "swecClose error %d", rc);
	    return result;
	    }

	rc = swecDeregister(appHandle, &deregRec);
	if( rc != SWEC_STATUS_SUCCESS) {
	    if(debug)
	       fprintf( stderr, "swecDeregister error %d\n", rc);
	    syslog( LOG_ERR, "swecDeregister error %d", rc);
	    return result;
	    }

	(void) swecUninit( SWEC_FALSE);

	return result;

} /* end of acp_netsafeword_validate() */

/*********************************************************************/
/*
 * void _assert()
 * This is a vendor-supplied patch for symbol missing in the
 * library swecapi.a
 * If "__assert" comes up undefined, set NEED_ENIGMA_ASSERT_PATCH
 * in the Makefile.
 */
#ifdef NEED_ENIGMA_ASSERT_PATCH
int _assert	OF(( void));
int
_assert()
{
	return 0;
} /* end of _assert() patch */
#endif /* NEED_ENIGMA_ASSERT_PATCH */

/*********************************************************************/

#endif /* NET_ENIGMA_ACP */
