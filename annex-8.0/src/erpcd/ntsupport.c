/*****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *
 *	NT support routines for erpcd.
 *
 * Original Author: Sinin Lu     Created on: 95/12/14
 *
 *
******************************************************************************/
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <crtdbg.h>
//...
#include "../inc/port/install_dir.h"
#include "../inc/config.h"
#include <stdio.h>
#include <lm.h>
#include <process.h>
#include "../inc/port/port.h"
#include "acp.h"
#include "acp_policy.h"
#include "acp_regime.h"
#include "../ntsrc/syslogd/syslogmsg.h"
#include "../ntsrc/acplog/acplogmsg.h"
#include "../inc/rom/syslog.h"
#include "../ntsrc/registry/xyreg.h"
#include "acp_group.h"

#define MAX_SERVICE_NAME  30  /* length of the service name string */
#define MAX_EVENT_NAME  20 	 /* length of the event name string */
#define MAX_SYSLOG_FORMAT_LEN 2048 /* longest expanded format */
#define MAX_SYSLOG_MESSAGE_LEN 2048 /* longest logged message */
extern int debug;

extern StructErpcdOption *ErpcdOpt;
extern StructRadiusOption *RadiusOpt;
extern int radius_server_count;
/* -----------------------------------------------
	This variable must only be changed under
	control of UseCriticalSection()
 */
extern CRITICAL_SECTION	GlobalCriticalSection;
extern Radius_serverinfo *radius_head;
/* ---------------------------------------------- */

extern char *service_name[];
extern char *event_name[];
extern char szDefaultDomain[];
static  ALARMSTRUCT AlarmStruct;        // alarm function
static HANDLE hThreadAlarm;

int syslog( int pri, const char *format, ...);
char *PrependDomainNameAndFix(char *src, char *dest);

void sdump(char *);

BOOL GetPrimaryDomainName(int cbszDefaultDomain)
{
    int len = -1;
    int i;
	WKSTA_INFO_100 *pWk;

    szDefaultDomain[0] = 0;

	for (i = 0; i < 10; ++i) {
        if (NERR_Success != NetWkstaGetInfo(NULL, 100, (LPBYTE*)&pWk)){
			sleep(1000);
			continue;
		}
		
		len = WideCharToMultiByte(CP_ACP,
			                      WC_COMPOSITECHECK,
								  (LPCWSTR)(pWk->wki100_langroup),
								  -1,
                                  szDefaultDomain,
                                  cbszDefaultDomain,
								  NULL,
								  NULL);
		
        _strlwr(szDefaultDomain);
		break;
	}

    if ( len == 0 )
    {
        if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
            syslog(LOG_ERR, "Domain name exceeds buffer size.");
        else
            syslog(LOG_ERR, "WideChartoMultiByte failure in %s, Line: %d."
                    __FILE__, __LINE__);
        return(FALSE);
    }
    else if ( len == -1 )
    {
        syslog(LOG_ERR, "Error getting NetWkstaGetInfo.");
        return(FALSE);
    }
    
    return(TRUE);
        
}

void PrependDomainName(char *str)
{
#define MAX_DOMAINNAME 20
	char buf[MAX_DOMAINNAME];
	BOOL bHasDomainName = FALSE;
	int i;

	strncpy(buf, str, MAX_DOMAINNAME);
	buf[MAX_DOMAINNAME-1] = '\0';

	for (i=0; buf[i]; i++)
		if (buf[i] == '\\')
			bHasDomainName = TRUE;

	if (!bHasDomainName)
		sprintf(str, "%s\\%s", szDefaultDomain, buf);
}

/*****************************************************************************
 *
 * NAME:  PrependDomainNameAndFix
 *
 * DESCRIPTION:  Adds domain name to src string if necessary
 *
 * ARGUMENTS:
 *
 *      src - src user name
 *         may be user, domain\user, or domain\\user
 *      dest - pointer to buffer to use if needed
 *
 * RETURN VALUE:
 *
 *      pointer to final form == domain\user
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 *      dest large enough to hold data
 */

char *PrependDomainNameAndFix(char *src, char *dest)
{
	char *backslash;
	int len;

	if ((backslash = strchr(src, (int)'\\')) == NULL){
		/* No domain in src, append default */
		sprintf(dest, "%s\\%s", szDefaultDomain, src);
		return(dest);
	}
	/* src has domain */
	if (*(backslash + 1) == '\\'){
		/* Handle double backslash */
	        len = (int)(backslash - src) + 1;
		strncpy(dest, src, len);
		/* terminate string */
		*(dest + len) = '\0';
		/* add user name */
		strcat(dest, backslash + 2);
		return(dest);
	}
	else {
		/* Single backslash OK */
		return(src);
	}
}


int NTCreateGroupList(struct group_entry **group_list,char *username)
{
	struct  group_entry *head, *gentry;
	int len, i;
	char buf[128], *pszDomain, *pszUserName;
	LPSTR lpsz = buf;
	int nWCharNeeded;
    LPWSTR pwszDomain = NULL;
    LPWSTR pwszServer = NULL;
    LPWSTR pwszUserName = NULL;
	DWORD d;
	GROUP_USERS_INFO_0 *pBuf = NULL;
    LPBYTE lpB = NULL;
	DWORD entries, totalentries;
	long result;
	LPVOID lpMessageBuffer;
	int ReturnValue = FALSE;

	/* default to empty list */
	*group_list = NULL;

    if (debug)
	    printf("---------NTCreateGroupList-- username=%s\n", username);
	strncpy(buf, username, 127);
	buf[127]=0;
	pszUserName = buf;
	pszDomain = szDefaultDomain;
	for (i=0; buf[i]; i++)
		if (buf[i] == '\\')
		{
			pszDomain = &buf[0];
			buf[i]=0;
			pszUserName = &buf[i+1];
			break;
		}
    if (debug)
	    printf("----------- Domain=%s, User=%s\n", pszDomain, pszUserName);

	/* convert domain name to UNICODE */
	nWCharNeeded = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED,
                             pszDomain, -1, NULL, 0 );
    _ASSERT(nWCharNeeded == 0);

    if ( NULL == (pwszDomain = (LPWSTR) GlobalAlloc (GPTR, (nWCharNeeded) * 2)) )
    {
        result = FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM,
                    NULL,
                    GetLastError(),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
                    (LPTSTR) &lpMessageBuffer,
                    0,
                    NULL );
        _ASSERT(result != 0);
        syslog(LOG_ERR, "In %s, GlobalAlloc failed: %s", __FILE__, lpMessageBuffer);
		// Free the buffer allocated by the system
		LocalFree( lpMessageBuffer );
        goto error_exit;
    }

    nWCharNeeded = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED,
							 pszDomain, -1,
                             pwszDomain, nWCharNeeded);
    _ASSERT(nWCharNeeded == 0);

	/* convert user name to UNICODE */
	nWCharNeeded = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED,
                             pszUserName, -1, NULL, 0 );
    _ASSERT(nWCharNeeded == 0);

    if ( NULL == (pwszUserName = (LPWSTR) GlobalAlloc (GPTR, (nWCharNeeded) * 2)) )
    {
        result = FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM,
                    NULL,
                    GetLastError(),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
                    (LPTSTR) &lpMessageBuffer,
                    0,
                    NULL );
        _ASSERT(result != 0);
        syslog(LOG_ERR, "In %s, GlobalAlloc failed: %s", __FILE__, lpMessageBuffer);
		// Free the buffer allocated by the system
		LocalFree( lpMessageBuffer );
        goto error_exit;
    }


    nWCharNeeded = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED,
							 pszUserName, -1,
                             pwszUserName, nWCharNeeded);
    _ASSERT(nWCharNeeded == 0);

	/* Get domain controller name */
    if ( (d = NetGetDCName (NULL, pwszDomain, &lpB)) != NERR_Success ) {
        syslog( LOG_ERR, "In %s, line %d, NetGetDCName: Primary Domain Controller could not be found."
                    __FILE__, __LINE__);
        goto error_exit;
	}
	pwszServer = (LPWSTR)lpB;

    if (debug)
	    printf("NetGetDCName=%d----------- \n", d);

	/* Get the groups for the user */
	d = NetUserGetGroups(pwszServer, pwszUserName, 0, (LPBYTE *) &pBuf, 16000, &entries, &totalentries);
    if (d != NERR_Success)
    {
		if (d == NERR_UserNotFound){
			/* If the user doesn't exist, he doesn't belong to groups */
			/* this isn't a problem for radius security users */
			/* and will show up earlier for NT security */
			ReturnValue = TRUE;
            goto error_exit;
		}
        /* Some other problem */
        syslog( LOG_ERR, "In %s, line %d, NetUserGetGroups failed", __FILE__, __LINE__);
        goto error_exit;
	}

	head = NULL;
    if (debug)
	    printf("NetUserGetGroups=%d----------- entries=%d, totalentries=%d\n", d,entries, totalentries);

	for ( i = 0 ; i< (int)entries; i++)
	{
		char tempGroup[MAX_GROUP_NAME];
        gentry = (struct group_entry *)malloc(sizeof(struct group_entry));
        if ( gentry == NULL )
        {
            syslog( LOG_ERR, "In %s, line %d, malloc failed", __FILE__, __LINE__);
            goto error_exit;
        }
		len = WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK, pBuf[i].grui0_name,
					-1, tempGroup, MAX_GROUP_NAME, NULL, NULL);
        if ( len == 0 )
        {
            if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
                syslog(LOG_ERR, "Group name exceeds buffer size.");
            else
                syslog(LOG_ERR, "WideChartoMultiByte failure in %s, Line: %d."
                        __FILE__, __LINE__);
            goto error_exit;
        }
		sprintf(gentry->groupname, "%s\\%s", pszDomain, tempGroup);
		_strlwr(gentry->groupname);
		gentry->next = head;
		head = gentry;
		if (debug)
			printf("--------- groupname=%s\n", gentry->groupname);
	}
	*group_list = head;

    ReturnValue = TRUE;

error_exit:
    if ( pwszUserName != NULL )
       GlobalFree(pwszUserName);

    if ( pwszDomain != NULL )
       GlobalFree(pwszDomain);

    if ( lpB != NULL )
        NetApiBufferFree(lpB);

    return(ReturnValue);

}



/*****************************************************************************
 *
 * NAME:  ReadRegistryParam
 *
 * DESCRIPTION:  read the ERPCD options from registry
 *
 * ARGUMENTS:
 *
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void ReadRegistryParam()
{
	htConfig htc;
	if (GetRegistry(&htc) < 0)
		return;

    memcpy(&(ErpcdOpt->htc),  &htc, sizeof(htConfig));  /* assign the whole structure */
    ErpcdOpt->UseSyslog = atoi(htc.szLogToEventLog) != 0;
	ErpcdOpt->UseLogfile = atoi(htc.szLogToLogFile) != 0;
	ErpcdOpt->UseSeconds = atoi(htc.szLogTimeInSecondsFormat) != 0;
	ErpcdOpt->UseHostName = atoi(htc.szLogNetAddressInHostName) != 0;
	ErpcdOpt->UseGroupAuthentication = atoi(htc.szGroupAuthentication) != 0;
	install_dir = ErpcdOpt->htc.szDirSecurity; 
	root_dir = ErpcdOpt->htc.szDirLoadDump;	
	ErpcdOpt->UseRadiusLogging = atoi(htc.szLogToRadiusLog) != 0;
	ErpcdOpt->RadiusAuthentication = FALSE;	/* Radius Authentication enabled */
	ErpcdOpt->SecuridAuthentication = FALSE;	/* SecurID Authentication enabled */
	ErpcdOpt->SafewordAuthentication = FALSE;	/* Safeword Authentication enabled */

	switch (atoi(htc.szSecurityRegime))
	{
	case NT_SECURITY:
		/* NT Authentication only, nothing to set */
		break;
	case RADIUS_SECURITY:
		ErpcdOpt->RadiusAuthentication = TRUE;	/* Radius Authentication enabled */
		break;
	case SECURID_SECURITY:
		ErpcdOpt->SecuridAuthentication = TRUE;	/* SecurID Authentication enabled */
		break;
	case SAFEWORD_SECURITY:
		ErpcdOpt->SafewordAuthentication = TRUE;	/* Safeword Authentication enabled */
		break;
	default:	// invalid security regime, reset to NT
        syslog(LOG_CRIT, "Fatal ACP Error, no security regime specified");
    	ErpcdExit(0);
	}

	/* Copy the Radius server information */

    if ( strcmp(htc.szRadiusAuthenticationServer, "<Local>") == 0 )
    {
        strcpy(RadiusOpt->RadiusAuthenticationServer, "");
    }
    else
    {
        strcpy(RadiusOpt->RadiusAuthenticationServer, htc.szRadiusAuthenticationServer);
    }

    if ( strcmp(htc.szRadiusAccountingServer, "<Local>") == 0 )
    {
        strcpy(RadiusOpt->RadiusAccountingServer, "");
    }
    else if ( strcmp(htc.szRadiusAccountingServer, "<Same as Authentication>") == 0 )
    {
        strcpy(RadiusOpt->RadiusAccountingServer, RadiusOpt->RadiusAuthenticationServer);
    }
    else
    {
        strcpy(RadiusOpt->RadiusAccountingServer, htc.szRadiusAccountingServer);
    }
	memcpy(RadiusOpt->aServer, htc.aServer, sizeof(htc.aServer));
	radius_server_count = htc.SrvrCnt;
}

/*****************************************************************************
 *
 * NAME:  UpdateErpcdOpt
 *
 * DESCRIPTION:  This thread updates the ERPCD option structure when corresponding
 *                              registry entry changed.
 * ARGUMENTS:
 *
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void UpdateErpcdOpt(void *dummy)
{
	char szTemp[MAX_PATH];
	HKEY hk;
	LONG lSuccess;
	Radius_serverinfo *old_head, *to_be_freed;
	LPVOID	lpMessageBuffer;

	//
    //Find out the company and product name of the host tool.
    //
    sprintf(szTemp, "SOFTWARE\\%s\\%s", ErpcdOpt->htc.szCompanyName, ErpcdOpt->htc.szProductName);
    lSuccess = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szTemp, 0, KEY_READ, &hk);
    if ( lSuccess != ERROR_SUCCESS )
        syslog(LOG_ERR, "RegOpenKey failed for %s in File: %s, Line: %d",
                 szTemp, __FILE__, __LINE__);
    

    for (;;)
    {
        if ( ERROR_SUCCESS != RegNotifyChangeKeyValue(hk, TRUE, REG_NOTIFY_CHANGE_LAST_SET, NULL, FALSE) )
        {
            lSuccess = FormatMessage(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM,
                        NULL,
                        GetLastError(),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
                        (LPTSTR) &lpMessageBuffer,
                        0,
                        NULL );
            _ASSERT(lSuccess != 0);

            //... now output this string
#ifdef USE_SYSLOG
            syslog (LOG_ERR, "In %s, RegNotifyChangeKeyValue: %s, Line: %d",
                        __FILE__, lpMessageBuffer, __LINE__);
#endif

            // Free the buffer allocated by the system
            LocalFree( lpMessageBuffer );
        }
            
		//
		// when the above call returns, the registry has changed
		//
        ReadRegistryParam();

		//
		//  If RADIUS is the security regime, re-parse the radius parameters
		//
		if ( ErpcdOpt->RadiusAuthentication == TRUE )
		{
			//
	    	// Re-parse the registry data into in a linked list
    		// structure and store the head on return
    		//
			old_head = radius_head;			// save a copy of the old pointer
    		radius_head = create_radius_configs();

			/* Request ownership of the critical section. */
			__try {
    			EnterCriticalSection(&GlobalCriticalSection);
				//
				// Release the memory used by the old copy of the structure
				//
				to_be_freed = old_head;
	   			while(to_be_freed)
	   			{
	     			old_head = old_head->next;
	     			free(to_be_freed);
	     			to_be_freed = old_head;
				}
			}
			__finally {
    			/* Release ownership of the critical section. */
    			LeaveCriticalSection(&GlobalCriticalSection);
			}
		}
    }
}

/*****************************************************************************
 *
 * NAME:  ServiceControlStop
 *
 * DESCRIPTION:  thread that receive service control stop message and stop the
 *                              erpcd.
 * ARGUMENTS:   dummy
 *
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void ServiceControlStop( void *dummy)
{
	WaitForSingleObject(hEventStop, INFINITE);
    if (hEventStop != NULL)
        CloseHandle(hEventStop);

    exit(0);	 /* force to exit */
}


/*****************************************************************************
 *
 * NAME:  RegistAlarmHandler
 *
 * DESCRIPTION:	 register the SIGALM signal handler;
 *
 * ARGUMENTS: 	func - pointer to the signal handler
 *
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void RegistAlarmHandler(void *func)
{
	AlarmStruct.alarmfunc = func;
}

/*****************************************************************************
 *
 * NAME:  alarmthread
 *
 * DESCRIPTION:	 simulat UNIX alarm signal.
 *
 * ARGUMENTS:
 *		pTimerParm - dummy
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void alarmthread(VOID *pDummy)
{
	for (;;)
	{
		WaitForSingleObject(AlarmStruct.hEventEnableAlarm, INFINITE);

		switch(WaitForSingleObject(AlarmStruct.hEventAlarm, AlarmStruct.Timeout_val))
		{
		case WAIT_TIMEOUT:
			if (debug)
				fprintf(stderr,"Session timeout\n");
			(*AlarmStruct.alarmfunc)();
			break;

		case WAIT_OBJECT_0:
			break;

		case WAIT_ABANDONED:
            syslog(LOG_ERR, "------WaitForSingleObject Failed %d\n", GetLastError());
			break;

		default:
            syslog(LOG_ERR, "------WaitForSingleObject Failed %d\n", GetLastError());
			break;
		}
	}
}
void InitAlarmThread()
{
//	DWORD thread_id;
    AlarmStruct.hEventEnableAlarm = CreateEvent(NULL, TRUE, FALSE, NULL);
    AlarmStruct.hEventAlarm = CreateEvent(NULL, TRUE, FALSE, NULL);

/*	CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)alarmthread,
					(LPVOID)NULL,0,&thread_id);*/
    hThreadAlarm = (HANDLE)_beginthread (alarmthread, 0, (void *)NULL);
    if ( hThreadAlarm == (HANDLE)0xFFFFFFFF )
    {
        syslog(LOG_ERR, "_beginthread failed, alarmthread, %s, Line: %d, Error: %s",
                    __FILE__, __LINE__, strerror( errno ));
    }
}

/*****************************************************************************
 *
 * NAME:  alarm
 *
 * DESCRIPTION:	 simulate UNIX alarm signal
 *
 * ARGUMENTS:
 *		x - time in seconds
 *		func - pointer to a call back function
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void alarm(int second)
{
	if (second > 0)
	{
		AlarmStruct.Timeout_val = second * ONE_SECOND;
		ResetEvent(AlarmStruct.hEventAlarm);
		SetEvent(AlarmStruct.hEventEnableAlarm);
	}
	else
	{
		ResetEvent(AlarmStruct.hEventEnableAlarm);
		SetEvent(AlarmStruct.hEventAlarm);
	}
}
#if 0
/*****************************************************************************
 *
 * NAME:  syslog
 *
 * DESCRIPTION:	used to replace UNIX syslog in ERPCD under Windows NT.
 *
 * ARGUMENTS:
 *		pri	- priority
 *		format	- format string as in sprintf (plus, "%m" is allowed)
 *		...	- args required by "format" in order and of correct type
 * REMARKS:
 *
 *	Formerly this was called SyslogToEventLog, when it did not have full
 *	syslog() functionality.
 *
 * RETURN VALUE:
 *
 *	Always 0.  The UNIX man page does not discuss return values and
 *	ignores them in all examples, but implies it's an int function.
 *
 * SIDE EFFECTS:
 *
 *	Adds entries to Windows NT event log.
 *
 * EXCEPTIONS:
 *
 *	None; however as with any *printf function, args that don't match
 *	the format can blow the code out of the water.
 *
 * ASSUMPTIONS:
 *
 *	Format string and resulting message will each fit in 2K buffer.
 *	(see defines for sizes at top of file)
 */
int syslog(int pri, const char *format, ...)
{
	va_list ap;
	HANDLE hAppLog;
	int fac, prilev;
	WORD wIdCategory;
	DWORD dwIdEvent;
	WORD wEventType;
	BOOL bSuccess;
	char *pszInsertStr[2];
	char nformat[MAX_SYSLOG_FORMAT_LEN+1];
	char msg[MAX_SYSLOG_MESSAGE_LEN+1];
	const char *cp;
	char *ncp;

	/* copy and convert format; the whole purpose is to process "%m" */
	for( cp = format, ncp = nformat; *cp; cp++) {
	    if( *cp != '%') {
		*ncp++ = *cp;
		}
	    /* check for "%%" which must be passed even if followed by 'm' */
	    else if( *(cp+1) == '%') {
		cp++;		/* extra increment (doing 2 chars here) */
		*ncp++ = '%';
		*ncp++ = '%';
		}
	    /* check for "%m" and replace with errno string when found */
	    else if( *(cp+1) == 'm') {
		cp++;		/* extra increment (doing 2 chars here) */
		strcpy( ncp, strerror(errno));
		ncp += strlen(ncp);	/* skip to end of appended string */
		}
	    /* "normal" %-format-specifier */
	    else {
		*ncp++ = *cp;
		}
	    }
	*ncp = '\0';

	va_start(ap, format);
	vsprintf(msg, nformat, ap);
	va_end(ap);

	pszInsertStr[0] = "erpcd";
	pszInsertStr[1] = msg;

	if (debug)
		printf("syslog: pri %o, msg %s\n", pri, msg);

	/* extract facility and priority level */
	fac = LOG_FACMASK & pri;
	prilev = LOG_PRIMASK & pri;


	switch(fac)
	{
	case LOG_KERN:
		wIdCategory = CAT_LOG_KERN;
		break;
	case LOG_USER:
		wIdCategory = CAT_LOG_USER;
		break;
	case LOG_MAIL:
		wIdCategory = CAT_LOG_MAIL;
		break;
	case LOG_DAEMON:
		wIdCategory = CAT_LOG_DAEMON;
		break;
	case LOG_AUTH:
		wIdCategory = CAT_LOG_AUTH;
		break;
	case LOG_SYSLOG:
		wIdCategory = CAT_LOG_SYSLOG;
		break;
	case LOG_LPR:
		wIdCategory = CAT_LOG_LPR;
		break;
	case LOG_NEWS:
		wIdCategory = CAT_LOG_NEWS;
		break;
	case LOG_UUCP:
		wIdCategory = CAT_LOG_UUCP;
		break;
	case LOG_CRON:
		wIdCategory = CAT_LOG_CRON;
		break;
	case LOG_LOCAL0:
		wIdCategory = CAT_LOG_LOCAL0;
		break;
	case LOG_LOCAL1:
		wIdCategory = CAT_LOG_LOCAL1;
		break;
	case LOG_LOCAL2:
		wIdCategory = CAT_LOG_LOCAL2;
		break;
	case LOG_LOCAL3:
		wIdCategory = CAT_LOG_LOCAL3;
		break;
	case LOG_LOCAL4:
		wIdCategory = CAT_LOG_LOCAL4;
		break;
	case LOG_LOCAL5:
		wIdCategory = CAT_LOG_LOCAL5;
		break;
	case LOG_LOCAL6:
		wIdCategory = CAT_LOG_LOCAL6;
		break;
	case LOG_LOCAL7:
		wIdCategory = CAT_LOG_LOCAL7;
		break;
	}


	switch(prilev)
	{
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
	case LOG_ERR:
		wEventType = EVENTLOG_ERROR_TYPE;
		dwIdEvent = MSG_ERROR;
		break;
	case LOG_WARNING:
		wEventType = EVENTLOG_WARNING_TYPE;
		dwIdEvent = MSG_WARNING;
		break;
	case LOG_NOTICE:
	case LOG_INFO:
	case LOG_DEBUG:
		wEventType = EVENTLOG_INFORMATION_TYPE;
		dwIdEvent = MSG_INFO;
		break;
	default:        // assume it's bad!!
		wEventType = EVENTLOG_ERROR_TYPE;
		dwIdEvent = MSG_ERROR;
		break;
	}


	hAppLog = RegisterEventSource(NULL,   /* use local machine      */
						     SYSLOG_SOURCE); /* source name            */

	//
	//Now report the event, which will add this event to the event log
	//
	bSuccess = ReportEvent(hAppLog,    /* event-log handle      */
			 wEventType,               /* event type                  */
			 wIdCategory,              /* category ID                 */
			 dwIdEvent,                /* event ID                    */
			 NULL,                     /* no user SID                 */
			 2,                 /* # of substitution strings   */
			 0,                        /* no binary data              */
			 pszInsertStr,               /* string array                */
			 NULL);                    /* address of data             */

	if(!bSuccess && debug)
		printf("%s: Error from ReportEvent on line %d\n", __FILE__, __LINE__);
	DeregisterEventSource(hAppLog);
	return 0;
}
#endif


/*****************************************************************************
 *
 * NAME:  LogACPToEventLog
 *
 * DESCRIPTION:  Log ACP to NT event log.
 *
 * ARGUMENTS:
 *              type    - type of acp event.
 *              service - acp service
 *              aname   - host name.
 *              port    - port number
 *              Message - Log message.
 *
 * RETURN VALUE:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
void LogACPToEventLog(int type, int service, char *aname, int port, char *Message)
{
        HANDLE hAppLog;
        WORD wIdCategory;
        DWORD dwIdEvent;
        WORD wEventType;
        BOOL bSuccess;
        char *pszInsertStr[1];
        char buf[MAX_SERVICE_NAME+MAX_EVENT_NAME+MAXHOSTNAMELEN+ACP_MAXUSTRING+20];


		/* Messages used in this switch are defined in acplogmsg.mc */

        switch(type)
        {
        case EVENT_BOOT:
                dwIdEvent = MSG_BOOT;
                break;
        case EVENT_LOGIN:
                dwIdEvent = MSG_LOGIN;
                break;
        case EVENT_LOGOUT:
                dwIdEvent = MSG_LOGOUT;
                break;
        case EVENT_TIMEOUT:
                dwIdEvent = MSG_TIMEOUT;
                break;
        case EVENT_PROVIDE:
                dwIdEvent = MSG_PROVIDE;
                break;
        case EVENT_DIAL:
                dwIdEvent = MSG_DIAL;
                break;
        case EVENT_ACCT:
                dwIdEvent = MSG_ACCT;
                break;
        case EVENT_NOPROVIDE:
                dwIdEvent = MSG_NOPROVIDE;
                break;
        case EVENT_REJECT:
                dwIdEvent = MSG_REJECT;
                break;
        case EVENT_BADRESP:
                dwIdEvent = MSG_BADRESP;
                break;
        case EVENT_OPT_REF:
                dwIdEvent = MSG_OPT_REF;
                break;
        case EVENT_PARSE:
                dwIdEvent = MSG_PARSE;
                break;
        case EVENT_BLACKLIST:
                dwIdEvent = MSG_BLACKLIST;
                break;
        case EVENT_ACCEPT_CALL:
                dwIdEvent = MSG_ACCEPT_CALL;
                break;
        case EVENT_REJECT_CALL:
                dwIdEvent = MSG_REJECT_CALL;
                break;
        case EVENT_DISC_CALL:
                dwIdEvent = MSG_DISC_CALL;
                break;
        case EVENT_NEGO_ADDR:
                dwIdEvent = MSG_NEGO_ADDR;
                break;
		case EVENT_CONNECT_CALL:
                dwIdEvent = MSG_CONNECT_CALL;
                break;
        case EVENT_MP_ATTACH:
                dwIdEvent = MSG_MP_ATTACH;
                break;
        case EVENT_MP_DETACH:
                dwIdEvent = MSG_MP_DETACH;
                break;
        case EVENT_LINE_SEIZURE:
                dwIdEvent = MSG_LINE_SEIZURE;
                break;
        }

		/* Messages used in the previous switch are defined in 
		   /vobs/annex_src/ntsrc/acplog/acplogmsg.mc 
		   ANY MESSAGES ADDED MUST BE DEFINED THERE */

        switch(type)
        {
        case EVENT_BOOT:
        case EVENT_LOGIN:
        case EVENT_LOGOUT:
        case EVENT_TIMEOUT:
        case EVENT_PROVIDE:
        case EVENT_DIAL:
        case EVENT_ACCT:
        case EVENT_OPT_REF:
        case EVENT_PARSE:
        case EVENT_BLACKLIST:
        case EVENT_ACCEPT_CALL:
        case EVENT_REJECT_CALL:
        case EVENT_DISC_CALL:
	    case EVENT_NEGO_ADDR:
	    case EVENT_CONNECT_CALL:
        case EVENT_MP_ATTACH:
        case EVENT_MP_DETACH:
        case EVENT_LINE_SEIZURE:
                wEventType = EVENTLOG_INFORMATION_TYPE;
                break;

        case EVENT_BADRESP:
        case EVENT_NOPROVIDE:
        case EVENT_REJECT:
                wEventType = EVENTLOG_WARNING_TYPE;
                break;
        }

		/* Messages used in this switch are defined in acplogmsg.mc */

        switch(service)
        {
        case SERVICE_SECURITY:
                wIdCategory = CAT_SERVICE_SECURITY;
                break;
        case SERVICE_CLI:
                wIdCategory = CAT_SERVICE_CLI;
                break;
        case SERVICE_CALL:
                wIdCategory = CAT_SERVICE_CALL;
                break;
        case SERVICE_RLOGIN:
                wIdCategory = CAT_SERVICE_RLOGIN;
                break;
        case SERVICE_TELNET:
                wIdCategory = CAT_SERVICE_TELNET;
                break;
        case SERVICE_PORTS:
                wIdCategory = CAT_SERVICE_PORTS;
                break;
        case SERVICE_DIALUP:
                wIdCategory = CAT_SERVICE_DIALUP;
                break;
        case SERVICE_SLIP:
                wIdCategory = CAT_SERVICE_SLIP;
                break;
        case SERVICE_PPP:
                wIdCategory = CAT_SERVICE_PPP;
                break;
        case SERVICE_CONNECT:
                wIdCategory = CAT_SERVICE_CONNECT;
                break;
        case SERVICE_SLIP_DYNDIAL:
                wIdCategory = CAT_SERVICE_SLIP_DYNDIAL;
                break;
        case SERVICE_PPP_DYNDIAL:
                wIdCategory = CAT_SERVICE_PPP_DYNDIAL;
                break;
        case SERVICE_DIALBACK:
                wIdCategory = CAT_SERVICE_DIALBACK;
                break;
        case SERVICE_ARAP:
                wIdCategory = CAT_SERVICE_ARAP;
                break;
        case SERVICE_FTP:
                wIdCategory = CAT_SERVICE_FTP;
                break;
        case SERVICE_CLI_HOOK:
                wIdCategory = CAT_SERVICE_CLI_HOOK;
                break;
        case SERVICE_IPX:
                wIdCategory = CAT_SERVICE_IPX;
                break;
        case SERVICE_IPX_DIALBACK:
                wIdCategory = CAT_SERVICE_IPX_DIALBACK;
                break;
        case SERVICE_RCF:
                wIdCategory = CAT_SERVICE_RCF;
                break;
        case SERVICE_PPP_TMOUT:
                wIdCategory = CAT_SERVICE_PPP_TMOUT;
                break;
        case SERVICE_PPP_DYNDIAL_TMOUT:
                wIdCategory = CAT_SERVICE_PPP_DYNDIAL_TMOUT;
                break;
        case SERVICE_SLIP_TMOUT:
                wIdCategory = CAT_SERVICE_SLIP_TMOUT;
                break;
        case SERVICE_SLIP_DYNDIAL_TMOUT:
                wIdCategory = CAT_SERVICE_SLIP_DYNDIAL_TMOUT;
                break;
        case SERVICE_VMS:
                wIdCategory = CAT_SERVICE_VMS;
                break;
        case SERVICE_SYNC_PPP:
                wIdCategory = CAT_SERVICE_SYNC_PPP;
                break;
        case SERVICE_VPN_PPP:
                wIdCategory = CAT_SERVICE_VPN_PPP;
                break;
        case SERVICE_SYNC_DIALUP:
                wIdCategory = CAT_SERVICE_SYNC_DIALUP;
                break;
        case SERVICE_DYNDIALPASS:
                wIdCategory = CAT_SERVICE_DYNDIALPASS;
                break;
        case SERVICE_SECRET:
                wIdCategory = CAT_SERVICE_SECRET;
                break;
        case SERVICE_CH_GOOD:
                wIdCategory = CAT_SERVICE_CH_GOOD;
                break;
        case SERVICE_CH_BAD:
                wIdCategory = CAT_SERVICE_CH_BAD;
                break;
        case SERVICE_CH_OPT_REF:
                wIdCategory = CAT_SERVICE_CH_OPT_REF;
                break;
        case SERVICE_DIALUP_IPX:
                wIdCategory = CAT_SERVICE_DIALUP_IPX;
                break;
        case SERVICE_OUTPUTSTRING:
                wIdCategory = CAT_SERVICE_OUTPUTSTRING;
                break;
        case SERVICE_PROMPTSTRING:
                wIdCategory = CAT_SERVICE_PROMPTSTRING;
                break;
        case SERVICE_AT_PROFILE:
                wIdCategory = CAT_SERVICE_AT_PROFILE;
                break;
        case SERVICE_NONE:
                wIdCategory = CAT_SERVICE_NONE;
                break;
        case SERVICE_AUDITLOG:
                wIdCategory = CAT_SERVICE_AUDITLOG;
                break;
        case SERVICE_SHELL:
                wIdCategory = CAT_SERVICE_SHELL;
                break;
        case SERVICE_FILTERS:
                wIdCategory = CAT_SERVICE_FILTERS;
                break;
        case SERVICE_PRIMGR:
                wIdCategory = CAT_SERVICE_PRIMGR;
                break;
        case SERVICE_CHAP:
                wIdCategory = CAT_SERVICE_CHAP;
                break;
        case SERVICE_MP:
                wIdCategory = CAT_SERVICE_MP;
                break;
		case SERVICE_MODEM:
				wIdCategory = CAT_SERVICE_MODEM;
				break;
 		case SERVICE_MAX_LOGON:
				wIdCategory = CAT_SERVICE_MAX_LOGON;
				break;
		case SERVICE_DVS:
				wIdCategory = CAT_SERVICE_DVS;
				break;
       }

        sprintf(buf,"%s:%s:[%s/%d]:%s", event_name[type],
                        service_name[service], aname, port, Message);
        pszInsertStr[0] = buf;
        hAppLog = RegisterEventSource(NULL,   /* use local machine      */
                                                     ACPLOG_SOURCE); /* source name            */
        //
        //Now report the event, which will add this event to the event log
        //
        bSuccess = ReportEvent(hAppLog,    /* event-log handle      */
                         wEventType,               /* event type                  */
                         wIdCategory,              /* category ID                 */
                         dwIdEvent,                /* event ID                    */
                         NULL,                     /* no user SID                 */
                         1,                 /* # of substitution strings   */
                         0,                        /* no binary data              */
                         pszInsertStr,               /* string array                */
                         NULL);                    /* address of data             */

	if(!bSuccess && debug)
		printf("%s: Error from ReportEvent on line %d\n", __FILE__, __LINE__);
        DeregisterEventSource(hAppLog);
}


/*****************************************************************************
 *
 * NAME:  gettimeofday
 *
 * DESCRIPTION:  emulate UNIX system call
 *
 * ARGUMENTS: 	refer to the man page
 *
 * RETURN VALUE: refer to the man page
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
int gettimeofday(struct timeval* tm, struct timezone *tz)
{
	DWORD tod_errno;
	TIME_ZONE_INFORMATION lptzi ;
	SYSTEMTIME t1;
	int monthday[13] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
	int leap = 0;
	long year=0, month=0, day=0, hour = 0, min=0, sec=0;

	tod_errno = GetTimeZoneInformation(&lptzi);
	if(tod_errno ==	0xFFFFFFFF){
        syslog(LOG_ERR, "GetTimeZoneInformation failed, error: %d", GetLastError());
		return -1;
	}
	GetLocalTime(&t1);
	if(tz){
		tz->tz_minutewest = lptzi.Bias;
	}

	if(t1.wYear > 1970){
		for(year = t1.wYear; year>1970; year--){
			if((year % 4 == 0 && year % 100 !=0) || year % 400 == 0)
				leap ++;
		}
	}else{
		for(year = t1.wYear; year <= 1970; year++){
			if((year % 4 == 0 && year % 100 !=0) || year % 400 == 0)
				leap ++;
		}
	}


	year = (t1.wYear-1970);
	year = (year>0) ? year:(year * (-1));

	month = t1.wMonth ;
	while(month >1){
		month --;
		day += monthday[month];
	}

	day += ((year*365 + leap) + t1.wDay);
	hour = 24*day + t1.wHour;
	min = (60 * hour) + t1.wMinute;
	sec = (60 * min) + t1.wSecond;
	tm->tv_sec = sec;
	tm->tv_usec = t1.wMilliseconds;
	return 0;
}
