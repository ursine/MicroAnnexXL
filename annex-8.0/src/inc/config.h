/* map function names */
/*
 *****************************************************************************
 *
 *        Copyright 1990, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	defines for NT build, or for UNIX at development time. This file
 *	is generate by installation script when customer use installation
 *	script to install host tools.
 *
 * Original Author: slu	Created on: 9/1/95
 *
 * Revision Control Information:
 * $Id: $
 *
 * This file created by RCS from
 * $Source: $
 *
 * Revision History:
 * $Log:$
 * This file is currently under revision by: $Locker: loverso $
 *
 ****************************************************************************
 */
#ifndef _CONFIG_H_
#define _CONFIG_H_


#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

#else
#include <sys/types.h>
#include <sys/locking.h>
#include <io.h>
#include <winsock.h>
#define PERR(lSuccess, api) {if(lSuccess!=ERROR_SUCCESS) printf("%s: Error %d from %s \
    on line %d\n", __FILE__, lSuccess, api, __LINE__);}

/* map function names */

#define far

#define need_ether_addr
#define need_sendmsg
#define need_recvmsg

#define need_bcopy
#define need_bzero

#define sendmsg_func xylo_sendmsg
#define recvmsg_func xylo_recvmsg
#define bcopy xylo_bcopy
#define bzero xylo_bzero
#define index strchr
#define mrand48() (((rand() << 17) & 0xff000000) | ((rand() << 9) & 0xff0000) |\
                   ((rand() << 1) & 0xff00) | (rand() >> 7))

#define srand48 srand
#define strncasecmp strnicmp
#define strcasecmp stricmp
#define lockf _locking
#define F_TLOCK	_LK_LOCK
#define F_ULOCK	_LK_UNLCK


#define BFS "\\bfs"
typedef char * caddr_t;
typedef void (*voidfunc)(void);
typedef struct AlarmStruct{
	DWORD Timeout_val;
	HANDLE hEventAlarm;
	HANDLE hEventEnableAlarm;
	voidfunc alarmfunc;
} ALARMSTRUCT;

struct timezone{
		int  tz_minutewest; //UTC = local + tz_minutewest
		int  tz_dsttime;
};

#include "port/libannex.h"
extern int pcount;
extern HANDLE hEventSIGCHLD;
extern HANDLE hEventSIGHUP;
extern HANDLE hEventSIGPWR;
extern HANDLE hEventContinue;
extern HANDLE hEventStop;
extern HANDLE hEventOKToExit;
extern HANDLE hSemaphoreChildCount;

extern HANDLE hThreadSIGHUP;
extern HANDLE hThreadSIGPWR;

extern DWORD dwThreadID;

#define sleep(x)    Sleep(x)    /* windows no longer provides sleep(x) */
#endif /* _WIN32 */

#endif /* _CONFIG_H_ */
