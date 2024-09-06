/*
 *****************************************************************************
 *
 *        Copyright 1993, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains global host-related compatibility
 *	definitions.
 *
 * Original Author: James Carlson	Created on: 29DEC93
 *
 * Revision Control Information:
 *
 * $Header: /annex/mckinley/src/inc/port/RCS/port.h,v 1.1.5.1 1995/08/29 10:21:16 slu Exp $
 *
 * This file created by RCS from $Source: /annex/mckinley/src/inc/port/RCS/port.h,v $
 *
 * Revision History:
 *
 * $Log: port.h,v $
 * Revision 1.1.5.1  1995/08/29  10:21:16  slu
 * Move definations from inc/config.h to port.h to solve the problem installation
 * script overwrite inc/config.h.
 *
 * Revision 1.1  1993/12/29  16:47:03  carlson
 * Initial revision
 *
 *
 * This file is currently under revision by:
 *
 * $Locker: deluca $
 *
 *  DATE:	$Date: 1995/08/29 10:21:16 $
 *  REVISION:	$Revision: 1.1.5.1 $
 *
 ****************************************************************************
 */

#ifndef _PORT_H
#define _PORT_H

/*
 * On 64 bit machines, "int"s are 32 bits and "long"s are 64 bits.
 */
#ifdef USE_64
#	define UINT32	unsigned int
#	define INT32	int
#else /* !USE_64 */
#	define UINT32	unsigned long
#	define INT32	long
#endif /* USE_64 */

#ifndef _WIN32

#define ErpcdExit(n)	 exit(n)
typedef struct _ErpcdOption {
	int UseSyslog;
	int UseLogfile;
	int UseHostName;
	int UseSeconds;
	int UseGroupAuthentication;
} StructErpcdOption;

#else /* _WIN32	 */
#include "../ntsrc/registry/xyreg.h"

typedef struct _ErpcdOption {
	htConfig htc;
	BOOL UseSyslog;
	BOOL UseLogfile;
	BOOL UseHostName;
	BOOL UseRadiusLogging;			/* Use Radius Logging */
	BOOL RadiusAuthentication;		/* Radius Authentication enabled */
	BOOL SecuridAuthentication; 	/* SecurID Authentication enabled */
	BOOL SafewordAuthentication;	/* Safeword Authentication enabled */
	BOOL UseSeconds;
	BOOL UseGroupAuthentication;
	HANDLE hMainUDPSocket;
	HANDLE hMainTCPSocket;
} StructErpcdOption;

typedef struct _RadiusOption {
	char RadiusAuthenticationServer[MAX_HOST_NAME];
	char RadiusAccountingServer[MAX_HOST_NAME];
	Server	aServer[MAX_RADIUS_SERVERS];	/* space for radius server data */
} StructRadiusOption;

extern int udp_child;
extern HANDLE hEventOKToExitUDP;
extern HANDLE hEventOKToExitTCP;
extern int newtcpsock;
extern CRITICAL_SECTION	GlobalCriticalSection;
int api_close();
#define ErpcdExit(n)				 \
{									 \
	if (udp_child)			 \
		ReleaseSemaphore(hSemaphoreChildCount, 1, NULL);	\
	else			  \
      api_close(newtcpsock);   \
  WaitForSingleObject(udp_child ? hEventOKToExitUDP : hEventOKToExitTCP, INFINITE);		\
  DeleteCriticalSection(&GlobalCriticalSection);            \
	exit(n);								 \
}

#define MAXHOSTNAMELEN  64

#endif /* _WIN32 */
#endif /* _PORT_H */
