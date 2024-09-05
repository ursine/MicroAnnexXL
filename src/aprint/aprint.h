/*
 * vi: set ts=4 sw=4 :
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 * Command to spool to an Annex, serial or parallel port.
 *
 * Original Author: Jack Oneil		Created on: June 3, 1986
 *
 * Module Reviewers: harris oneil lint
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/./aprint/RCS/aprint.h,v 2.5 1994/02/17 13:59:48 defina Exp $
 *
 * This file created by RCS from:
 *
 * $Source: /annex/common/src/./aprint/RCS/aprint.h,v $
 *
 * Revision History:
 *
 * $Log: aprint.h,v $
 * Revision 2.5  1994/02/17  13:59:48  defina
 * *** empty log message ***
 *
 * Revision 2.4.1.1  1993/12/16  16:17:15  couto
 * Upped MAX_SERIAL_PORTS to 72
 *
 * Revision 2.4  1992/01/30  14:35:39  raison
 * added support for multiple parallel printer ports.
 *
 * Revision 2.3  91/03/01  13:18:37  pjc
 * Changed maximum number of ports supported for Annex 3,
 * and also for DPTG use.
 * 
 * Revision 2.2  89/04/05  12:08:15  loverso
 * Changed copyright notice
 * 
 * Revision 2.1  87/08/15  00:13:49  loverso
 * *** empty log message ***
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *****************************************************************************
 */

/*
 *	Macro Definitions
 */

#ifndef NULL
#define NULL 0
#endif
#define CNULL (char *)NULL

#ifndef BUFSIZ
#define BUFSIZ 512
#endif

#define PRINTCAP "/etc/printcap"

#define DEFAULT_PRINTER "lp"

#if		NDPTG > 0
#define MAX_SERIAL_PORTS 999	/* allow for DPTG ports */
#else
#define MAX_SERIAL_PORTS 72		/* allow for ANNEX 3 */
#endif

#define MAX_PRINTER_PORTS 2		/* allow for ANNEX 3 */
#define SERIAL 1
#define PARALLEL 2
