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
 *	Description of /etc/shadow reading routines.
 *	(Similar to AT&T's shadow.h file -- copyright (c) 1988.)
 *
 * Original Author: James Carlson & AT&T	Created on: 20JAN93
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/./inc/RCS/ashadow.h,v 1.2 1993/05/26 18:34:00 reeve Rel $
 *
 * This file created by RCS from $Source: /annex/common/src/./inc/RCS/ashadow.h,v $
 *
 * Revision History:
 *
 * $Log: ashadow.h,v $
 * Revision 1.2  1993/05/26  18:34:00  reeve
 * Changed name to ashadow.h.  Necessary to stop infinite-loop including.
 *
 * Revision 1.1  1993/01/21  10:53:07  carlson
 * Initial revision
 *
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *  DATE:	$Date: 1993/05/26 18:34:00 $
 *  REVISION:	$Revision: 1.2 $
 *
 ****************************************************************************
 */


#define DAY	(24*60*60L)	/* number of seconds in a day */
#define DAY_NOW	(time(0)/DAY)

struct spwd {
	char	*sp_namp;	/* User's login name */
	char	*sp_pwdp;	/* Salted password entry */
	long	sp_lstchg;	/* Last changed date */
	long	sp_min;		/* Minimum days between changes */
	long	sp_max;		/* Maximum days password is valid */
	long	sp_warn;	/* Number of days to warn user */
	long	sp_inact;	/* Maximum days account can languish */
	long	sp_expire;	/* Date when account expires */
	long	sp_flag;	/* unused field */
};

void setspent(),endspent();
struct spwd *getspent();
