/*
 *****************************************************************************
 *
 *        Copyright 1996 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * File description: Macro defined simultaneously in different modules.
 * 
 * Original Author: Mohammed Ali		Created on: 8/18/96
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

#ifndef _COMDEFS_H_
#define _COMDEFS_H_

#ifndef ROOT_RDWR
#define ROOT_RDWR              0x8180  /* root permission */
#endif /* ROOT_RDWR */

#ifndef CANCELLED
#define CANCELLED              1       /* secur-id, abort authentication*/
#endif /* CANCELLED */

#ifndef UNAVAILABLE
#define UNAVAILABLE           -1       /* In secur-id, user's entry not */
#endif /* UNAVAILABLE */               /* not available */

#ifndef USER_ABORT
#define USER_ABORT            -2
#endif /* USER_ABORT */

#endif /* _COMDEFS_H_ */






