/*****************************************************************************
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
 *	Where things reside in the Xenix UDP SL/IP world
 *
 * Original Author:  Paul Mattes		Created on: 01/04/88
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/./inc/slip/RCS/slip_user.h,v 1.3 1989/04/05 14:48:20 root Rel $
 *
 * This file created by RCS from:
 * $Source: /annex/common/src/./inc/slip/RCS/slip_user.h,v $
 *
 * Revision History:
 *
 * $Log: slip_user.h,v $
 * Revision 1.3  1989/04/05  14:48:20  root
 * Changed copyright notice
 *
 * Revision 1.2  88/05/31  17:08:33  parker
 * Changes for new install-annex script
 * 
 * Revision 1.1  88/04/15  12:18:50  mattes
 * Initial revision
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *****************************************************************************/


/*****************************************************************************
 *									     *
 * Local defines and macros						     *
 *									     *
 *****************************************************************************/

#define CFGFILE		INSTALL_DIR/slipcfg"
#define SLIPDATA	"/usr/spool/slipd/D.%d"
#define OUTPIPE		"/usr/spool/slipd/outpipe"
#define PORTLOCK	"/usr/spool/slipd/portlock"


/*****************************************************************************
 *									     *
 * Structure and union definitions					     *
 *									     *
 *****************************************************************************/

struct sockiobuf {
    char *sb_base;	/* base address */
    char *sb_curr;	/* current address */
    int sb_len;		/* useful length */
    };


/*****************************************************************************
 *									     *
 * External data							     *
 *									     *
 *****************************************************************************/

/*****************************************************************************
 *									     *
 * Global data								     *
 *									     *
 *****************************************************************************/

/*****************************************************************************
 *									     *
 * Static data								     *
 *									     *
 *****************************************************************************/

/*****************************************************************************
 *									     *
 * Forward definitions							     *
 *									     *
 *****************************************************************************/
