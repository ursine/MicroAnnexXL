/******************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *  %$(Description)$%
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/./netadm/RCS/reset_annex.c,v 1.3.5.1 1995/08/16 13:35:59 slu Exp $
 *
 * This file created by RCS from:
 * $Source: /annex/common/src/./netadm/RCS/reset_annex.c,v $
 *
 * Revision History:
 *
 * $Log: reset_annex.c,v $
 * Revision 1.3.5.1  1995/08/16  13:35:59  slu
 * Support NT.
 *
 * Revision 1.3  1991/04/09  00:13:31  emond
 * Accommodate generic TLI interface
 *
 * Revision 1.2  89/04/05  12:44:30  loverso
 * Changed copyright notice
 * 
 * Revision 1.1  88/06/01  16:36:37  mattes
 * Initial revision
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 ******************************************************************************/

#define RCSDATE $Date: 1995/08/16 13:35:59 $
#define RCSREV  $Revision: 1.3.5.1 $
#define RCSID   "$Header: /annex/common/src/./netadm/RCS/reset_annex.c,v 1.3.5.1 1995/08/16 13:35:59 slu Exp $"
#ifndef lint
static char rcsid[] = RCSID;
#endif

/* Include Files */
#include "../inc/config.h"

#include <sys/types.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/uio.h>
#else 
#include "../inc/port/xuio.h"
#endif 

#include "../libannex/api_if.h"

#include "../inc/courier/courier.h"
#include "../inc/erpc/netadmp.h"
#include "netadm.h"
#include "netadm_err.h"

/* External Data Declarations */


/* Defines and Macros */

#define OUTGOING_COUNT  3

/* Structure Definitions */


/* Forward Routine Declarations */
int rpc();


/* Global Data Declarations */


/* Static Declarations */


reset_annex(Pinet_addr, subsystem, range_included, dorset)
    struct sockaddr_in *Pinet_addr;
    u_short         subsystem;
    u_short         range_included;
    u_char         *dorset;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_short         param_one;
    u_short         param_two;

    /* This is an array of bytes used to send a bitmapped range of dialout
       routes over to the annex when resetting the "dialout" subsystem. */
    u_char          tmp_dorset[(ALL_DORS + (NBBY - 1)) /NBBY];

    /* Loop variable */
    int  i;

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
       outgoing[0] is only used by erpc_callresp().
       outgoing[1] contains the subsystem to reset. 
       outgoing[2] contains whether a route set was included.
       outgoing[3] contains dialout route set (whether needed or not) */

    param_one = htons(subsystem);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(range_included);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    for (i=0; i<((ALL_DORS + (NBBY - 1)) / NBBY); i++)
      tmp_dorset[i] = htons(dorset[i]);
    outgoing[3].iov_base = (caddr_t)&tmp_dorset[0];
    outgoing[3].iov_len = sizeof(tmp_dorset);

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    return rpc(Pinet_addr, RPROC_RESET_ANNEX, OUTGOING_COUNT, outgoing,
	       (char *)0, (u_short)0);

}   /* reset_annex() */
