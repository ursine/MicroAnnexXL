/*
 *****************************************************************************
 *
 *        Copyright 1993 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 * 	A RPC call to return the number of synchronous ports on a annex.
 *
 * Original Author: Owain Phillips      Created on: December 16th 1993
 *
 * Revision Control Information:
 *
 * $Id: get_sync_cnt.c 1.1.5.1 1995/08/16 09:39:07 slu Exp $
 *
 * This file created by RCS from:
 * $Source: /annex/mckinley/src/netadm/RCS/get_sync_cnt.c $
 *
 * Revision History:
 *
 * $Log: get_sync_cnt.c $
 * Revision 1.1.5.1  1995/08/16  09:39:07  slu
 * Support NT.
 *
 * Revision 1.1  1994/01/06  15:37:59  wang
 * Initial revision
 *
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *****************************************************************************
 */



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

#define OUTGOING_COUNT  0

/* Structure Definitions */


/* Forward Routine Declarations */
int rpc();


/* Global Data Declarations */


/* Static Declarations */


get_sync_count(Pinet_addr, type, Pdata)
    struct sockaddr_in *Pinet_addr;
    u_short         type;
    char            *Pdata;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
     *  outgoing[0] is only used by erpc_callresp().
     */

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    return rpc(Pinet_addr, RPROC_GET_SYNCS, OUTGOING_COUNT, outgoing,
	       Pdata, type);

}   /* get_sync_count() */
