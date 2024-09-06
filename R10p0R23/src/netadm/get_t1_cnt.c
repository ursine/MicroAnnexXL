/*
 *****************************************************************************
 *
 *        Copyright 1995 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 * 	A RPC call to return the number of t1 ports on a annex.
 *
 * Original Author: Paul Couto      Created on: April 7, 1995
 *
 * Revision Control Information:
 *
 * $Id: get_t1_cnt.c,v 1.1.5.1 1995/08/16 13:33:32 slu Exp $
 *
 * This file created by RCS from:
 * $Source: /annex/common/src/./netadm/RCS/get_t1_cnt.c,v $
 *
 * Revision History:
 *
 * $Log: get_t1_cnt.c,v $
 * Revision 1.1.5.1  1995/08/16  13:33:32  slu
 * Support NT.
 *
 * Revision 1.1  1995/05/04  16:16:59  sasson
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


int get_t1_count(Pinet_addr, type, Pdata)
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

    return rpc(Pinet_addr, RPROC_GET_T1S, OUTGOING_COUNT, outgoing,
	       Pdata, type);

}   /* get_t1_count() */
