/*
 *****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *  Issue PRI module reset RPC
 *
 * Original Author: James Carlson    Created on: 23 January 1996
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

#define OUTGOING_COUNT  2

/* Structure Definitions */


/* Forward Routine Declarations */


/* Global Data Declarations */


/* Static Declarations */


reset_pri(Pinet_addr, module_no, reset_type)
    struct sockaddr_in *Pinet_addr;
    u_short         module_no;
    u_short         reset_type;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_short         param_one,
                    param_two;

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
       outgoing[0] is only used by erpc_callresp().
       outgoing[1] contains the module number (1 based)
       outgoing[2] contains the reset type */

    param_one = htons(module_no);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(reset_type);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    return rpc(Pinet_addr, RPROC_RESET_PRI, OUTGOING_COUNT, outgoing,
	       (char *)0, (u_short)0);

}   /* reset_pri() */
