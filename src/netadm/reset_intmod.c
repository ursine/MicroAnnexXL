/*
 *****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
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
 * $Header: /annex/common/src/./netadm/RCS/reset_intmod.c,v 1.1.5.1 1995/08/16 13:36:21 slu Exp $
 *
 * This file created by RCS from $Source: /annex/common/src/./netadm/RCS/reset_intmod.c,v $
 *
 * Revision History:
 *
 * $Log: reset_intmod.c,v $
 * Revision 1.1.5.1  1995/08/16  13:36:21  slu
 * Support NT.
 *
 * Revision 1.1  1995/05/04  16:17:28  sasson
 * Initial revision
 *
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *
 ******************************************************************************/

#define RCSDATE $Date: 1995/08/16 13:36:21 $
#define RCSREV  $Revision: 1.1.5.1 $
#define RCSID   "$Header: /annex/common/src/./netadm/RCS/reset_intmod.c,v 1.1.5.1 1995/08/16 13:36:21 slu Exp $"
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

#define OUTGOING_COUNT  2

/* Structure Definitions */


/* Forward Routine Declarations */
int rpc();

/* Global Data Declarations */


/* Static Declarations */


int reset_intmod(Pinet_addr, engine_no, modem_no)
    struct sockaddr_in *Pinet_addr;
    u_short         engine_no;
    u_short         modem_no;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_short         param_one,
                    param_two;

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
       outgoing[0] is only used by erpc_callresp().
       outgoing[1] contains the engine number (1 based)
       outgoing[2] contains the modem number (1 based) */

    param_one = htons(engine_no);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(modem_no);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    return rpc(Pinet_addr, RPROC_RESET_INT_MOD, OUTGOING_COUNT, outgoing,
	       (char *)0, (u_short)0);

}   /* reset_intmod() */
