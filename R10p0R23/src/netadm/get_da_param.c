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
 ******************************************************************************/


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


get_dla_param(Pinet_addr, cat, number, type, Pdata)
    struct sockaddr_in *Pinet_addr;
    u_short	    cat;
    u_short         number;
    u_short         type;
    char            *Pdata;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_short         param_one,
                    param_two;
    int retv;

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
       outgoing[0] is only used by erpc_callresp().
       outgoing[1] contains the catagory.
       outgoing[2] contains the dla param number. */

    param_one = htons(cat);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(number);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    retv = rpc(Pinet_addr, RPROC_GET_DLA_PARAM, OUTGOING_COUNT, outgoing,
	       Pdata, type);

    if (retv == 0 && cat == DFE_CAT && number == DFE_SELECTED_MODULES) {
      param_two = htons(DFE_SELMODS2);
      retv = rpc(Pinet_addr, RPROC_GET_DLA_PARAM, OUTGOING_COUNT, outgoing,
		 Pdata+2, type);
      /* Just for old Annex support */
      if (retv != 0)
	if (*(u_short *)Pdata == 0x7FFF)
	  ((u_short *)Pdata)[1] = 0xFFFF;
	else
	  ((u_short *)Pdata)[1] = 0;
      retv = 0;
    }

    return retv;
}   /* get_dla_param() */
