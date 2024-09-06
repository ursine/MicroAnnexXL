/******************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *  Set modem category parameter using RPCs
 *
 * Original Author: James Carlson    Created on: 23 January 1996
 *
 ******************************************************************************
 */


/* Include Files */
#include "../inc/config.h"

#include "../inc/port/port.h"
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
extern UINT32 get_long(), get_unspec_long();


/* Defines and Macros */

#define OUTGOING_COUNT  5

/* Structure Definitions */


/* Forward Routine Declarations */


/* Global Data Declarations */


/* Static Declarations */


set_modem_param(Pinet_addr, device_type, line_number, cat, number, type, Pdata)
    struct sockaddr_in *Pinet_addr;
    u_short         device_type;
    u_short         line_number;
    u_short         cat;
    u_short         number;
    u_short         type;
    char            *Pdata;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_short         param_one,
                    param_two,
                    param_three,
                    param_four,
                    group;

    u_short         string_length;

    PARAM           param_five;
    u_char	    *fmptr, *toptr;
    int		    error;

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
       outgoing[0] is only used by erpc_callresp().
       outgoing[1] contains the device_type.
       outgoing[2] contains the line_number.
       outgoing[3] contains the category.
       outgoing[4] contains the line param number.
       outgoing[5] contains the line param. */

    param_one = htons(device_type);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(line_number);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    param_three = htons(cat);
    outgoing[3].iov_base = (caddr_t)&param_three;
    outgoing[3].iov_len = sizeof(param_three);

    param_four = htons(number);
    outgoing[4].iov_base = (caddr_t)&param_four;
    outgoing[4].iov_len = sizeof(param_four);

    param_five.type = htons(type);
    switch (type) {
    case BOOLEAN_P:
      param_five.data.short_data = htons(*(u_short *)Pdata);
      outgoing[5].iov_len = 2 * sizeof(u_short);
      break;
    default:
      return NAE_TYPE;
    }
    outgoing[5].iov_base = (caddr_t)&param_five;

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    return rpc(Pinet_addr, RPROC_SET_MODEM_PARAM, OUTGOING_COUNT, outgoing,
	       (char *)0, (u_short)0);

}   /* set_modem_param() */
