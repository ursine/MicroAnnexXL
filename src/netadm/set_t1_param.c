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
 * 	Use RPC's to set T1 parameters in a remote Annex.
 *
 * Original Author: Paul Couto      Created on: April 7, 1995
 *
 * Revision Control Information:
 *
 * $Id: set_t1_param.c,v 1.3.5.1 1995/08/16 13:39:21 slu Exp $
 *
 * This file created by RCS from:
 * $Source: /annex/common/src/./netadm/RCS/set_t1_param.c,v $
 *
 * Revision History:
 *
 * Revision 1.4 1995/08/24  18:25:40  sasson
 * Change max t1 string length from 128 to 120 (max e2 record length).
 * Reviewed by Russ Lamoreaux.
 *
 * $Log: set_t1_param.c,v $
 * Revision 1.3.5.1  1995/08/16  13:39:21  slu
 * Support NT.
 *
 * Revision 1.3  1995/05/18  14:22:59  sasson
 * Ooops. Last check-in was incomplete.
 *
 * Revision 1.2  1995/05/18  12:36:08  sasson
 * Changed the BLOCK_32 parameter type case to handle the ds0 bit mask.
 *
 * Revision 1.1  1995/05/04  16:18:47  sasson
 * Initial revision
 *
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *****************************************************************************
 */


#define RCSDATE $Date: 1995/08/16 13:39:21 $
#define RCSREV  $Revision: 1.3.5.1 $
#define RCSID   "$Header: /annex/common/src/./netadm/RCS/set_t1_param.c,v 1.3.5.1 1995/08/16 13:39:21 slu Exp $"
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

#define OUTGOING_COUNT  5

/* Structure Definitions */


/* Forward Routine Declarations */
int rpc();


/* Global Data Declarations */


/* Static Declarations */


set_t1_param(Pinet_addr, device_type, engine_number, cat, number, type, Pdata)
    struct sockaddr_in *Pinet_addr;
    u_short         device_type;
    u_short         engine_number;
    u_short         cat;
    u_short         number;
    u_short         type;
    char            *Pdata;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_short         param_one,
                    param_two,
                    param_three,
                    param_four;

    u_short         string_length;

    PARAM           param_five;

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
       outgoing[0] is only used by erpc_callresp().
       outgoing[1] contains the device_type.
       outgoing[2] contains the t1 engine_number.
       outgoing[3] contains the catagory.
       outgoing[4] contains the t1 param number.
       outgoing[5] contains the t1 param. */

    param_one = htons(device_type);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(engine_number);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    param_three = htons(cat);
    outgoing[3].iov_base = (caddr_t)&param_three;
    outgoing[3].iov_len = sizeof(param_three);

    param_four = htons(number);
    outgoing[4].iov_base = (caddr_t)&param_four;
    outgoing[4].iov_len = sizeof(param_four);

    param_five.type = htons(type);
    switch (type)
        {
        case BYTE_P:
        case CARDINAL_P:
        case BOOLEAN_P:
            param_five.data.short_data = htons(*(u_short *)Pdata);
	    outgoing[5].iov_len = 2 * sizeof(u_short);
            break;

	case BLOCK_32:
	case BLOCK_32_X_2:
            (void)bcopy(Pdata, param_five.data.raw_data, T1_DS0_INFO_SZ);
            outgoing[5].iov_len = sizeof(u_short) + T1_DS0_INFO_SZ;
            break;

	case STRING_P_120:
	    string_length = *(u_short *)Pdata;
	    param_five.data.string.count = htons(string_length);
	    (void)bcopy(&Pdata[sizeof(u_short)], param_five.data.string.data,
	     (int)string_length);
	    outgoing[5].iov_len = 2 * sizeof(u_short) + string_length;
	    break;

        default:
            return NAE_TYPE;
        }
    outgoing[5].iov_base = (caddr_t)&param_five;

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    return rpc(Pinet_addr, RPROC_SET_T1_PARAM, OUTGOING_COUNT, outgoing,
	       (char *)0, (u_short)0);

}   /* set_t1_param() */
