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
 *      %$(Description)$%
 *
 * Original Author: %$(author)$%        Created on: %$(created-on)$%
 *
 *****************************************************************************
 */


/* Include Files */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include "../libannex/api_if.h"

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/uio.h>
#else 
#include "../inc/port/xuio.h"
#endif 


#include "../inc/courier/courier.h"
#include "../inc/erpc/netadmp.h"
#include "../inc/na/naconst.h"
#include "netadm.h"
#include "netadm_err.h"

/* External Data Declarations */
extern UINT32 get_long(), get_unspec_long();

/* defines and Macros */

#define OUTGOING_COUNT  3

/* Structure Definitions */


/* Forward Routine Declarations */
void set_long();
void set_unspec_long();
int get_dla_param();
int rpc();

/* Global Data Declarations */


/* Static Declarations */


set_dla_param(Pinet_addr, cat, number, type, Pdata)
    struct sockaddr_in *Pinet_addr;
    u_short         cat;
    u_short         number;
    u_short         type;
    char            *Pdata;

{
    struct iovec    outgoing[OUTGOING_COUNT + 1];

    u_char	    *fmptr, *toptr;
    int		    error;
    u_short         param_one,
                    param_two,
    	            string_length,
		    group;

    PARAM           param_three;
    u_char	    group_code[LAT_GROUP_SZ];

    /* Check *Pinet_addr address family. */

    if (Pinet_addr->sin_family != AF_INET)
        return NAE_ADDR;

    /* Set up outgoing iovecs.
    outgoing[0] is used only by erpc_callresp().
    outgoing[1] contains the catagory.
    outgoing[2] contains the dla param number.
    outgoing[3] contains the data. */

    param_one = htons(cat);
    outgoing[1].iov_base = (caddr_t)&param_one;
    outgoing[1].iov_len = sizeof(param_one);

    param_two = htons(number);
    outgoing[2].iov_base = (caddr_t)&param_two;
    outgoing[2].iov_len = sizeof(param_two);

    param_three.type = htons(type);
    switch (type)
        {
        case CARDINAL_P:
        case BOOLEAN_P:
            param_three.data.short_data = htons(*(u_short *)Pdata);
            outgoing[3].iov_len = 2 * sizeof(u_short);
            break;

        case LONG_CARDINAL_P:
            set_long(param_three.data.long_data,
				get_unspec_long((u_short *)Pdata));
            outgoing[3].iov_len = sizeof(u_short) + sizeof(UINT32);
            break;

        case LONG_UNSPEC_P:
            set_unspec_long(param_three.data.long_data,
				get_unspec_long((u_short *)Pdata));
            outgoing[3].iov_len = sizeof(u_short) + sizeof(UINT32);
            break;

        case ENET_ADDR_P:
            (void)bcopy(Pdata, param_three.data.raw_data, ENET_ADDR_SZ);
            outgoing[3].iov_len = sizeof(u_short) + ENET_ADDR_SZ;
            break;

        case MOP_PASSWD_P:
            (void)bcopy(Pdata, param_three.data.raw_data, MOP_PASSWD_SZ);
            outgoing[3].iov_len = sizeof(u_short) + MOP_PASSWD_SZ;
            break;

        case STRING_P:
        case STRING_P_100:
        case ADM_STRING_P:
        case RIP_ROUTERS_P:
	case KERB_HOST_P:
	case IPX_STRING_P:
            string_length = *(u_short *)Pdata;
            param_three.data.string.count = htons(string_length);
	    (void)bcopy(&Pdata[sizeof(u_short)], param_three.data.string.data,
	     (int)string_length);
            outgoing[3].iov_len = 2 * sizeof(u_short) + string_length;
            break;

        case LAT_GROUP_P:

	    /* in the case of this type, we are requested to turn on */
	    /* or off certain bits in a 32 byte field.  To do this, we */
	    /* must first get the current value, then manipulate it. */

            param_three.data.string.count = htons(LAT_GROUP_SZ);
	    if(error = get_dla_param(Pinet_addr, (u_short)cat,
				(u_short)number, (u_short)type, group_code)) {
			return(error);
	    }
	    fmptr = (u_char *) Pdata;
	    toptr = group_code;
	    if (Pdata[LAT_GROUP_SZ]) {		/* if enable */
		for (group = 0; group < LAT_GROUP_SZ; group++) {
		    *toptr++ |= *fmptr++;
		}
	    } else {					/* else disable */
		for (group = 0; group < LAT_GROUP_SZ; group++) {
		    *toptr++ &= ~(*fmptr++);
		}
	    }
	    (void)bcopy(group_code, param_three.data.raw_data,
	     					(int)LAT_GROUP_SZ);
            outgoing[3].iov_len = sizeof(u_short) + LAT_GROUP_SZ;
            break;

        default:
            return NAE_TYPE;
        }
    outgoing[3].iov_base = (caddr_t)&param_three;

    /* Call rpc() to communicate the request to the annex via erpc or srpc. */

    error = rpc(Pinet_addr, RPROC_SET_DLA_PARAM, OUTGOING_COUNT, outgoing,
	       (char *)0, (u_short)0);

    if (error == 0 && cat == DFE_CAT && number == DFE_SELECTED_MODULES) {
      param_two = htons(DFE_SELMODS2);
      param_three.data.short_data = htons(((u_short *)Pdata)[1]);
      /* Intentionally ignoring the error here! */
      rpc(Pinet_addr, RPROC_SET_DLA_PARAM, OUTGOING_COUNT, outgoing,
	  (char *)0, (u_short)0);
    }

    return error;
}       /* set_dla_param() */
