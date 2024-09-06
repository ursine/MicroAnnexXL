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
 *****************************************************************************
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
#include "../inc/na/naconst.h"
#include "netadm.h"
#include "netadm_err.h"

/* External Data Declarations */
extern UINT32 get_unspec_long();

/* Defines and Macros */


/* Structure Definitions */


/* Forward Routine Declarations */
void set_long();
void set_unspec_long();


/* Global Data Declarations */


/* Static Declarations */


return_param(Pdata, type, response, rmsgsize)

    char    *Pdata;		/* place to put final result */
    u_short type;		/* type of parameter expected */
    char    response[];		/* return message offset, no courier hdr */
    int     rmsgsize;		/* size of return message w/o courier */
{
    u_short string_length;
    u_short return_type;
    UINT32  longval;		/* properly aligned long for conversion */

    PARAM   *Pparam;

    /* If no Pdata, no conversion is performed! */

    if(!Pdata)
	return NAE_SUCC;

    Pparam = (PARAM *)(&response[0]);

    /* Check the type of the returned param, unless a RAW_BLOCK_P. */
    /* If requested type is STRING_P_100 and we got type STRING_P, */
    /* we are probably dealing with and old annex, this is not an error. */

    return_type = ntohs(Pparam->type);

    if ((return_type != type)  &&
	(type != RAW_BLOCK_P)  &&
	!( (type == STRING_P_100) && (return_type == STRING_P) ) &&
	!( (type == BYTE_P) && (return_type == CARDINAL_P)))
      return NAE_TYPE;
    /* Pass the param back to the caller. */

    switch (type)
        {
        case CARDINAL_P:
	case BOOLEAN_P:
        case BYTE_P:
	    if (rmsgsize < 2 * sizeof(u_short))
                return NAE_SRES;

            string_length = ntohs(Pparam->data.short_data);
	    (void)bcopy(&string_length,Pdata,sizeof(u_short));

            break;

        case LONG_CARDINAL_P:
	    if (rmsgsize < sizeof(u_short) + sizeof(UINT32))
                return NAE_SRES;

	    longval = get_unspec_long(Pparam->data.long_data);
	    set_long((u_short *)Pdata, longval);

            break;

        case LONG_UNSPEC_P:
	    if (rmsgsize < sizeof(u_short) + sizeof(UINT32))
                return NAE_SRES;

	    longval = get_unspec_long(Pparam->data.long_data);
	    set_unspec_long((u_short *)Pdata, longval);

            break;

        case ENET_ADDR_P:

            if (rmsgsize < sizeof(u_short) + ENET_ADDR_SZ)
                return NAE_SRES;

            (void)bcopy(Pparam->data.raw_data, Pdata, ENET_ADDR_SZ);

            break;

        case STRING_P:
        case ADM_STRING_P:
        case STRING_P_100:
        case STRING_P_120:
        case STRING_P_128:
        case RIP_ROUTERS_P:
	case KERB_HOST_P:
	case IPX_STRING_P:
	case MOP_PASSWD_P:
	    if (rmsgsize < 2 * sizeof(u_short))
                return NAE_SRES;

	    string_length = ntohs(Pparam->data.string.count);

	    if (rmsgsize < 2 * sizeof(u_short) + string_length)
	        return NAE_SRES;

	    (void)bcopy(&string_length,Pdata,sizeof(u_short));
	    (void)bcopy(Pparam->data.string.data,Pdata+sizeof(u_short),
		string_length);

            break;

        case RAW_BLOCK_P:
	    if (rmsgsize < sizeof(u_short))
                return NAE_SRES;

	    (void)bcopy(response,&string_length,sizeof(u_short));
	    string_length = ntohs(string_length);

	    if (rmsgsize < sizeof(u_short) + string_length)
	        return NAE_SRES;

	    (void)bcopy(&string_length,Pdata,sizeof(u_short));
	    (void)bcopy(response+sizeof(u_short),Pdata+sizeof(u_short),
		string_length);

            break;
	case LAT_GROUP_P:
	    if (rmsgsize < sizeof(u_short) + LAT_GROUP_SZ)
	        return NAE_SRES;

             (void)bcopy(Pparam->data.raw_data, Pdata, LAT_GROUP_SZ);

            break;

	case BLOCK_32:
	    if (rmsgsize < sizeof(u_short) + 32)
	        return NAE_SRES;

             (void)bcopy(Pparam->data.raw_data, Pdata, 32);

            break;

	case BLOCK_32_X_2:
	    if (rmsgsize < sizeof(u_short) + 64)
	        return NAE_SRES;

             (void)bcopy(Pparam->data.raw_data, Pdata, 64);

            break;

	case BLOCK_32_X_4:
	    if (rmsgsize < sizeof(u_short) + 128)
	      return NAE_SRES;
	    (void)bcopy(Pparam->data.raw_data, Pdata, 128);
	    break;

	case BLOCK_32_X_6:
	    if (rmsgsize < sizeof(u_short) + 192)
	      return NAE_SRES;
	    (void)bcopy(Pparam->data.raw_data, Pdata, 192);
	    break;

        default:
            return NAE_RTYP;

        } /* switch (type) */

    return NAE_SUCC;

}   /* return_param() */
