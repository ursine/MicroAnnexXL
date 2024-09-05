/******************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *  %$(description)$%
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 *****************************************************************************/

#ifndef NETADM_H
#define NETADM_H

#ifndef NACONST_H
#include "../inc/na/naconst.h"
#endif

#define RPC_DELAY   2
#define TIMEOUT 5

#define RESPONSE_SIZE	1100

#define MESSAGE_LENGTH 1024
#define SIZE_BLOCK_32_X_4 128
#define SIZE_BLOCK_32_X_6 196


/* type definitions */

typedef union
    {
    char     chr;
    COUR_MSG msg;
    CMCALL   call;
    CMREJECT rej;
    CMABORT  ab;
    CMRETURN ret;
    }        COUR_HDR;

typedef struct
    {
    u_short count;
    char    data[MAX_STRING_120 + 4];
    }       STRING;

typedef struct
    {
    u_short     type;
    union
	{
	u_short short_data;
	u_short long_data[2];
	u_char	raw_data[SIZE_BLOCK_32_X_6];
	STRING  string;
	}       data;
    }           PARAM;

/* to keep lint from complaining */
#ifndef AIX
char *strcpy();
#endif

#endif /* NETADM_H */
