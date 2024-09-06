/*****************************************************************************
 *
 *        Copyright 1997 Bay Networks, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module: conv.h
 *
 * Author: Murtaza S. Chiba
 *
 * Module Description: This module holds the enums that correspond
 *                     to the *_values char arrays found in conv.c
 *                 
 *
 *****************************************************************************
 */

#ifndef _CONV_H_
#define _CONV_H_
/* these are related to the *_values char arrays in conv.c and need to be changed if
   those are changed */
enum auth_protocol{ DEFAULT_PROTOCOL, ACP_PROTOCOL, RADIUS_PROTOCOL};
enum rad_acct_level{ DEFAULT_LEVEL, STANDARD_LEVEL, ADVANCED_LEVEL, BASIC_LEVEL};
enum port_encoding{DEFAULT_ENCODING, DEVICE_ENCODING, CHANNEL_ENCODING};
enum address_origin{DEFAULT_ADDR_ORIG, AUTH_SERVER_ADDR_ORIG, LOCAL_ADDR_ORIG, 
		    DHCP_ADDR_ORIG, ACP_ADDR_ORIG,IPPOOL_ADDR_ORIG};
enum compat_mode {DEFAULT_MODE, BAY_MODE, USR_MODE, ASCEND_MODE};   

/* PPP Trace Level defines */
#define PPTRC_DEF	0x00
#define PPTRC_CNTL	0x01
#define PPTRC_DATA	0x02
#define PPTRC_HEX	0x04
#define PPTRC_ALL	0x07

#endif /* _CONV_H_ */







