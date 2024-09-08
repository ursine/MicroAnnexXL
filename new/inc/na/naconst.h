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
 * Include file description:
 *	Manifest constants used in parameter processing.
 *
 * Original Author: James Carlson	Created on: 12 April 1996
 *
 ****************************************************************************
 */

#ifndef NACONST_H
#define NACONST_H

#define ALL_PORTS	72
#define ALL_PRINTERS	2
#define ALL_INTERFACES	(1 + ALL_PORTS)
#define ALL_T1S         1
#define ALL_INTMODS     62
#define ALL_DS0S        24
#define ALL_BS		32
#define ALL_PRIS         2
#define ALL_MODEMS	62
#define ALL_DORS      6000   /* Maximum number of specified dialout routes.
				This value must match the value for M_DORS
				specified in the annex file param.h!  */

#define ALL_TRUNKS	(unsigned long)0xffffffff

#ifndef	NBBY
#define	NBBY	8
#endif

#define MAX_STRING_8	8	/* 8 string length */
#define MAX_E2_STRING	16	/* Common string length */
#define MAX_STRING_100  100	/* length of image_name on ANNEX3.Also defined*/
				/* in netadm/netadm.h and inc/rom/e2rom.h */
#define MAX_STRING_120	120	/* String length for channelized T1 */
#define MAX_STRING_128	128	/* String length for 128 char username */
				/* 128 is the max data length in e2 records */
#define	MAX_ADM_STRING	32	/* for lat strings, also in inc/rom/e2rom.h */
				/* length of image_name and term_var: */
				/* length of annex username,passwd prompt
				   parameters for radius */

#define MAX_KERB_EXT_STRING	67
#define MAX_KERB_STRING		17
#define MAX_KERB_INT_STRING	MAX_KERB_STRING  /* Max length of 4 ip addresses plus length */

#define MAX_IPX_STRING	48	/* Yet another unreasonable assumption */

#define	MAX_RIP_STRING	33	/* for rip network list strings */
#define	MAX_RIP_INT_STRING MAX_RIP_STRING	/* rip network list strings 
							(internal format)*/
#define	MAX_RIP_EXT_STRING	138	/* rip network list strings 
					   (external human readable format)*/
#define RIP_LEN_MASK	0x7f	/* mask off include/exclude bit from rip
					string length byte */

#define	MAX_BIT_STRING	(ALL_INTERFACES + (NBBY - 1 ))/NBBY /* max length of
							bit string in byte */

#define ENET_ADDR_SZ		6
#define MOP_PASSWD_SZ		8

#define	LAT_GROUP_SZ	32

#define SHORTPARAM_LENGTH 8	/*   Annex I */
#define LONGPARAM_LENGTH 16	/*   Annex II, TIU */
#define MIN_HW_FOR_LONG	ANX_II	/* first hardware to have long parameters */
#define MAXVALUE  1024		/* size of string values, > UNIXPARAM_LENGTH */
#define ADM_MAX_BCAST_MSG 1024	/* length of broadcast messages */

/* boot command switch values */
#define SWABORT   1  /* abort option  (-a) */
#define SWDELAY   2  /* delayed option (-t) */
#define SWDIAG    4  /* diag option (-h) */
#define SWQUIET   8  /* quiet option (-q) */
#define SWDUMP   16  /* dump option -d */
#define SWFLASH  32  /* dump option -l */

/*
*   defines for 5.0 host_tbl_size parameters  passed as u_short to oper
*   code and then put into e2
*/

#define HTAB_NONE	       254 
#define HTAB_UNLIMITED	       255

#define THISNET_LEN     4
#define THIS_NET_MAX    0xfeff  /* this_net parameter maximum */

#define WARNING_LENGTH 256	/* length of warning matches cli limit */
#define HOSTNAME_LENGTH 32      /* length of hostname, match with cli limit */
#define USERNAME_LENGTH 32      /* length of username. matches with cli limit */
#define FILENAME_LENGTH 100	/* length of filenames for commands */

#ifdef NA
/* This message should match the above define */
#define LONG_FILENAME	"maximum filename length is 100 characters"
#endif

#endif /* NACONST_H */
