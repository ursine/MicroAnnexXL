/*
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	%$(description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/netadm/RCS/netadm_err.h,v 1.9 1995/09/20 10:15:23 gmg Exp $
 *
 * This file created by RCS from $Source: /annex/common/src/netadm/RCS/netadm_err.h,v $
 *
 * Revision History:
 *
 * $Log: netadm_err.h,v $
 * Revision 1.9  1995/09/20  10:15:23  gmg
 * Fixed SPR 5327: Misleading error code interpretation.
 *
 * Revision 1.8  1993/05/05  16:14:16  carlson
 * Added two missing error codes and some missing comments.
 *
 * Revision 1.7  92/01/15  15:34:10  reeve
 * Added error codes for H/W platforms not accepting certain
 * parameter values.
 * 
 * Revision 1.6  91/12/30  16:10:58  reeve
 * Added new error code for receipt of reject.
 * 
 * Revision 1.5  90/04/17  17:54:32  emond
 * Made "details[]" and "errors[]" externs (ifdef'd) to compile on Ultrix
 * and SGI machines.
 * 
 * Revision 1.4  89/04/05  12:44:27  loverso
 * Changed copyright notice
 * 
 * Revision 1.3  88/07/08  14:05:45  harris
 * New reject NAE_SESSION, new abort NAE_RSRC.
 * 
 * Revision 1.2  88/05/04  23:19:46  harris
 * New NA error messages.
 * 
 * Revision 1.1  86/05/07  11:16:22  goodmon
 * Initial revision
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *  DATE:	$Date: 1995/09/20 10:15:23 $
 *  REVISION:	$Revision: 1.9 $
 *
 ****************************************************************************
 */

/* error codes -- must match error messages in na.ern */

#define NAE_SUCC	0	/* success: no errors */
#define NAE_ADDR	1	/* unsupported address family */
#define NAE_TIME	2	/* erpc timeout */
#define NAE_SOCK	3	/* socket error */
#define NAE_CNT		4	/* read_memory count too large */
#define NAE_SRES	5	/* read_memory response too short */
#define NAE_TYPE	6	/* incorrect parameter or statistic type */
#define NAE_RTYP	7	/* unsupported response type */
#define NAE_CTYP	8	/* invalid courier response type */
#define NAE_REJ		9	/* erpc message rejected: details unknown */
#define NAE_PROG	10	/* erpc mes reject: invalid program number */
#define NAE_VER		11	/* erpc mes reject: invalid version number */
#define NAE_PROC	12	/* erpc mes reject: invalid procedure number */
#define NAE_ARG		13	/* erpc mes reject: invalid argument */
#define NAE_SREJECT	14	/* erpc mes reject: SRPC encryption error */
#define NAE_SESSION	15	/* erpc mes reject: SRPC required */
#define NAE_ABT		16	/* erpc message abort:  details unknown */
#define NAE_PTYP	17	/* erpc mes abort: invalid parameter type */
#define NAE_PCNT	18	/* erpc mes abort: invalid parameter count */
#define NAE_PVAL	19	/* erpc mes abort: invalid parameter value */
#define NAE_E2WR	20	/* erpc mes abort: eerom write error */
#define NAE_RSRC	21	/* srpc mes abort: insufficient resources */
#define	NAE_SABORT	22	/* srpc session aborted for unknown reasons */
#define	NAE_NOANXSUP	23	/* erpc mes abort: Annex doesn't support prog */
#define NAE_BADDEV	24	/* srpc mes abort: bad device requested */
#define NAE_INTERNAL	25	/* srpc mes abort: internal Annex error */
#define NAE_BADBOOT	26	/* erpc mes abort: can't boot load a self-boot box */

/* details[] and errors[] are initialized in netadm/rpc.c */

#define MAX_DETAIL 7

#ifndef INIT
extern
#endif
int details[]
#ifdef INIT
    =
        {
        NAE_PROG,
        NAE_VER,
        NAE_PROC,
        NAE_ARG,
	NAE_SREJECT,
	NAE_SESSION,
	NAE_NOANXSUP,
	NAE_PVAL
        }
#endif
    ;

#define MAX_ERROR 10

#ifndef INIT
extern
#endif
int errors[]

#ifdef INIT
    =
        {		    /* Names from inc/na/netadmp.h */
	NAE_ABT,	    /* 0 -- ? */
	NAE_PTYP,	    /* 1:  BAD_TYPE */
	NAE_PCNT,	    /* 2:  BAD_COUNT */
	NAE_PVAL,	    /* 3:  BAD_PARAM */
	NAE_E2WR,	    /* 4:  WRITE_FAILURE */
	NAE_RSRC,	    /* 5:  TOO_MANY_SESSIONS */
	NAE_BADDEV,	    /* 6:  BAD_DEVICE */
	NAE_INTERNAL,	    /* 7:  INTERNAL_ERROR */
	NAE_ABT,	    /* 8:  BAD_T1DS0_VAL */
	NAE_BADBOOT,	    /* 9:  BAD_BOOT_ARG */
	NAE_PVAL
        }
#endif
    ;
