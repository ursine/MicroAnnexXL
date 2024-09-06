/*
 *****************************************************************************
 *
 *        Copyright 1992, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *
 *	Defines TELNET protocol
 *
 * Original Author:  Berkeley			Created on: 86/01/29
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/./newrtelnet/RCS/rtelnet.h,v 1.2 1992/08/13 17:17:13 carlson Rel $
 *
 * This file created by RCS from $Source: /annex/common/src/./newrtelnet/RCS/rtelnet.h,v $
 *
 * Revision History:
 *
 * $Log: rtelnet.h,v $
 * Revision 1.2  1992/08/13  17:17:13  carlson
 * Added MDIO return codes for integrated I/O routines.
 *
 * Revision 1.1  92/08/05  15:40:28  carlson
 * Initial revision
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *  DATE:	$Date: 1992/08/13 17:17:13 $
 *  REVISION:	$Revision: 1.2 $
 *
 ****************************************************************************
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 *	@(#)telnet.h	5.1 (Berkeley) 5/30/85
 */

#ifndef RTELNET_H
#define RTELNET_H

/* Turn this switch on to eliminate all debugging code. */
/* #define NO_DEBUG 1 */

/*
 * Definitions for the TELNET protocol.
 */
#define	IAC	255		/* interpret as command: */
#define	DONT	254		/* you are not to use option */
#define	DO	253		/* please, you use option */
#define	WONT	252		/* I won't use option */
#define	WILL	251		/* I will use option */
#define	SB	250		/* interpret as subnegotiation */
#define	GA	249		/* you may reverse the line */
#define	EL	248		/* erase the current line */
#define	EC	247		/* erase the current character */
#define	AYT	246		/* are you there */
#define	AO	245		/* abort output--but let prog finish */
#define	IP	244		/* interrupt process--permanently */
#define	BREAK	243		/* break */
#define	DM	242		/* data mark--for connect. cleaning */
#define	NOP	241		/* nop */
#define	SE	240		/* end sub negotiation */
#define EOR     239             /* end of record (transparent mode) */

#define	LMABORT 	238	/* linemode abort process signal */
#define	LMSUSP  	237	/* linemode suspend process signal */
#define LMEOF	236		/* linemode end of file signal */

#define SYNCH	242		/* for telfunc calls */

#ifdef TELCMDS
char *telcmds[] = {
	"SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
	"EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC"
};
#endif

/* telnet options */
#define TELOPT_BINARY	0	/* 8-bit data path (rfc 856) */
#define TELOPT_ECHO	1	/* echo (rfc 857) */
#define	TELOPT_RCP	2	/* prepare to reconnect */
#define	TELOPT_SGA	3	/* suppress go ahead (rfc 858) */
#define	TELOPT_NAMS	4	/* approximate message size */
#define	TELOPT_STATUS	5	/* give status (rfc 859) */
#define	TELOPT_TM	6	/* timing mark (rfc 860) */
#define	TELOPT_RCTE	7	/* remote controlled transmission and echo (rfc 726) */
#define TELOPT_NAOL 	8	/* negotiate about output line width */
#define TELOPT_NAOP 	9	/* negotiate about output page size */
#define TELOPT_NAOCRD	10	/* negotiate about CR disposition */
#define TELOPT_NAOHTS	11	/* negotiate about horizontal tabstops */
#define TELOPT_NAOHTD	12	/* negotiate about horizontal tab disposition */
#define TELOPT_NAOFFD	13	/* negotiate about formfeed disposition */
#define TELOPT_NAOVTS	14	/* negotiate about vertical tab stops */
#define TELOPT_NAOVTD	15	/* negotiate about vertical tab disposition */
#define TELOPT_NAOLFD	16	/* negotiate about output LF disposition */
#define TELOPT_XASCII	17	/* extended ascic character set (rfc 698) */
#define	TELOPT_LOGOUT	18	/* force logout (rfc 727) */
#define	TELOPT_BM	19	/* byte macro (rfc 735) */
#define	TELOPT_DET	20	/* data entry terminal (rfc 1043) */
#define	TELOPT_SUPDUP	21	/* supdup protocol (rfc 736) */
#define	TELOPT_SUPDUPOUTPUT 22	/* supdup output (rfc 749) */
#define	TELOPT_SNDLOC	23	/* send location (rfc 779) */
#define	TELOPT_TTYPE	24	/* terminal type (rfc 1091) */
#define	TELOPT_EOR	25	/* end of record (rfc 885) */
#define TELOPT_TUID	26	/* TACACS user ident (rfc 927) */
#define TELOPT_OUTMRK	27	/* output marking (rfc 933) */
#define TELOPT_TTYLOC	28	/* terminal location (rfc 946) */
#define TELOPT_3270REGIME 29	/* IBM 3270 (rfc 1041) */
#define TELOPT_X3PAD	30	/* X.3 PAD option (rfc 1053) */
#define TELOPT_NAWS	31	/* nego. about window size (rfc 1073) */
#define TELOPT_TSPEED	32	/* terminal speed (rfc 1079) */
#define TELOPT_LFLOW	33	/* remote flow control (rfc 1080) */
#define TELOPT_LINEMODE	34	/* linemode (LM) (rfc 1184) */
#define TELOPT_XDISPLOC	35	/* X display location (rfc 1096) */
#define TELOPT_EXOPL	255	/* extended-options-list (rfc 861) */

/* TELOPT_LINEMODE:  linemode suboption values */
#define LM_MODE		1	
		/* linemode mode mask values */
#	define LM_EDIT 		0x01	/* local editing */
#	define LM_TRAPSIG	0x02	/* local signal trapping */
#	define LM_MODE_ACK	0x04	/* client agrees to mode */
#define LM_FORWARDMASK	2	
#define LM_SLC		3	/* Set Local Characters */
	/* definable local functions */
#	define SLC_SYNCH        1
#	define SLC_BRK          2
#	define SLC_IP           3
#	define SLC_AO           4
#	define SLC_AYT          5
#	define SLC_EOR          6
#	define SLC_ABORT        7
#	define SLC_EOF          8
#	define SLC_SUSP         9
#	define SLC_EC          10
#	define SLC_EL          11
#	define SLC_EW          12
#	define SLC_RP          13	/* reprint line */
#	define SLC_LNEXT       14	/* literal next */
#	define SLC_XON         15	/* xon character */
#	define SLC_XOFF        16	/* xoff character */
#	define SLC_FORW1       17	/* alternate buffer forward */
#	define SLC_FORW2       18

#	define MAX_SLC_FN      18	/* value of highest fn def +1*/
					/* to make table size */

	/* SLC function modifiers */
#	define SLC_DEFAULT      3
#	define SLC_VALUE        2
#	define SLC_CANTCHANGE   1
#	define SLC_NOSUPPORT    0
#	define SLC_LEVEL_MASK   3
#	define SLC_ACK        128
#	define SLC_FLUSHIN     64
#	define SLC_FLUSHOUT    32

/* telnet X.3 PAD options */
#define SET	0
#define RESPONSESET	1
#define IS	2
#define RESPONSEIS	3
#define SEND	4

#ifdef TELOPTS
char *telopts[] = {
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
	"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP", "NAOCRD",
	"NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS", "NAOVTD", "NAOLFD",
	"EXTENDED ASCII", "LOGOUT", "BYTE MACRO", "DATA ENTRY TERMINAL",
	"SUPDUP", "SUPDUP OUTPUT", "SEND LOCATION", "TERMINAL TYPE",
	"END OF RECORD", "TACACS UID", "OUTPUT MARKING", "TTYLOC",
	"3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW", "LINEMODE",
	"XDISPLOC"
};
#define	NTELOPTS	(sizeof(telopts)/sizeof(char *))
#endif

#define MAX_PORT	72	/* Maximum port count */
#define PORT_MAP_BASE   5000
#define RAW_MAP_BASE    7000

/* sub-option qualifiers */
#define	TELQUAL_IS	0	/* option is... */
#define	TELQUAL_SEND	1	/* send option */

/* For wait_for_io */
#define FROM_PTY	1
#define FROM_NET	2
#define TO_PTY		4
#define TO_NET		8
#define ERR_PTY		0x10
#define ERR_NET		0x20
#define WFIO_TIMEOUT	0x40
#define ALL_NET		(FROM_NET|TO_NET|ERR_NET)
#define ALL_PTY		(FROM_PTY|TO_PTY|ERR_PTY)

/* For mode */
#define MODEF_RAW	0
#define MODEF_ECHO	1

/* For input/output routines */
#define MDIO_ERROR	(-1)	/* Unexpected I/O error */
#define MDIO_DEFER	(-2)	/* Nothing sent/received; would block */
#define MDIO_UNSELECT	(-3)	/* Don't select next time around */
#define MDIO_CLOSED	(-4)	/* Closed connection or socket */

#ifdef NO_DEBUG
#define DBG(x)
#else
#define DBG(x)	_DBG x
extern void _DBG();
#endif

#define D_INIT	0	/* Entry/Exit messages */
#define D_INFO	1	/* Informational messages */
#define D_WARN	2	/* Warnings */
#define D_ERR	3	/* Errors */
#define D_FATL	4	/* Fatal internal problems */

#endif /* RTELNET_H */
