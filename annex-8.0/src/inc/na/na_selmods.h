/*
 *****************************************************************************
 *
 *        Copyright 1991, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	Interpretation of selectable modules parameter
 *
 * Original Author: Jim Barnes		Created on: 3 February 1992
 *
 ****************************************************************************
 */

#ifndef NA_SELMODS_H
#define NA_SELMODS_H

/* Disabled modules settings only: */

#define OPT_ADMIN	0x00000001	/* admin cli command */
#define OPT_TSTTY	0x00000002	/* Tstty */
#define OPT_LAT		0x00000004	/* lat prot; connect, services cmds */
#define OPT_PPP		0x00000008	/* ppp procotol and ppp cli command */
#define OPT_SLIP	0x00000010	/* slip prot; and slip cli command */
#define OPT_SNMP	0x00000020	/* snmp protocol and agent */
#define OPT_NAMESERVER	0x00000040	/* nameserver */
#define OPT_FINGERD	0x00000080	/* fingerd */
#define OPT_CLIEDIT	0x00000100	/* stand-alone editor */
#define OPT_ATALK	0x00000200	/* AppleTalk and ARAP   */
#define OPT_TN3270	0x00000400	/* Tn3270 */
#define OPT_DIALOUT	0x00000800	/* Dial-out and Active routing */
#define OPT_FTPD	0x00001000	/* FTP Daemon */
#define OPT_IPX		0x00002000	/* IPX Stuff */
#define OPT_DEC		0x00004000	/* DECserver interface */
#define OPT_SELEC_NONE	0x00008000
#define OPT_UDAS	0x00010000	/* PPP virtual private network */
#define OPT_HTTPD	0x00020000	/* Web server */

#ifdef ANNEX
#define OPT_ALL		0xFFFF7FFFul	/* everything disabled */
#else
#define OPT_ALL		0xFFFF7FFF	/* everything disabled */
#endif

/*
 * The "OPT_SELEC_NONE" flag is necessary because the default list
 * was changed from 'none' to 'vci' and because set-to-zero is
 * indistinguishable from set-to-default in the EEROM interface.
 */

/* default to VCI (DEC user interface) disabled */
#define OPT_DEFAULT	OPT_DEC


/* Must be in alphabetic order by text of option */
#define OPT_MASK_TABLE \
{ \
    { OPT_ADMIN,	"admin" }, \
    { OPT_ALL,		"all" }, \
    { OPT_ATALK,	"atalk" }, \
    { OPT_DEFAULT,	"default" }, \
    { OPT_DIALOUT,	"dialout" }, \
    { OPT_CLIEDIT,	"edit" }, \
    { OPT_FINGERD,	"fingerd" }, \
    { OPT_FTPD,		"ftpd" }, \
    { OPT_HTTPD,	"httpd" }, \
    { OPT_IPX,		"ipx" }, \
    { OPT_LAT,		"lat" }, \
    { OPT_NAMESERVER,	"nameserver" }, \
    { OPT_SELEC_NONE,	"none" }, \
    { OPT_PPP,		"ppp" }, \
    { OPT_SLIP,		"slip" }, \
    { OPT_SNMP,		"snmp" }, \
    { OPT_TN3270,	"tn3270" }, \
    { OPT_TSTTY,	"tstty" }, \
    { OPT_UDAS,		"dvs" }, \
    { OPT_UDAS,		"udas" }, \
    { OPT_DEC,		"vci" }, \
    { 0,		(char *)0 } \
}

/* This must be in the same order as the option bits (LSB to MSB) */
#define OPT_NAMES_TABLE \
{ \
    "local admin",	/* OPT_ADMIN */ \
    "TSTTY",		/* OPT_TSTTY */ \
    "LAT",		/* OPT_LAT */ \
    "PPP",		/* OPT_PPP */ \
    "SLIP",		/* OPT_SLIP */ \
    "SNMP",		/* OPT_SNMP */ \
    "name services",	/* OPT_NAMESERVER */ \
    "fingerd",		/* OPT_FINGERD */ \
    "text editor",	/* OPT_CLIEDIT */ \
    "AppleTalk",	/* OPT_ATALK */ \
    "TN3270",		/* OPT_TN3270 */ \
    "dialout/RIP/filtering", /* OPT_DIALOUT */ \
    "ftpd",		/* OPT_FTPD */ \
    "IPX",		/* OPT_IPX */ \
    "DECserver interface", /* OPT_DEC */ \
    NULL,		/* OPT_SELEC_NONE */ \
    "Virtual Private Net", /* OPT_UDAS */ \
    "httpd",		/*OPT_HTTPD */ \
}

#endif /* NA_SELMODS_H */
