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
 *	Common display header text shared by na/parse.c and dfe/cli_adm.c
 *
 * Original Author: Jim Barnes
 *
 ****************************************************************************
 */

#ifndef _NA_DISP_TEXT

#define _NA_DISP_TEXT

static char *hdr_fmt = /*NOSTR*/"\n\t\t\t%s\n\n";

static char *box_generic = "Annex Generic Parameters";
static char *box_vcli = "VCLI Parameters";
#if NNAME_SERVERS > 0
static char *box_nameserver = "Nameserver Parameters";
#endif
static char *box_security = "Security Parameters";
static char *box_time = "Time Parameters";
static char *box_syslog = "SysLog Parameters";
#if NLAT > 0
static char *box_lat = "LAT Parameters";
#endif
#if NARAP > 0
static char *box_arap = "AppleTalk Parameters";
#endif
static char *box_rip = "Router Parameters";
#if NDEC > 0
static char *box_vms = "MOP and \"Login\" user Parameters";
#endif
#if NKERB > 0
static char *box_kerberos = "Kerberos Security Parameters";
#endif
#if NIPXOPT > 0
static char *box_ipx = "IPX Parameters";
#endif
#if NTMUX > 0
static char *box_tmux = "TMux Parameters";
#endif
#if NDHCPCLIENT > 0
static char *box_dhcp = "DHCP Parameters";
#endif
#if NCMUSNMP > 0
static char *box_snmp = "SNMP Parameters";
#endif

static char *port_generic = "Port Generic Parameters";
static char *port_flow = "Flow Control and Signal Parameters";
static char *port_timers = "Port Timers and Counters";
#if NDEC > 0
static char *port_login = "\"Login\" User Parameters";
#endif
static char *port_security = "Port Security Parameters";
#if NEDIT > 0
static char *port_edit = "CLI Line Editing Parameters";
#endif
#if NSLIP > 0 || NPPP > 0
static char *port_serialproto = "Serial Networking Protocol Parameters";
#endif
#if NSLIP > 0
static char *port_slip = "SLIP Parameters";
#endif
#if NPPP > 0
static char *port_ppp = "PPP Parameters";
#endif
#if NARAP > 0
static char *port_arap = "Port AppleTalk Parameters";
#endif
#if NCLITN3270 > 0
static char *port_tn3270 = "Port TN3270 Parameters";
#endif
#if NLAT > 0
static char *port_lat = "Port LAT Parameters";
#endif
#if NPRINTER > 0
static char *printer_generic = "Printer Port Generic Parameters";
#endif
static char *interface_rip = "Interface Routing Parameters";

#if NT1_ENG > 0
static char *t1_generic = "Channelized T1 Generic Parameters";
static char *t1_ds0_map = "T1 DS0 Map Parameters";
static char *t1_ds0_sig = "T1 DS0 Signaling Protocol Parameters";
static char *t1_ds0_ring = "T1 DS0 Ring Parameters";
#endif /* NT1_ENG */

#if NPRI > 0
static char *wan_generic = "WAN Generic Parameters";
static char *wan_channel_group = "WAN B/DS0 Channel Parameters";
/* static char *modem_generic = "Modem Generic Parameters"; */
#endif /* NT1_ENG */

#endif
