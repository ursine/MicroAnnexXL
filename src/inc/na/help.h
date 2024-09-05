/*
 *****************************************************************************
 *
 *        Copyright 1989,1990 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *
 *	Help messages and command dictionary for Xylogics Annex version of NA
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 ****************************************************************************
 */

/* Command and help message definitions */


char *cmd_string[] =
{
#ifdef NA
	 "       annex:  enter default Annex list",
	 "        boot:  boot an Annex",
	 "        copy:  copy annex/port/printer parameters to other Annexes",
	 "    dumpboot:  boot an Annex and produce an upline dump",
	 "        echo:  echo the remainder of the line to standard output",
	 "           #:  indicate a comment line (useful in command files)",
	 "    password:  enter default password",
	 "        read:  read and execute a script file",
	 "       write:  write the current configuration to a script file",
	 "   help or ?:  get help; \"help <command>\" displays command syntax",
#else
	 "   help or ?:  display this help screen",
#endif

	 "   broadcast:  send a broadcast message to a port or ports",
#if NPRI == 0 || NA == 1
	 "        port:  enter default port set",
#endif
#if NPRINTER > 0
	 "     printer:  enter default printer set",
#endif
#if NPRI > 0
	 "       modem:  enter default modem set",
#endif
	 "   interface:  enter default interface set",
	 "        quit:  terminate administration",
	 "       reset:  reset a port, interface or subsystem",
	 "        show:  display the current value of an eeprom parameter",
	 "         set:  modify the value of an eeprom parameter",
	 (char *)NULL
};

#if NPRI > 0
/* List of parameters to show for "port sync" category */
int port_sync_parm_list[] = {
  PORT_NAME,
  PORT_PASSWORD,
  P_PPP_UNAMERMT,
  P_PPP_PWORDRMT,
  P_SLIP_SECURE,
  P_PPP_DIALUP_ADDR,
  P_PPP_ADDR_ORIGIN,
  P_PPP_SECURITY,
  P_PPP_NCP,
  P_SLIP_METRIC,
  P_SLIP_NETMASK,
  P_PPP_MRU,
  INACTIVITY_TIMER,
  INPUT_ACT,
  OUTPUT_ACT,
  RESET_IDLE,
  P_SLIP_NET_INACTIVITY,
  P_SLIP_NET_INACT_UNITS,
  P_MP_MRRU,
  P_MP_ENDP_OPT,
  P_MP_ENDP_VAL,
  P_IPCP_UNNUMBERED,
  P_DROP_FIRST_REQ,
  -1
};

/* List of parameters to show for "port vpn" category */
int port_vpn_parm_list[] = {
  PORT_NAME,
  PORT_PASSWORD,
  P_PPP_UNAMERMT,
  P_PPP_PWORDRMT,
  P_SLIP_SECURE,
  P_PPP_DIALUP_ADDR,
  P_PPP_ADDR_ORIGIN,
  P_PPP_SECURITY,
  P_PPP_NCP,
  P_SLIP_METRIC,
  P_SLIP_NETMASK,
  P_PPP_MRU,
  INACTIVITY_TIMER,
  INPUT_ACT,
  OUTPUT_ACT,
  RESET_IDLE,
  P_SLIP_NET_INACTIVITY,
  P_SLIP_NET_INACT_UNITS,
  P_MP_MRRU,
  P_MP_ENDP_OPT,
  P_MP_ENDP_VAL,
  P_IPCP_UNNUMBERED,
  P_DROP_FIRST_REQ,
  -1
};
#endif /* NPRI */

static char void_entry_string[] = /*NOSTR*/"table_entry_void";

static definition dictionary[] =
{
#ifdef NA
{"#",			A_COMMAND,	COMMENT_CMD
, "# <comments>"
},
#endif /* NA */
{"?",			A_COMMAND,	QUEST_CMD
#ifdef NA
, "?                               lists commands\n\t\
? *                             shows entire help dictionary\n\t\
? <command_name>                shows command syntax\n\t\
? <parameter_name>              explains parameter, shows valid values\n\t\
? <help_token>                  explains details of a sub-syntax\n\t\
? syntax                        explains help syntax"
#endif /* NA */
},
{"__dui_flow",          PORT_PARAM,     DUI_FLOW
#ifdef NA
, "For internal use only."
#endif /* NA */
},
{"__dui_iflow",         PORT_PARAM,     DUI_IFLOW
#ifdef NA
, "For internal use only."
#endif /* NA */
},
{"__dui_oflow",         PORT_PARAM,     DUI_OFLOW
#ifdef NA
, "For internal use only."
#endif /* NA */
},
{"a_router",		BOX_PARAM,	A_ROUTER
#ifdef NA
, "The node ID of the network's A_ROUTER, legal values are \n\t\
xx-xx-xx-xx-xx-xx"
#endif /* NA */
},
{"acp_key",		BOX_PARAM,	ACP_KEY
#ifdef NA
, "ACP encryption key: a string, maximum 15 characters"
#endif /* NA */
},
{"address_origin",PORT_PARAM,	P_PPP_ADDR_ORIGIN
#ifdef NA
, "Origin of dial-up addresses: acp, local, or dhcp."
#endif /* NA */
},
#if NT1_ENG > 0
{"alarmsyslog",         T1_PARAM,      T1_LOG_ALARM_D
#ifdef NA
, "Enables syslogging of alarm events.\n\t\
'all' syslogs all alarms, 'none' disables alarm syslogs"
#endif /* NA */
},
#endif /* NT1_ENG */
{"all",			BOX_PARAM,	ALL_BOX
#ifdef NA
, "show annex [= <annex_list>] all"
#endif /* NA */
},
{"all",			PORT_PARAM,	ALL_PORTP
#ifdef NA
, "show port [= <port_set>] all"
#endif /* NA */
},
#if NPRINTER > 0
{"all",			PRINTER_PARAM,	ALL_PRINTER
#ifdef NA
, "show printer [= <printer_set>] all"
#endif /* NA */
},
#endif /* NPRINTER */
{"all",			INTERFACE_PARAM, ALL_INTERFACEP
#ifdef NA
, "show interface [= <interface_set>] all"
#endif /* NA */
},
#if NT1_ENG > 0
{"all",			T1_PARAM, ALL_T1P
#ifdef NA
, "show t1 all"
#endif /* NA */
},
{"all",			T1_DS0_PARAM, ALL_T1DS0P
#ifdef NA
, "show t1 ds0[=<ds0_set>] all"
#endif /* NA */
},
#endif /* NT1_ENG */
#if NPRI > 0
{"all",			WAN_PARAM, ALL_WANP
#ifdef NA
, "show wan all"
#endif /* NA */
},
{"all",			WAN_CHAN_PARAM, ALL_WANCHANP
#ifdef NA
, "show wan b/ds0=all"
#endif /* NA */
},
{"all",			MODEM_PARAM, ALL_MODEMP
#ifdef NA
, "show modem all"
#endif /* NA */
},
#endif /* NPRI */
#ifdef NA
{"all",			HELP_ENTRY,	0
, "\
port all                set default asynchronous port list to all ports\n\t\
asynchronous all        set default asynchronous port list to all ports\n\t\
broadcast = all         broadcast to all serial and virtual CLI ports\n\t\
reset all               reset all serial ports and all virtual CLI ports\n\t\
set port = all          set asynchronous port parameter on all ports\n\t\
set asynchronous = all  set asynchronous port parameter on all ports\n\t\
set interface = all     set interface parameter on all interfaces\n\t\
show port = all         show asynchronous port parameter on all ports\n\t\
show asynchronous = all show asynchronous port parameter on all ports\n\t\
show interface = all    show interface parameter on all interfaces"
},
#endif /* NA */
{"allow_broadcast",	PORT_PARAM,	BROADCAST_ON
#ifdef NA
, "allow NA broadcast to this port: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"allow_compression,slip_allow_compression",PORT_PARAM,	P_SLIP_EN_COMP
#ifdef NA
, "when enabled, the Annex will use TCP/IP header compression\n\t\
on this link only if the remote end initiates the compression.\n\t\
Y or y to enable; N or n to disable. By default it is disabled."
#endif /* NA */
},
{"allow_snmp_sets",	BOX_PARAM,	ALLOW_SNMP_SETS
#ifdef NA
, "allow SNMP set commands: Y or y to enable; N or n to disable"
#endif /* NA */
},
#if NPRI > 0
{"analog_encoding",	WAN_PARAM,	WAN_ANALOG_D
#ifdef NA
, "the analog encoding format used for modem-type calls on this WAN\n\t\
interface.  This parameter can be set to any of \"auto\", \"mu_law\",\n\t\
or \"a_law\".  The default is \"auto\", which means that the Annex\n\t\
will automatically choose A law for E1 lines and mu law for T1 lines."
#endif /* NA */
},
{"ani",        WAN_PARAM,      WAN_ANI_D
#ifdef NA
, "Whether or not to allow CAS ANI digits, (per provisioning).\n\t\
Y or y to enable; N or n to disable. By default it is disabled."
#endif /* NA */
},
#endif /* NPRI */
#ifdef NA
{"annex",		A_COMMAND,	BOX_CMD
, "annex <annex_list>"
},
#endif /* NA */
{"annex",		PARAM_CLASS,	BOX_CLASS
#ifdef NA
, "set/show annex [= <annex_list>] ..."
#endif /* NA */
},
#ifdef NA
{"annex_identifier",	HELP_ENTRY,	0
, "an Internet address (a.b/a.b.c/a.b.c.d) or a hostname (/etc/hosts)"
},
{"annex_list",		HELP_ENTRY,	0
, "<annex_identifier> [, <annex_identifier>]*"
},
#endif /* NA */
{"appletalk,arap",		BOX_CATEGORY,	BOX_APPLETALK
#ifdef NA
, "Show the AppleTalk subset of Annex parameters"
#endif /* NA */
},
{"appletalk,arap",		PORT_CATEGORY,	PORT_APPLETALK
#ifdef NA
, "Show the AppleTalk subset of port parameters"
#endif /* NA */
},
#ifndef NA
{"arpt_kill_timer",	BOX_PARAM,	ARPT_TTKILLC
#ifdef NA
, "Time for a temporary created entry in an ARP Table to remain active.\n\t\
Value in minutes: range 1 to 255, default value is 20 minutes."
#endif /* NA */
},
#endif
{"arap_v42bis",		PORT_PARAM,	P_ARAP_V42BIS
#ifdef NA
, "Allow the enabling of V.42bis compression\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef NOT_USED
{"asd_forward",		BOX_PARAM,	ASD_FORWARD
#ifdef NA
, "to be defined"
#endif /* NA */
},
#endif /* NOT_USED */
{"at_guest",		PORT_PARAM,	P_ARAP_AT_GUEST
#ifdef NA
, "Allow ARAP guest login service, Y or y to enable; N or n to disable"
#endif /* NA */
},
{"at_nodeid",		PORT_PARAM,	P_ARAP_AT_NODEID
#ifdef NA
, "the AppleTalk node ID hint the ANNEX will acquire and defined\n\t\
for the port, legal values are xxxx.xx, where xxxx range from 0..0xfeff\n\t\
and xx range from 0..0xfd"
#endif /* NA */
},
{"at_security",		PORT_PARAM,	P_ARAP_AT_SECURITY
#ifdef NA
, "enabling or disabling AppleTalk security: y or Y to enable;\n\t\
n or N to disable"
#endif /* NA */
},
{
"attn_string,attn_char",		PORT_PARAM,	ATTN_CHAR
#ifdef NA
, "CLI attention (interrupt) characters: a character or string (precede\n\t\
with \\ to force string interpretation)"
#endif /* NA */
},
{"authoritative_agent",		BOX_PARAM,	AUTH_AGENT
#ifdef NA
, "only authoritative agents may respond to ICMP subnet\n\t\
mask requests:  Y or y to enable; N or n to disable"
#endif /* NA */
},
{"authorized_groups",	PORT_PARAM,	AUTHORIZED_GROUPS
#ifdef NA
, "This Annex parameter will specify which remote group codes\n\t\
are accessible to a user on a particular Annex port. Each port\n\t\
has its own set of group codes. Syntax:\n\t\
set port authorized_groups <group range> enable | disable\n\t\
where <group range> is the set of groups ([similar to port set]\n\t\
between 0, and 255 inclusive) to affect (i.e. 1,2,3; 2; 5-10 are\n\t\
all valid group ranges).  A shortcut method can be used to enable or \n\t\
disable all group values.  To enable all groups, use:\n\t\
set port authorized_groups all \n\t\
To disable all groups, use:\n\t\
set port authorized_groups none"
#endif /* NA */
},
{"auth_protocol",     BOX_PARAM,      AUTHENTICATION_PROTOCOL
#ifdef NA
, "This is represents the protocol to be used for authentication.  At\n\t\
the moment it is limited to either \"acp\" or \"radius\" with, a default\n\t\
\"acp\"."
#endif /* NA */
},
{"autobaud",    PORT_PARAM,     PORT_AUTOBAUD
#ifdef NA
, "This Port parameter will specify if autobauding is used:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
#if NPRI > 0
{"auto_busyout_enable",	WAN_PARAM,	WAN_AUTOBUSYENA_D
#ifdef NA
, "This WAN parameter governs whether the remaining ds0s will be\n\t\
automatically busied out when the last modem is used.  The default\n\t\
value is N."
#endif /* NA */
},
#endif /* NPRI */
{"autodetect_timeout", PORT_PARAM, AUTODETECT_TIMEOUT
#ifdef NA
, "This Port parameter will specify the maximum amount of time\n\t\
in seconds the annex will wait for a client who has dialled in\n\t\
to an auto-detect or auto-adapt port, to identify itself as a PPP\n\t\
or CLI client. After the specified number of seconds, the annex\n\t\
will default the user to CLI mode. The default value of this \n\t\
parameter is 30 seconds. The minimum value is 1 second, and the \n\t\
maximum value is 60 seconds."
#endif /* NA */
},
{"backward_key",	PORT_PARAM,	BACKWARD_KEY
#ifdef NA
, "hot-key used to cause a port to switch backward to previous session:\n\t\
any key or key sequence that is not used for another purpose."
#endif /* NA */
},
{"banner", PORT_PARAM, BANNER
#ifdef NA
, "Controls the actions in displaying the banner and motd:\n\t\t\
default, Y, yes, unset:\tbanner before security, motd after\n\t\t\
before_sec:\t\tbanner and motd before security\n\t\t\
after_sec:\t\tbanner and motd after security\n\t\t\
motd_before_sec:\t\tmotd before security; no banner\n\t\t\
motd_after_sec:\t\tmotd after security; no banner\n\t\t\
none, N:\t\tno banner or motd"
#endif /*NA*/
},
{"bes_threshold",	BOX_PARAM,	BES_THRESHOLD
#ifdef NA
, "The number of Bursty Errored Seconds that must occur on a \n\t\
WAN module in a 15 minute interval before wanBesThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"bidirectional_modem",	PORT_PARAM,	BIDIREC_MODEM
#ifdef NA
, "bidirectional modem: Y or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef NA
{"boot",		A_COMMAND,	BOOT_CMD
, "\
boot [-adhlq] <time> <annex_list> <filename> <warning>\n\t\
    a: abort a delay boot\n\t\
    d: create a code dump\n\t\
    h: cause a halt or reset diag\n\t\
    l: load the boot image into flash (for selfboot)\n\t\
    q: dumps quietly; send no warnings\n\t\
WARNING: booting the Annex with a non-existent image\n\t\
filename will cause the Annex to hang trying to find\n\t\
the image.  You must press the reset button to recover."
},
#endif /* NA */
{"bpv_threshold", BOX_PARAM, BIPOLAR_THRESHOLD
#ifdef NA
, "The number of Bipolar Violation or Line Code Violation errors that must \n\t\
occur on a WAN module in a 15 minute interval before wanBpvThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"broadcast",		A_COMMAND,	BROADCAST_CMD
#ifdef NA
, "broadcast [= <port_set>] <message>"
#endif /* NA */
},
{"broadcast_addr",	BOX_PARAM,	BROAD_ADDR
#ifdef NA
, "Internet address that the Annex uses for broadcasting: an inet address"
#endif /* NA */
},

{"broadcast_direction",	PORT_PARAM,	BROADCAST_DIR
#ifdef NA
, "Broadcast messages to network or port on slave ports"
#endif /* NA */
},
#if NPRI > 0
{"buildout",	WAN_PARAM,	WAN_BUILDOUT_D
#ifdef NA
, "the dB loss on the loop from the CSU to the central office.  Values\n\t\
are 0dB, 7.5dB, 15dB, or 22.5dB.  This number is normally supplied by\n\t\
the telephone company.  The default is 0dB."
#endif /* NA */
},
{"busy_out",		MODEM_PARAM,	MODEM_BUSY_OUT_D
#ifdef NA
, "Set to Y to mark a modem as unusable; defaults to N.  This parameter\n\t\
is used to disable failing modems without running the ROM diagnostics."
#endif /* NA */
},
#endif /* NPRI */
#if NPRI > 0
{"busy_signal_bits",	WAN_PARAM,	WAN_BUSYSIGTYPE_D
#ifdef NA
, "The type of busy signal."
#endif /* NA */
},
#endif /* NPRI */
#if NT1_ENG > 0
{"bypass",              T1_PARAM,      T1_BYPASS_D
#ifdef NA
, "T1 engine bypass: Y to take T1 engine out of the network,\n\t\
N to keep the engine on line."
#endif /* NA */
},
#endif /* NT1_ENG */
{"call_begin_trap",	BOX_PARAM,	CALL_BEGIN_ENABLE
#ifdef NA
, "enable or disable SNMP traps on call-begin events.  Set to \"y\" to\n\t\
enable or \"n\" to disable."
#endif /* NA */
},
{"call_end_trap_inc",	BOX_PARAM,	CALL_END_INCR
#ifdef NA
, "count of call-end events after which a call-end SNMP trap will be\n\t\
sent.  Range is 0 (to disable call-end traps) to 65535."
#endif /* NA */
},
{"call_history_limit",	BOX_PARAM,	CALL_HISTORY_LIMIT
#ifdef NA
, "maximum number of call history records which will be retained by\n\t\
the Annex.  Range is 0 (to disable call history storage) to 65535."
#endif /* NA */
},
{"chap_auth_name",	BOX_PARAM,	CHAP_AUTH_NAME
#ifdef NA
, "Used in the name field in chap challenge messages. Maximim string\n\t\
length is 16 characters."
#endif /* NA */
},
{"char_erase",		PORT_PARAM,	CHAR_ERASING
#ifdef NA
, "destructive character erasing: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"circuit_timer",		BOX_PARAM,	CIRCUIT_TIMER
#ifdef NA
, "the time interval in 10's of milliseconds between the transmission of\n\t\
LAT packets:  an integer, 1 - 100 inclusive.\n\t\
set annex circuit_timer <value>"
#endif /* NA */
},
{"cli_imask7",		PORT_PARAM,	CLI_IMASK7
#ifdef NA
, "Masks input at the CLI to 7 bits: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"cli_inactivity",	PORT_PARAM,	INACTIVITY_CLI
#ifdef NA
, "CLI inactivity timer interval: 0 or \"off\" to disable, \"immediate\"\n\t\
to hangup after last session, or an integer (time in minutes)"
#endif /* NA */
},
{"cli_interface",              PORT_PARAM,     USER_INTERFACE
#ifdef NA
, "Specifies either a Unix or VMS command line interface.\n\t\
The default is uci, the alternative being vci."
#endif /* NA */
},
{"cli_prompt",		BOX_PARAM,	CLI_PROMPT_STR
#ifdef NA
, "Annex Command Line Interpreter prompt string: a prompt_string"
#endif /* NA */
},
{"cli_security",	PORT_PARAM,	CLI_SECURITY
#ifdef NA
, "ACP authorization required to use CLI: Y or y to enable; N or n to\n\t\
disable"
#endif /* NA */
},
#ifdef NA
{"command_name",	HELP_ENTRY,	0
, "the name of one of the Network Administrator commands"
},
{"comments",		HELP_ENTRY,	0
, "any sequence of characters - used only for documentation"
},
#endif /* NA */
{"config_file",		BOX_PARAM,	CONFIG_FILE
#ifdef NA
, "Specifies the configuration file to access on the load host. This file\n\t\
contains information about gateways, rotaries, macros, and services"
#endif /* NA */
},
{"connect_security",	PORT_PARAM,	CONNECT_SECURITY
#ifdef NA
, "ACP authorization required to make host login connections:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"control_lines",	PORT_PARAM,	CONTROL_LINE_USE
#ifdef NA
, "usage of control lines: none, flow_control, modem_control, both"
#endif /* NA */
},
#ifdef NA
{"copy",		A_COMMAND,	COPY_CMD
, "\
copy annex   [<annex_identifier>] [<annex_list>]\n\t\
copy printer [<printer_number>@<annex_identifier>] [<printer_set>]\n\t\
copy port    [<port_number>@<annex_id>] [<port_set>]\n\t\
copy asynchronous [<port_number>@<annex_id>] [<port_set>]\n\t\
copy interface    [<interface_number>@<annex_id>] [<interface_set>]"
},
#endif /* NA */
{"css_threshold",	BOX_PARAM,	CSS_THRESHOLD
#ifdef NA
, "The number of Controlled Slip Seconds that must occur on a \n\t\
WAN module in a 15 minute interval before wanCssThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"cv_threshold",	BOX_PARAM,	CV_THRESHOLD
#ifdef NA
, "The number of CRC6 Error Event conditions that must occur on a \n\t\
WAN module in a 15 minute interval before wanCvThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"data_bits",		PORT_PARAM,	BITS_PER_CHAR
#ifdef NA
, "number of bits per character: 5, 6, 7, 8"
#endif /* NA */
},
{"daylight_savings",	BOX_PARAM,	TZ_DLST
#ifdef NA
, "type of Daylight Savings Time to use:\n\t\
us, australian, west_european, mid_european, east_european, british,\n\t\
canadian, or none"
#endif /* NA */
},
{"dedicated_address",	PORT_PARAM,	DEDICATED_ADDRESS
#ifdef NA
, "remote address to use when port is in \"dedicated\" mode:\n\t\
a host_identifier\n\n\t\
This parameter is now obsolete; see \"dedicated_arguments\"."
#endif /* NA */
},
{"dedicated_arguments", PORT_PARAM,	DEDICATED_ARGUMENTS
#ifdef NA
, "command line arguments to be passed to process started by a dedicated\n\t\
port with mode set to \"telnet\", \"tn3270\", \"rlogin\", \"connect\" (if LAT\n\t\
is in use) or \"call\" (MX images only):\n\t\t\
a string of up to 100 characters."
#endif /* NA */
},
{"dedicated_port",	PORT_PARAM,	DEDICATED_PORT
#ifdef NA
, "remote TCP port number to use when port is in \"dedicated\" mode:\n\t\
\"telnet\", \"rlogin\", \"call\" (Annex-MX only) or a number.\n\n\t\
This parameter is now obsolete; see \"dedicated_arguments\"."
#endif /* NA */
},
{"default_modem_hangup",PORT_PARAM,	DEFAULT_HPCL
#ifdef NA
, "(4.2 only) always hang up the modem line after the last close:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"default_session_mode",PORT_PARAM,     DEF_SESS_MODE
#ifdef NA
, "This is the initial session mode for LAT connections: \n\t\
\"interactive\", \"pasthru\", \"passall\", \"transparent\"."
#endif /* NA */
},
{"default_traphost",	BOX_PARAM,	DEF_TRAPHOST
#ifdef NA
, "Default SNMP trap host; a single IP address.  Multiple IP addresses\n\t\
may be specified in the %gateway section of the config.annex file."
#endif /* NA */
},
{"default_zone_list",		BOX_PARAM,	DEF_ZONE_LIST
#ifdef NA
, "the zone list sent to ARAP clients as the local backup to ACP failure\n\t\
a string, maximum 100 characters"
#endif /* NA */
},
{"demand_dial",	PORT_PARAM,	P_SLIP_NET_DEMAND_DIAL
#ifdef NA
, "dial on demand: y or Y to enable, n or N to disable"
#endif /* NA */
},
{"dhcp",	            BOX_CATEGORY,      BOX_DHCP
#ifdef NA
, "Show the DHCP subset of Annex parameters"
#endif /* NA */
},
{"dhcp_bcast",     BOX_PARAM,      DHCP_BCAST
#ifdef NA
, "the Internet address of the preferred DHCP server that the client\n\t\
will attempt to discover as a backup source for DHCP services."
#endif /* NA */
},
{"diallink_trap_enable",BOX_PARAM,      DIALLNK_TRAP_EN
#ifdef NA
, "When enabled, SNMP link up and down traps are generated for remote\n\t\
dialin interfaces. Y or y to enable; N or n to disable. By default it\n\t\
is disabled."
#endif /* NA */
},
{"dialup_addresses",PORT_PARAM,	P_PPP_DIALUP_ADDR
#ifdef NA
, "Request dialup addresses from ACP.\n\t\
Y or y to enable; N or n to disable.\n\t\
For versions later than R13.1, see address_origin"
#endif /* NA */
},
#if NPRI > 0
{"digit_power_1", WAN_PARAM,      WAN_DIGITPOWER_1_D
#ifdef NA
, "the power to be applied to one of the two tones of the tone pair."
#endif /* NA */
},
{"digit_power_2", WAN_PARAM,      WAN_DIGITPOWER_2_D
#ifdef NA
, "the power to be applied to one of the two tones of the tone pair."
#endif /* NA */
},
{"digit_width", WAN_PARAM,      WAN_DIGITWIDTH_D
#ifdef NA
, "the width (in msecs) of each dialed digit."
#endif /* NA */
},
#endif
{"disabled_modules", 	BOX_PARAM,      SELECTED_MODULES
#ifdef NA
, "lists the software modules that are currently disabled. Valid \n\t\
module names are the constructs \"all\", \"default\", or \"none\",\n\t\
or any combination of the following:\n\t\
  admin,atalk,dialout,edit,fingerd,ftpd,httpd,ipx,lat,nameserver,\n\t\
  ppp,slip,snmp,tn3270,tstty,udas,vci\n\t\
This parameter works in conjunction with the lat_key."
#endif /* NA */
},
#if NPRI > 0
{"dnis",        WAN_PARAM,      WAN_DNIS_D
#ifdef NA
, "the number of CAS DNIS digits, (per provisioning).\n\t\
0 to disable, 30 digits maximum."
#endif /* NA */
},
#endif
{"do_compression,slip_do_compression",	PORT_PARAM,	P_SLIP_DO_COMP
#ifdef NA
, "when enabled, the Annex will start TCP/IP header compression\n\t\
on this asynchronous link.\n\t\
Y or y to enable; N or n to disable. By default it is disabled."
#endif /* NA */
},
{"drop_first_req",	PORT_PARAM,	P_DROP_FIRST_REQ
#ifdef NA
, "when enabled, the Annex will drop the first PPP LCP Configure-Request\n\t\
it generates instead of sending it.  This is for compatibility with broken\n\t\
peers which get confused when we send the first request.\n\t\
Y or y to enable; N or n to disable. By default, this mode is disabled."
#endif /* NA */
},
{"ds0_error_threshold", BOX_PARAM, DS0_ERROR_THRESHOLD
#ifdef NA
, "The number of errors that must occur on a ds0 channel \n\t\
in a 15 minute interval before ds0ErrorThresholdTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
#if NPRI > 0
{"dsx1_line_length",	WAN_PARAM,	WAN_DISTANCE_D
#ifdef NA
, "the distance from the WAN DS1 interface to the CSU in meters.  This\n\t\
parameter is resolved into one of the following ranges on input:\n\t\
\t0-25\t26-65\t66-100\n\t\
\t101-135\t136-165\t166-185\n\t\
\t186-210\n\t\
The default is 0-25 meters."
#endif /* NA */
},
#endif /* NPRI */
#ifdef NA
{"dumpboot",		A_COMMAND,	DUMPBOOT_CMD
, "dumpboot [-aq] <time> <annex_list> <filename> <warning>\n\t\
\tWARNING: booting the Annex with a non-existent image\n\t\
\tfilename will cause the Annex to hang, trying to find\n\t\
\tthe image.  You must press the reset button to recover."
},
{"echo",		A_COMMAND,	ECHO_CMD
, "echo [<message>]"
},
#endif /* NA */
{"echo",		PORT_PARAM,	INPUT_ECHO
#ifdef NA
, "perform input echoing: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"editing",		PORT_CATEGORY,	PORT_EDITING
#ifdef NA
, "Show the port editing subset of port parameters"
#endif /* NA */
},
{"enable_radius_acct",	BOX_PARAM,	ENABLE_RADIUS_ACCT
#ifdef NA
, "If set to Y this parameter will enable radius accounting for generating accounting logs"
#endif /* NA */
},
{"enable_security",	BOX_PARAM,	ENABLE_SECURITY
#ifdef NA
, "Selects if security (ACP or local security) is enabled or disabled for\n\t\
the entire Annex.  If this parameter is disabled, then all security is\n\t\
disabled.  Y or y to enable; N or n to disable"
#endif /* NA */
},
{"erase_char",		PORT_PARAM,	ERASE_CHAR
#ifdef NA
, "character used to erase a character: a character"
#endif /* NA */
},
{"erase_line",		PORT_PARAM,	ERASE_LINE
#ifdef NA
, "character used to erase a line: a character"
#endif /* NA */
},
{"erase_word",		PORT_PARAM,	ERASE_WORD
#ifdef NA
, "character used to erase a word: a character"
#endif /* NA */
},
{"es_threshold", BOX_PARAM, ERRSECS_THRESHOLD
#ifdef NA
, "The number of Errored Seconds conditions that must occur on a \n\t\
WAN module in a 15 minute interval before wanEsThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"esf_threshold",	BOX_PARAM,	ESF_THRESHOLD
#ifdef NA
, "The number of ESF Error Event conditions that must occur on a \n\t\
WAN module in a 15 minute interval before wanEsfThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"facility_num",	BOX_PARAM,	HOST_NUMBER
#ifdef NA
, "an integer identifying the Annex's LAT facility number\n\t\
(0 - 32767):  set annex facility_num <value>"
#endif /* NA */
},
{"fail_to_connect",	BOX_PARAM,	FAIL_TO_CONNECT
#ifdef NA
, "a count of the maximum number of consecutive connection failures\n\t\
tolerated on a built-in modem before that modem is automatically\n\t\
disabled.  Integer in the range 0 (to disable) to 255."
#endif /* NA */
},
{"pass_break",	BOX_PARAM,	PASS_BREAK
#ifdef NA
, "Pass the short break: Y or y to enable; N or n to disable"
#endif /* NA */
},
#if NPRI > 0
{"fdl_type",	WAN_PARAM,	WAN_FDLTYPE_D
#ifdef NA
, "the type of Facilities Data Link protocol in use; allowable values\n\t\
are \"ansi\" and \"att\", and the default is \"ansi\"."
#endif /* NA */
},
#endif /* NPRI */
#ifdef NA
{"filename",		HELP_ENTRY,	0
, "a UNIX filename or pathname"
},
#endif /* NA */
{"flow",		PORT_CATEGORY,	PORT_FLOW
#ifdef NA
, "Show the flow control subset of Annex parameters"
#endif /* NA */
},
{"forward_key",		PORT_PARAM,	FORWARD_KEY
#ifdef NA
, "hot-key used to cause A port to switch forward to next session:\n\t\
any key or key sequence that is not used for another purpose."
#endif /* NA */
},
{"forwarding_count",	PORT_PARAM,	FORWARD_COUNT
#ifdef NA
, "the minimum number of characters to be received by the port before\n\t\
the characters are forwarded: an integer"
#endif /* NA */
},
{"forwarding_timer",	PORT_PARAM,	FORWARDING_TIMER
#ifdef NA
, "forwarding timer interval: 0 or \"off\" to disable or an integer\n\t\
up to 255 (time in tens of milliseconds)"
#endif /* NA */
},
#if NPRI > 0
{"framing",        WAN_PARAM,      WAN_FRAMING_D
#ifdef NA
, "controls the super frame format used on the T1/E1 Network\n\t\
Interface: (T1) d4 (super frame), esf (extended super frame)\n\t\
           (E1) ddf (double frame), mff_crc4 (multiframe), \n\t\
                mff_crc4_g706 (multiframe with g706)"
#endif /* NA */
},
#endif
{"generic",		BOX_CATEGORY,	BOX_GENERIC
#ifdef NA
, "Show the generic subset of Annex parameters"
#endif /* NA */
},
{"generic",		PORT_CATEGORY,	PORT_GENERIC
#ifdef NA
, "Show the generic subset of port parameters"
#endif /* NA */
},
{"group_value",		BOX_PARAM,	GROUP_CODE
#ifdef NA
, "Annex LAT group code for permitting access to LAT services.  To\n\t\
access a specific LAT services, the Annex must have at least one\n\t\
enabled group code match the service's set group codes.  In fact,\n\t\
the Annex will not maintain any information about unauthorized\n\t\
services :\n\t\t\
set annex group_value <group range> enable | disable\n\t\
where <group range> is the set of groups ([similar to port set]\n\t\
between 0, and 255 inclusive) to affect (i.e. 1,2,3; 2; 5-10 are\n\t\
all valid group ranges).  A shortcut method can be used to enable or \n\t\
disable all group values.  To enable all groups, use:\n\t\
set annex group_value all \n\t\
To disable all groups, use:\n\t\
set annex group_value none"
#endif /* NA */
},
{"hardware_tabs",	PORT_PARAM,	PORT_HARDWARE_TABS
#ifdef NA
, "hardware tab operation: Y or y to enable; N or n to disable"
#endif /* NA */
},
#if NPRINTER > 0
{"hardware_tabs",	PRINTER_PARAM,	PRINT_HARDWARE_TABS
#ifdef NA
, "hardware tab operation: Y or y to enable; N or n to disable"
#endif /* NA */
},
#endif /* NPRINTER */
{"help",		A_COMMAND,	HELP_CMD
#ifdef NA
, "help                            lists commands\n\t\
help *                          shows entire help dictionary\n\t\
help <command_name>             shows command syntax\n\t\
help <parameter_name>           explains parameter, shows valid values\n\t\
help <help_token>               explains details of a sub-syntax\n\t\
help syntax                     explains help syntax"
#endif /* NA */
},
#ifdef NA
{"help_token",		HELP_ENTRY,	0
, "a metasymbol used in the text of help messages (this is one)"
},
{"host_identifier",	HELP_ENTRY,	0
, "an Internet address (a.b/a.b.c/a.b.c.d) or a hostname (/etc/hosts)"
},
#endif /* NA */
{"host_table_size",	BOX_PARAM,	HTABLE_SZ
#ifdef NA
, "the maximum number of host names that can be stored in the Annex\n\t\
host table: an integer, 1 - 250 or the keywords \"none\" for no host table\n\t\
or \"unlimited\" for no upper bounds for host table size"
#endif /* NA */
},
{"image_name",		BOX_PARAM,	IMAGE_NAME
#ifdef NA
, "the default boot image filename: a filename, maximum 100 characters"
#endif /* NA */
},
{"imask_7bits",		PORT_PARAM,	IMASK_7BITS
#ifdef NA
, "clear the 8th bit of received 8-bit characters:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"inactivity_timer",	PORT_PARAM,	INACTIVITY_TIMER
#ifdef NA
, "serial port inactivity timer interval: 0 or \"off\" to disable or\n\t\
an integer (time in minutes)"
#endif /* NA */
},
{"forced_call_inc",	BOX_PARAM,	INACTIVITY_TRAP_INCR
#ifdef NA
, "count of call-disconnect events caused by inactivity timers after\n\t\
which a forcedCallDisconnectTrap SNMP trap will be sent.  Range is\n\t\
0 (to disable forcedCallDisconnectTrap traps) to 65535."
#endif /* NA */
},
{"inet_addr",		BOX_PARAM,	INET_ADDR
#ifdef NA
, "the Annex's Internet address: an annex_identifier"
#endif /* NA */
},
{"input_buffer_size",	PORT_PARAM,	INPUT_BUFFER_SIZE
#ifdef NA
, "number of 256 byte input buffers allocated to port: an integer"
#endif /* NA */
},
{"input_flow_control",	PORT_PARAM,	INPUT_FLOW_CONTROL
#ifdef NA
, "type of input flow control: none, eia, start/stop, bell"
#endif /* NA */
},
{"input_is_activity", PORT_PARAM,	INPUT_ACT
#ifdef NA
, "Port input should reset the port inactivity_timer:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"input_start_char",	PORT_PARAM,	INPUT_START_CHAR
#ifdef NA
, "start character for input flow control: a character"
#endif /* NA */
},
{"input_stop_char",	PORT_PARAM,	INPUT_STOP_CHAR
#ifdef NA
, "stop character for input flow control: a character"
#endif /* NA */
},
#if NPRI > 0
{"inter_digit", WAN_PARAM,      WAN_INTERDIGIT_D
#ifdef NA
, "the time (in msecs) between dialed digits."
#endif /* NA */
},
#endif
{"interface",		A_COMMAND,	INTERFACE_CMD
#ifdef NA
, "interface <interface_set>"
#endif /* NA */
},
{"interface",		PARAM_CLASS,	INTERFACE_CLASS
#ifdef NA
, "set/show interface [= <interface_set>] ..."
#endif /* NA */
},
{"ip_forward_broadcast", BOX_PARAM,	IP_FWD_BCAST
#ifdef NA
, "forward broadcasted IP messages to all interfaces:\n\t\
\tY or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef NOT_USED
{"ip_ttl",		BOX_PARAM,	IP_TTL
#ifdef NA
, "to be defined"
#endif /* NA */
},
#endif
{"ipcp_unnumbered",	PORT_PARAM,	P_IPCP_UNNUMBERED
#ifdef NA
, "force use of so-called \"unnumbered\" mode on PPP links by refusing\n\
\tto negotiate IP addresses.  A boolean value; default is N.  Note that\n\
\tsetting this switch on is generally discouraged."
#endif /* NA */
},
{"ipencap_type",	BOX_PARAM,	IPENCAP_TYPE
#ifdef NA
, "type of IP encapsulation: ethernet, or ieee802 for IEEE 802.2/802.3"
#endif /* NA */
},
{"ipso_class",           PORT_PARAM,    IPSO_CLASS
#ifdef NA
, "Defines the IP security classification for packets sent\n\t\
and received on this port. Possible schemes are topsecret,\n\t\
secret, confidential, unclassified and none.\n\t\
The default value is none."
#endif /* NA */
},
{"ipx",            	BOX_CATEGORY,	BOX_IPX
#ifdef NA
, "Show the IPX subset of Annex parameters"
#endif /* NA */
},
{"ipx_do_checksum",	BOX_PARAM,	IPX_DO_CHKSUM
#ifdef NA
, "Allows the user to enable IPX checksum - the feature is\n\t\
only supported on Netware version 3.12 and 4.xx.\n\t\
Y or y to enable; N or n to disable. By default it is disabled."
#endif /* NA */
},
{"ipx_dump_password",	BOX_PARAM,	IPX_DUMP_PWD
#ifdef NA
,"This field defines the User's password that the Annex will\n\t\
use to log into the Novell File server it booted from. It is\n\t\
required to perform a dump of the Annex image to the file server.\n\t\
Maximim string length is 48 characters."
#endif /* NA */
},
{"ipx_dump_path",	BOX_PARAM,	IPX_DUMP_PATH
#ifdef NA
, "This field defines the full Novell path to store the dump\n\t\
image on the file server. Maximim string length is 100 characters."
#endif /* NA */
},
{"ipx_dump_username",	BOX_PARAM,	IPX_DUMP_UNAME
#ifdef NA
, "This field defines the User Name that the Annex will use\n\t\
to log into the Novell File server it booted from. It is\n\t\
required to perform a dump of the Annex image to the File server.\n\t\
Maximim string length is 48 characters."
#endif /* NA */
},
{"ipx_file_server",	BOX_PARAM,	IPX_FILE_SERVER
#ifdef NA
, "This field defines the name of the Novell File server from\n\t\
which the Annex is going to boot. Maximim string length is 48 \n\t\
characters."
#endif /* NA */
},
{"ipx_frame_type",	BOX_PARAM,	IPX_FRAME_TYPE
#ifdef NA
, "The framing used for IPX protocol packets. Legal values are raw802_3,\n\t\
ethernetII, 802_2 and 802_2snap. The default value is raw802_3."
#endif /* NA */
},
#if NPRI > 0
{"ipx_network",		WAN_CHAN_PARAM,	WAN_IPX_NETWORK_D
#ifdef NA
, "This parameter defines the IPX network number to be used\n\t\
for a session on a given B channel.\n\t\
The default value is zero."
#endif /* NA */
},
{"ipx_node",		WAN_CHAN_PARAM,	WAN_IPX_NODE_D
#ifdef NA
, "This parameter defines the IPX node number to be used\n\t\
for a session on a given B channel.\n\t\
The default value is zero."
#endif /* NA */
},
#endif /* NPRI */
{"ipx_security",         PORT_PARAM,    IPX_SECURITY
#ifdef NA
, "Controls whether IPX security is enabled on this port.\n\t\
The default is disabled. Y or y to enable; N or n to disable"
#endif /* NA */
},
{"ixany_flow_control",	PORT_PARAM,	IXANY_FLOW_CONTROL
#ifdef NA
, "any character restarts output: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"keep_alive_timer",		BOX_PARAM,	KA_TIMER
#ifdef NA
, "the time interval in seconds between LAT id packets during times\n\t\
of LAT network inactivity: an integer, 10 - 255 inclusive.\n\t\
set annex keep_alive_timer <value>"
#endif /* NA */
},
#ifdef NOT_USED
{"kerbclock_skew",       BOX_PARAM,     KERBCLK_SKEW
#ifdef NA
, "The value in minutes that the clocks of the various Kerberos\n\t\
servers and clients may differ. This is used to prevent replay\n\t\
attacks. The default value is 5 minutes."
#endif /* NA */
},
{"kerberos",            BOX_CATEGORY,      BOX_KERBEROS
#ifdef NA
, "Show the Kerberos subset of Annex parameters"
#endif /* NA */
},
{"kerberos_host",        BOX_PARAM,     KERB_HOST
#ifdef NA
, "A list of zero to four IP addresses (in dotted decimal form)\n\t\
or host names of the Kerberos authentication servers to be used\n\t\
when authenticating a new user. The names and addresses are \n\t\
separated by commas."
#endif /* NA */
},
{"kerberos_security",         BOX_PARAM,     KERB_SECURITY_ENA
#ifdef NA
, "Controls whether the Annex uses a Kerberos authentication\n\t\
server for user authentication.\n\t\
The default is no. Y or y to enable; N or n to disable"
#endif /* NA */
},
#endif /* NOT_USED */
#ifdef NA
{"keyword",	HELP_ENTRY,	0
, "Specifies a logical group of parameters associated with the annex:\n\t\
    annex keywords: all/appletalk/generic/lat/nameserver/router/\n\t\
                    security/syslog/time/vcli\n\t\
    port keywords: appletalk/editing/flow/generic/lat/ppp/security/\n\t\
                   serial/slip/timers/tn3270"
},
#endif
{"lat",			BOX_CATEGORY,	BOX_LAT
#ifdef NA
, "Show the LAT subset of Annex parameters"
#endif /* NA */
},
{"lat",			PORT_CATEGORY,	PORT_LAT
#ifdef NA
, "Show the LAT subset of port parameters"
#endif /* NA */
},
{"lat_key",		BOX_PARAM,	KEY_VALUE
#ifdef NA
, "the lat_key is a security mechanism which restricts unauthorized\n\t\
activation of LAT in the Annex:\n\t\
set annex lat_key <value>\n\t\
This parameter works in conjunction with disabled_modules"
#endif /* NA */
},
{"lat_queue_max",	BOX_PARAM,	QUEUE_MAX
#ifdef NA
, "This parameter defines the maximum number of host requests (HIC's)\n\t\
that the Annex will save in its internal queue when the requested\n\t\
resource is not available (port busy). The syntax is:\n\t\
set annex lat_queue_max <number between 1 and 255>."
#endif /* NA */
},
{"latb_enable",		PORT_PARAM,	LATB_ENABLE
#ifdef NA
, "controls interpretation of LAT Data-B packets received from host:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef DO_LEAP_PROTOCOL
{"leap_protocol_on",	PORT_PARAM,	DO_LEAP_PROTOCOL
#ifdef NA
, "enable LEAP protocol: Y or y to enable; N or n to disable"
#endif /* NA */
},
#endif
#if NPRI > 0
{"line_code",      WAN_PARAM,       WAN_LINECODE_D
#ifdef NA
, "selects the line code used on the T1/E1 Network\n\t\
Interface: (T1) ami, b8zs\n\t\
           (E1) ami, hdb3"
#endif /* NA */
},
#endif
{"line_erase",		PORT_PARAM,	LINE_ERASING
#ifdef NA
, "destructive line erasing: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"load_broadcast",	 BOX_PARAM,	LOADSERVER_BCAST
#ifdef NA
, "broadcast for file loading server to use if none found:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"load_dump_gateway",	BOX_PARAM,	LOADUMP_GATEWAY
#ifdef NA
, "if the preferred load or dump host is on a different network or subnet,\n\t\
the Internet address of a gateway to use: a host_identifier"
#endif /* NA */
},
{"load_dump_sequence",	BOX_PARAM,	LOADUMP_SEQUENCE
#ifdef NA
, "list of network interfaces to use when downloading or upline dumping.\n\n\t\
The load_dump_sequence, \"self\" indicates to boot the image and load\n\t\
the configuration files from the local media.  The Annex will not dump\n\t\
to itself, instead it will dump to the first non-local interface\n\t\
specified in the load_dump_sequence, or to the net interface by default:\n\t\
set annex load_dump_sequence <net_interface>[,<net_interface>]*"
#endif /* NA */
},
{"local_address,slip_local_address",	PORT_PARAM,	P_SLIP_LOCALADDR
#ifdef NA
, "the Internet address of the local endpoint of the interface\n\t\
associated with the port: a host_identifier\n\t\
The default value is 0.0.0.0"
#endif /* NA */
},
#if NPRI > 0
{"local_phone_number",	WAN_PARAM,	WAN_LOCALPHONENO_D
#ifdef NA
, "the local phone number of the WAN interface."
#endif /* NA */
},
#endif /* NPRI */
{"location",		PORT_PARAM,	LOCATION
#ifdef NA
, "Port Device location printed by \"who\" command:\n\t\
a string, maximum 16 characters"
#endif /* NA */
},
{"lock_enable",         BOX_PARAM,      LOCK_ENABLE
#ifdef NA
, "Enables the lock command on ports"
#endif /* NA */
},
{"lofc_threshold",	BOX_PARAM,	LOFC_THRESHOLD
#ifdef NA
, "The number of Loss of Frame Count errors that must occur on a \n\t\
WAN module in a 15 minute interval before wanLofcThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"login_password",       BOX_PARAM,     LOGIN_PASSWD
#ifdef NA
, "The Password for all ports where the cli_interface is\n\t\
set to vci and the login_port_password is enabled.\n\t\
When defined this string is displayed as \"<set>\". The default\n\t\
value is \"<unset>\"."
#endif /* NA */
},
{"login_port_password",       PORT_PARAM,    DUI_PASSWD
#ifdef NA
, "Enables the port password if the port is configured as\n\t\
a DECserver interface port.\n\t\
The default is disabled. Y or y to enable; N or n to disable"
#endif /* NA */
},
{"login_prompt",                BOX_PARAM,      LOGIN_PROMPT
#ifdef NA
, "This is a string that specifies the port prompt for port with\n\t\
the user_interface_type set to \"vms\"."
#endif /* NA */
},
{"login_timeout",        PORT_PARAM,    DUI_INACT_TIMEOUT
#ifdef NA
, "Enables a login timer if the port is configured as a\n\t\
DECserver interface port.\n\t\
The default is disabled. Y or y to enable; N or n to disable"
#endif /* NA */
},
{"login_timer",          BOX_PARAM,     LOGIN_TIMER
#ifdef NA
, "the inactivity timer for all ports whose cli_interface parameter\n\t\
is set to vci. Legal values are in the range of 1-60 minutes.\n\t\
By default this is 30 minutes."
#endif /* NA */
},
{"long_break",		PORT_PARAM,	LONG_BREAK
#ifdef NA
, "accept long line break as CLI attention character:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"loose_source_route",	BOX_PARAM,	LOOSE_SOURCE_RT
#ifdef NA
, "allow internet protocol loose source routing:\n\t\
Y or y to enable (default); N or n to disable"
#endif /* NA */
},
#if NT1_ENG > 0
{"map",                 T1_DS0_PARAM,       T1_MAP_D
#ifdef NA
, "controls the DS0 channel mapping between the modems, the\n\t\
Drop & Insert Interface, and the T1 Network Interface.\n\t\
Syntax:\n\t\
set t1 ds0=<channel_number> map <map_val> <modem_number>\n\t\
where <map_val> = [ ds1_modem | di_modem ].\n\t\
set t1 ds0=<channel_set> map <map_val>\n\t\
where <map_val> = [ unused | voice | data ]."
#endif /* NA */
},
#endif /* NT1_ENG */
{"map_to_lower",	PORT_PARAM,	MAP_U_TO_L
#ifdef NA
, "upper to lower case mapping: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"map_to_upper",	PORT_PARAM,	MAP_L_TO_U_PORT
#ifdef NA
, "lower to upper case mapping: Y or y to enable; N or n to disable"
#endif /* NA */
},
#if NPRINTER > 0
{"map_to_upper",	PRINTER_PARAM,	MAP_L_TO_U_PRINT
#ifdef NA
, "lower to upper case mapping: Y or y to enable; N or n to disable"
#endif /* NA */
},
#endif /* NPRINTER */
{"max_chap_chall_int",	BOX_PARAM,	MAX_CHAP_CHALL_INT
#ifdef NA
, "Specifies maximum value for the random CHAP re-challenge interval.\n\t\
Valid values are in range of 0 to 65535 seconds.  Value of 0 for this\n\t\
parameter will turn off random chap re-challenges.  As default, random \n\t\
rechallenges have been turn off by having default value for this\n\t\
parameter is set to 0."
#endif /* NA */
},
{"max_session_count",	PORT_PARAM,	MAX_SESSIONS
#ifdef NA
, "maximum number of CLI sessions allowed: an integer, 1 - 16"
#endif /* NA */
},
{"max_vcli",		BOX_PARAM,	VCLI_LIMIT
#ifdef NA
, "maximum number of Virtual CLIs: an integer, 0 - 254, or \"unlimited\""
#endif /* NA */
},
#ifdef NA
{"message",		HELP_ENTRY,	0
, "the text of the message to be broadcast or echoed"
},
#endif /* NA */
{"metric",		PORT_PARAM,	P_SLIP_METRIC
#ifdef NA
, "the metric (cost) of using the serial interface associated with the\n\t\
port: an integer"
#endif /* NA */
},
{"min_unique_hostnames",BOX_PARAM,	NMIN_UNIQUE
#ifdef NA
, "accept abbreviated host names if they are unique:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"mode",		PORT_PARAM,	PORT_MODE
#ifdef NA
, "the mode of an async port (valid options are):  cli, slave,\n\t\
adaptive, slip, ppp, dedicated, arap, printer, ndp, auto_detect,\n\t\
ipx and unused.  The default setting is cli.\n\t\
NOTE: some port mode options are keyed options\n\t\
    cli           Command Line Interface\n\t\
    slave         Available via the port server\n\t\
    adaptive      Adapts to cli or slave mode on a fcfs basis\n\t\
    slip          Serial Line Internet Protocol\n\t\
    ppp           Point-to-Point Protocol\n\t\
    dedicated     Virtual connection to a specific host\n\t\
    arap          Appletalk Reverse Access Protocol\n\t\
    printer       Currently equivelant to slave\n\t\
    auto_detect   Auto Detection of incoming IPX, SLIP, PPP, and CLI\n\t\
    auto_adapt    Adapts to auto_detect or slave mode on a fcfs basis\n\t\
    ndp           Novell LMMGR/LMUSER Utilities\n\t\
    ipx           incoming IPX only\n\t\
    call          Dedicated call-protocol connection\n\t\
    connect       Dedicated LAT-protocol connection\n\t\
    rlogin        Dedicated rlogin-protocol connection\n\t\
    telnet        Dedicated TELNET-protocol connection\n\t\
    tn3270        Dedicated tn3270-protocol connection\n\t\
    unused        Unused port"
#endif /* NA */
},
#if NPRI > 0
{"modem",		A_COMMAND,	MODEM_CMD
#ifdef NA
, "modem <modem_set>"
#endif /* NA */
},
{"modem",		PARAM_CLASS,	MODEM_CLASS
#ifdef NA
, "set/show modem [= <modem_set>] ..."
#endif /* NA */
},
#endif /* NPRI */
{"modem_acc_entries",	BOX_PARAM,	ACC_ENTRIES
#ifdef NA
, "modem accounting entries"
#endif /* NA */
},
{"modem_error_threshold", BOX_PARAM,     MODEM_THRESHOLD
#ifdef NA
, "The number of consecutive modem errors that must occur before\n\t\
wanMdmErrorThresTrap is sent.  Setting this parameter to 0 disables the\n\t\
trap.  The default value is 0."
#endif /* NA */
},
{"mop",			BOX_CATEGORY,      BOX_MOP
#ifdef NA
, "Show the MOP subset of Annex parameters"
#endif /* NA */
},
{"mop_password",                BOX_PARAM,      MOP_PASSWD
#ifdef NA
, "MOP password for administrative net connection"
#endif /* NA */
},
{"motd_file",		BOX_PARAM,	MOTD
#ifdef NA
, "Name of host file that contains The Message-Of-The-Day"
#endif /* NA */
},
{"mp_endpoint_address",		PORT_PARAM,	P_MP_ENDP_VAL
#ifdef NA
, "This parameter is the endpoint address. The value entered here\n\t\
is used only if mp_endpoint_class is 'psndn'  and respresents a Public\n\t\
Switched Network Directory Number. It can be up to 15 characters."
#endif /* NA */
},
{"mp_endpoint_class",	PORT_PARAM,	P_MP_ENDP_OPT
#ifdef NA
, "This parameter specifies what the mp_endpoint_value contains\n\t\
the following are the valid endpoint options and meanings:\n\t\
   null  - mp_endpoint_address not used\n\t\
   NA    - not supported \n\t\
   ip    - mp_endpoint_address is ignored, Annex IP address is used\n\t\
   mac   - mp_endpoint_address is ignored, Annex MAC address is used\n\t\
   NA    - not supported\n\t\
   psndn - mp_endpoint_address needs to be entered and is the Public\n\t\
       Switched Network Directory Number."
#endif /* NA */
},
{"mp_mrru",		PORT_PARAM,	P_MP_MRRU
#ifdef NA
, "This parameter sets the Multilink PPP (MP) Maximum Received\n\t\
Reconstructed Unit in octets.  This will be the MTU on the peer's\n\t\
network interface(s).  Legal values are in the range 64 through 1600.\n\t\
The default value is 1500."
#endif /* NA */
},
{"mmp_enabled",		BOX_PARAM,	BOX_MP_ENABLED
#ifdef NA
, "This parameter indicates if Annex is configured for use of MMP\n\t\
functionality."
#endif /* NA */
},
{"multicast_timer",             BOX_PARAM,      MULTI_TIMER
#ifdef NA
, "MOP Multicast timer for system id announcements"
#endif /* NA */
},
{"multisessions_enable",        BOX_PARAM,      BOX_MULTISESS
#ifdef NA
, "Multisessions allowed on the box:\n\t\
\tY or y to enable; N or n to disable"
#endif /* NA */
},
{"multisessions_enable",       PORT_PARAM,     PORT_MULTISESS
#ifdef NA
, "Multisessions allowed on the port:\n\t\
\tY or y to enable; N or n to disable"
#endif /* NA */
},
{
"name_server_1",	BOX_PARAM,	PRIMARY_NS
#ifdef NA
, "primary name server to use for host name translation:\n\t\
none, ien_116, dns"
#endif /* NA */
},
{"name_server_2",	BOX_PARAM,	SECONDARY_NS
#ifdef NA
, "secondary name server to use for host name translation:\n\t\
none, ien_116, dns"
#endif /* NA */
},
{"nameserver",		BOX_CATEGORY,	BOX_NAMESERVER
#ifdef NA
, "Show the nameserver subset of Annex parameters"
#endif /* NA */
},
{"nameserver_broadcast", BOX_PARAM,	NAMESERVER_BCAST
#ifdef NA
, "broadcast for name server to use for host name translation:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"nameserver_override", BOX_PARAM,	NAMESERVER_OVERRIDE
#ifdef NA
, "override PPP Client's nameserver address during IPCP negotiations:\n\t\
Y or y for server override; N or n for client override"
#endif /* NA */
},
#ifdef NOT_USED
{"nd_forward",		BOX_PARAM,	ND_FORWARD
#ifdef NA
, "to be defined"
#endif /* NA */
},
#endif
{"need_dsr",		PORT_PARAM,	NEED_DSR
#ifdef NA
, "need the DSR signal to be asserted when connecting to slave port:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"net_inactivity",	PORT_PARAM,	P_SLIP_NET_INACTIVITY
#ifdef NA
, "SLIP/PPP inactivity timer interval: 0 or\n\t\
to disable or time (net_inactivity_units controls units) maximum is 255"
#endif /* NA */
},
{"net_inactivity_units",PORT_PARAM,	P_SLIP_NET_INACT_UNITS
#ifdef NA
, "units to use for the net_inactivity parameter:\n\t\
minutes or seconds"
#endif /* NA */
},
{"net_interface",	HELP_ENTRY,	0
#ifdef NA
, "the name of a network interface: net (Ethernet) or sl<n> (SLIP\n\t\
interface <n>), where <n> is an integer, 2 - 64"
#endif /* NA */
},
{"network_turnaround",	BOX_PARAM,	NET_TURNAROUND
#ifdef NA
, "turnaround timeout for network (seconds): an integer, 1 - 10"
#endif /* NA */
},
{"newline_terminal",	PORT_PARAM,	NEWLINE_TERMINAL
#ifdef NA
, "newline operation: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"node_id",		BOX_PARAM,	NODE_ID
#ifdef NA
, "the ANNEX AppleTalk node ID hint, legal values are xxxx.xx where \n\t\
xxxx range from 0..0xfeff and xx range from 0..0xfd"
#endif /* NA */
},
#if NPRI > 0
{"num_b_channels",	WAN_PARAM,	WAN_NUM_BCHAN_D
#ifdef NA
, "the number of B channels provisioned on PRI line; an integer.  The\n\t\
default is 0, which means the maximum allowable for the type of\n\t\
switch configured."
#endif /* NA */
},
#endif /* NPRI */
{"oof_threshold", BOX_PARAM, FRAMING_THRESHOLD
#ifdef NA
, "The number of Out of Frame errors that must occur on a WAN module \n\t\
in a 15 minute interval before wanOofThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"option_key",		BOX_PARAM,	OPTION_KEY
#ifdef NA
, "the option_key is a security mechanism which restricts unauthorized\n\t\
activation of keyed features in the Annex:\n\t\
set annex option_key <value>\n\t\
This parameter works in conjunction with disabled_modules"
#endif /* NA */
},
{"output_flow_control",	PORT_PARAM,	OUTPUT_FLOW_CONTROL
#ifdef NA
, "type of output flow control: none, eia, start/stop, both"
#endif /* NA */
},
{"output_is_activity",	PORT_PARAM,	OUTPUT_ACT
#ifdef NA
, "Port output should reset the port inactivity_timer:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"output_start_char",	PORT_PARAM,	OUTPUT_START_CHAR
#ifdef NA
, "start character for output flow control: a character"
#endif /* NA */
},
{"output_stop_char",	PORT_PARAM,	OUTPUT_STOP_CHAR
#ifdef NA
, "stop character for output flow control: a character"
#endif /* NA */
},
{"output_ttl",           BOX_PARAM,     OUTPUT_TTL
#ifdef NA
, "The value that is placed in the ttl field of all locally\n\t\
generated IP packets. The default value is 64."
#endif /* NA */
},
#ifdef NA
{"parameter_name",	HELP_ENTRY,	0
, "the name of one of the annex/port/printer eeprom parameters"
},
#endif /* NA */
{"parity",		PORT_PARAM,	PARITY
#ifdef NA
, "type of parity: even, odd, none"
#endif /* NA */
},
{"passwd_limit",                BOX_PARAM,      PASSWD_LIMIT
#ifdef NA
, "Number of times that password is prompted before logging out the user"
#endif /* NA */
},
{"password",		BOX_PARAM,	BOX_PASSWORD
#ifdef NA
, "Annex administration password: a string, maximum 15 characters"
#endif /* NA */
},
#ifdef NA
{"password",		A_COMMAND,	PASSWORD_CMD
, "password [<password>]"
},
#endif /* NA */
{"phone_number",	PORT_PARAM,	P_SLIP_NET_PHONE
#ifdef NA
, "phone number for demand dialing: a string, maximum 32 characters"
#endif /* NA */
},
#if NPRI == 0 || NA == 1
{"port,asynchronous",		A_COMMAND,	PORT_CMD
#ifdef NA
, "port <port_set>"
#endif /* NA */
},
#endif
{"port,asynchronous",		PARAM_CLASS,	PORT_CLASS
#ifdef NA
, "set/show port [= <port_set>] ..."
#endif /* NA */
},
#ifdef NA
{"port_list",		HELP_ENTRY,	0
, "<port_range> [, <port_range>]*  /  all / virtual / serial"
},
#endif /* NA */
#ifdef NA
{"port_number",		HELP_ENTRY,	0
, "an integer from 1 to 64"
},
#endif /* NA */
{"port_password",	PORT_PARAM,	PORT_PASSWORD
#ifdef NA
, "Port password for local security: a string, maximum 15 characters\n\t\
When defined this string is displayed as \"<set>\". The default\n\t\
value is \"<unset>\"."
#endif /* NA */
},
#ifdef NA
{"port_range",		HELP_ENTRY,	0
, "<port_number> [- <port_number>]"
},
#endif /* NA */
{"port_server_security",PORT_PARAM,	PORT_SERVER_SECURITY
#ifdef NA
, "ACP authorization required to access port via port server feature:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef NA
{"port_set",		HELP_ENTRY,	0
, "<port_list> [@ <annex_list>] [; <port_list> [@ <annex_list>]]*"
},
#endif /* NA */
{"ppp",			PORT_CATEGORY,	PORT_PPP
#ifdef NA
, "Show the PPP subset of port parameters"
#endif /* NA */
},
{"ppp_acm",		PORT_PARAM,	P_PPP_ACM
#ifdef NA
, "mask used by peer to avoid sending unwanted\n\t\
characters: a four octet bit mask, entered as 8 hex\n\t\
characters. (0x00000000)"
#endif /* NA */
},
#ifdef P_PPP_ACTOPEN
{"ppp_active_open",	PORT_PARAM,	P_PPP_ACTOPEN
#ifdef NA
, "have ANNEX initiate LCP negoatiation or wait for\n\t\
peer to do so.  Y or y to enable; N or n to disable"
#endif /* NA */
},
#endif
{"ppp_ipx_network",	PORT_PARAM,	P_PPP_IPX_NETNUM
#ifdef NA
, "This parameter defines the IPX network number to be used\n\t\
for a port.\n\t\
The default value is zero."
#endif /* NA */
},
{"ppp_ipx_node",	PORT_PARAM,	P_PPP_IPX_NODENUM
#ifdef NA
, "This parameter defines the IPX node number to be used\n\t\
for a port.\n\t\
The default value is zero."
#endif /* NA */
},
{"ppp_mru",		PORT_PARAM,	P_PPP_MRU
#ifdef NA
, "This parameter set the PPP Maximum Receive Unit in octets.  For\n\t\
regular PPP, this will be the MTU on the peer's network interface(s).\n\t\
For Multilink PPP (MP), this will be the maximum fragment size.  Legal\n\t\
values are in the range 64 through 1600.  The default value is 1500."
#endif /* NA */
},
{"ppp_ncp",		PORT_PARAM,	P_PPP_NCP
#ifdef NA
, "the network protocol(s) running over PPP on this interface. \n\t\
Allowed values: all, or one or more of ipcp, atcp, ipxcp, ccp, or\n\t\
mp, separated by commas. The default is all."
#endif /* NA */
},
{"ppp_password_remote",	PORT_PARAM,	P_PPP_PWORDRMT
#ifdef NA
, "The password used by the Annex to identify itself if the\n\t\
remote peer asks for authentication. When defined this string\n\t\
is displayed as \"<set>\". The default value is \"<unset>\"."
#endif /* NA */
},
{"ppp_sec_auto",       PORT_PARAM,     P_PPP_SEC_AUTO
#ifdef NA
, "This parameter is used with the ppp_security_protocol parameter\n\t\
when the port mode is auto-detect or auto-adapt. If ppp_sec_auto is\n\t\
set to Y and the user comes in as CLI and then goes into PPP mode\n\t\
(via the ppp command), the annex acts as if the ppp_security_protocol\n\t\
parameter was set to none. If ppp_sec_auto is set to Y and the user is\n\t\
auto-detected as PPP, the annex uses the ppp_security_protocol value\n\t\
previously specified by the user. If ppp_sec_auto is set to N, the\n\t\
effect of this parameter is disabled. The default value is N."
#endif
},
{"ppp_security_protocol",	PORT_PARAM,	P_PPP_SECURITY
#ifdef NA
, "type of authentication to be used for protocol level security\n\t\
check if Annex enable_security is enabled. Legal values are \n\t\
none, pap, chap or chap-pap. The default is none."
#endif /* NA */
},
{"ppp_username_remote",	PORT_PARAM,	P_PPP_UNAMERMT
#ifdef NA
, "The Username used by the Annex to identify itself if the\n\t\
remote peer asks for authentication. The default value is empty."
#endif /* NA */
},
{"pref_dhcp1_host",     BOX_PARAM,      PREF1_DHCPADDR
#ifdef NA
, "the Internet address of the preferred DHCP server that the client\n\t\
will attempt to discover as the primary source for DHCP services."
#endif /* NA */
},
{"pref_dhcp2_host",     BOX_PARAM,      PREF2_DHCPADDR
#ifdef NA
, "the Internet address of the preferred DHCP server that the client\n\t\
will attempt to discover as a backup source for DHCP services."
#endif /* NA */
},
{"dhcp_giaddr",     BOX_PARAM,          DHCP_GIADDR
#ifdef NA
, "This parameter corresponds to the DHCP relay agent gateway Internet\n\t\
address. It is used in conjunction with RAS unicasts to DHCP servers that\n\t\
reside on a LAN other than its own. The RAS sets the GIADDR field to the\n\t\
value of this parameter when initiating unicast BOOTREQUESTs to a DHCP\n\t\
relay agent. The field exists to facilitate the delivery of BOOTREPLY\n\t\
messages from the DHCP servers, through BOOTP relay agents, back to the\n\t\
RAS. RFC 1542 states that the client (RAS) should set this address to\n\t\
zero and it is the duty of the relay agent to fill in. In reality,\n\t\
some DHCP relay agents require the RAS to fill in the GIADDR field with\n\t\
the IP address of the relay agent interface that is connected to the same\n\t\
LAN as the RAS."
#endif /* NA */
},
{"pref_dump_addr",	BOX_PARAM,	PREF_DUMP
#ifdef NA
, "the Internet address of the preferred dump host: a host_identifier"
#endif /* NA */
},
{"pref_load_addr",	BOX_PARAM,	PREF_LOAD
#ifdef NA
, "the Internet address of the preferred load host: a host_identifier"
#endif /* NA */
},
{"pref_mop_host",       BOX_PARAM,      MOP_PREF_HOST
#ifdef NA
, "The ethernet address of the preferred load MOP host"
#endif /* NA */
},
{"pref_name1_addr",	BOX_PARAM,	PRIMARY_NS_ADDR
#ifdef NA
, "the Internet address of the preferred primary domain name server:\n\t\
a host_identifier"
#endif /* NA */
},
{"pref_name2_addr",	BOX_PARAM,	SECONDARY_NS_ADDR
#ifdef NA
, "the Internet address of the preferred secondary domain name server:\n\t\
a host_identifier"
#endif /* NA */
},
{"pref_nbns1_addr",	BOX_PARAM,	PRIMARY_NBNS_ADDR
#ifdef NA
, "the Internet address of the preferred primary NetBIOS name server:\n\t\
a host_identifier (used for NS negotiations with PPP Clients only)"
#endif /* NA */
},
{"pref_nbns2_addr",	BOX_PARAM,	SECONDARY_NBNS_ADDR
#ifdef NA
, "the Internet address of the preferred secondary NetBIOS name server:\n\t\
a host_identifier (used for NS negotiations with PPP Clients only)"
#endif /* NA */
},
{"pref_secure1_host,pref_secure_host", BOX_PARAM, PREF_SECURE_1
#ifdef NA
, "the Internet address of the preferred primary security host:\n\t\
a host_identifier"
#endif /* NA */
},
{"pref_secure2_host",	BOX_PARAM,	PREF_SECURE_2
#ifdef NA
, "the Internet address of the preferred secondary security host:\n\t\
a host_identifier"
#endif /* NA */
},
#if NPRINTER > 0
{"printer",		A_COMMAND,	PRINTER_CMD
#ifdef NA
, "printer <printer_set>"
#endif /* NA */
},
{"printer",		PARAM_CLASS,	PRINTER_CLASS
#ifdef NA
, "set/show printer [= <printer_set>] ..."
#endif /* NA */
},
{"printer_crlf",	PRINTER_PARAM,	PRINTER_CR_CRLF
#ifdef NA
, "convert <CR> to <CR><LF>: Y or y to enable (default); N or n to disable"
#endif /* NA */
},
#endif /* NPRINTER */
{"printer_host",	PORT_PARAM,	P_TN3270_PRINTER_HOST
#ifdef NA
, "the IP address of a host running a printer spooler"
#endif /* NA */
},
{"printer_name",	PORT_PARAM,	P_TN3270_PRINTER_NAME
#ifdef NA
, "the printer name"
#endif /* NA */
},
#if NPRINTER > 0
{"printer_speed",	PRINTER_PARAM,	PRINTER_SPD
#ifdef NA
, "printer speed on Micro-Annex: \"normal\", \"high_speed\""
#endif /* NA */
},
{"printer_width",	PRINTER_PARAM,	PRINTER_WIDTH
#ifdef NA
, "printer width (columns per line): an integer"
#endif /* NA */
},
#endif /* NPRINTER */
{"prompt",		PORT_PARAM,	PORT_PROMPT
#ifdef NA
, "CLI prompt for this port: a prompt_string"
#endif /* NA */
},
#ifdef NA
{"prompt_string",	HELP_ENTRY,	0
, "a string with embedded format sequences, used as a prompt:\n\t\
   %a  the string \"annex\"     %c  the string \": \"\n\t\
   %d  the date and time      %i  the Annex's Internet address\n\t\
   %j  a newline character    %l  port location, or \"port n\"\n\t\
   %n  the Annex's name       %p  the port number\n\t\
   %r  the string \"port\"      %s  a space\n\t\
   %t  the time hh:mm:ss      %u  the user name of the port\n\t\
   %%  the string \"%\""
},
#endif /* NA */
#ifdef OBSOLETE_T1_PARAMETER
{"proto_arg",           T1_DS0_PARAM,       T1_PROTO_ARG_D
#ifdef NA
, "reserved"
#endif /* NA */
},
#endif /*OBSOLETE_T1_PARAMETER*/
{"proxy_arp_enabled", PORT_PARAM, PROXY_ARP_ENABLED
#ifdef NA
, "Enables all remote connections with an internet IP address to\n\t\
respond to arp requests. The ethernet hardware address returned\n\t\
is the annex. If disabled then only IP addresses having the same\n\t\
subnet as the annex will respond to arp requests."
#endif /* NA */
},
{"silent_mode_enable", PORT_PARAM, SILENT_MODE_ENABLE
#ifdef NA
, "This parameter, if enabled, turns off all error messages from\n\t\
being printed on CLI. It also skips annex: prompt."
#endif /* NA */
},
{"ps_history_buffer",	PORT_PARAM,	PS_HISTORY_BUFF
#ifdef NA
, "specifies how much data to buffer on a slave port\n\t\
(0 - 32767): 0 to disable or an integer (number of characters)\n\t\
NOTE: Not supported on R13.0 and later images"
#endif /* NA */
},
{"quit",		A_COMMAND,	QUIT_CMD
#ifdef NA
, "quit"
#endif /* NA */
},
{"radius_acct1_host", BOX_PARAM, RADIUS_ACCT1_HOST
#ifdef NA
, "the Internet address of the preferred primary radius accounting host:\n\t\
a host_identifier"
#endif /* NA */
},
{"radius_acct1_port,radius_acct_port",  BOX_PARAM,      RADIUS_ACCT_PORT
#ifdef NA
 , "This is the destination port to be used when sending \n\t\
 accounting requests to the primary radius accounting server. \n\t\
 Default is 1646"
#endif /* NA */
},
{"radius_acct1_secret",     BOX_PARAM,      RADIUS_ACCT1_SECRET
#ifdef NA
, "This is the secret shared between the annex and the primary radius \n\t\
accounting server."
#endif /* NA */
},
{"radius_acct2_host", BOX_PARAM, RADIUS_ACCT2_HOST
#ifdef NA
, "the Internet address of the preferred backup radius accounting host:\n\t\
a host_identifier"
#endif /* NA */
},
{"radius_acct2_port",  BOX_PARAM,      RADIUS_ACCT2_PORT
#ifdef NA
 , "This is the destination port to be used when sending \n\t\
 accounting requests to the backup radius accounting server. \n\t\
 Default is 1646"
#endif /* NA */
},
{"radius_acct2_secret",     BOX_PARAM,      RADIUS_ACCT2_SECRET
#ifdef NA
, "This is the secret shared between the annex and the backup radius \n\t\
accounting server."
#endif /* NA */
},
{"radius_acct_level",    BOX_PARAM,   RAD_ACCT_LEVEL
#ifdef NA
, "Is the level of RADIUS accounting.  If set to basic the Annex only \n\t\
logs Starts, Stops, Accounting-On, and Accounting-Off.  Setting it to \n\t\
advanced permits the Annex to log all other events, including MP."
#endif /* NA */
},
{"radius_acct_timeout",    BOX_PARAM,      RADIUS_ACCT_TIMEOUT
#ifdef NA
, "This is the time to be used to calculate wait time for a packet to be \n\t\
received from the radius server."
#endif /* NA */
},
{"radius_auth1_port,radius_auth_port",  BOX_PARAM,      RADIUS_AUTH_PORT
#ifdef NA
 , "This is the destination port to be used when sending \n\t\
 authentication requests to the primary radius server. Default is 1645."
#endif /* NA */
},
{"radius_auth1_secret,radius_secret",     BOX_PARAM,      RADIUS_SECRET
#ifdef NA
, "This is the secret shared between the annex and the primary radius \n\t\
authentication server."
#endif /* NA */
},
{"radius_auth2_port",  BOX_PARAM,      RADIUS_AUTH2_PORT
#ifdef NA
 , "This is the destination port to be used when sending \n\t\
 authentication requests to the backup radius server. Default is 1645."
#endif /* NA */
},
{"radius_auth2_secret",     BOX_PARAM,      RADIUS_AUTH2_SECRET
#ifdef NA
, "This is the secret shared between the annex and the backup radius \n\t\
authentication server."
#endif /* NA */
},
{"radius_auth_timeout,radius_timeout",    BOX_PARAM,      RADIUS_TIMEOUT
#ifdef NA
, "This is the maximum time to wait for a packet to be received from\n\t\
the radius server."
#endif /* NA */
},
{"radius_pass_prompt",    BOX_PARAM,      RADIUS_PASSWD_PROMPT
#ifdef NA
, "Annex security password prompt string. This is valid \n\t\
only when auth_protocol is radius and does not hold for local \n\t\
authentication or when auth_protocol is acp."
#endif /* NA */
},
{"radius_port_encoding",    BOX_PARAM,      RAD_PORT_ENCODING
#ifdef NA
, "This parameter sets the way that radius accounting will report port numbers\n\t\
The valid choices are device and channel.  When set to device it gives the\n\t\
internal number used by the annex.  When set to channel it reports the number as\n\t\
tllcc where t is the device type; ll is the wan number and cc is the channel."
#endif /* NA */
},
{"radius_retries",    BOX_PARAM,      RADIUS_RETRIES
#ifdef NA
, "This is the maximum number of times to try sending a packet to the \n\t\
the radius server whilst awaiting a reply."
#endif /* NA */
},
{"radius_user_prompt",    BOX_PARAM,      RADIUS_USER_PROMPT
#ifdef NA
, "Annex security login prompt string. This is valid \n\t\
only when auth_protocol is radius and does not hold for local \n\t\
authentication or when auth_protocol is acp."
#endif /* NA */
},
#ifdef NA
{"read",		A_COMMAND,	READ_CMD
, "read <filename>"
},
#endif /* NA */
{"redisplay_line",	PORT_PARAM,	REDISPLAY_LINE
#ifdef NA
, "character used to redisplay input line: a character"
#endif /* NA */
},
#if NPRI > 0
{"remote_address",	WAN_CHAN_PARAM,	WAN_REMOTE_ADDRESS_D
#ifdef NA
, "the Internet address of the remote endpoint of the interface\n\t\
associated with the channel.  This parameter acts as an IP address pool\n\t\
for when dialup_addresses are not in use.  The default value is 0.0.0.0"
#endif /* NA */
},
#endif /* NPRI */
{"remote_address,slip_remote_address",	PORT_PARAM,	P_SLIP_REMOTEADDR
#ifdef NA
, "the Internet address of the remote endpoint of the interface\n\t\
associated with the port: a host_identifier\n\t\
The default value is 0.0.0.0"
#endif /* NA */
},
{"reset",		A_COMMAND,	RESET_CMD
#ifdef NA
, "\
reset annex [<subsystem>]*\n\t\
reset printer [<printer_set>]\n\t\
reset [<port_set>]\n\t\
reset port [<port_set>]\n\t\
reset asynchronous [<port_set>]\n\t\
reset interface [<interface_set>]\n\t\
reset int_modem [<internal_modem_set>] [ hard, soft ]\n\t\
Subsystems are: all, dialout <range>, lat, macros, modem, motd,\n\t\
nameserver, security, session, syslog"
#endif /* NA */
},
{"reset_idle_time_on", PORT_PARAM,	RESET_IDLE
#ifdef NA
, "Data direction that should reset the idle time displayed by \"who\":\n\t\
input or output"
#endif /* NA */
},
{"resolve_protocol", PORT_PARAM, RESOLVE_PROTOCOL
#ifdef NA
, "default protocol to use for a dedicated port if the dedicated port\n\t\
protocol is ambiguous.  Can be set to one of \"telnet\", \"lat\" or\n\t\
\"any\"."
#endif /* NA */
},
{"retrans_limit",		BOX_PARAM,	RETRANS_LIMIT
#ifdef NA
, "the number of times to retransmit a packet before notifying user of\n\t\
network failure:  an integer, 4 - 120 inclusive.\n\t\
set annex retrans_limit <value>"
#endif /* NA */
},
#if NT1_ENG > 0
{"ring",                T1_DS0_PARAM,       T1_RING_D
#ifdef NA
, "specifies if the an audible ring need to be provided to the\n\t\
central office for incoming calls. Syntax:\n\t\
set t1 ds0=<channel_set> ring [ no | yes ]"
#endif /* NA */
},
#endif /* NT1_ENG */
{"ring_priority",	BOX_PARAM,	RING_PRIORITY
#ifdef NA
, "access priority for IEEE 802.5 Token Ring: an integer, 0-3,\n\t\
where: 0 is lowest priority and 3 is highest priority"
#endif /* NA */
},
#if NPRI > 0
{"ringback",                WAN_CHAN_PARAM,       WAN_RINGBACK_D
#ifdef NA
, "specifies if an audible ring needs to be provided to the\n\t\
central office for incoming calls. Syntax:\n\t\
set cas ds0=<channel_set> ring [ no | yes ]"
#endif /* NA */
},
#endif /* NPRI */
{"rip_accept",		INTERFACE_PARAM,	RIP_ACCEPT
#ifdef NA
, "Control which networks are accepted from RIP update. The legal values\n\t\
are none , all or up to eight inclusive or exclusive list of networks"
#endif /* NA */
},
{"rip_advertise",	INTERFACE_PARAM,	RIP_ADVERTISE
#ifdef NA
, "Control which networks are advertised. The legal values are none, all\n\t\
or up to eight inclusive or exclusive list of networks"
#endif /* NA */
},
{"rip_auth",		BOX_PARAM,	RIP_AUTH
#ifdef NA
, "Control RIP packets authentication. The legal value is the clear-text\n\t\
password to be used to authenticate the packets"
#endif /* NA */
},
{"rip_force_newrt",     BOX_PARAM,      RIP_FORCE_NEWRT
#ifdef NA
, "When enabled, this parameter specifies the timeout value in seconds\n\t\
that the Annex waits for a router to send periodic RIP updates. If the\n\t\
Annex does not hear from the primary router within this timeout period\n\t\
and a secondary router broadcasts a valid replacement route, then the\n\t\
replacement route takes precedence regardless of the metric. The default\n\t\
and recommended value is 0 or \"off\" which disables this feature. The\n\t\
maximum value is 255 seconds."
#endif /* NA */
},
{"rip_default_route",	INTERFACE_PARAM,	RIP_DEFAULT_ROUTE
#ifdef NA
, "Control override of configured default route. If a default route update\n\t\
is received with a metric less than or equal to the current setting\n\t\
the current default route will be overridden. The legal value is\n\t\
between 1 and 15 (inclusive)"
#endif /* NA */
},
{"rip_horizon",		INTERFACE_PARAM,	RIP_HORIZON
#ifdef NA
, "Set the split horizon algorithm, the legal values are split, off\n\t\
or poison"
#endif /* NA */
},
{"rip_next_hop",	INTERFACE_PARAM,	RIP_NEXT_HOP
#ifdef NA
, "Control inclusion of next hop value in version 2 advertisements.\n\t\
May be set to never, needed or always."
#endif /* NA */
},
#ifdef NOT_USED
{"rip_override_default",	INTERFACE_PARAM,	RIP_OVERRIDE_DEFAULT
#ifdef NA
, "to be defined"
#endif /* NA */
},
#endif
{"rip_recv_version",		INTERFACE_PARAM,	RIP_RECV_VERSION
#ifdef NA
, "Set the RIP version will be accepted, the legal values are 1, 2 or both"
#endif /* NA */
},
{"rip_routers",		BOX_PARAM,	RIP_ROUTERS
#ifdef NA
, "Control periodic RIP responses to be directed to a list of routers\n\t\
or broadcast. The legal values are all or a list of up to eight routers'\n\t\
IP addresses"
#endif /* NA */
},
{"rip_send_version",		INTERFACE_PARAM,	RIP_SEND_VERSION
#ifdef NA
, "Set the RIP version will be sent, the legal values are 1, 2 or \n\t\
compatibility"
#endif /* NA */
},
{"rip_sub_accept",		INTERFACE_PARAM,	RIP_SUB_ACCEPT
#ifdef NA
, "Control acceptance of subnet routes: y or Y to enable, n or N to disable"
#endif /* NA */
},
{"rip_sub_advertise",		INTERFACE_PARAM,	RIP_SUB_ADVERTISE
#ifdef NA
, "Control advertising of subnet routes: y or Y to enable, \n\t\
n or N to disable"
#endif /* NA */
},
{"routed",		BOX_PARAM,	NROUTED
#ifdef NA
, "Listen to routed broadcasts to fill the Annex routing table:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"router",		BOX_CATEGORY,	BOX_ROUTER
#ifdef NA
, "Show the router subset of Annex parameters"
#endif /* NA */
},
{"rwhod",		BOX_PARAM,	NRWHOD
#ifdef NA
, "Listen to rwho broadcasts to fill the Annex host table:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef NOT_USED
{"sd_forward",		BOX_PARAM,	SD_FORWARD
#ifdef NA
, "to be defined"
#endif /* NA */
},
#endif
{"security",		BOX_CATEGORY,	BOX_SECURITY
#ifdef NA
, "Show the security subset of Annex parameters"
#endif /* NA */
},
{"security",		PORT_CATEGORY,	PORT_SECURITY
#ifdef NA
, "Show the security subset of port parameters"
#endif /* NA */
},
{"security_broadcast", BOX_PARAM,	SECURSERVER_BCAST
#ifdef NA
, "broadcast for security server to use if none found:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"ses_threshold",	BOX_PARAM,	SES_THRESHOLD
#ifdef NA
, "The number of Severely Errored Seconds that must occur on a \n\t\
WAN module in a 15 minute interval before wanSesThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"seg_jumper_bay5k,seg_jumper_5390",	BOX_PARAM,	JUMPER_BAY5K
#ifdef NA
, "cmb bay5k jumper"
#endif /* NA */
},
{"serial",		PORT_CATEGORY,	PORT_SERIAL
#ifdef NA
, "Show the generic serial interface subset of port parameters"
#endif /* NA */
},
#ifdef NA
{"serial",		HELP_ENTRY,	0
, "port serial          set default port list to all serial ports\n\t\
broadcast = serial   broadcast to all serial ports\n\t\
reset serial         reset all serial ports"
},
#endif /* NA */
{"server_capability",	BOX_PARAM,	SERVER_CAP
#ifdef NA
, "list of files that the Annex can provide to other Annexes:\n\t\
image, config, motd, all or none"
#endif /* NA */
},
{"server_name",		BOX_PARAM,	HOST_NAME
#ifdef NA
, "A string identifying the Annex's LAT host name (maximum\n\t\
of 16 characters): set annex server_name <string>"
#endif /* NA */
},
{"service_limit",		BOX_PARAM,	SERVICE_LIMIT
#ifdef NA
, "the maximum number of LAT service names that can be stored in the\n\t\
Annex service table: an integer, 16 - 2048 inclusive.\n\t\
set annex service_limit <value>"
#endif /* NA */
},
{"session_limit",             BOX_PARAM,      SESSION_LIMIT
#ifdef NA
, "the session_limit is the maximum number of sessions allowed on the\n\t\
Annex. The default value is 1152, setting a value of 0 sets no limit;\n\t\
the maximum value is normally 16 times the number of ports on the Annex.\n\t\
set annex session_limit <value>"
#endif /* NA */
},
{"set",			A_COMMAND,	SET_CMD
#ifdef NA
, "\
set annex   [= <annex_list>] [<parameter_name> <value>]*\n\t\
set printer [= <printer_set>] [<parameter_name> <value>]*\n\t\
set port    [= <port_set>] [<parameter_name> <value>]*\n\t\
set asynchronous [= <port_set>] [<parameter_name> <value>]*\n\t\
set interface    [= <interface_set>] [<parameter_name> <value>]*\n"
#endif /* NA */
},
{"short_break",		PORT_PARAM,	SHORT_BREAK
#ifdef NA
, "short line break: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"show",		A_COMMAND,	SHOW_CMD
#ifdef NA
, "\
show annex   [= <annex_list>] [<parameter_name>]*\n\t\
show printer [= <printer_set>] [<parameter_name>]*\n\t\
show port    [= <port_set>] [<parameter_name>]* [<keyword>]*\n\t\
show asynchronous [= <port_set>] [<parameter_name>]* [<keyword>]*\n\t\
show interface    [= <interface_set>] [<parameter_name>]*\n"
#endif /* NA */
},
#if NT1_ENG > 0
{"sigproto",             T1_DS0_PARAM,       T1_SIGPROTO_D
#ifdef NA
, "specifies the inbound and the outbound signaling protocol\n\t\
used in each DS0. Syntax:\n\t\
set t1 ds0=<channel_set> sigproto <proto_in> <proto_out>\n\t\
valid proto_in and proto_out settings are loop_start,ground_start,\n\t\
wink_start,immediate_start, or none."
#endif /* NA */
},
#endif /* NT1_ENG */
#if NPRI > 0
{"sigproto",             WAN_CHAN_PARAM,       WAN_SIGPROTO_D
#ifdef NA
, "specifies the inbound and the outbound signaling protocol\n\t\
used in each DS0. Syntax:\n\t\
set wan ds0=<channel_set> sigproto <proto>\n\t\
valid proto settings are loop_in, loop_out, loop_bi, gnd_in, gnd_out,\n\t\
gnd_bi, wink_in, wink_out, wink_bi, imm_in, imm_out, r1_in, r1_out,\n\t\
r1_bi, r2_in, r2_out, r2_bi, p7_bi, p7_in, p7_out, or none."
#endif /* NA */
},
#endif /* NPRI */
{"slip",		PORT_CATEGORY,	PORT_SLIP
#ifdef NA
, "Show the SLIP subset of port parameters"
#endif /* NA */
},
{"slip_allow_dump",	PORT_PARAM,	P_SLIP_ALLOW_DUMP
#ifdef NA
, "allow upline memory dump over the SLIP interface associated with\n\t\
the port: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"slip_load_dump_host",	PORT_PARAM,	P_SLIP_LOADUMP_HOST
#ifdef NA
, "the address of the host to load from or dump to over the SLIP\n\t\
interface associated with the port: a host_identifier"
#endif /* NA */
},
{"slip_mtu_size",	PORT_PARAM,	P_SLIP_LARGE_MTU
#ifdef NA
, "force CSLIP interface to use Large \"1006\" or Small \"256\"\n\t\
MTU (Maximum transmission unit): large or small (default)"
#endif /* NA */
},
{"slip_no_icmp",	PORT_PARAM,	P_SLIP_NO_ICMP
#ifdef NA
, "silently discard all ICMP packets destined to traverse this SLIP\n\t\
interface: Y or y to enable; N or n to disable"
#endif /* NA */
},
{"slip_ppp_security,slip_security",       PORT_PARAM,     P_SLIP_SECURE
#ifdef NA
, "ACP authorization required to use slip or ppp command from a CLI not\n\t\
secured by ACP : Y or y to enable; N or n to disable"
#endif
},
{"slip_tos",		PORT_PARAM,	P_SLIP_FASTQ
#ifdef NA
, "transmit interactive traffic before any other traffic over this SLIP\n\t\
interface for cheap type-of-service queuing:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"snmp",		BOX_CATEGORY,	BOX_SNMP
#ifdef NA
, "show the SNMP subset of the Annex parameters."
#endif /* NA */
},
{"speed",		PORT_PARAM,	PORT_SPEED
#ifdef NA
, "the speed of the port: 50, 75, 110, 134.5, 150, 200, 300, 600, 1200,\n\t\
1800, 2000, 2400, 3600, 4800, 7200, 9600, 19200, 38400, 57600, 64000,\n\t\
76800, 115200, autobaud or autobaud with a default output speed\n\t\
specified as autobaud/(speed)."
#endif /* NA */
},
{"stop_bits",		PORT_PARAM,	STOP_BITS
#ifdef NA
, "number of stop bits: 1, 1.5, 2"
#endif /* NA */
},
{"subnet_mask",		BOX_PARAM,	SUBNET_MASK
#ifdef NA
, "the Annex network subnet mask: an Internet address mask"
#endif /* NA */
},
{"subnet_mask",	PORT_PARAM,	P_SLIP_NETMASK
#ifdef NA
, "the subnet mask of the point-to-point network defined by the SLIP\n\t\
interface associated with the port: an Internet address mask"
#endif /* NA */
},
#if NPRI > 0
{"switch_type",		WAN_PARAM,	WAN_SWITCH_TYPE_D
#ifdef NA
, "the attached central office switch type for a WAN interface (for\n\t\
the mixed traffic products). If this string value is left unset;\n\t\
a qualified guess is attempted on initial boot."
#endif /* NA */
},
#endif /* NPRI */
#if NT1_ENG > 0
{"switch_type",             T1_PARAM,       T1_SWITCH_TYPE_D
#ifdef NA
, "Type of T1 switch which we will interact (on a t1 only platform):\n\t\
standard (default), hk, 1aess"
#endif /* NA */
},
#endif /* NT1_ENG */
{"sync",		PORT_CATEGORY,  PORT_SYNC
#ifdef NA
, "Show the synchronous subset of port parameters"
#endif /* NA */
},
#ifdef NA
{"syntax",		HELP_ENTRY,	0
, "\n\t\
When entering mnemonics, use minimum uniqueness principle.\n\t\
Strings may be enclosed in double-quote characters.\n\t\
\n\t\
[syntax]                optional (may be omitted)\n\t\
[syntax]*		may be omitted, or occur one or more times\n\t\
one_way / another	choice between one_way and another (not both)\n\t\
...			continue according to appropriate command\n\t\
<help_token>		a sub-syntax - help <help_token> gives details\n\t\
\n\t\
Other symbols are actual commands or parameters to be entered."
},
#endif /* NA */
{"sys_location",	BOX_PARAM,	HOST_ID
#ifdef NA
, "system location string (maximum of 32 characters).  LAT uses this\n\t\
string for the host identification field."
#endif /* NA */
},
{"syslog",		BOX_CATEGORY,	BOX_SYSLOG
#ifdef NA
, "Show the syslog subset of Annex parameters"
#endif /* NA */
},
{"syslog_facility",	BOX_PARAM,	SYSLOG_FAC
#ifdef NA
, "Annex syslog facility code: log_local[0-7] or number"
#endif /* NA */
},
{"syslog_host",		BOX_PARAM,	SYSLOG_HOST
#ifdef NA
, "Host to which Annex syslog messages are logged: a host_identifier"
#endif /* NA */
},
{"syslog_mask",		BOX_PARAM,	SYSLOG_MASK
#ifdef NA
, "list of syslog severity levels the Annex should report: emergency,\n\t\
alert, critical, error, warning, notice, info, debug, none, and all"
#endif /* NA */
},
{"syslog_port",		BOX_PARAM,	SYSLOG_PORT
#ifdef NA
, "Port to which Annex syslog messages are logged: a port_identifier"
#endif /* NA */
},
#if NT1_ENG > 0
{"t1",   PARAM_CLASS,    T1_CLASS
#ifdef NA
, "set/show t1 ..."
#endif /* NA */
},
#endif /* NT1_ENG */
#if NPRI_WAN > 0
{"t1_sigproto",         WAN_CHAN_PARAM,       WAN_T1_SIGPROTO_D
#ifdef NA
, "specifies the inbound and the outbound signaling protocol\n\t\
used in each DS0. Syntax:\n\t\
set wan ds0=<channel_set> sigproto <proto_in> <proto_out>\n\t\
valid proto_in and proto_out settings are loop_start,ground_start,\n\t\
wink_start,immediate_start, r1_in, r1_out, r1_bi, r2_in,\n\t\
r2_out, r2_bi, p7_bi, p7_in, p7_out, or none."
#endif /* NA */
},
#endif /* NPRI */
#if NT1_ENG > 0
{"t1_info",             T1_PARAM,      T1_INFO_D
#ifdef NA
, "T1 line installation information; a string up to 120 bytes long"
#endif /* NA */
},
#endif /* NT1_ENG */
{"tcp_keepalive",	BOX_PARAM,	TCP_KEEPALIVE
#ifdef NA
, "default TCP connection keepalive timer value in minutes:\n\t\
\tInteger in the range 0 to 255 -- default value if zero is\n\t\
\t120 minutes."
#endif /* NA */
},
{"tcp_keepalive",	PORT_PARAM,	TCPA_KEEPALIVE
#ifdef NA
, "default TCP keepalive timer for serial port connections in minutes:\n\t\
\tInteger in the range 0 to 255.  If set to zero, then the\n\t\
\tdefault value as set by the \"annex tcp_keepalive\" value\n\t\
\tis used."
#endif /* NA */
},
#if NPRINTER > 0
{"tcp_keepalive",	PRINTER_PARAM,	TCPP_KEEPALIVE
#ifdef NA
, "default TCP keepalive timer for print connections in minutes:\n\t\
\tInteger in the range 0 to 255.  If set to zero, then the\n\t\
\tdefault value as set by the \"annex tcp_keepalive\" value\n\t\
\tis used."
#endif /* NA */
},
#endif /* NPRINTER */
#if NT1_ENG > 0
{"tdi_distance",        T1_PARAM,      T1_TDI_DISTANCE_D
#ifdef NA
, "distance, in feet, of the cable run between the T1 Drop & Insert \n\t\
Interface ant the equipment attached to it. Integer: 0 to 655."
#endif /* NA */
},
{"tdi_framing",        T1_PARAM,       T1_TDI_FRAMING_D
#ifdef NA
, "controls the super frame format used on the T1 Drop & Insert\n\t\
Interface: d4 (super frame), esf (extended super frame)."
#endif /* NA */
},
{"tdi_line_code",      T1_PARAM,       T1_TDI_LINE_CODE_D
#ifdef NA
, "selects the line code used on the T1 Drop & Insert\n\t\
Interface: ami, b8zs."
#endif /* NA */
},
#endif /* NT1_ENG */
{"telnet_crlf",		PORT_PARAM,	TELNET_CRLF
#ifdef NA
, "newline sequence to use for telnet: when enabled, telnet uses\n\t\
<CR><LF>; when disabled, telnet uses <CR><NULL>\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"telnet_escape",	PORT_PARAM,	TELNET_ESC
#ifdef NA
, "escape character to use with the telnet command: a character"
#endif /* NA */
},
#ifdef NOT_USED
{"telnetd_key",               BOX_PARAM,     TELNETD_KEY
#ifdef NA
, "The Kerberos service key used by the kerberised telnetd on\n\t\
this Annex. This service key is used to decrypt a Kerberos ticket\n\t\
received from the user when attempting to access the telnetd\n\t\
service on this Annex. When defined this string is displayed as\n\t\
\"<set>\". The default value is \"<unset>\"."
#endif /* NA */
},
#endif /* NOT_USED */
{"term_var",		PORT_PARAM,	TERM_VAR
#ifdef NA
, "Terminal type variable: a string, maximum sixteen characters"
#endif /* NA */
},
{"tftp_dump_name",		BOX_PARAM,	TFTP_DUMP_NAME
#ifdef NA
, "the filename to which the Annex should dump in the event of a critical\n\t\
system error.  This filename including complete parent directory names\n\t\
(maximum 100 characters)"
#endif /* NA */
},
{"tftp_load_dir,tftp_dir_name",		BOX_PARAM,	TFTP_DIR_NAME
#ifdef NA
, "the tftp directory name which is prepended to Annex file names\n\t\
for tftp transfers during Annex loading.  Used for image file name and\n\t\
support files (i.e. gateways, rotaries, etc)"
#endif /* NA */
},
#ifdef NOT_USED
{"tgs_host",             BOX_PARAM,     TGS_HOST
#ifdef NA
, "A list of zero to four IP addresses (in dotted decimal form)\n\t\
or host names of the Kerberos ticket granting servers to be used\n\t\
when a user requests a Kerberos ticket. The names and addresses are \n\t\
separated by commas."
#endif /* NA */
},
#endif /* NOT_USED */
{"time",		BOX_CATEGORY,	BOX_TIME
#ifdef NA
, "Show the time subset of Annex parameters"
#endif /* NA */
},
{"time_broadcast",	 BOX_PARAM,	TIMESERVER_BCAST
#ifdef NA
, "broadcast for time service if primary server doesn't respond:\n\t\
Y or y to enable; N or n to disable"
#endif /* NA */
},
{"time_server",	 BOX_PARAM,	TIMESERVER_HOST
#ifdef NA
, "IP address of host providing time service.  Boot host will be used\n\t\
if this field is 0.0.0.0.  No direct queries will be made if this\n\t\
field is set to 127.0.0.1."
#endif /* NA */
},
{"timers",		PORT_CATEGORY,	PORT_TIMERS
#ifdef NA
, "Show the timer subset of port parameters"
#endif /* NA */
},
{"timezone_minuteswest",BOX_PARAM,	TZ_MINUTES
#ifdef NA
, "Minutes west of GMT: an integer"
#endif /* NA */
},
{"tmux",	            BOX_CATEGORY,      BOX_TMUX
#ifdef NA
, "Show the TMUX subset of Annex parameters"
#endif /* NA */
},
{"tmux_delay",           BOX_PARAM,     TMUX_DELAY
#ifdef NA
, "The maximum amount of time (in mS) used to accumulate smaller\n\t\
packets into a larger TMUX packet. When the time expires,\n\t\
the multiplexed packet is sent, regardless how large it is.\n\t\
The default timeout is 20mS."
#endif /* NA */
},
{"tmux_enable",               BOX_PARAM,     TMUX_ENA
#ifdef NA
, "Controls whether the Annex uses TMUX to multiplex small\n\t\
TCP or UDP packets into a single IP packet. The host\n\t\
must also support TMUX, otherwise the Annex will drop back\n\t\
to non-multiplexing mode even when this parameter is enabled.\n\t\
The default is no. Y or y to enable; N or n to disable"
#endif /* NA */
},
{"tmux_max_host",	BOX_PARAM,     TMUX_MAX_HOST
#ifdef NA
, "The Maximum size of the TMUX address table. If the \n\t\
number of host addresses exceeds this limit the oldest\n\t\
entry is flushed. The default value is 64."
#endif /* NA */
},
{"tmux_max_mpx",         BOX_PARAM,     TMUX_MAX_MPX
#ifdef NA
, "The largest packet that can be placed in a TMUX packet. Larger\n\t\
packets are not multiplexed but are directly passed on to the IP\n\t\
layer. The default size is 700 bytes."
#endif /* NA */
},
{"tn3270",		PORT_CATEGORY,	PORT_TN3270
#ifdef NA
, "Show the tn3270 subset of port parameters"
#endif /* NA */
},
#if NT1_ENG > 0
{"tni_circuit_id",      T1_PARAM,       T1_TNI_CIRCUIT_ID_D
#ifdef NA
, "ascii string with circuit id provided by the telephone\n\t\
company. Up to 127 bytes."
#endif /* NA */
},
{"tni_clock",          T1_PARAM,       T1_TNI_CLOCK_D
#ifdef NA
, "specifies the T1 engine clock source: loop, local, external."
#endif /* NA */
},
{"tni_esf_fdl",        T1_PARAM,       T1_TNI_ESF_FDL_D
#ifdef NA
, "specifies one of two standards when running ESF framing\n\t\
on the T1 Network Interface: ansi, att."
#endif /* NA */
},
{"tni_framing",        T1_PARAM,       T1_TNI_FRAMING_D
#ifdef NA
, "controls the super frame format used on the T1 Network\n\t\
Interface: d4 (super frame), esf (extended super frame)."
#endif /* NA */
},
{"tni_line_buildout",  T1_PARAM,       T1_TNI_LINE_BUILDOUT_D
#ifdef NA
, "specifies the T1 line buildout, in db's, supplied\n\t\
by the telephone company: 0db, 7.5db, 15db, 22.5db."
#endif /* NA */
},
{"tni_line_code",      T1_PARAM,       T1_TNI_LINE_CODE_D
#ifdef NA
, "selects the line code used on the T1 Network\n\t\
Interface: ami, b8zs."
#endif /* NA */
},
{"tni_ones_density",   T1_PARAM,       T1_TNI_ONES_DENSITY_D
#ifdef NA
, "turns on or off the T1 engine's internal\n\t\
ones density monitor."
#endif /* NA */
},
#endif /* NT1_ENG */
{"toggle_output",	PORT_PARAM,	TOGGLE_OUTPUT
#ifdef NA
, "character used to toggle output: a character"
#endif /* NA */
},
{"type",		PORT_PARAM,	PORT_TYPE
#ifdef NA
, "the type of the port: hardwired, dial_in, terminal, modem, printer"
#endif /* NA */
},
#if NPRINTER > 0
{"type",	PRINTER_PARAM,	PRINTER_INTERFACE
#ifdef NA
, "printer interface style: (dataproducts or centronics)"
#endif /* NA */
},
#endif /* NPRINTER */
{"type_of_modem",		PORT_PARAM, 	MODEM_VAR	
#ifdef NA
, "the modem type connected to the port: a string, maximum 16 characters"
#endif /* NA */
},
{"uas_threshold",	BOX_PARAM,	UAS_THRESHOLD
#ifdef NA
, "The number of Unavailable Seconds that must occur on a \n\t\
WAN module in a 15 minute interval before wanUasThreshTrap is sent. \n\t\
Setting this parameter to 0 disables the trap.  The default value is 0."
#endif /* NA */
},
{"unexpected_trap_inc",	BOX_PARAM,	UNEXPECTED_TRAP_INCR
#ifdef NA
, "count of unexpected call-disconnect events after which an unexpected-\n\t\
call-disconnect SNMP trap will be sent.  Range is 0 (to disable\n\t\
unexpected-call-disconnect traps) to 65535."
#endif /* NA */
},
{"user_name",		PORT_PARAM,	PORT_NAME
#ifdef NA
, "Default username printed by \"who\" command and passed by \"rlogin\":\n\t\
a string, maximum 16 characters"
#endif /* NA */
},
{"v120_mru",		PORT_PARAM,	V120_MRU
#ifdef NA
, "Maximum receive unit for V.120 protocol.  Legal values are 30-260;\n\t\
default is 256."
#endif /* NA */
},
#ifdef NA
{"value",		HELP_ENTRY,	0
, "the value of an annex/port/printer eeprom parameter\n\t\
\n\t\
A value may be enclosed in double-quotes.  Integers may range \n\t\
from 0 to 255, 0 is converted to a default.  Characters may \n\t\
be entered in ^X notation, hexadecimal (0x58), octal (0130),\n\t\
or literally.  Note that '00' is the character NULL which\n\t\
converts to the default, while '0' is ASCII zero.\n\t\
\n\t\
the default value for a parameter which is a list of names/values can\n\t\
be set by the command:\n\t\
\n\t\
	set ... <parameter_name> default"
},
#endif /* NA */
{"vci",			PORT_CATEGORY,     PORT_LOGIN
#ifdef NA
, "Show the vci subset of port parameters"
#endif /* NA */
},
{"vcli",		BOX_CATEGORY,	BOX_VCLI
#ifdef NA
, "Show the vcli subset of Annex parameters"
#endif /* NA */
},
{"vcli_groups",		BOX_PARAM,	VCLI_GROUPS
#ifdef NA
, "This Annex parameter will specify which remote group codes\n\t\
are accessible to virtual cli users. All virtual cli users have\n\t\
the same group code. Syntax:\n\t\
set annex vcli_groups <group range> enable | disable\n\t\
where <group range> is the set of groups ([similar to port set]\n\t\
between 0, and 255 inclusive) to affect (i.e. 1,2,3; 2; 5-10 are\n\t\
all valid group ranges).  A shortcut method can be used to enable or \n\t\
disable all group values.  To enable all groups, use:\n\t\
set annex vcli_groups all \n\t\
To disable all groups, use:\n\t\
set annex vcli_groups none"
#endif /* NA */
},
{"vcli_inactivity",     BOX_PARAM,      VCLI_INACTIVITY
#ifdef NA
, "This annex parameter will specify the amount of time in minutes\n\t\
that a VCLI line can remain inactive, before the line is reset. The\n\t\
default value for this parameter is off (indicating the timer is\n\t\
currently inactive). The maximum value is 255 minutes."
#endif /* NA */
},
{"vcli_password",	BOX_PARAM,	VCLI_PASSWORD
#ifdef NA
, "VCLI password: a string, maximum 15 characters"
#endif /* NA */
},
{"vcli_security",	BOX_PARAM,	VCLI_SEC_ENA
#ifdef NA
, "ACP authorization required to use VCLI: Y or y to enable; N or n to\n\t\
disable"
#endif /* NA */
},
{"attn_kill_enable",	BOX_PARAM,	ATTN_KILL_ENABLE
#ifdef NA
, "Kill the currently running job upon pressing control sequence defined \n\t\
by attn_string: Y or y to enable; N or n to disable"
#endif /* NA */
},
#ifdef NA
{"virtual",		HELP_ENTRY,	0
, "broadcast = virtual  broadcast to all virtual CLI ports\n\t\
reset virtual        reset all virtual CLI ports"
},
#endif
#if NPRI > 0
{"wan,pri",		A_COMMAND,	WAN_CMD
#ifdef NA
, "wan <wan_set>"
#endif /* NA */
},
{"wan,pri",		PARAM_CLASS,	PRI_CLASS
#ifdef NA
, "set/show wan [= <wan_set>] ..."
#endif /* NA */
},
#endif /* NPRI */
#ifdef NA
{"write",		A_COMMAND,	WRITE_CMD
, "write <annex_identifier> <filename>"
},
#endif /* NA */
{"zone",		BOX_PARAM,	ZONE
#ifdef NA
, "the hint for the AppleTalk zone to be used at startup\n\t\
a string up to 32 bytes"
#endif /* NA */
},
{"disable_unarp",      BOX_PARAM,      BOX_TOGGLE_UNARP
#ifdef NA
, "toggle the UNARP extension of ARP. see rfc1868"
#endif /* NA */
},
{(char *)NULL,		0,		0
#ifdef NA
, "Beyond Table"
#endif
}
};
