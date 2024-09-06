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
 * (Include file) OR (Module) description:
 *	%$(description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 ****************************************************************************
 */
#ifndef CMD_H_PARAMS_ONLY
#ifdef NA
char *changes_will = "\tChanges will take effect ";
char *immediately = "immediately.\n";
char *imm_local = "immediately for local sessions, and, for na\n\
\tsessions, at next %s boot";
char *next_boot = "at next %s boot";
char *or_passwd_cmd = "at next CLI passwd change or\n\t";
char *annex_reset_secureserver = ", reset %s security,";
char *annex_reset_nameserver = ", reset %s nameserver,";
char *annex_reset_motd = ", reset %s motd,";
char *annex_reset_lat = ", reset %s lat,";
char *cr_reset_all = "\n\tor reset %s all.\n";
char *or_reset_all = " or reset %s all.\n";

char *annex_msg   = ".\n";
char *port_msg    = " or port reset.\n";
char *printer_msg = " or printer reset.\n";
char *interface_msg = " or interface reset.\n";
char *pri_msg	= " or PRI module reset.\n";
char *modem_msg = " or modem reset.\n";

#ifndef isdigit
#define isdigit(x) (x >= '0' && x <= '9')
#endif

#endif /* ifdef NA */
#endif /* CMD_H_PARAMS_ONLY */

extern time_t time();

char	*get_password();

#define A_COMMAND		0
#define PARAM_CLASS		1
#define BOX_PARAM		2
#define PORT_PARAM		3
#define PRINTER_PARAM		4
#define HELP_ENTRY		5
#define INTERFACE_PARAM		6
#define BOX_CATEGORY		7
#define PORT_CATEGORY		8
#define T1_PARAM		9
#define T1_DS0_PARAM		10
#define WAN_PARAM		11
#define WAN_CHAN_PARAM		12
#define MODEM_PARAM		13

#ifdef NA
#ifndef CMD_H_PARAMS_ONLY
char *usage_table[] =
{
	"command",
	"parameter class",
	BOX_PARAMETER,
	"asynchronous port parameter",
	"printer parameter",
	"help entry",
	"interface parameter",
	"annex parameter category",
	"asynchronous port category",
        "channelized T1 category",
        "channelized T1 ds0 category",
	"WAN category",
	"WAN DS0/B-channel category",
	"modem category",
};
#endif /* CMD_H_PARAMS_ONLY */

#define BOX_CMD                 0
#define BOOT_CMD                (BOX_CMD + 1)
#define COMMENT_CMD             (BOX_CMD + 2)
#define COPY_CMD                (BOX_CMD + 3)
#define DUMPBOOT_CMD            (BOX_CMD + 4)
#define ECHO_CMD                (BOX_CMD + 5)
#define PASSWORD_CMD            (BOX_CMD + 6)
#define READ_CMD                (BOX_CMD + 7)
#define WRITE_CMD               (BOX_CMD + 8)
#define BROADCAST_CMD           (BOX_CMD + 9)
#else /* !NA */
#define BROADCAST_CMD           0
#endif /* ifdef NA */

#define HELP_CMD                (BROADCAST_CMD + 1)
#if NPRI > 0 && NA == 0
#define PORT_CMD		HELP_CMD
#else
#define PORT_CMD		(HELP_CMD + 1)
#endif
#define QUIT_CMD                (PORT_CMD + 1)
#define RESET_CMD               (PORT_CMD + 2)
#define SET_CMD                 (PORT_CMD + 3)
#define SHOW_CMD                (PORT_CMD + 4)
#define QUEST_CMD               (PORT_CMD + 5)
#if NPRINTER > 0
#define PRINTER_CMD             (QUEST_CMD + 1)
#else
#define PRINTER_CMD		QUEST_CMD
#endif
#define INTERFACE_CMD           (PRINTER_CMD + 1)
#if NPRI > 0
#define MODEM_CMD		(INTERFACE_CMD + 1)
#define WAN_CMD			(MODEM_CMD + 1)
#else
#define MODEM_CMD		INTERFACE_CMD
#define WAN_CMD			INTERFACE_CMD
#endif

#define NCOMMANDS               (WAN_CMD + 1)

#ifdef NA
int	adm_box_cmd();
int	adm_boot_cmd();
int	adm_comment_cmd();
int	adm_copy_cmd();
int	adm_dumpboot_cmd();
int	adm_echo_cmd();
int	adm_password_cmd();
int	adm_read_cmd();
int	adm_write_cmd();
int	adm_broadcast_cmd();
int	adm_help_cmd();
int	adm_port_cmd();
int	adm_quit_cmd();
int	adm_reset_cmd();
int	adm_set_cmd();
int	adm_show_cmd();
int	adm_printer_cmd();
int	adm_interface_cmd();
int	adm_modem_cmd();
int	adm_wan_cmd();

#ifndef CMD_H_PARAMS_ONLY
int (*cmd_actions[])() =
{
	adm_box_cmd,
	adm_boot_cmd,
	adm_comment_cmd,
	adm_copy_cmd,
	adm_dumpboot_cmd,
	adm_echo_cmd,
	adm_password_cmd,
	adm_read_cmd,
	adm_write_cmd,
	adm_broadcast_cmd,
	adm_help_cmd,
	adm_port_cmd,
	adm_quit_cmd,
	adm_reset_cmd,
	adm_set_cmd,
	adm_show_cmd,
	adm_help_cmd,
	adm_printer_cmd,
	adm_interface_cmd,
	adm_modem_cmd,
	adm_wan_cmd,
};
#endif /* CMD_H_PARAMS_ONLY */

#else	/* ! NA */
errno_t	adm_broadcast_cmd();
errno_t	adm_help_cmd();
#if NPRI == 0
errno_t	adm_port_cmd();
#endif
errno_t	adm_quit_cmd();
errno_t	adm_reset_cmd();
errno_t	adm_set_cmd();
errno_t	adm_show_cmd();
#if NPRINTER > 0
errno_t	adm_printer_cmd();
#endif
errno_t	adm_interface_cmd();
#if NPRI > 0
errno_t	adm_modem_cmd();
errno_t adm_wan_cmd();
#endif

#ifndef CMD_H_PARAMS_ONLY
errno_t (*cmd_actions[])() =
{
	adm_broadcast_cmd,
	adm_help_cmd,
#if NPRI == 0
	adm_port_cmd,
#endif
	adm_quit_cmd,
	adm_reset_cmd,
	adm_set_cmd,
	adm_show_cmd,
	adm_help_cmd,
#if NPRINTER > 0
	adm_printer_cmd,
#endif
	adm_interface_cmd,
#if NPRI > 0
	adm_modem_cmd,
	adm_wan_cmd,
#endif
};
#endif /* CMD_H_PARAMS_ONLY */
#endif /*ifdef NA */

#ifndef CMD_H_PARAMS_ONLY 
char *cmd_spellings[NCOMMANDS + 1];
#endif /* CMD_H_PARAMS_ONLY */

#define BOX_CLASS		0
#define PORT_CLASS		(BOX_CLASS + 1)
#if NPRINTER > 0
#define PRINTER_CLASS		(PORT_CLASS + 1)	
#else
#define PRINTER_CLASS		PORT_CLASS
#endif
#define INTERFACE_CLASS		(PRINTER_CLASS + 1)	
#if NT1_ENG > 0
#define T1_CLASS		(INTERFACE_CLASS + 1)
#else
#define T1_CLASS		INTERFACE_CLASS
#endif
#if NPRI > 0
#define PRI_CLASS		(T1_CLASS + 1)
#define MODEM_CLASS		(PRI_CLASS + 1)
#else
#define MODEM_CLASS		T1_CLASS
#endif

#define NCLASSES		(MODEM_CLASS + 1)

#ifndef CMD_H_PARAMS_ONLY
char *param_classes[NCLASSES + 1];
#endif /* ifndef CMD_H_PARAMS_ONLY */


/********************************************************************
 ********************************************************************
 **   NOTE:
 **
 **	IF YOU ALTER THE ORDER OF THESE PARAMETERS YOU MUST CHANGE
 **	THE ORDER OF THE ENTRIES IN THE TABLE annexp_table  
 **
 ********************************************************************
 */

/*
 * The following are display groupings which define the way
 * of paramters in the various menus as display grouping is not
 * related to E2ROM paramter offset!!!
 */

#define BOX_GENERIC_GROUP       0

#define INET_ADDR               BOX_GENERIC_GROUP
#define SUBNET_MASK             BOX_GENERIC_GROUP + 1
#define PREF_LOAD               BOX_GENERIC_GROUP + 2
#define PREF_DUMP               BOX_GENERIC_GROUP + 3
#define LOADSERVER_BCAST        BOX_GENERIC_GROUP + 4
#define BROAD_ADDR              BOX_GENERIC_GROUP + 5
#define LOADUMP_GATEWAY         BOX_GENERIC_GROUP + 6
#define LOADUMP_SEQUENCE        BOX_GENERIC_GROUP + 7
#define IMAGE_NAME              BOX_GENERIC_GROUP + 8
#define MOTD                    BOX_GENERIC_GROUP + 9
#define CONFIG_FILE             BOX_GENERIC_GROUP + 10
#define AUTH_AGENT              BOX_GENERIC_GROUP + 11
#define NROUTED                 BOX_GENERIC_GROUP + 12
#define SERVER_CAP              BOX_GENERIC_GROUP + 13
#define SELECTED_MODULES        BOX_GENERIC_GROUP + 14
#define TFTP_DIR_NAME           BOX_GENERIC_GROUP + 15
#define TFTP_DUMP_NAME          BOX_GENERIC_GROUP + 16
#define IPENCAP_TYPE            BOX_GENERIC_GROUP + 17
#define RING_PRIORITY           BOX_GENERIC_GROUP + 18
#define IP_FWD_BCAST            BOX_GENERIC_GROUP + 19
#define TCP_KEEPALIVE           BOX_GENERIC_GROUP + 20
#define OPTION_KEY              BOX_GENERIC_GROUP + 21
#define ACC_ENTRIES             BOX_GENERIC_GROUP + 22
#define JUMPER_BAY5K            BOX_GENERIC_GROUP + 23
#define SESSION_LIMIT           BOX_GENERIC_GROUP + 24
#define OUTPUT_TTL              BOX_GENERIC_GROUP + 25
#define ARPT_TTKILLC            BOX_GENERIC_GROUP + 26
#define FAIL_TO_CONNECT		BOX_GENERIC_GROUP + 27
#define BOX_MP_ENABLED		BOX_GENERIC_GROUP + 28
#define PASS_BREAK		BOX_GENERIC_GROUP + 29
#define BOX_TOGGLE_UNARP        BOX_GENERIC_GROUP + 30
#define BOX_VCLI_GROUP          BOX_GENERIC_GROUP + 31 

#define VCLI_LIMIT              BOX_VCLI_GROUP
#define CLI_PROMPT_STR          BOX_VCLI_GROUP + 1
#define VCLI_SEC_ENA            BOX_VCLI_GROUP + 2
#define VCLI_PASSWORD           BOX_VCLI_GROUP + 3
#define VCLI_INACTIVITY         BOX_VCLI_GROUP + 4
#define ATTN_KILL_ENABLE        BOX_VCLI_GROUP + 5

#define BOX_NAMESERVER_GROUP    BOX_VCLI_GROUP + 6

#define NAMESERVER_BCAST        BOX_NAMESERVER_GROUP
#define NRWHOD                  BOX_NAMESERVER_GROUP + 1
#define PRIMARY_NS_ADDR         BOX_NAMESERVER_GROUP + 2
#define PRIMARY_NS              BOX_NAMESERVER_GROUP + 3
#define SECONDARY_NS_ADDR       BOX_NAMESERVER_GROUP + 4
#define SECONDARY_NS            BOX_NAMESERVER_GROUP + 5
#define HTABLE_SZ               BOX_NAMESERVER_GROUP + 6
#define NMIN_UNIQUE             BOX_NAMESERVER_GROUP + 7
#define PRIMARY_NBNS_ADDR       BOX_NAMESERVER_GROUP + 8
#define SECONDARY_NBNS_ADDR     BOX_NAMESERVER_GROUP + 9
#define NAMESERVER_OVERRIDE     BOX_NAMESERVER_GROUP + 10

#define BOX_SECURITY_GROUP      BOX_NAMESERVER_GROUP + 11

#define ENABLE_SECURITY         BOX_SECURITY_GROUP
#define SECURSERVER_BCAST       BOX_SECURITY_GROUP + 1
#define PREF_SECURE_1           BOX_SECURITY_GROUP + 2
#define PREF_SECURE_2           BOX_SECURITY_GROUP + 3
#define NET_TURNAROUND          BOX_SECURITY_GROUP + 4
#define LOOSE_SOURCE_RT         BOX_SECURITY_GROUP + 5
#define ACP_KEY                 BOX_SECURITY_GROUP + 6
#define BOX_PASSWORD            BOX_SECURITY_GROUP + 7
#define LOCK_ENABLE             BOX_SECURITY_GROUP + 8
#define PASSWD_LIMIT            BOX_SECURITY_GROUP + 9
#define CHAP_AUTH_NAME          BOX_SECURITY_GROUP + 10
#define MAX_CHAP_CHALL_INT      BOX_SECURITY_GROUP + 11
#define AUTHENTICATION_PROTOCOL BOX_SECURITY_GROUP + 12
#define ENABLE_RADIUS_ACCT      BOX_SECURITY_GROUP + 13
#define RADIUS_ACCT1_HOST       BOX_SECURITY_GROUP + 14
#define RADIUS_ACCT2_HOST       BOX_SECURITY_GROUP + 15
#define RADIUS_AUTH_PORT        BOX_SECURITY_GROUP + 16
#define RADIUS_AUTH2_PORT       BOX_SECURITY_GROUP + 17
#define RADIUS_ACCT_PORT        BOX_SECURITY_GROUP + 18
#define RADIUS_ACCT2_PORT       BOX_SECURITY_GROUP + 19
#define RADIUS_SECRET           BOX_SECURITY_GROUP + 20
#define RADIUS_AUTH2_SECRET     BOX_SECURITY_GROUP + 21
#define RADIUS_ACCT1_SECRET     BOX_SECURITY_GROUP + 22
#define RADIUS_ACCT2_SECRET     BOX_SECURITY_GROUP + 23
#define RADIUS_TIMEOUT          BOX_SECURITY_GROUP + 24
#define RADIUS_ACCT_TIMEOUT     BOX_SECURITY_GROUP + 25
#define RADIUS_RETRIES          BOX_SECURITY_GROUP + 26
#define RAD_ACCT_LEVEL          BOX_SECURITY_GROUP + 27
#define RAD_PORT_ENCODING       BOX_SECURITY_GROUP + 28
#define RADIUS_USER_PROMPT      BOX_SECURITY_GROUP + 29
#define RADIUS_PASSWD_PROMPT    BOX_SECURITY_GROUP + 30


#ifdef NOT_USED
/* Sorry no other way to remove this from NA right now */
#define BOX_KERBEROS_GROUP      BOX_SECURITY_GROUP + 31
#define KERB_SECURITY_ENA       BOX_KERBEROS_GROUP
#define KERB_HOST               BOX_KERBEROS_GROUP + 1
#define TGS_HOST                BOX_KERBEROS_GROUP + 2
#define TELNETD_KEY             BOX_KERBEROS_GROUP + 3
#define KERBCLK_SKEW            BOX_KERBEROS_GROUP + 4
#endif

#define BOX_TIME_GROUP          BOX_SECURITY_GROUP + 31

#define TIMESERVER_BCAST        BOX_TIME_GROUP
#define TZ_DLST                 BOX_TIME_GROUP + 1
#define TZ_MINUTES              BOX_TIME_GROUP + 2
#define TIMESERVER_HOST         BOX_TIME_GROUP + 3

#define BOX_SYSLOG_GROUP        BOX_TIME_GROUP + 4

#define SYSLOG_MASK             BOX_SYSLOG_GROUP
#define SYSLOG_FAC              BOX_SYSLOG_GROUP + 1
#define SYSLOG_HOST             BOX_SYSLOG_GROUP + 2
#define SYSLOG_PORT             BOX_SYSLOG_GROUP + 3

#define BOX_VMS_GROUP           BOX_SYSLOG_GROUP + 4

#define MOP_PREF_HOST           BOX_VMS_GROUP
#define MOP_PASSWD              BOX_VMS_GROUP + 1
#define LOGIN_PASSWD            BOX_VMS_GROUP + 2
#define LOGIN_PROMPT            BOX_VMS_GROUP + 3
#define LOGIN_TIMER             BOX_VMS_GROUP + 4

#define BOX_LAT_GROUP           BOX_VMS_GROUP + 5

#define KEY_VALUE               BOX_LAT_GROUP
#define HOST_NUMBER             BOX_LAT_GROUP + 1
#define HOST_NAME               BOX_LAT_GROUP + 2
#define HOST_ID                 BOX_LAT_GROUP + 3
#define QUEUE_MAX               BOX_LAT_GROUP + 4
#define SERVICE_LIMIT           BOX_LAT_GROUP + 5
#define KA_TIMER                BOX_LAT_GROUP + 6
#define CIRCUIT_TIMER           BOX_LAT_GROUP + 7
#define RETRANS_LIMIT           BOX_LAT_GROUP + 8
#define GROUP_CODE              BOX_LAT_GROUP + 9
#define VCLI_GROUPS             BOX_LAT_GROUP + 10
#define MULTI_TIMER             BOX_LAT_GROUP + 11
#define BOX_MULTISESS           BOX_LAT_GROUP + 12

#define BOX_ARAP_GROUP          BOX_LAT_GROUP + 13

#define A_ROUTER                BOX_ARAP_GROUP
#define DEF_ZONE_LIST           BOX_ARAP_GROUP + 1
#define NODE_ID                 BOX_ARAP_GROUP + 2
#define ZONE                    BOX_ARAP_GROUP + 3

#define BOX_RIP_GROUP           BOX_ARAP_GROUP + 4

#define RIP_AUTH                BOX_RIP_GROUP
#define RIP_ROUTERS             BOX_RIP_GROUP + 1
#define RIP_FORCE_NEWRT         BOX_RIP_GROUP + 2

#ifdef NOT_USED
#define IP_TTL                  BOX_RIP_GROUP + 3
#define ND_FORWARD              BOX_RIP_GROUP + 4
#define ASD_FORWARD             BOX_RIP_GROUP + 5
#define SD_FORWARD              BOX_RIP_GROUP + 6
#endif

#define BOX_IPX_GROUP           BOX_RIP_GROUP + 3

#define IPX_FILE_SERVER         BOX_IPX_GROUP
#define IPX_FRAME_TYPE          BOX_IPX_GROUP + 1
#define IPX_DUMP_UNAME          BOX_IPX_GROUP + 2
#define IPX_DUMP_PWD            BOX_IPX_GROUP + 3
#define IPX_DUMP_PATH           BOX_IPX_GROUP + 4
#define IPX_DO_CHKSUM           BOX_IPX_GROUP + 5

#define BOX_TMUX_GROUP          BOX_IPX_GROUP + 6

#define TMUX_ENA                BOX_TMUX_GROUP
#define TMUX_MAX_HOST           BOX_TMUX_GROUP + 1
#define TMUX_DELAY              BOX_TMUX_GROUP + 2
#define TMUX_MAX_MPX            BOX_TMUX_GROUP + 3

#define BOX_DHCP_GROUP          BOX_TMUX_GROUP + 4

#define PREF1_DHCPADDR          BOX_DHCP_GROUP
#define PREF2_DHCPADDR          BOX_DHCP_GROUP + 1
#define DHCP_BCAST              BOX_DHCP_GROUP + 2
#define DHCP_GIADDR             BOX_DHCP_GROUP + 3

#define BOX_SNMP_GROUP		BOX_DHCP_GROUP + 4


#define ALLOW_SNMP_SETS         BOX_SNMP_GROUP
#define DEF_TRAPHOST		BOX_SNMP_GROUP + 1
#define CALL_BEGIN_ENABLE	BOX_SNMP_GROUP + 2
#define CALL_END_INCR		BOX_SNMP_GROUP + 3
#define INACTIVITY_TRAP_INCR	BOX_SNMP_GROUP + 4
#define UNEXPECTED_TRAP_INCR	BOX_SNMP_GROUP + 5
#define BIPOLAR_THRESHOLD       BOX_SNMP_GROUP + 6
#define FRAMING_THRESHOLD       BOX_SNMP_GROUP + 7
#define ERRSECS_THRESHOLD       BOX_SNMP_GROUP + 8
#define DIALLNK_TRAP_EN         BOX_SNMP_GROUP + 9
#define CALL_HISTORY_LIMIT	BOX_SNMP_GROUP + 10
#define CV_THRESHOLD		BOX_SNMP_GROUP + 11
#define ESF_THRESHOLD		BOX_SNMP_GROUP + 12
#define SES_THRESHOLD		BOX_SNMP_GROUP + 13
#define UAS_THRESHOLD		BOX_SNMP_GROUP + 14
#define BES_THRESHOLD		BOX_SNMP_GROUP + 15
#define LOFC_THRESHOLD		BOX_SNMP_GROUP + 16
#define CSS_THRESHOLD		BOX_SNMP_GROUP + 17
#define DS0_ERROR_THRESHOLD	BOX_SNMP_GROUP + 18
#define MODEM_THRESHOLD		BOX_SNMP_GROUP + 19

#define BOX_BOX_GROUP           BOX_SNMP_GROUP + 20

#define BOX_GENERIC             BOX_BOX_GROUP
#define BOX_VCLI                BOX_BOX_GROUP + 1
#define BOX_NAMESERVER          BOX_BOX_GROUP + 2
#define BOX_SECURITY            BOX_BOX_GROUP + 3
#ifdef NOT_USED
#define BOX_KERBEROS            BOX_BOX_GROUP + 4
#endif
#define BOX_TIME                BOX_BOX_GROUP + 4
#define BOX_SYSLOG              BOX_BOX_GROUP + 5
#define BOX_MOP                 BOX_BOX_GROUP + 6
#define BOX_LAT                 BOX_BOX_GROUP + 7
#define BOX_APPLETALK           BOX_BOX_GROUP + 8
#define BOX_ROUTER              BOX_BOX_GROUP + 9
#define BOX_IPX                 BOX_BOX_GROUP + 10
#define BOX_TMUX                BOX_BOX_GROUP + 11
#define BOX_DHCP                BOX_BOX_GROUP + 12
#define BOX_SNMP                BOX_BOX_GROUP + 13
#define ALL_BOX                 BOX_BOX_GROUP + 14
#define NBOXP                   BOX_BOX_GROUP + 15


#ifndef CMD_H_PARAMS_ONLY

char *annex_params[NBOXP + 1];

#endif /* ifndef CMD_H_PARAMS_ONLY */

/********************************************************************
 ********************************************************************
 **   NOTE:
 **
 **	IF YOU ALTER THE ORDER OF THESE PARAMETERS YOU MUST CHANGE
 **	THE ORDER OF THE ENTRIES IN THE TABLE portp_table  BELOW
 **
 ********************************************************************
 */

#define PORT_GENERIC_GROUP	0

#define PORT_MODE               PORT_GENERIC_GROUP
#define LOCATION                PORT_GENERIC_GROUP + 1
#define PORT_TYPE               PORT_GENERIC_GROUP + 2
#define TERM_VAR                PORT_GENERIC_GROUP + 3
#define PORT_PROMPT             PORT_GENERIC_GROUP + 4
#define USER_INTERFACE          PORT_GENERIC_GROUP + 5
#define PORT_SPEED              PORT_GENERIC_GROUP + 6
#define PORT_AUTOBAUD           PORT_GENERIC_GROUP + 7
#define BITS_PER_CHAR           PORT_GENERIC_GROUP + 8
#define STOP_BITS               PORT_GENERIC_GROUP + 9
#define PARITY                  PORT_GENERIC_GROUP + 10
#define MAX_SESSIONS            PORT_GENERIC_GROUP + 11
#define BROADCAST_ON            PORT_GENERIC_GROUP + 12
#define BROADCAST_DIR           PORT_GENERIC_GROUP + 13
#define IMASK_7BITS             PORT_GENERIC_GROUP + 14
#define CLI_IMASK7              PORT_GENERIC_GROUP + 15
#define PS_HISTORY_BUFF         PORT_GENERIC_GROUP + 16
#define BANNER                  PORT_GENERIC_GROUP + 17
#define TCPA_KEEPALIVE          PORT_GENERIC_GROUP + 18
#define DEDICATED_ADDRESS       PORT_GENERIC_GROUP + 19
#define DEDICATED_PORT          PORT_GENERIC_GROUP + 20
#define MODEM_VAR               PORT_GENERIC_GROUP + 21
#define DEF_SESS_MODE           PORT_GENERIC_GROUP + 22
#define DEDICATED_ARGUMENTS	PORT_GENERIC_GROUP + 23
#define RESOLVE_PROTOCOL	PORT_GENERIC_GROUP + 24
#define PROXY_ARP_ENABLED	PORT_GENERIC_GROUP + 25
#define SILENT_MODE_ENABLE	PORT_GENERIC_GROUP + 26

#define PORT_FLOWCONTROL_GROUP  PORT_GENERIC_GROUP + 27

#define CONTROL_LINE_USE        PORT_FLOWCONTROL_GROUP
#define INPUT_FLOW_CONTROL      PORT_FLOWCONTROL_GROUP + 1
#define INPUT_START_CHAR        PORT_FLOWCONTROL_GROUP + 2
#define INPUT_STOP_CHAR         PORT_FLOWCONTROL_GROUP + 3
#define OUTPUT_FLOW_CONTROL     PORT_FLOWCONTROL_GROUP + 4
#define OUTPUT_START_CHAR       PORT_FLOWCONTROL_GROUP + 5
#define OUTPUT_STOP_CHAR        PORT_FLOWCONTROL_GROUP + 6
#define DUI_FLOW                PORT_FLOWCONTROL_GROUP + 7
#define DUI_IFLOW               PORT_FLOWCONTROL_GROUP + 8
#define DUI_OFLOW               PORT_FLOWCONTROL_GROUP + 9
#define INPUT_BUFFER_SIZE       PORT_FLOWCONTROL_GROUP + 10
#define BIDIREC_MODEM           PORT_FLOWCONTROL_GROUP + 11
#define IXANY_FLOW_CONTROL      PORT_FLOWCONTROL_GROUP + 12
#define NEED_DSR                PORT_FLOWCONTROL_GROUP + 13
#define V120_MRU		        PORT_FLOWCONTROL_GROUP + 14

#define PORT_TIMER_GROUP        PORT_FLOWCONTROL_GROUP + 15

#define FORWARDING_TIMER        PORT_TIMER_GROUP
#define FORWARD_COUNT           PORT_TIMER_GROUP + 1
#define INACTIVITY_CLI          PORT_TIMER_GROUP + 2
#define INACTIVITY_TIMER        PORT_TIMER_GROUP + 3
#define INPUT_ACT               PORT_TIMER_GROUP + 4
#define OUTPUT_ACT              PORT_TIMER_GROUP + 5
#define RESET_IDLE              PORT_TIMER_GROUP + 6
#define LONG_BREAK              PORT_TIMER_GROUP + 7
#define SHORT_BREAK             PORT_TIMER_GROUP + 8
#define AUTODETECT_TIMEOUT      PORT_TIMER_GROUP + 9

#define PORT_SECURITY_GROUP     PORT_TIMER_GROUP + 10

#define PORT_NAME               PORT_SECURITY_GROUP
#define CLI_SECURITY            PORT_SECURITY_GROUP + 1
#define CONNECT_SECURITY        PORT_SECURITY_GROUP + 2
#define PORT_SERVER_SECURITY    PORT_SECURITY_GROUP + 3
#define PORT_PASSWORD           PORT_SECURITY_GROUP + 4
#define IPSO_CLASS              PORT_SECURITY_GROUP + 5
#define IPX_SECURITY            PORT_SECURITY_GROUP + 6

#define PORT_LOGINUSR_GROUP     PORT_SECURITY_GROUP + 7

#define DUI_PASSWD              PORT_LOGINUSR_GROUP
#define DUI_INACT_TIMEOUT       PORT_LOGINUSR_GROUP + 1

#define PORT_CHAR_GROUP         PORT_LOGINUSR_GROUP + 2

#define ATTN_CHAR               PORT_CHAR_GROUP
#define INPUT_ECHO              PORT_CHAR_GROUP + 1
#define TELNET_ESC              PORT_CHAR_GROUP + 2
#define TELNET_CRLF             PORT_CHAR_GROUP + 3
#define MAP_U_TO_L              PORT_CHAR_GROUP + 4
#define MAP_L_TO_U_PORT         PORT_CHAR_GROUP + 5
#define CHAR_ERASING            PORT_CHAR_GROUP + 6
#define LINE_ERASING            PORT_CHAR_GROUP + 7
#define PORT_HARDWARE_TABS      PORT_CHAR_GROUP + 8
#define ERASE_CHAR              PORT_CHAR_GROUP + 9
#define ERASE_WORD              PORT_CHAR_GROUP + 10
#define ERASE_LINE              PORT_CHAR_GROUP + 11
#define REDISPLAY_LINE          PORT_CHAR_GROUP + 12
#define TOGGLE_OUTPUT           PORT_CHAR_GROUP + 13
#define NEWLINE_TERMINAL        PORT_CHAR_GROUP + 14
#define FORWARD_KEY		PORT_CHAR_GROUP + 15
#define BACKWARD_KEY		PORT_CHAR_GROUP + 16

#define PORT_NETADDR_GROUP      PORT_CHAR_GROUP + 17

#define P_SLIP_LOCALADDR        PORT_NETADDR_GROUP
#define P_SLIP_REMOTEADDR       PORT_NETADDR_GROUP + 1
#define P_PPP_DIALUP_ADDR       PORT_NETADDR_GROUP + 2
#define P_SLIP_METRIC           PORT_NETADDR_GROUP + 3
#define P_SLIP_SECURE           PORT_NETADDR_GROUP + 4
#define P_SLIP_NET_DEMAND_DIAL  PORT_NETADDR_GROUP + 5
#define P_SLIP_NET_INACTIVITY   PORT_NETADDR_GROUP + 6
#define P_SLIP_NET_PHONE        PORT_NETADDR_GROUP + 7
#define P_SLIP_DO_COMP          PORT_NETADDR_GROUP + 8
#define P_SLIP_EN_COMP          PORT_NETADDR_GROUP + 9
#define	P_SLIP_NET_INACT_UNITS	PORT_NETADDR_GROUP + 10
#define	P_PPP_ADDR_ORIGIN	PORT_NETADDR_GROUP + 11

#define PORT_SLIP_GROUP         PORT_NETADDR_GROUP + 12

#define P_SLIP_NETMASK          PORT_SLIP_GROUP
#define P_SLIP_LOADUMP_HOST     PORT_SLIP_GROUP + 1
#define P_SLIP_ALLOW_DUMP       PORT_SLIP_GROUP + 2
#define P_SLIP_LARGE_MTU        PORT_SLIP_GROUP + 3
#define P_SLIP_NO_ICMP          PORT_SLIP_GROUP + 4
#define P_SLIP_FASTQ            PORT_SLIP_GROUP + 5

#define PORT_PPP_GROUP          PORT_SLIP_GROUP + 6

#define P_PPP_MRU               PORT_PPP_GROUP
#define P_PPP_ACM               PORT_PPP_GROUP + 1
#define P_PPP_SECURITY          PORT_PPP_GROUP + 2
#define P_PPP_UNAMERMT          PORT_PPP_GROUP + 3
#define P_PPP_PWORDRMT          PORT_PPP_GROUP + 4
#define P_PPP_NCP               PORT_PPP_GROUP + 5
#define P_PPP_IPX_NETNUM	PORT_PPP_GROUP + 6
#define P_PPP_IPX_NODENUM	PORT_PPP_GROUP + 7
#define P_PPP_SEC_AUTO          PORT_PPP_GROUP + 8
#define P_MP_MRRU               PORT_PPP_GROUP + 9
#define P_MP_ENDP_OPT           PORT_PPP_GROUP + 10
#define P_MP_ENDP_VAL           PORT_PPP_GROUP + 11
#define P_IPCP_UNNUMBERED       PORT_PPP_GROUP + 12
#define P_DROP_FIRST_REQ	PORT_PPP_GROUP + 13

#define PORT_ARAP_GROUP         PORT_PPP_GROUP + 14
#define P_ARAP_AT_GUEST         PORT_ARAP_GROUP
#define P_ARAP_AT_NODEID        PORT_ARAP_GROUP + 1
#define P_ARAP_AT_SECURITY      PORT_ARAP_GROUP + 2
#define P_ARAP_V42BIS           PORT_ARAP_GROUP + 3

#define PORT_TN3270_GROUP       PORT_ARAP_GROUP + 4
#define P_TN3270_PRINTER_HOST   PORT_TN3270_GROUP
#define P_TN3270_PRINTER_NAME   PORT_TN3270_GROUP + 1

#define AUTHORIZED_GROUPS       PORT_TN3270_GROUP + 2
#define LATB_ENABLE             AUTHORIZED_GROUPS + 1
#define PORT_MULTISESS          AUTHORIZED_GROUPS + 2

#ifdef ns16000
#define PORT_LAT_GROUP          LATB_ENABLE
#else
#define PORT_LAT_GROUP          AUTHORIZED_GROUPS
#endif

#define PORT_MX_GROUP           AUTHORIZED_GROUPS + 3

#define DEFAULT_HPCL            PORT_MX_GROUP

#define PORT_GENERIC            PORT_MX_GROUP + 1
#define PORT_FLOW               PORT_MX_GROUP + 2
#define PORT_SECURITY           PORT_MX_GROUP + 3
#define PORT_LOGIN              PORT_MX_GROUP + 4
#define PORT_EDITING            PORT_MX_GROUP + 5
#define PORT_SERIAL             PORT_MX_GROUP + 6
#define PORT_SLIP               PORT_MX_GROUP + 7
#define PORT_PPP                PORT_MX_GROUP + 8
#define PORT_LAT                PORT_MX_GROUP + 9
#define PORT_TIMERS             PORT_MX_GROUP + 10
#define PORT_APPLETALK          PORT_MX_GROUP + 11
#define PORT_TN3270             PORT_MX_GROUP + 12
#define PORT_SYNC		PORT_MX_GROUP + 13

#define ALL_PORTP               PORT_MX_GROUP + 14
#define NPORTP                  PORT_MX_GROUP + 15

/*
#define LOGIN_TIMER		11
#define DO_LEAP_PROTOCOL	43
#define P_PPP_ACTOPEN		77
*/

/********************************************************************
 ********************************************************************
 **   NOTE:
 **
 **     IF YOU ALTER THE ORDER OF THESE PARAMETERS YOU MUST CHANGE
 **     THE ORDER OF THE ENTRIES IN THE TABLE t1p_table  BELOW
 **
 ********************************************************************
 */

#if NT1_ENG > 0
/* channelized T1 card parameters */
#define T1_GENERIC_GROUP     0

#define T1_LOG_ALARM_D               T1_GENERIC_GROUP
#define T1_BYPASS_D                  T1_GENERIC_GROUP + 1 
#define T1_INFO_D                    T1_GENERIC_GROUP + 2 
#define T1_TNI_CLOCK_D               T1_GENERIC_GROUP + 3 
#define T1_TNI_LINE_BUILDOUT_D       T1_GENERIC_GROUP + 4 
#define T1_TNI_ONES_DENSITY_D        T1_GENERIC_GROUP + 5 
#define T1_TNI_FRAMING_D             T1_GENERIC_GROUP + 6 
#define T1_TNI_LINE_CODE_D           T1_GENERIC_GROUP + 7 
#define T1_TNI_ESF_FDL_D             T1_GENERIC_GROUP + 8 
#define T1_TNI_CIRCUIT_ID_D          T1_GENERIC_GROUP + 9 
#define T1_TDI_FRAMING_D             T1_GENERIC_GROUP + 10
#define T1_TDI_LINE_CODE_D           T1_GENERIC_GROUP + 11
#define T1_TDI_DISTANCE_D            T1_GENERIC_GROUP + 12
#define T1_SWITCH_TYPE_D             T1_GENERIC_GROUP + 13
#define T1_DS0_MAP                   T1_GENERIC_GROUP + 14

#define T1_MAP_D                     T1_DS0_MAP + 0
#define T1_DS0_SIGPROTO              T1_DS0_MAP + 1

#define T1_SIGPROTO_D                T1_DS0_SIGPROTO + 0

#ifdef OBSOLETE_T1_PARAM
#define T1_DS0_PROTOARG       T1_DS0_SIGPROTO + 1
#define T1_PROTO_ARG_D               T1_DS0_PROTOARG + 0
#define T1_DS0_RING           T1_DS0_PROTOARG + 1
#else
#define T1_DS0_RING           T1_DS0_SIGPROTO + 1
#endif /*OBSOLETE_T1_PARAM*/
#define T1_RING_D                    T1_DS0_RING + 0

#define ALL_T1DS0P                   T1_DS0_RING + 1
#define ALL_T1P                      T1_DS0_RING + 2
#define NT1P                         T1_DS0_RING + 3

#ifndef CMD_H_PARAMS_ONLY
char *t1_all_params[NT1P + 1];
char *t1_ds0_params[NT1P + 1];
#endif /* CMD_H_PARAMS_ONLY */
#endif /* NT1_ENG */

/********************************************************************
 ********************************************************************
 **   NOTE:
 **
 **     IF YOU ALTER THE ORDER OF THESE PARAMETERS YOU MUST CHANGE
 **     THE ORDER OF THE ENTRIES IN THE TABLE prip_table  BELOW
 **
 ********************************************************************
 */

#if NPRI > 0 
#define WAN_GENERIC_GROUP 0
#define WAN_SWITCH_TYPE_D	WAN_GENERIC_GROUP
#define WAN_BUILDOUT_D		WAN_GENERIC_GROUP + 1
#define WAN_FDLTYPE_D		WAN_GENERIC_GROUP + 2
#define WAN_NUM_BCHAN_D		WAN_GENERIC_GROUP + 3
#define WAN_DISTANCE_D		WAN_GENERIC_GROUP + 4
#define WAN_ANALOG_D		WAN_GENERIC_GROUP + 5
#define WAN_FRAMING_D           WAN_GENERIC_GROUP + 6
#define WAN_LINECODE_D          WAN_GENERIC_GROUP + 7
#define WAN_DNIS_D              WAN_GENERIC_GROUP + 8
#define WAN_ANI_D               WAN_GENERIC_GROUP + 9
#define WAN_DIGITWIDTH_D        WAN_GENERIC_GROUP + 10
#define WAN_INTERDIGIT_D        WAN_GENERIC_GROUP + 11
#define WAN_DIGITPOWER_1_D      WAN_GENERIC_GROUP + 12
#define WAN_DIGITPOWER_2_D      WAN_GENERIC_GROUP + 13
#define WAN_BUSYSIGTYPE_D	WAN_GENERIC_GROUP + 14
#define WAN_LOCALPHONENO_D	WAN_GENERIC_GROUP + 15
#define WAN_AUTOBUSYENA_D	WAN_GENERIC_GROUP + 16
#define WAN_CHANNEL_GROUP       WAN_GENERIC_GROUP + 17
#define WAN_REMOTE_ADDRESS_D	WAN_CHANNEL_GROUP
#define WAN_IPX_NETWORK_D	WAN_CHANNEL_GROUP + 1
#define WAN_IPX_NODE_D		WAN_CHANNEL_GROUP + 2
#define WAN_SIGPROTO_D          WAN_CHANNEL_GROUP + 3
#define WAN_RINGBACK_D          WAN_CHANNEL_GROUP + 4
#define ALL_WANCHANP            WAN_CHANNEL_GROUP + 5
#define ALL_WANP                ALL_WANCHANP + 1
#define NWANP			ALL_WANCHANP + 2


#ifndef CMD_H_PARAMS_ONLY
char *wan_all_params[NWANP + 1];
char *wan_chan_params[NWANP + 1];
#endif /* CMD_H_PARAMS_ONLY */

#endif /* NPRI */

/********************************************************************
 ********************************************************************
 **   NOTE:
 **
 **     IF YOU ALTER THE ORDER OF THESE PARAMETERS YOU MUST CHANGE
 **     THE ORDER OF THE ENTRIES IN THE TABLE modemp_table  BELOW
 **
 ********************************************************************
 */

#if NPRI > 0
#define MODEM_GENERIC_GROUP 0

#define MODEM_BUSY_OUT_D	MODEM_GENERIC_GROUP

#define ALL_MODEMP		MODEM_BUSY_OUT_D + 1
#define NMODEMP			ALL_MODEMP + 1

#ifndef CMD_H_PARAMS_ONLY
char *modem_params[NMODEMP + 1];
#endif /* CMD_H_PARAMS_ONLY */

#endif /* NPRI */

/********************************************************************
 ********************************************************************
 **   NOTE:
 **
 **	IF YOU ALTER THE ORDER OF THESE PARAMETERS YOU MUST CHANGE
 **	THE ORDER OF THE ENTRIES IN THE TABLE interfacep_table  BELOW
 **
 ********************************************************************
 */

/* RIP per interface parameter */
#define INTERFACE_RIP_GROUP	0

#define RIP_SEND_VERSION        INTERFACE_RIP_GROUP
#define RIP_RECV_VERSION        INTERFACE_RIP_GROUP + 1
#define RIP_HORIZON             INTERFACE_RIP_GROUP + 2
#define RIP_DEFAULT_ROUTE       INTERFACE_RIP_GROUP + 3
#define RIP_NEXT_HOP            INTERFACE_RIP_GROUP + 4
#define RIP_SUB_ADVERTISE       INTERFACE_RIP_GROUP + 5
#define RIP_SUB_ACCEPT          INTERFACE_RIP_GROUP + 6
#define RIP_ADVERTISE           INTERFACE_RIP_GROUP + 7
#define RIP_ACCEPT              INTERFACE_RIP_GROUP + 8
#define ALL_INTERFACEP          INTERFACE_RIP_GROUP + 9
#define NINTERFACEP             INTERFACE_RIP_GROUP + 10

#ifndef CMD_H_PARAMS_ONLY
char *port_params[NPORTP + 1];
char *interface_params[NINTERFACEP + 1];
#endif /* CMD_H_PARAMS_ONLY */

#define MAP_L_TO_U_PRINT 	0
#define PRINTER_WIDTH		1
#define PRINT_HARDWARE_TABS	2
#define PRINTER_INTERFACE	3
#define PRINTER_SPD		4
#define PRINTER_CR_CRLF		5
#define TCPP_KEEPALIVE		6

#define ALL_PRINTER		7
#define NPRINTP			8
#define	NRESET			12

#ifndef CMD_H_PARAMS_ONLY
char *printer_params[NPRINTP + 1];


char *reset_params[NRESET + 1] =
{
	"all",
	"security",
	"motd",
	"nameserver",
	"macros",
	"lat",
	"modem_table",
	"dialout",
	"syslog",
	"session",
	"dnis",
	"filters",
	(char *)0
};

#if NT1_ENG > 0
#define	N_T1_RESET		3
char *reset_t1_params[N_T1_RESET + 1] =
{
	"esf",
	"hard",
	"soft",
	(char *)0
};
#endif

#if NDIGIMODEM > 0
char *reset_modem_params[] = {
  "hard",
  "soft",
  (char *)0
};
#endif
#endif /* CMD_H_PARAMS_ONLY */


/*
 * These defines are used to exclude parameters from local adm.
 * To exclude a param have the MACHINE defines convert the
 * category into the VOID_CAT.  Use the machine version masks
 * to exclude the parameter from NA.
 */

#if (NRDRP > 0)
#define RDRP(x) (x)
#else
#define RDRP(x) (VOID_CAT)
#endif

#if (NPRONET_FOUR > 0)
#define PRONET_FOUR(x) (x)
#else
#define PRONET_FOUR(x) (VOID_CAT)
#endif

#if (NARAP > 0)
#define ARAP(x) (x)
#else
#define ARAP(x)	(VOID_CAT)
#endif

#if (NPPP > 0)
#define PPP(x) (x)
#else
#define PPP(x)	(VOID_CAT)
#endif

#if (NSLIP > 0)
#define SLIP(x) (x)
#else
#define SLIP(x) (VOID_CAT)
#endif

/* Used for things that are *NOT* in the ELS */
#ifdef MICRO_ELS
#define NO_ELS(x) (VOID_CAT)
#else
#define NO_ELS(x) (x)
#endif

#if NLAT > 0
#define LAT(x)	(x)

#define LAT_NO_A2(x)	(x)

#else
#define LAT(x)	(VOID_CAT)
#define LAT_NO_A2(x)	(VOID_CAT)
#endif /* NLAT > 0 */

#if NDEC > 0
#define DEC(x)  (x)
#else
#define DEC(x)  (VOID_CAT)
#endif

#if NDPTG > 0
#define DPTG(x)	(x)
#else
#define DPTG(x)	(VOID_CAT)
#endif

#define NO_A2(x) (x)

#if defined(NA)
#define NA_ONLY(x)	(x)
#else
#define NA_ONLY(x)	(VOID_CAT)
#endif

#if defined(MICRO_ANNEX) || defined(NA)
#define MICRO_ONLY(x) (x)
#else
#define MICRO_ONLY(x) (VOID_CAT)
#endif

#if NTFTP_PROTO > 0
#define TFTP_PROTO(x) (x)
#else
#define TFTP_PROTO(x) (VOID_CAT)
#endif

#ifdef ANNEX_II
#define STRING_ANXII	STRING_P
#else
#define STRING_ANXII	STRING_P_100
#endif

#if NCMUSNMP > 0
#define SNMP(x)		(x)
#else
#define SNMP(x)		(VOID_CAT)
#endif

#if NKERB > 0
#define KERB(x)		(x)
#else
#define KERB(x)		(VOID_CAT)
#endif

#if NPRI > 0
#ifdef NA
#define XPRI(x)		(x)
#else
#define XPRI(x)		(VOID_CAT)
#endif
#define PRIO(x)		(x)
#else
#define XPRI(x)		(x)
#define PRIO(x)		(VOID_CAT)
#endif

#if NMLPPP > 0
#define MLP(x)		(x)
#else
#define MLP(x)		(VOID_CAT)
#endif

/**************************************************************
 **************************************************************
 **  NOTE:
 **	THE ORDER OF THE ENTRIES IN THIS TABLE IS DEFINED BY
 **	THE NUMERIC ORDER OF THE PORT PARAMETER DEFINES ABOVE.
 **************************************************************
 */
#ifndef CMD_H_PARAMS_ONLY
parameter_table portp_table[] =
{
{PORT_MODE,	      DEV_CAT,  DEV_MODE,		P_GENERIC_CAT,CARDINAL_P, CNV_PM
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{LOCATION,		DEV_CAT,  DEV_LOCATION,		P_GENERIC_CAT,STRING_P,   CNV_STRING
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{PORT_TYPE,		XPRI(DEV_CAT),  DEV_LTYPE,	P_GENERIC_CAT,CARDINAL_P, CNV_PT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{TERM_VAR,		DEV_CAT,  DEV_TERM,		P_GENERIC_CAT,STRING_P,   CNV_STRING
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{PORT_PROMPT,		EDIT_CAT, EDIT_PROMPT,		P_GENERIC_CAT,STRING_P,   CNV_PROMPT
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{USER_INTERFACE, EDIT_CAT, EDIT_USER_INTF, P_GENERIC_CAT, CARDINAL_P, CNV_USER_INTF
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{PORT_SPEED,		XPRI(INTF_CAT), INTER_IBAUD,		P_GENERIC_CAT,CARDINAL_P, CNV_PS
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{PORT_AUTOBAUD, XPRI(INTF_CAT), INTER_ABAUD, P_GENERIC_CAT, BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, 0 }
#endif
},
{BITS_PER_CHAR,		INTF_CAT, INTER_BCHAR,		P_GENERIC_CAT,CARDINAL_P, CNV_BPC
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{STOP_BITS,		INTF_CAT, INTER_STOPB,		P_GENERIC_CAT,CARDINAL_P, CNV_SB
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{PARITY,		INTF_CAT, INTER_PCHECK,		P_GENERIC_CAT,CARDINAL_P, CNV_P
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{MAX_SESSIONS,		DEV_CAT,  DEV_SESSIONS,		P_GENERIC_CAT,CARDINAL_P, CNV_MS
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{BROADCAST_ON,		DEV_CAT,  DEV_NBROADCAST,	P_GENERIC_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{BROADCAST_DIR,		DEV_CAT,  DEV_RBCAST, 	P_GENERIC_CAT,BOOLEAN_P, CNV_RBCAST
#ifdef NA
     , { V_5_N, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{IMASK_7BITS,		INTF_CAT, INTER_IMASK7,		P_GENERIC_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{CLI_IMASK7,		DEV_CAT, DEV_CLI_IMASK7,	P_GENERIC_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_6_N, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{PS_HISTORY_BUFF, NA_ONLY(DEV_CAT),DEV_PS_HISTORY_BUFF, P_GENERIC_CAT,CARDINAL_P, CNV_HIST_BUFF
#ifdef NA
     , { 0, 0, 0, V_7_13, V_7_13, 0, V_7_1_13, 0 }
#endif
},
{BANNER, DEV_CAT, DEV_BANNER, P_GENERIC_CAT, CARDINAL_P, CNV_BANNER
#ifdef NA
	, { 0, V_7_N, V_7_N, V_7_N, V_7_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TCPA_KEEPALIVE, NO_A2(DEV_CAT), DEV_KEEPALIVE, P_GENERIC_CAT, CARDINAL_P, CNV_BYTE_ZERO_OK
#ifdef NA
	, { 0, 0, 0, V_7_1_N, V_7_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{DEDICATED_ADDRESS,	XPRI(DEV_CAT),  DEV_DEDICATED_ADDR,  P_GENERIC_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{DEDICATED_PORT,	XPRI(DEV_CAT),  DEV_DEDICATED_PORT,	P_GENERIC_CAT,CARDINAL_P, CNV_DPORT
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{MODEM_VAR, XPRI(NO_ELS(DEV_CAT)), DEV_MODEM_VAR, P_GENERIC_CAT,STRING_P, CNV_STRING_NOSPACE
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, 0 }
#endif
},
{DEF_SESS_MODE, DEV_CAT,   DEV_SESS_MODE,  P_GENERIC_CAT, CARDINAL_P,     CNV_SESS_MODE
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{DEDICATED_ARGUMENTS,	DEV_CAT,  DEV_DEDICATED_ARGUMENTS,	P_GENERIC_CAT,STRING_P_100, CNV_STRING_100
#ifdef NA
     , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, 0, V_PRIMATE_N }
#endif
},
{RESOLVE_PROTOCOL,	DEV_CAT,  DEV_RESOLVE_PROTOCOL,	P_GENERIC_CAT, CARDINAL_P, CNV_RESOLVE
#ifdef NA
     , { 0, 0, 0, V_DENALI_N, V_DENALI_N, 0, 0, V_PRIMATE_N }
#endif
},
{PROXY_ARP_ENABLED,	DEV_CAT,  DEV_PROXY_ARP_ENABLED, P_GENERIC_CAT, BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{SILENT_MODE_ENABLE,	DEV_CAT,  DEV_SILENT_MODE_ENABLE, P_GENERIC_CAT, BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{CONTROL_LINE_USE,      XPRI(INTF_CAT), INTER_MODEM,	P_FLOW_CAT,CARDINAL_P, CNV_MC
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{INPUT_FLOW_CONTROL,	DEV_CAT,  DEV_IFLOW,		P_FLOW_CAT,CARDINAL_P, CNV_FC
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{INPUT_START_CHAR,	DEV_CAT,  DEV_ISTARTC,		P_FLOW_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{INPUT_STOP_CHAR,	DEV_CAT,  DEV_ISTOPC,		P_FLOW_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{OUTPUT_FLOW_CONTROL,	DEV_CAT,  DEV_OFLOW,		P_FLOW_CAT,CARDINAL_P, CNV_FC
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{OUTPUT_START_CHAR,	DEV_CAT,  DEV_OSTARTC,		P_FLOW_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{OUTPUT_STOP_CHAR,	DEV_CAT,  DEV_OSTOPC,		P_FLOW_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{DUI_FLOW,      VOID_CAT,  DEV_DFLOW,   0, CARDINAL_P, CNV_FC
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{DUI_IFLOW,     VOID_CAT,  DEV_DIFLOW,  0, BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{DUI_OFLOW,     VOID_CAT,  DEV_DOFLOW,  0, BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{INPUT_BUFFER_SIZE,  NA_ONLY(DEV_CAT),  DEV_ISIZE,		P_FLOW_CAT,CARDINAL_P, CNV_BYTE
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_BB, V_6_1_BB, 0, V_7_1_BB, 0 }
#endif
},
{BIDIREC_MODEM,		NA_ONLY(DEV_CAT),  DEV_CARRIER_OVERRIDE,	P_FLOW_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
	/* leave the annex1,2,2e to N... they will never be asked */
     , { V_1_N, V_1_N, V_5_N, V_6_BB, V_6_1_BB, 0, V_7_1_BB, 0 }
#endif
},
{IXANY_FLOW_CONTROL,	DEV_CAT,  DEV_IXANY,		P_FLOW_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_3_N, V_3_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{NEED_DSR,	NO_A2(DEV_CAT), DEV_NEED_DSR,   	P_FLOW_CAT,BOOLEAN_P, CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_6_1_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{V120_MRU,	PRIO(DEV_CAT),DEV_V120_MRU, P_FLOW_CAT, CARDINAL_P, CNV_V120_MRU
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, V_PRIMATE_N }
#endif /* NA */
},
{FORWARDING_TIMER,	DEV_CAT,  DEV_TIMOUT,		P_TIMERS_CAT,CARDINAL_P, CNV_INT5OFF
#ifdef NA
     , { V_3_N, V_3_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{FORWARD_COUNT,		DEV_CAT, DEV_FORWARD_COUNT,    	P_TIMERS_CAT,CARDINAL_P, CNV_INT
#ifdef NA
     , { V_6_N, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{INACTIVITY_CLI,	DEV_CAT,  DEV_INACTCLI,		P_TIMERS_CAT,CARDINAL_P,CNV_INACTCLI
#ifdef NA
     , { V_4_1_N, V_4_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{INACTIVITY_TIMER,	DEV_CAT,  DEV_INACTIVE,		P_TIMERS_CAT,CARDINAL_P, CNV_INT0OFF
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{INPUT_ACT,		DEV_CAT,  DEV_INPUT_ACT,	P_TIMERS_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{OUTPUT_ACT,		DEV_CAT,  DEV_OUTPUT_ACT,	P_TIMERS_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{RESET_IDLE,		DEV_CAT,  DEV_RESET_IDLE,	P_TIMERS_CAT,BOOLEAN_P,  CNV_RESET_IDLE
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{LONG_BREAK,		DEV_CAT,  DEV_NLBRK,		P_TIMERS_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{SHORT_BREAK,		DEV_CAT,  DEV_NSBRK,		P_TIMERS_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{AUTODETECT_TIMEOUT,    DEV_CAT,  DEV_AUTOD_TIMEOUT,    P_TIMERS_CAT, CARDINAL_P, CNV_TIMER /*CNV_INTOFF before */
#ifdef NA
     , { 0, 0, 0, V_PRIMATE_N, V_PRIMATE_N, 0, 0, V_PRIMATE_N }
#endif
},
{PORT_NAME,		DEV_CAT,  DEV_NAME,		P_SECURITY_CAT, STRING_P_128,   CNV_STRING_128
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{CLI_SECURITY,NO_ELS(DEV_CAT),  DEV_CLI_SECURITY,  P_SECURITY_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{CONNECT_SECURITY,NO_ELS(DEV_CAT), DEV_CONNECT_SECURITY,  P_SECURITY_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{PORT_SERVER_SECURITY,NO_ELS(DEV_CAT), DEV_PORT_SECURITY, P_SECURITY_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{PORT_PASSWORD,		DEV2_CAT,  DEV2_PORT_PASSWD,	P_SECURITY_CAT,STRING_P,   CNV_STRING
#ifdef NA
     , { 0, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{IPSO_CLASS, DEV_CAT, DEV_IPSO_CLASS, P_SECURITY_CAT, CARDINAL_P, CNV_IPSO_CLASS
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{IPX_SECURITY, DEV_CAT, DEV_IPX_SECURE, P_SECURITY_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{DUI_PASSWD,    DEV_CAT,  DEV_DUI_PASSWD,  P_LOGIN_CAT,  BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{DUI_INACT_TIMEOUT,     DEV_CAT,  DEV_DUI_TIMEOUT, P_LOGIN_CAT, BOOLEAN_P,  CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{
ATTN_CHAR,		DEV_CAT,  DEV_ATTN,		P_EDITING_CAT,STRING_P, CNV_ATTN
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif /* NA */
},
{INPUT_ECHO,		EDIT_CAT, EDIT_INECHO,		P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TELNET_ESC,		EDIT_CAT, EDIT_TESC,		P_EDITING_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TELNET_CRLF,		DEV_CAT, DEV_TELNET_CRLF,	P_EDITING_CAT,BOOLEAN_P, CNV_DFT_N
#ifdef NA
     , { 0, V_6_1_N, V_6_1_N, V_6_1_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{MAP_U_TO_L,		EDIT_CAT, EDIT_IUCLC,		P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{MAP_L_TO_U_PORT,	EDIT_CAT, EDIT_OLCUC,		P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{CHAR_ERASING,		EDIT_CAT, EDIT_OCRTCERA,	P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{LINE_ERASING,		EDIT_CAT, EDIT_OCRTLERA,	P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{PORT_HARDWARE_TABS,	EDIT_CAT, EDIT_OTABS,		P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{ERASE_CHAR,		EDIT_CAT, EDIT_CERA,		P_EDITING_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{ERASE_WORD,		EDIT_CAT, EDIT_WERA,		P_EDITING_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{ERASE_LINE,		EDIT_CAT, EDIT_LERA,		P_EDITING_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{REDISPLAY_LINE,	EDIT_CAT, EDIT_LDISP,		P_EDITING_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TOGGLE_OUTPUT,		EDIT_CAT, EDIT_FLUSH,		P_EDITING_CAT,CARDINAL_P, CNV_PRINT
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{NEWLINE_TERMINAL,	EDIT_CAT, EDIT_NEWLIN,		P_EDITING_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{FORWARD_KEY,	DEV_CAT,  DEV_FORWARD_KEY, P_EDITING_CAT, STRING_P, CNV_ATTN
#ifdef NA
     , { 0, 0, 0, V_DENALI_N, V_DENALI_N, 0, 0, V_PRIMATE_N }
#endif /* NA */
},
{BACKWARD_KEY,	DEV_CAT,  DEV_BACKWARD_KEY, P_EDITING_CAT, STRING_P, CNV_ATTN
#ifdef NA
     , { 0, 0, 0, V_DENALI_N, V_DENALI_N, 0, 0, V_PRIMATE_N }
#endif /* NA */
},
{P_SLIP_LOCALADDR,SLIP(NET_CAT), SLIP_LOCALADDR,     P_SERIAL_CAT,LONG_UNSPEC_P,CNV_NET_Z
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_SLIP_REMOTEADDR, XPRI(SLIP(NET_CAT)), SLIP_REMOTEADDR,    P_SERIAL_CAT,LONG_UNSPEC_P,CNV_NET_Z
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{P_PPP_DIALUP_ADDR,NA_ONLY(NO_ELS(SLIP(NET_CAT))),PPP_DIALUP_ADDR,P_SERIAL_CAT,BOOLEAN_P,CNV_DFT_N
#ifdef NA
     , { 0, V_6_2_RUSHMORE, V_6_2_RUSHMORE, V_6_2_RUSHMORE, V_6_2_RUSHMORE, 0, 0, V_6_2_RUSHMORE }
#endif	/* NA */
},
{P_SLIP_METRIC,	SLIP(NET_CAT), SLIP_METRIC,             P_SERIAL_CAT,CARDINAL_P, CNV_BYTE_ZERO_OK
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_SLIP_SECURE,NO_ELS(SLIP(NET_CAT)),SLIP_SECURE,P_SERIAL_CAT,BOOLEAN_P,CNV_DFT_N
#ifdef NA
     , { 0, V_6_2_N, V_6_2_N, V_6_2_N, V_6_2_N, 0, 0, V_PRIMATE_N }
#endif
},
{P_SLIP_NET_DEMAND_DIAL, NA_ONLY(NO_ELS(SLIP(NET_CAT))),SLIP_DEMAND_DIAL,P_SERIAL_CAT,BOOLEAN_P,CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_8_BB, V_8_BB, 0, 0, 0 }
#endif
},
{P_SLIP_NET_INACTIVITY,NO_ELS(SLIP(NET_CAT)),SLIP_NET_INACTIVITY,P_SERIAL_CAT,CARDINAL_P,CNV_INACTCLI
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{P_SLIP_NET_PHONE,XPRI(NO_ELS(SLIP(NET_CAT))), SLIP_PHONE,   P_SERIAL_CAT,ADM_STRING_P,  CNV_ADM_STRING
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, 0 }
#endif
},
{P_SLIP_DO_COMP,SLIP(NET_CAT), SLIP_DO_COMP,	       	P_SERIAL_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_SLIP_EN_COMP,SLIP(NET_CAT), SLIP_EN_COMP,	       	P_SERIAL_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_SLIP_NET_INACT_UNITS,NO_ELS(SLIP(NET_CAT)),SLIP_NET_INACT_UNITS,P_SERIAL_CAT,BOOLEAN_P,CNV_UNITS
#ifdef NA
     , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, 0, V_PRIMATE_N }
#endif
},
{P_PPP_ADDR_ORIGIN,NO_ELS(SLIP(NET_CAT)),SLIP_ADDR_ORIGIN,P_SERIAL_CAT,CARDINAL_P,CNV_ADDR_ORIGIN
#ifdef NA
     , { 0, 0, 0, V_WASHINGTON_N, V_WASHINGTON_N, 0, 0, V_WASHINGTON_N }
#endif	/* NA */
},
{P_SLIP_NETMASK,SLIP(NET_CAT), SLIP_NETMASK,	      P_SLIP_CAT,LONG_UNSPEC_P,CNV_NET_Z
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_SLIP_LOADUMP_HOST, NA_ONLY(SLIP(NET_CAT)), SLIP_LOADUMPADDR,   P_SLIP_CAT,LONG_UNSPEC_P,CNV_NET_Z
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{P_SLIP_ALLOW_DUMP, NA_ONLY(SLIP(NET_CAT)), SLIP_NODUMP,       	P_SLIP_CAT,BOOLEAN_P,  CNV_DFT_Y
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, 0 }
#endif
},
{P_SLIP_LARGE_MTU,SLIP(SLIP_CAT), SLIP_LGMTU,	       	P_SLIP_CAT,BOOLEAN_P,  CNV_LG_SML
#ifdef NA
     , { 0, V_6_2_N, V_6_2_N, V_6_2_N, V_6_2_N, 0, V_7_1_N, V_PRIMATE_N }
#endif	/* NA */
},
{P_SLIP_NO_ICMP,SLIP(NET_CAT), SLIP_NO_ICMP,	       	P_SLIP_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_SLIP_FASTQ,	SLIP(NET_CAT), SLIP_FASTQ, P_SLIP_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{P_PPP_MRU, PPP(NET_CAT),  PPP_MRU,         P_PPP_CAT,CARDINAL_P, CNV_MRU
#ifdef NA
	, { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_PPP_ACM, PPP(NET_CAT),  PPP_ACM,         P_PPP_CAT,LONG_CARDINAL_P, CNV_BML
#ifdef NA
	, { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_PPP_SECURITY, PPP(NET_CAT),  PPP_SECURITY,	P_PPP_CAT,CARDINAL_P, CNV_SEC
#ifdef NA
	, { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_PPP_UNAMERMT,        PPP(NET_CAT),  PPP_UNAMERMT,    P_PPP_CAT, STRING_P_128,   CNV_STRING_128
#ifdef NA
	, { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_PPP_PWORDRMT,        PPP(NET_CAT),  PPP_PWORDRMT,	P_PPP_CAT,STRING_P,   CNV_STRING
#ifdef NA
	, { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_PPP_NCP,        PPP(NET_CAT),  PPP_NCP,	P_PPP_CAT,CARDINAL_P,   CNV_PPP_NCP
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_PPP_IPX_NETNUM, PPP(NET_CAT), PPP_IPX_NETNUM, P_PPP_CAT, LONG_CARDINAL_P, CNV_LONG_HEX
#ifdef NA
	, { 0, 0, 0, V_DENALI_N, V_DENALI_N, 0, 0, 0 }
#endif	/* NA */
},
{P_PPP_IPX_NODENUM, PPP(NET_CAT), PPP_IPX_NODENUM, P_PPP_CAT, ENET_ADDR_P, CNV_ENET_ADDR
#ifdef NA
	, { 0, 0, 0, V_DENALI_N, V_DENALI_N, 0, 0, 0 }
#endif	/* NA */
},
{P_PPP_SEC_AUTO,    PPP(NET_CAT),  PPP_SEC_AUTO,   P_PPP_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_PRIMATE_N, V_PRIMATE_N, 0, 0, V_PRIMATE_N }
#endif
},
{P_MP_MRRU, MLP(NET_CAT), MP_MRRU, P_PPP_CAT, CARDINAL_P, CNV_MRRU
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, V_RUSHMORE_N }
#endif  /* NA */
},
{P_MP_ENDP_OPT, MLP(NET_CAT), MP_ENDP_OPT, P_PPP_CAT, CARDINAL_P, CNV_MP_ENDP_OPT
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, V_RUSHMORE_N }
#endif  /* NA */
},
{P_MP_ENDP_VAL, MLP(NET_CAT), MP_ENDP_VAL, P_PPP_CAT, STRING_P, CNV_MP_ENDP_VAL
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, V_RUSHMORE_N }
#endif  /* NA */
},
{P_IPCP_UNNUMBERED, NET_CAT, IPCP_UNNUMBERED, P_PPP_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, V_14_0_N }
#endif  /* NA */
},
{P_DROP_FIRST_REQ, PPP(NET_CAT), DROP_FIRST_REQ, P_PPP_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif  /* NA */
},
{P_ARAP_AT_GUEST,        ARAP(NET_CAT),  ARAP_AT_GUEST,	P_ATALK_CAT,BOOLEAN_P,   CNV_DFT_N
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_ARAP_AT_NODEID,        ARAP(NET_CAT),  ARAP_AT_NODEID,	P_ATALK_CAT,LONG_CARDINAL_P,   CNV_THIS_NET_RANGE
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_ARAP_AT_SECURITY,        ARAP(NET_CAT),  ARAP_AT_SECURITY,	P_ATALK_CAT,BOOLEAN_P,   CNV_DFT_N
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_ARAP_V42BIS,        ARAP(NET_CAT),  ARAP_V42BIS,	P_ATALK_CAT,BOOLEAN_P,   CNV_DFT_Y
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_TN3270_PRINTER_HOST,        DEV_CAT,  TN3270_PRINTER_HOST,P_TN3270_CAT,LONG_UNSPEC_P,   CNV_NET_Z
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{P_TN3270_PRINTER_NAME,        DEV_CAT,  TN3270_PRINTER_NAME,P_TN3270_CAT,STRING_P,   CNV_STRING
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif	/* NA */
},
{AUTHORIZED_GROUPS,LAT_NO_A2(DEV_CAT),LAT_AUTHORIZED_GROUPS,P_LAT_CAT,LAT_GROUP_P, CNV_GROUP_CODE
#ifdef NA
     , { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif
},
{LATB_ENABLE,	LAT(DEV_CAT), DEV_LATB_ENABLE,	P_LAT_CAT,BOOLEAN_P, CNV_DFT_N
#ifdef NA
     , { 0, V_6_2_N, V_6_2_N, V_6_2_N, V_6_2_N, 0, 0, V_PRIMATE_N }
#endif
},
{PORT_MULTISESS,LAT(DEV_CAT),  DEV_MULTISESS,	P_LAT_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_MCK2_N, V_MCK2_N, 0, V_MCK2_N, V_PRIMATE_N }
#endif
},
{DEFAULT_HPCL,	VOID_CAT,  DEV_DEFAULT_HPCL,	0,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_3_8, V_3_8, V_5_8, V_6_8, V_6_1_8, 0, 0, V_PRIMATE_N }
#endif
},

/*
{LOGIN_TIMER,		VOID_CAT,  DEV_LOGINT,		0,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { VS_1, VS_1, VS_1, V_6_1_N, 0, 0, 0, V_PRIMATE_N }
#endif
},
*/

/*
{P_PPP_ACTOPEN,         VOID_CAT,  PPP_ACTOPEN,	0,BOOLEAN_P, CNV_DFT_Y
#ifdef NA
	, { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif
},
*/

{PORT_GENERIC,		GRP_CAT,  P_GENERIC_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_FLOW,		GRP_CAT,  P_FLOW_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_SECURITY,		GRP_CAT,  P_SECURITY_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_LOGIN,		GRP_CAT,  P_LOGIN_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_EDITING,		GRP_CAT,  P_EDITING_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_SERIAL,		GRP_CAT,  P_SERIAL_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_SLIP,		GRP_CAT,  P_SLIP_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_PPP,		GRP_CAT,  P_PPP_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_LAT,		LAT(GRP_CAT),  P_LAT_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_TIMERS,		GRP_CAT,  P_TIMERS_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_APPLETALK,	GRP_CAT,  P_ATALK_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_TN3270,		GRP_CAT,  P_TN3270_CAT,	0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{PORT_SYNC,		GRP_CAT,  P_SYNC_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{ALL_PORTP,		GRP_CAT,  ALL_CAT,		0,0,          0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{-1,			0,	  0,			0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};


/**************************************************************
 **************************************************************
 **  NOTE:
 **	THE ORDER OF THE ENTRIES IN THIS TABLE IS DEFINED BY
 **	THE NUMERIC ORDER OF THE ANNEX PARAMETER DEFINES ABOVE.
 **************************************************************
 */

parameter_table annexp_table[] =
{
{INET_ADDR,	DLA_CAT,	DLA_INETADDR,	B_GENERIC_CAT, LONG_UNSPEC_P,	CNV_NET
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{SUBNET_MASK,	DLA_CAT,	DLA_SUBNET,	B_GENERIC_CAT, LONG_UNSPEC_P,	CNV_NET_Z
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{PREF_LOAD,	DLA_CAT,	DLA_PREF_LOAD,	B_GENERIC_CAT, LONG_UNSPEC_P,	CNV_NET_Z
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{PREF_DUMP,	DLA_CAT,	DLA_PREF_DUMP,	B_GENERIC_CAT, LONG_UNSPEC_P,	CNV_NET_Z
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{LOADSERVER_BCAST,DFE_CAT,      DFE_LOADSVR_BCAST,B_GENERIC_CAT, BOOLEAN_P,    CNV_DFT_Y
#ifdef NA
     , { V_5_N, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{BROAD_ADDR,    DLA_CAT,        DLA_BROAD_ADDR, B_GENERIC_CAT, LONG_UNSPEC_P,  CNV_NET_Z
#ifdef NA
      , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{LOADUMP_GATEWAY,DLA_CAT,       DLA_LOADUMP_GATE,B_GENERIC_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { 0, V_3_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{LOADUMP_SEQUENCE,DLA_CAT,      DLA_LOADUMP_SEQ,B_GENERIC_CAT,LONG_UNSPEC_P,  CNV_SEQ
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{IMAGE_NAME,	DLA_CAT,	DLA_IMAGE,	B_GENERIC_CAT, STRING_ANXII,	CNV_STRING_100
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{MOTD,		NO_ELS(DFE_CAT), DFE_MOTD,	B_GENERIC_CAT, STRING_P,	CNV_STRING
#ifdef NA
     , { V_4_1_N, V_4_1_N, V_5_N, V_6_N, V_6_1_N, VS_1, 0, V_PRIMATE_N }
#endif
},
{CONFIG_FILE,	DFE_CAT,	DFE_CONFIG,	B_GENERIC_CAT, STRING_P,	CNV_STRING
#ifdef NA
     , { 0, V_7_N, V_7_N, V_7_N, V_7_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{AUTH_AGENT,DFE_CAT,	DFE_AGENT,	B_GENERIC_CAT,BOOLEAN_P,	CNV_DFT_Y
#ifdef NA
     , { V_6_N, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{NROUTED,	DFE_CAT,	DFE_NROUTED,	B_GENERIC_CAT,BOOLEAN_P,	CNV_DFT_Y
#ifdef NA
     , { V_4_1_N, V_4_1_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{SERVER_CAP,	DFE_CAT,	DFE_SERVER_CAP,	B_GENERIC_CAT,CARDINAL_P,	CNV_SCAP
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{SELECTED_MODULES, DFE_CAT, DFE_SELECTED_MODULES,   B_GENERIC_CAT,CARDINAL_P, CNV_SELECTEDMODS
#ifdef NA
     , { 0, V_7_N, V_7_N, V_7_N, V_7_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TFTP_DIR_NAME, TFTP_PROTO(DLA_CAT),DLA_TFTP_DIR,B_GENERIC_CAT,STRING_P_100,	CNV_STRING_100
#ifdef NA
     , { 0, 0, 0, V_6_1_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TFTP_DUMP_NAME, TFTP_PROTO(DLA_CAT),	DLA_TFTP_DUMP,	B_GENERIC_CAT,STRING_P_100,	CNV_STRING_100
#ifdef NA
     , { 0, 0, 0, V_6_1_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{IPENCAP_TYPE,	DLA_CAT,	DLA_IPENCAP,	B_GENERIC_CAT,BOOLEAN_P,	CNV_IPENCAP
#ifdef NA
     , { 0, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{RING_PRIORITY,	PRONET_FOUR(DLA_CAT),DLA_RING_PRIORITY,	0,CARDINAL_P, CNV_RNGPRI
#ifdef NA
     , { 0, V_4_1_N, V_5_N, V_6_N, V_6_1_N, 0, 0, 0 }
#endif
},
{IP_FWD_BCAST,NO_A2(DFE_CAT),DFE_FWDBCAST,B_GENERIC_CAT,BOOLEAN_P,CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_7_1_N, V_7_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TCP_KEEPALIVE, NO_A2(DFE_CAT), DFE_KEEPALIVE, B_GENERIC_CAT, CARDINAL_P, CNV_BYTE_ZERO_OK
#ifdef NA
	, { 0, 0, 0, V_7_1_N, V_7_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{OPTION_KEY, DFE_CAT,	DFE_OPTION_KEY,	B_GENERIC_CAT,STRING_P, CNV_STRING
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{ACC_ENTRIES, VOID_CAT, DFE_MODEM_ACC_ENTRIES, B_GENERIC_CAT, CARDINAL_P,
CNV_BYTE
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
#if (defined(ANNEX3) && defined(DEBUG))
{JUMPER_BAY5K, DFE_CAT, DFE_SEG_JUMPER_BAY5K,B_GENERIC_CAT,CARDINAL_P,
CNV_BYTE_ZERO_OK
#else
{JUMPER_BAY5K, VOID_CAT, DFE_SEG_JUMPER_BAY5K, B_GENERIC_CAT, CARDINAL_P,
CNV_BYTE_ZERO_OK
#endif
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{SESSION_LIMIT,     DFE_CAT, DFE_SESSION_LIMIT, B_GENERIC_CAT,
CARDINAL_P, CNV_SESS_LIM
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{OUTPUT_TTL, DFE_CAT, DFE_OUTPUT_TTL, B_GENERIC_CAT, CARDINAL_P,
CNV_BYTE
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
#ifndef NA
{ARPT_TTKILLC, DFE_CAT, DFE_ARPT_TTKILLC , B_GENERIC_CAT, CARDINAL_P, CNV_BYTE
#ifdef NA
	, { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
#endif
{FAIL_TO_CONNECT, DFE_CAT, DFE_FAIL_TO_CONNECT, B_GENERIC_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, V_14_0_N, 0, 0, V_14_0_N }
#endif
},
{BOX_MP_ENABLED, DLA_CAT, DLA_MP_ENABLED, B_GENERIC_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif  /* NA */
},
{PASS_BREAK, DFE_CAT, DFE_PASS_BREAK, B_GENERIC_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_TOGGLE_UNARP, DFE_CAT, DFE_TOGGLE_UNARP, B_GENERIC_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_WASH_2_N, V_WASH_2_N, 0, 0, V_WASH_2_N }
#endif
},
{VCLI_LIMIT, DFE_CAT, DFE_VCLI_LIMIT, B_VCLI_CAT,CARDINAL_P, CNV_VCLILIM
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{CLI_PROMPT_STR, DFE_CAT, DFE_PROMPT, B_VCLI_CAT,STRING_P, CNV_PROMPT
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{VCLI_SEC_ENA, NO_ELS(DFE_CAT), DFE_VCLI_SEC_ENA,B_VCLI_CAT,BOOLEAN_P,	CNV_DFT_N
#ifdef NA
     , { 0, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{VCLI_PASSWORD,	DFE_CAT,	DFE_VCLI_PASSWD,B_VCLI_CAT,STRING_P,	CNV_STRING
#ifdef NA
     , { 0, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{VCLI_INACTIVITY, DFE_CAT,      DFE_VCLI_INACTIV,B_VCLI_CAT,CARDINAL_P, CNV_INT0OFF
#ifdef NA
     , { 0, 0, 0, V_PRIMATE_N, V_PRIMATE_N, 0, 0, V_PRIMATE_N }
#endif
},
{ATTN_KILL_ENABLE, NO_ELS(DFE_CAT), DFE_ATTN_KILL_ENABLE,B_VCLI_CAT,BOOLEAN_P,
CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{NAMESERVER_BCAST,DFE_CAT,	DFE_NAMESVR_BCAST,B_NAMESERVER_CAT,BOOLEAN_P,	CNV_DFT_N
#ifdef NA
     , { V_5_N, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{NRWHOD,	DFE_CAT,	DFE_NRWHOD,	B_NAMESERVER_CAT,BOOLEAN_P,	CNV_DFT_Y
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{PRIMARY_NS_ADDR,DFE_CAT,	DFE_1ST_NS_ADDR,B_NAMESERVER_CAT,LONG_UNSPEC_P,	CNV_NET_Z
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{PRIMARY_NS,	DFE_CAT,	DFE_1ST_NS,	B_NAMESERVER_CAT,CARDINAL_P,	CNV_NS
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{SECONDARY_NS_ADDR,DFE_CAT,	DFE_2ND_NS_ADDR,B_NAMESERVER_CAT,LONG_UNSPEC_P,	CNV_NET_Z
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{SECONDARY_NS,DFE_CAT,DFE_2ND_NS,B_NAMESERVER_CAT,CARDINAL_P,CNV_NS
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{HTABLE_SZ,	DFE_CAT,	DFE_HTABLE_SZ,	B_NAMESERVER_CAT,CARDINAL_P,	CNV_HT
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{NMIN_UNIQUE,	DFE_CAT,	DFE_NMIN_UNIQUE,B_NAMESERVER_CAT,BOOLEAN_P,	CNV_DFT_Y
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{PRIMARY_NBNS_ADDR,DFE_CAT, DFE_1ST_NBNS_ADDR,B_NAMESERVER_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{SECONDARY_NBNS_ADDR,DFE_CAT, DFE_2ND_NBNS_ADDR,B_NAMESERVER_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{NAMESERVER_OVERRIDE,DFE_CAT, DFE_NS_OVERRIDE,B_NAMESERVER_CAT,BOOLEAN_P,
CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{ENABLE_SECURITY,DFE_CAT,	DFE_SECURE,	B_SECURITY_CAT,CARDINAL_P,	CNV_DFT_N
#ifdef NA
     , { V_3_N, V_3_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{SECURSERVER_BCAST,NO_ELS(DFE_CAT),DFE_SECRSVR_BCAST,B_SECURITY_CAT,BOOLEAN_P,	CNV_DFT_Y
#ifdef NA
     , { V_5_N, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{PREF_SECURE_1,	NO_ELS(DFE_CAT), DFE_PREF1_SECURE,B_SECURITY_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{PREF_SECURE_2,	NO_ELS(DFE_CAT), DFE_PREF2_SECURE,B_SECURITY_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { V_5_N, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{NET_TURNAROUND, NO_ELS(DFE_CAT), DFE_NET_TURNAROUND,B_SECURITY_CAT,CARDINAL_P,	CNV_NET_TURN
#ifdef NA
     , { V_3_N, V_3_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{LOOSE_SOURCE_RT, NO_A2(DFE_CAT), DFE_LOOSE_SOURCE_RT,B_SECURITY_CAT,BOOLEAN_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_7_1_N, V_7_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{ACP_KEY, NO_ELS(DFE_CAT), DFE_ACP_KEY,	B_SECURITY_CAT,STRING_P, CNV_STRING
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{BOX_PASSWORD,	DFE_CAT,	DFE_PASSWORD,	B_SECURITY_CAT,STRING_P,	CNV_STRING
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{LOCK_ENABLE, DFE_CAT, DFE_LOCK_ENABLE, B_SECURITY_CAT, BOOLEAN_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{PASSWD_LIMIT, DFE_CAT, DFE_PASSWD_LIMIT, B_SECURITY_CAT, CARDINAL_P, CNV_PASSLIM
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{CHAP_AUTH_NAME, DFE_CAT, DFE_CHAP_AUTH_NAME, B_SECURITY_CAT, STRING_P, CNV_STRING
#ifdef NA
     , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{MAX_CHAP_CHALL_INT, DFE_CAT, DFE_MAX_CHAP_CHALL_INT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_WASHINGTON_N, V_WASHINGTON_N, 0, 0, V_WASHINGTON_N }
#endif
},
{AUTHENTICATION_PROTOCOL, DFE_CAT, DFE_AUTHENTICATION_PROTOCOL, B_SECURITY_CAT, CARDINAL_P, CNV_AUTH_PROTOCOL
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{ENABLE_RADIUS_ACCT, DFE_CAT, DFE_ENABLE_RADIUS_ACCT, B_SECURITY_CAT, CARDINAL_P, CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{RADIUS_ACCT1_HOST,	NO_ELS(DFE_CAT), DFE_RADIUS_ACCT1_HOST, B_SECURITY_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_ACCT2_HOST,	NO_ELS(DFE_CAT), DFE_RADIUS_ACCT2_HOST, B_SECURITY_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_AUTH_PORT, DFE_CAT, DFE_RADIUS_AUTH_PORT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{RADIUS_AUTH2_PORT, DFE_CAT, DFE_RADIUS_AUTH2_PORT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_ACCT_PORT, DFE_CAT, DFE_RADIUS_ACCT_PORT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{RADIUS_ACCT2_PORT, DFE_CAT, DFE_RADIUS_ACCT2_PORT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_SECRET, DFE_CAT, DFE_RADIUS_SECRET, B_SECURITY_CAT, STRING_P_100, CNV_RADIUS_SECRET
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{RADIUS_AUTH2_SECRET, DFE_CAT, DFE_RADIUS_AUTH2_SECRET, B_SECURITY_CAT, STRING_P_100, CNV_RADIUS_SECRET
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_ACCT1_SECRET, DFE_CAT, DFE_RADIUS_ACCT1_SECRET, B_SECURITY_CAT, STRING_P_100, CNV_RADIUS_SECRET
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_ACCT2_SECRET, DFE_CAT, DFE_RADIUS_ACCT2_SECRET, B_SECURITY_CAT, STRING_P_100, CNV_RADIUS_SECRET
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_TIMEOUT, DFE_CAT, DFE_RADIUS_TIMEOUT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{RADIUS_ACCT_TIMEOUT, DFE_CAT, DFE_RADIUS_ACCT_TIMEOUT, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{RADIUS_RETRIES, DFE_CAT, DFE_RADIUS_RETRIES, B_SECURITY_CAT, CARDINAL_P, CNV_INT
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{RAD_ACCT_LEVEL, DFE_CAT, DFE_RAD_ACCT_LEVEL, B_SECURITY_CAT, CARDINAL_P, CNV_RAD_ACCT_LEVEL
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
#if NPRI > 0
{RAD_PORT_ENCODING, DFE_CAT, DFE_RAD_PORT_ENCODING, B_SECURITY_CAT, CARDINAL_P, CNV_RAD_PORT_ENCODING
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
#else
{RAD_PORT_ENCODING, VOID_CAT, DFE_RAD_PORT_ENCODING, B_SECURITY_CAT, CARDINAL_P, CNV_RAD_PORT_ENCODING
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
#endif
{RADIUS_USER_PROMPT, DFE_CAT, DFE_RADIUS_USER_PROMPT, B_SECURITY_CAT,ADM_STRING_P, CNV_PROMPT_32
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
{RADIUS_PASSWD_PROMPT, DFE_CAT, DFE_RADIUS_PASSWD_PROMPT, B_SECURITY_CAT,ADM_STRING_P, CNV_PROMPT_32
#ifdef NA
     , { 0, 0, 0, V_14_2_N, V_14_2_N, 0, 0, V_14_2_N }
#endif
},
#ifdef NOT_USED
{KERB_SECURITY_ENA, KERB(DFE_CAT), DFE_KERB_SECUREN, B_KERB_CAT,
BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, 0 }
#endif
},
{KERB_HOST, KERB(DFE_CAT), DFE_KERB_HOST, B_KERB_CAT, KERB_HOST_P,
CNV_KERB_HOST
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, 0 }
#endif
},
{TGS_HOST, KERB(DFE_CAT), DFE_TGS_HOST, B_KERB_CAT, KERB_HOST_P,
CNV_KERB_HOST
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, 0 }
#endif
},
{TELNETD_KEY, KERB(DFE_CAT), DFE_TELNETD_KEY, B_KERB_CAT, STRING_P,
CNV_STRING
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, 0 }
#endif
},
{KERBCLK_SKEW, KERB(DFE_CAT), DFE_KERBCLK_SKEW, B_KERB_CAT,
CARDINAL_P, CNV_TIMER
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, 0 }
#endif
},
#endif /* NOT_USED */
{TIMESERVER_BCAST,DFE_CAT,	DFE_TIMESVR_BCAST,B_TIME_CAT,BOOLEAN_P,	CNV_DFT_N
#ifdef NA
     , { V_5_N, V_5_N, V_5_N, V_6_N, V_6_1_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{TZ_DLST,	DFE_CAT,	DFE_TZ_DLST,	B_TIME_CAT,CARDINAL_P,	CNV_DLST
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{TZ_MINUTES,	DFE_CAT,	DFE_TZ_MINUTES,	B_TIME_CAT,CARDINAL_P,	CNV_TZ_MIN
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{TIMESERVER_HOST, NO_A2(DFE_CAT), DFE_TIMESERVE, B_TIME_CAT,LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
	, { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{SYSLOG_MASK,	DFE_CAT,	DFE_SYSLOG_MASK, B_SYSLOG_CAT,CARDINAL_P,	CNV_SYSLOG
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{SYSLOG_FAC,	DFE_CAT,	DFE_SYSLOG_FAC,	B_SYSLOG_CAT,CARDINAL_P,	CNV_SYSFAC
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{SYSLOG_HOST,	DFE_CAT,	DFE_SYSLOG_ADDR, B_SYSLOG_CAT,LONG_UNSPEC_P,	CNV_NET_Z
#ifdef NA
     , { V_4_N, V_4_N, V_5_N, V_6_N, V_6_1_N, VS_1, V_7_1_N, V_PRIMATE_N }
#endif
},
{SYSLOG_PORT,	NO_A2(DFE_CAT),	DFE_SYSLOG_PORT, B_SYSLOG_CAT,CARDINAL_P,	CNV_PORT
#ifdef NA
     , { 0, 0, 0, V_7_N, V_7_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{MOP_PREF_HOST, DLA_CAT, DLA_MOP_HOST, B_MOP_CAT, ENET_ADDR_P, CNV_ENET_ADDR
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{MOP_PASSWD, DFE_CAT,      DFE_MOP_PASSWD, B_MOP_CAT, MOP_PASSWD_P, CNV_MOP_PASSWD
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{LOGIN_PASSWD, DFE_CAT, DFE_LOGIN_PASSWD, B_MOP_CAT, STRING_P, CNV_STRING
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{LOGIN_PROMPT,  DFE_CAT,   DFE_LOGIN_PROMPT, B_MOP_CAT, STRING_P,     CNV_STRING
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{LOGIN_TIMER, DFE_CAT,  DFE_DUI_TIMER, B_MOP_CAT, CARDINAL_P,  CNV_INT0OFF
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{KEY_VALUE, LAT(DFE_CAT),LAT_KEY_VALUE,	B_LAT_CAT,STRING_P, CNV_STRING
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{HOST_NUMBER, LAT(LAT_CAT), LAT_HOST_NUMBER, B_LAT_CAT,CARDINAL_P, CNV_HOST_NUMBER
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{HOST_NAME, LAT(LAT_CAT),	LAT_HOST_NAME,	B_LAT_CAT,STRING_P, CNV_STRING
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{HOST_ID, LAT(DFE_CAT),	LAT_HOST_ID,	B_LAT_CAT,ADM_STRING_P,	CNV_ADM_STRING
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{QUEUE_MAX, LAT(LAT_CAT),	LAT_QUEUE_MAX,	B_LAT_CAT,CARDINAL_P, CNV_QUEUE_MAX
#ifdef NA
     , { 0, V_7_N, V_7_N, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif
},
{SERVICE_LIMIT, LAT(LAT_CAT),	LAT_SERVICE_LIMIT,	B_LAT_CAT,CARDINAL_P, CNV_SERVICE_LIMIT
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{KA_TIMER,LAT(LAT_CAT),	LAT_KA_TIMER,	B_LAT_CAT,CARDINAL_P,	CNV_KA_TIMER
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{CIRCUIT_TIMER,LAT(LAT_CAT),	LAT_CIRCUIT_TIMER,B_LAT_CAT,CARDINAL_P, CNV_CIRCUIT_TIMER
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{RETRANS_LIMIT,LAT(LAT_CAT),	LAT_RETRANS_LIMIT,	B_LAT_CAT,CARDINAL_P, CNV_RETRANS_LIMIT
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{GROUP_CODE,LAT(LAT_CAT),	LAT_GROUP_CODE,	B_LAT_CAT,LAT_GROUP_P, CNV_GROUP_CODE
#ifdef NA
     , { 0, V_6_N, V_6_N, V_6_N, V_6_1_N, 0, 0, V_PRIMATE_N }
#endif
},
{VCLI_GROUPS,LAT_NO_A2(LAT_CAT),LAT_VCLI_GROUPS,B_LAT_CAT,LAT_GROUP_P, CNV_GROUP_CODE
#ifdef NA
     , { 0, 0, 0, V_7_N, V_7_N, 0, 0, V_PRIMATE_N }
#endif
},
{MULTI_TIMER,LAT(LAT_CAT), LAT_MULTI_TIMER, B_LAT_CAT, CARDINAL_P, CNV_MULTI_TIMER
#ifdef NA
     , { 0, 0, 0, V_7_1_DEC, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{BOX_MULTISESS,LAT(LAT_CAT), LAT_MULTISESS, B_LAT_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
     , { 0, 0, 0, V_MCK2_N, V_MCK2_N, 0, V_MCK2_N, V_PRIMATE_N }
#endif
},
{A_ROUTER, ARAP_CAT,	ARAP_A_ROUTER,	B_ATALK_CAT,ENET_ADDR_P, CNV_ENET_ADDR
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{DEF_ZONE_LIST, ARAP_CAT,	ARAP_DEF_ZONE_LIST, B_ATALK_CAT,STRING_P_100, CNV_DEF_ZONE_LIST
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{NODE_ID, ARAP_CAT,	ARAP_NODE_ID,	B_ATALK_CAT,LONG_CARDINAL_P, CNV_THIS_NET_RANGE
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{ZONE, ARAP_CAT,	ARAP_ZONE,	B_ATALK_CAT,ADM_STRING_P, CNV_ZONE
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
#ifdef NOT_USED
{IP_TTL, RIP_CAT,	RIP_IP_TTL,	B_ROUTER_CAT,CARDINAL_P, CNV_A_BYTE
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{ND_FORWARD, RIP_CAT,	RIP_ND_FORWARD,	B_ROUTER_CAT,CARDINAL_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{ASD_FORWARD, RIP_CAT,	RIP_ASD_FORWARD,	B_ROUTER_CAT,CARDINAL_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{SD_FORWARD, RIP_CAT,	RIP_SD_FORWARD,		B_ROUTER_CAT,CARDINAL_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
#endif /* NOT_USED */
{RIP_AUTH, RIP_CAT,     RIP_RIP_AUTH,   B_ROUTER_CAT, STRING_P, CNV_STRING
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_ROUTERS, RIP_CAT,	RIP_RIP_ROUTERS,	B_ROUTER_CAT,RIP_ROUTERS_P, CNV_BOX_RIP_ROUTERS
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_FORCE_NEWRT, RIP_CAT,      RIP_RIP_FORCE_NEWRT,    B_ROUTER_CAT,
CARDINAL_P, CNV_INT0OFF
#ifdef NA
     , { 0, 0, 0, V_14_1_N, V_14_1_N, 0, 0, V_14_1_N }
#endif
},
{IPX_FILE_SERVER, DLA_CAT, DLA_IPX_FILE_SERVER, B_IPX_CAT,IPX_STRING_P,CNV_IPX_STRING
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{IPX_FRAME_TYPE, DLA_CAT, DLA_IPX_FRAME_TYPE, B_IPX_CAT, CARDINAL_P, CNV_IPX_FMTY
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{IPX_DUMP_UNAME, DLA_CAT, DLA_IPX_DMP_USER_NAME, B_IPX_CAT,IPX_STRING_P,CNV_IPX_STRING
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{IPX_DUMP_PWD, DLA_CAT, DLA_IPX_DMP_PASSWD, B_IPX_CAT, IPX_STRING_P,CNV_IPX_STRING
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{IPX_DUMP_PATH, DLA_CAT, DLA_IPX_DMP_PATH, B_IPX_CAT, STRING_P_100 ,CNV_STRING_100
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{IPX_DO_CHKSUM, DLA_CAT, DLA_IPX_DO_CHECKSUM, B_IPX_CAT,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_BIG_BIRD_N, V_BIG_BIRD_N, 0, V_BIG_BIRD_N, V_PRIMATE_N }
#endif
},
{TMUX_ENA, DFE_CAT, DFE_TMUX_ENA, B_TMUX_CAT, BOOLEAN_P,
CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, V_PRIMATE_N }
#endif
},
{TMUX_MAX_HOST, DFE_CAT, DFE_TMUX_MAX_HOST, B_TMUX_CAT,
CARDINAL_P, CNV_TMAX_HOST
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, V_PRIMATE_N }
#endif
},
{TMUX_DELAY, DFE_CAT, DFE_TMUX_DELAY, B_TMUX_CAT, CARDINAL_P,
CNV_TDELAY
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, V_PRIMATE_N }
#endif
},
{TMUX_MAX_MPX, DFE_CAT, DFE_MAX_MPX, B_TMUX_CAT, CARDINAL_P,
CNV_TMAX_MPX
#ifdef NA
        , { 0, 0, 0, V_POST_BB_N, V_POST_BB_N, 0, V_POST_BB_N, V_PRIMATE_N }
#endif
},
{PREF1_DHCPADDR, DFE_CAT, DFE_PREF1_DHCPADDR, B_DHCP_CAT, LONG_UNSPEC_P,
CNV_NET_Z
#ifdef NA
	, { 0, 0, 0, V_WASHINGTON_N, V_WASHINGTON_N, 0, 0, V_WASHINGTON_N }
#endif
},
{PREF2_DHCPADDR, DFE_CAT, DFE_PREF2_DHCPADDR, B_DHCP_CAT, LONG_UNSPEC_P,
CNV_NET_Z
#ifdef NA
	, { 0, 0, 0, V_WASHINGTON_N, V_WASHINGTON_N, 0, 0, V_WASHINGTON_N }
#endif
},
{DHCP_BCAST, DFE_CAT, DFE_DHCP_BCAST, B_DHCP_CAT, BOOLEAN_P,
CNV_DFT_N
#ifdef NA
	, { 0, 0, 0, V_WASHINGTON_N, V_WASHINGTON_N, 0, 0, V_WASHINGTON_N }
#endif
},
{DHCP_GIADDR, DFE_CAT, DFE_DHCP_GIADDR, B_DHCP_CAT, LONG_UNSPEC_P,
CNV_NET_Z
#ifdef NA
        , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{ALLOW_SNMP_SETS, SNMP(DFE_CAT), DFE_SNMPSET, B_SNMP_CAT,BOOLEAN_P, CNV_DFT_N
#ifdef NA
     , { 0, V_7_N, V_7_N, V_7_N, V_7_N, 0, V_7_1_N, V_PRIMATE_N }
#endif
},
{DEF_TRAPHOST, SNMP(VOID_CAT), DFE_TRAPHOST, B_SNMP_CAT, LONG_UNSPEC_P, CNV_NET_Z
#ifdef NA
        , { 0, 0, 0, V_14_0_N, V_14_0_N, 0, 0, V_14_0_N }
#endif
},
{CALL_BEGIN_ENABLE, SNMP(DFE_CAT), DFE_CALLBEGIN, B_SNMP_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{CALL_END_INCR, SNMP(DFE_CAT), DFE_CALLEND, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{INACTIVITY_TRAP_INCR, SNMP(DFE_CAT), DFE_INACTIVITY_TRAP, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{UNEXPECTED_TRAP_INCR, SNMP(DFE_CAT), DFE_UNEXPECTED_TRAP, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{ BIPOLAR_THRESHOLD, SNMP(DFE_CAT), DFE_BIPOLAR_THRESHOLD, B_SNMP_CAT, CARDINAL_P,   CNV_INT
#ifdef NA
	, { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N}
#endif
},
{ FRAMING_THRESHOLD, SNMP(DFE_CAT), DFE_FRAMING_THRESHOLD, B_SNMP_CAT, CARDINAL_P,   CNV_INT
#ifdef NA
	, { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N}
#endif
},
{ ERRSECS_THRESHOLD, SNMP(DFE_CAT), DFE_ERRSECS_THRESHOLD, B_SNMP_CAT, CARDINAL_P,   CNV_INT
#ifdef NA
	, { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{ DIALLNK_TRAP_EN, SNMP(DFE_CAT), DFE_DIALLNK_TRAP_EN, B_SNMP_CAT, BOOLEAN_P, CNV_DFT_N
#ifdef NA
	, { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{CALL_HISTORY_LIMIT, SNMP(DFE_CAT), DFE_CALL_HISTORY, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{CV_THRESHOLD, SNMP(DFE_CAT), DFE_CV_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{ESF_THRESHOLD, SNMP(DFE_CAT), DFE_ESF_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{SES_THRESHOLD, SNMP(DFE_CAT), DFE_SES_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{UAS_THRESHOLD, SNMP(DFE_CAT), DFE_UAS_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{BES_THRESHOLD, SNMP(DFE_CAT), DFE_BES_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{LOFC_THRESHOLD, SNMP(DFE_CAT), DFE_LOFC_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{CSS_THRESHOLD, SNMP(DFE_CAT), DFE_CSS_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{DS0_ERROR_THRESHOLD, SNMP(DFE_CAT), DFE_DS0ERR_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},
{MODEM_THRESHOLD, SNMP(DFE_CAT), DFE_MODEM_THRESHOLD, B_SNMP_CAT, CARDINAL_P, CNV_INT
#ifdef NA
        , { 0, 0, 0, V_14_0_N, 0, 0, 0, V_14_0_N }
#endif
},

{BOX_GENERIC,	GRP_CAT,	B_GENERIC_CAT, 	0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_VCLI,	GRP_CAT,	B_VCLI_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_NAMESERVER,	GRP_CAT,	B_NAMESERVER_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_SECURITY,	GRP_CAT,	B_SECURITY_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
#ifdef NOT_USED
{BOX_KERBEROS,	KERB(GRP_CAT),	B_KERB_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
#endif
{BOX_TIME,	GRP_CAT,	B_TIME_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_SYSLOG,	GRP_CAT,	B_SYSLOG_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_MOP,	GRP_CAT,	B_MOP_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_LAT,	LAT(GRP_CAT),  	B_LAT_CAT,	0,	    0,0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_APPLETALK,	GRP_CAT,	B_ATALK_CAT, 0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_ROUTER,	GRP_CAT,	B_ROUTER_CAT,0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_IPX,	GRP_CAT,	B_IPX_CAT,0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_TMUX,	GRP_CAT,	B_TMUX_CAT,0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_DHCP,	GRP_CAT,	B_DHCP_CAT,0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{BOX_SNMP,      GRP_CAT,        B_SNMP_CAT,0,0,         0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{ALL_BOX,	GRP_CAT,	ALL_CAT,0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{-1,		0,		0,		0,0,		0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};

parameter_table printp_table[] =
{
{MAP_L_TO_U_PRINT,	LP_CAT,   PRINTER_OLTOU,	0,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_7_N, 0, V_7_1_N, 0 }
#endif
},
{PRINTER_WIDTH,		LP_CAT,   PRINTER_MCOL,		0,CARDINAL_P, CNV_INT
#ifdef NA
     , { V_2_N, V_2_N, V_5_N, V_6_N, V_7_N, 0, V_7_1_N, 0 }
#endif
},
{PRINT_HARDWARE_TABS,	LP_CAT,   PRINTER_OTABS,	0,BOOLEAN_P,  CNV_DFT_N
#ifdef NA
     , { V_1_N, V_1_N, V_5_N, V_6_N, V_7_N, 0, V_7_1_N, 0 }
#endif
},
{PRINTER_INTERFACE,	LP_CAT,   PRINTER_TYPE,	0,BOOLEAN_P,  CNV_PTYPE
#ifdef NA
     , { 0, 0, V_5_N, V_6_N, V_7_N, 0, V_7_1_N, 0 }
#endif
},
{PRINTER_SPD, LP_CAT,   PRINTER_SPEED,	0,BOOLEAN_P,  CNV_PSPEED
#ifdef NA
     , { 0, 0, 0, V_BIG_BIRD_N, V_7_N, 0, V_7_1_N, 0 }
#endif
},
{PRINTER_CR_CRLF,	LP_CAT,	PRINTER_CRLF,	0,BOOLEAN_P,	CNV_DFT_Y
#ifdef NA
     , { 0, 0, V_7_1_N, V_7_1_N, V_7_1_N, 0, V_7_1_N, 0 }
#endif
},
{TCPP_KEEPALIVE, NO_A2(LP_CAT), PRINTER_KEEPALIVE, 0, CARDINAL_P, CNV_BYTE_ZERO_OK
#ifdef NA
	, { 0, 0, 0, V_7_1_N, V_7_1_N, 0, V_7_1_N, 0 }
#endif
},
{ALL_PRINTER,		GRP_CAT,  ALL_CAT,		0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{-1,			0,	  0,			0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};


/**************************************************************
 **************************************************************
 **  NOTE:
 **	THE ORDER OF THE ENTRIES IN THIS TABLE IS DEFINED BY
 **	THE NUMERIC ORDER OF THE INTERFACE PARAMETER DEFINES ABOVE.
 **************************************************************
 */

parameter_table interfacep_table[] =
{
/* The followings are added to support RIP related parameters */
{RIP_SEND_VERSION, IF_CAT,	IF_RIP_SEND_VERSION,	0,CARDINAL_P, CNV_RIP_SEND_VERSION
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_RECV_VERSION, IF_CAT, IF_RIP_RECV_VERSION,		0,CARDINAL_P, CNV_RIP_RECV_VERSION
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_HORIZON, IF_CAT,	IF_RIP_HORIZON,	0,CARDINAL_P, CNV_RIP_HORIZON
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_DEFAULT_ROUTE, IF_CAT,	IF_RIP_DEFAULT_ROUTE,	0,CARDINAL_P, 	CNV_RIP_DEFAULT_ROUTE
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_NEXT_HOP, IF_CAT,	IF_RIP_NEXT_HOP,	0,CARDINAL_P, CNV_RIP_NEXT_HOP
#ifdef NA
     , { 0, 0, 0, V_DENALI_N, V_DENALI_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_SUB_ADVERTISE, IF_CAT,	IF_RIP_SUB_ADVERTISE,	0,BOOLEAN_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_SUB_ACCEPT, IF_CAT,	IF_RIP_SUB_ACCEPT,	0,BOOLEAN_P, CNV_DFT_Y
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_ADVERTISE, IF_CAT,	IF_RIP_ADVERTISE,0,RIP_ROUTERS_P, CNV_RIP_ROUTERS
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{RIP_ACCEPT, IF_CAT,	IF_RIP_ACCEPT,	0,RIP_ROUTERS_P, CNV_RIP_ROUTERS
#ifdef NA
     , { 0, 0, 0, V_8_N, V_8_N, 0, 0, V_PRIMATE_N }
#endif
},
{ALL_INTERFACEP,	GRP_CAT,  ALL_CAT,		0,0,          0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
},
{-1,			0,	  0,			0,0,	    0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};


#if NT1_ENG > 0
/**************************************************************
 **************************************************************
 **  NOTE:
 **     THE ORDER OF THE ENTRIES IN THIS TABLE IS DEFINED BY
 **     THE NUMERIC ORDER OF THE CHANNELIZED T1 PARAMETER DEFINES ABOVE.
 **	This table MUST match t1ds0p_table[] below.
 **************************************************************
 */

#ifdef NA
#define T1_VERSIONS \
     , { 0, 0, 0, V_DENALI_N, 0, 0, 0, 0 }
#else
#define T1_VERSIONS
#endif

parameter_table t1p_table[] =
{
{ T1_LOG_ALARM_D,         T1_CAT, T1_LOG_ALARM,         T1_GEN_CAT, BOOLEAN_P,    CNV_DFT_Y
T1_VERSIONS
},
{ T1_BYPASS_D,            T1_CAT, T1_BYPASS,            T1_GEN_CAT, BOOLEAN_P,    CNV_DFT_Y
T1_VERSIONS
},
{ T1_INFO_D,              T1_CAT, T1_INFO,              T1_GEN_CAT, STRING_P_120, CNV_STRING_P_120
T1_VERSIONS
},
{ T1_TNI_CLOCK_D,         T1_CAT, T1_TNI_CLOCK,         T1_GEN_CAT, BYTE_P,       CNV_TNI_CLOCK
T1_VERSIONS
},
{ T1_TNI_LINE_BUILDOUT_D, T1_CAT, T1_TNI_LINE_BUILDOUT, T1_GEN_CAT, BYTE_P,       CNV_TNI_LINE_BUILDOUT
T1_VERSIONS
},
{ T1_TNI_ONES_DENSITY_D,  T1_CAT, T1_TNI_ONES_DENSITY,  T1_GEN_CAT, BOOLEAN_P,    CNV_DFT_OFF
T1_VERSIONS
},
{ T1_TNI_FRAMING_D,       T1_CAT, T1_TNI_FRAMING,       T1_GEN_CAT, BYTE_P,       CNV_T1_FRAMING
T1_VERSIONS
},
{ T1_TNI_LINE_CODE_D,     T1_CAT, T1_TNI_LINE_CODE,     T1_GEN_CAT, BYTE_P,       CNV_T1_LINE_CODE
T1_VERSIONS
},
{ T1_TNI_ESF_FDL_D,       T1_CAT, T1_TNI_ESF_FDL,       T1_GEN_CAT, BYTE_P,       CNV_T1_ESF_FDL
T1_VERSIONS
},
{ T1_TNI_CIRCUIT_ID_D,    T1_CAT, T1_TNI_CIRCUIT_ID,    T1_GEN_CAT, STRING_P_120, CNV_STRING_P_120
T1_VERSIONS
},
{ T1_TDI_FRAMING_D,       T1_CAT, T1_TDI_FRAMING,       T1_GEN_CAT, BYTE_P,       CNV_T1_FRAMING
T1_VERSIONS
},
{ T1_TDI_LINE_CODE_D,     T1_CAT, T1_TDI_LINE_CODE,     T1_GEN_CAT, BYTE_P,       CNV_T1_LINE_CODE
T1_VERSIONS
},
{ T1_TDI_DISTANCE_D,      T1_CAT, T1_TDI_DISTANCE,      T1_GEN_CAT, CARDINAL_P,   CNV_T1_DISTANCE
T1_VERSIONS
},
{ T1_SWITCH_TYPE_D,       T1_CAT, T1_SWITCH_TYPE,       T1_GEN_CAT, BYTE_P,   CNV_T1_SWITCH_TYPE
T1_VERSIONS
},
{ T1_MAP_D,               T1_CAT, T1_MAP,               T1_DS0_CAT, BLOCK_32_X_2, CNV_T1_MAP
T1_VERSIONS
},
{ T1_SIGPROTO_D,          T1_CAT, T1_SIGPROTO,          T1_DS0_CAT, BLOCK_32_X_2, CNV_T1_SIG_PROTOCOL
T1_VERSIONS
},
#ifdef OBSOLETE_T1_PARAM
{ T1_PROTO_ARG_D,         VOID_CAT, T1_PROTO_ARG,         T1_DS0_CAT, BLOCK_32_X_2, CNV_T1_PROTO
T1_VERSIONS
},
#endif /*OBSOLETE_T1_PARAM*/
{ T1_RING_D,              T1_CAT, T1_RING,              T1_DS0_CAT, BLOCK_32,     CNV_T1_RING    
T1_VERSIONS
},
{-1,                    0,        0,                    0,0,        0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};

/**************************************************************
 **************************************************************
 **  NOTE:
 **	This table MUST match t1p_table[] above.
 **************************************************************
 */
parameter_table t1ds0p_table[] =
{
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ 0,         VOID_CAT, 0,         T1_GEN_CAT, 0,    0
T1_VERSIONS
},
{ T1_MAP_D,               T1_CAT, T1_MAP,               T1_DS0_CAT, BLOCK_32_X_2, CNV_T1_MAP
T1_VERSIONS
},
{ T1_SIGPROTO_D,          T1_CAT, T1_SIGPROTO,          T1_DS0_CAT, BLOCK_32_X_2, CNV_T1_SIG_PROTOCOL
T1_VERSIONS
},
#ifdef OBSOLETE_T1_PARAM
{ T1_PROTO_ARG_D,         VOID_CAT, T1_PROTO_ARG,         T1_DS0_CAT, BLOCK_32_X_2, CNV_T1_PROTO
T1_VERSIONS
},
#endif /*OBSOLETE_T1_PARAM*/
{ T1_RING_D,              T1_CAT, T1_RING,              T1_DS0_CAT, BLOCK_32,     CNV_T1_RING    
T1_VERSIONS
},
{-1,                    0,        0,                    0,0,        0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};
#endif /* NT1_ENG */


#if NPRI > 0
/**************************************************************
 **************************************************************
 **  NOTE:
 **     THE ORDER OF THE ENTRIES IN THIS TABLE IS DEFINED BY
 **     THE NUMERIC ORDER OF THE PRI PARAMETER DEFINES ABOVE.
 **	This table MUST match pribp_table[] below.
 **************************************************************
 */

#ifdef NA
#define WAN_VERSIONS \
     , { 0, 0, 0, 0, 0, 0, 0, V_PRIMATE_N }
#else
#define WAN_VERSIONS
#endif

#ifdef NA
#define WAN_V14_0 \
     , { 0, 0, 0, 0, 0, 0, 0, V_14_0_N }
#else
#define WAN_V14_0
#endif

/**************************************************************
 **************************************************************
 **  NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE:
 **  NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE:
 **  NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE:
 **  NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE:
 **  NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE: NOTE:
 **
 **	This table prip_table[] MUST match pribp_table[] below.
 **************************************************************
 */


parameter_table prip_table[] =
{
{ WAN_SWITCH_TYPE_D,	WAN_CAT, WAN_SWITCH_TYPE,	WAN_GEN_CAT, STRING_P,   CNV_STRING
WAN_VERSIONS
},
{ WAN_BUILDOUT_D,	WAN_CAT, WAN_BUILDOUT,		WAN_GEN_CAT, BYTE_P,	 CNV_TNI_LINE_BUILDOUT
WAN_VERSIONS
},
{ WAN_FDLTYPE_D,	WAN_CAT, WAN_FDLTYPE,		WAN_GEN_CAT, BYTE_P,	 CNV_T1_ESF_FDL
WAN_VERSIONS
},
{ WAN_NUM_BCHAN_D,	WAN_CAT, WAN_NUM_BCHAN,		WAN_GEN_CAT, CARDINAL_P, CNV_INT
WAN_VERSIONS
},
{ WAN_DISTANCE_D,	WAN_CAT, WAN_DISTANCE,		WAN_GEN_CAT, BYTE_P,	 CNV_WANDIST
WAN_VERSIONS
},
{ WAN_ANALOG_D,		WAN_CAT, WAN_ANALOG,		WAN_GEN_CAT, BYTE_P,	 CNV_WANANALOG
WAN_VERSIONS
},
{ WAN_FRAMING_D,	WAN_CAT, WAN_FRAMING,		WAN_GEN_CAT, BYTE_P,	 CNV_WAN_FRAMING
WAN_V14_0
},
{ WAN_LINECODE_D,	WAN_CAT, WAN_LINECODE,		WAN_GEN_CAT, BYTE_P,	 CNV_WAN_LINECODE
WAN_V14_0
},
{ WAN_DNIS_D,		WAN_CAT, WAN_DNIS,		WAN_GEN_CAT, BYTE_P,	 CNV_INT
WAN_V14_0
},
{ WAN_ANI_D,		WAN_CAT, WAN_ANI,		WAN_GEN_CAT, BYTE_P,	 CNV_DFT_N
WAN_V14_0
},
{ WAN_DIGITWIDTH_D,	WAN_CAT, WAN_DIGITWIDTH,	WAN_GEN_CAT, CARDINAL_P,	 CNV_INT
WAN_V14_0
},
{ WAN_INTERDIGIT_D,	WAN_CAT, WAN_INTERDIGIT,	WAN_GEN_CAT, CARDINAL_P,	 CNV_INT
WAN_V14_0
},
{ WAN_DIGITPOWER_1_D,	WAN_CAT, WAN_DIGITPOWER_1,	WAN_GEN_CAT, CARDINAL_P,	 CNV_INT
WAN_V14_0
},
{ WAN_DIGITPOWER_2_D,	WAN_CAT, WAN_DIGITPOWER_2,	WAN_GEN_CAT, CARDINAL_P,	 CNV_INT
WAN_V14_0
},
{ WAN_BUSYSIGTYPE_D,	WAN_CAT, WAN_BUSYSIGTYPE,	WAN_GEN_CAT, BYTE_P,	 CNV_BUSYSIG
WAN_V14_0
},
{ WAN_LOCALPHONENO_D,	WAN_CAT, WAN_LOCALPHONENO,	WAN_GEN_CAT, ADM_STRING_P,	 CNV_ADM_STRING
WAN_V14_0
},
{ WAN_AUTOBUSYENA_D,	WAN_CAT, WAN_AUTOBUSYENA,	WAN_GEN_CAT, BOOLEAN_P,		 CNV_DFT_N
WAN_V14_0
},
{ WAN_REMOTE_ADDRESS_D,	WAN_CAT, WAN_REMOTE_ADDRESS,	WAN_CHAN_CAT, BLOCK_32_X_4, CNV_WAN_REMADDR
WAN_VERSIONS
},
{ WAN_IPX_NETWORK_D,	WAN_CAT, WAN_IPX_NETWORK,	WAN_CHAN_CAT, BLOCK_32_X_4, CNV_WAN_IPXNET
WAN_VERSIONS
},
{ WAN_IPX_NODE_D,	WAN_CAT, WAN_IPX_NODE,		WAN_CHAN_CAT, BLOCK_32_X_6, CNV_WAN_IPXNODE
WAN_VERSIONS
},
{ WAN_SIGPROTO_D,	WAN_CAT, WAN_SIGPROTO,		WAN_CHAN_CAT, BLOCK_32_X_2, CNV_WAN_SIGPROTO
WAN_V14_0
},
{ WAN_RINGBACK_D,	WAN_CAT, WAN_RINGBACK,		WAN_CHAN_CAT, BLOCK_32,     CNV_WAN_RING
WAN_V14_0
},
{-1,                    0,       0,                     0,           0,          0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};

parameter_table pribp_table[] =
{
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_VERSIONS
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0 
WAN_VERSIONS
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_VERSIONS
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_VERSIONS
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0 
WAN_VERSIONS
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_VERSIONS
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0 
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ 0,                    VOID_CAT, 0,                  WAN_GEN_CAT,  0,            0
WAN_V14_0
},
{ WAN_REMOTE_ADDRESS_D,	WAN_CAT,  WAN_REMOTE_ADDRESS, WAN_CHAN_CAT, BLOCK_32_X_4, CNV_WAN_REMADDR
WAN_VERSIONS
},
{ WAN_IPX_NETWORK_D,	WAN_CAT,  WAN_IPX_NETWORK,    WAN_CHAN_CAT, BLOCK_32_X_4, CNV_WAN_IPXNET
WAN_VERSIONS
},
{ WAN_IPX_NODE_D,	WAN_CAT,  WAN_IPX_NODE,	      WAN_CHAN_CAT, BLOCK_32_X_6, CNV_WAN_IPXNODE
WAN_VERSIONS
},
{ WAN_SIGPROTO_D,	WAN_CAT,  WAN_SIGPROTO,	      WAN_CHAN_CAT, BLOCK_32_X_2, CNV_WAN_SIGPROTO
WAN_V14_0
},
{ WAN_RINGBACK_D,	WAN_CAT,  WAN_RINGBACK,	      WAN_CHAN_CAT, BLOCK_32,     CNV_WAN_RING
WAN_V14_0
},
{-1,                    0,        0,                  0,           0,            0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};

/**************************************************************
 **************************************************************
 **  NOTE:
 **     THE ORDER OF THE ENTRIES IN THIS TABLE IS DEFINED BY
 **     THE NUMERIC ORDER OF THE MODEM PARAMETER DEFINES ABOVE.
 **************************************************************
 */


parameter_table modemp_table[] =
{
{ MODEM_BUSY_OUT_D,	MODEM_CAT, MODEM_BUSY_OUT,	MODEM_GEN_CAT, BOOLEAN_P, CNV_DFT_N
WAN_VERSIONS
},
{-1,                    0,        0,                    0,0,        0
#ifdef NA
     , { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
}
};
#endif /* NPRI */

#endif /* ifndef CMD_H_PARAMS_ONLY */
