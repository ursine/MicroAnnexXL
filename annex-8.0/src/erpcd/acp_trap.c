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
 * Module Function:
 *
 *    ERPC listener process
 *
 * Original Author: Maryann Geiser    Created on: 96/1/12
 *
 *****************************************************************************
 */


/*
 *    Include Files
 */
#include "../inc/config.h"
 
#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/uio.h>

 
#include "../libannex/api_if.h"
#include "../inc/erpc/netadmp.h"
#include "acp_lib.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "../inc/port/install_dir.h"
#include "acp_policy.h"
#include "errno.h"
#include "../libannex/asn1.h"
#include "getacpuser.h"
#include "acp_trap.h"

#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#endif /* _WIN32 */


/*
 *    External Data Declarations
 */
extern struct in_addr myipaddr;
extern SECPORT *port_used;
extern int *addr_used;
extern int debug;
extern time_t erpcd_boottime;

/*
 *    Defines and Macros
 */

#define STDIN    0
#define STDOUT    1
#define STDERR    2

#define MAXARGS             16
#define MAX_COMM_LEN        21             /* Length + NULL */

#define DUMMYLEN	0x7f 

#define MAXTRAPHOSTS	10

static char trap_attack_msg[] =    "WARNING: User account disabled due to suspected attack";
static char trap_read_msg[] =      "ERPCD cannot read the database";
static char trap_write_msg[] =     "ERPCD cannot write to the database";
static char trap_protect_msg[] =   "ERPCD detects wrong database protection";

#define SAME(a,b) (strcasecmp((a),(b))==0)

#define BUFSIZE (1024)


/* #define DEBUG_SNMP 1 */

/*
 *    Structure Definitions
 */

/*
 *    Forward Routine Declarations
 */
void buftoargv();
void erpcd_read_config();
void erpcdtrap();
void erpcd_dbmErrorTrap();
void erpcd_suspectAttackTrap();

/*
 *      External Declarations
 */
FILE *fopen();
void shift_array();
int api_open();
int api_sndud();
int api_close();

/*
 *    Global Data Declarations
 */
struct acp_trapinfo {
    char snmpCommunity[MAX_COMM_LEN];
    struct in_addr snmpTrapHost;
} acp_trapinfo[MAXTRAPHOSTS];

int acp_numtraps;

char config_file[PATHSZ];

/*
 *    Static Declarations
 */
static oid trap_prefix[SNMP_TRAP_LEN] =	{XYL_TRAP_PREFIX};
static oid version_id[XYL_PROD_LEN] =		{XYL_PROD_PREFIX, PROD_OID, PRODOID_UNKNOWN};

void
erpcd_read_config()
{
    FILE *cnfg;
    char buf[BUFSIZ];
    errno_t err = ESUCCESS;
    int argc;			/* hold line argc */
    char *argv[MAXARGS];	/* hold line arg vector */
    int i;

    if (debug)
	printf("Reading %s\n",config_file);

    cnfg = fopen(config_file,"r");
    if (cnfg == NULL) {
	if (debug)
	    printf("error opening %s = %d\n",config_file,errno);
	if (errno == ENOENT)
	    syslog(LOG_NOTICE,"erpcd: No such file - %s\n",config_file);
	else
	    syslog(LOG_ERR,"erpcd: Error opening %s = %d\n",config_file,errno);
	return;
    }

    i = 0;
    while (fgets(buf,BUFSIZ,cnfg) != NULL) {
	if ((strlen(buf) == 0) ||
	   ((strlen(buf) == 1) && (buf[0] = '\n')) ||
	   (buf[0]=='#'))
            continue;
	if (i > MAXTRAPHOSTS) {
	    syslog(LOG_ERR,"erpcd: Maximum Trap Hosts exceeded\n");
	    fclose (cnfg);
	    return;
	}
	/* convert from buffer to argument vector */
	buftoargv(buf, &argc, argv);
	if (argc == 0) {
	    fclose (cnfg);
	    return;
	}

	if (SAME(argv[0],/*NOSTR*/"snmp")) {
	    if (SAME(argv[1],/*NOSTR*/"traphost")) {
		if (argc != 4) {
		    syslog(LOG_ERR, "erpcd: invalid entry in erpcd.config = %s\n",buf);
		    continue;
		}
		if ((acp_trapinfo[i].snmpTrapHost.s_addr = inet_address(argv[2])) == 0) {
		    syslog(LOG_ERR, "erpcd: invalid entry in erpcd.config = %s\n",buf);
		    continue;
		}
		bcopy (argv[3], acp_trapinfo[i].snmpCommunity, strlen (argv[2]));
		i++;
	    }
	}
    }
    acp_numtraps = i;

    fclose (cnfg);

    if (debug)
	printf("%s read\n",config_file);
    return;
}

u_char *
snmp_auth_build(data, length, sid, slen, version, messagelen)
    u_char	    *data;
    int		    *length;
    u_char	    *sid;
    int		    *slen;
    long	    *version;
    int		    messagelen;
{
    data = asn_build_header(data, length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), messagelen + *slen + 5);
    if (data == NULL){
	syslog(LOG_ERR,"erpcd: buildheader");
	return NULL;
    }
    data = asn_build_int(data, length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	    (long *)version, sizeof(*version));
    if (data == NULL){
	syslog(LOG_ERR,"erpcd: buildint");
	return NULL;
    }
    data = asn_build_string(data, length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR), 
	    sid, *slen);
    if (data == NULL){
	syslog(LOG_ERR,"erpcd: buildstring");
	return NULL;
    }
    return (u_char *)data;
}

u_char *
snmp_build_var_op(data, var_name, var_name_len, var_val_type, var_val_len, var_val, listlength)
    register u_char *data;	/* IN - pointer to the beginning of the output buffer */
    oid		*var_name;	/* IN - object id of variable */
    int		*var_name_len;	/* IN - length of object id */
    u_char	var_val_type;	/* IN - type of variable */
    int		var_val_len;	/* IN - length of variable */
    u_char	*var_val;	/* IN - value of variable */
    register int *listlength;    /* IN/OUT - number of valid bytes left in output buffer */
{
    int		    dummyLen,  headerLen, header_shift;
    u_char	    *dataPtr;
    u_char	    *dataHeader;
    u_char	    *dataFinal;

    dummyLen = *listlength;
    dataPtr = data;
    dataHeader = asn_build_header(data, &dummyLen, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (dataHeader == NULL){
	return NULL;
    }
    headerLen = dataHeader - dataPtr;
    *listlength -= headerLen;
    data = asn_build_objid(dataHeader, listlength,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
	    var_name, *var_name_len);
    if (data == NULL){
	return NULL;
    }
    switch(var_val_type){
	case ASN_INTEGER:
	case GAUGE:
	case COUNTER:
	case TIMETICKS:
	    data = asn_build_int(data, listlength, var_val_type,
		    (long *)var_val, var_val_len);
	    break;
	case ASN_OCTET_STR:
	case IPADDRESS:
	case OPAQUE:
	    data = asn_build_string(data, listlength, var_val_type,
		    var_val, var_val_len);
	    break;
	case ASN_OBJECT_ID:
	    data = asn_build_objid(data, listlength, var_val_type,
		    (oid *)var_val, var_val_len / sizeof(oid));
	    break;
	case ASN_NULL:
	    data = asn_build_null(data, listlength, var_val_type);
	    break;
	default:
	    syslog(LOG_ERR,"erpcd: wrong type");
	    return NULL;
    }
    if (data == NULL){
	return NULL;
    }
    dummyLen = (data - dataPtr) - headerLen;
    header_shift = 0;
    if (dummyLen >= 0x80){
	header_shift++;
	if (dummyLen > 0xFF)
	    header_shift++;
    }
    if (header_shift){
	/* should check available length here */
	shift_array(dataPtr + headerLen, dummyLen, header_shift);
	data += header_shift;
	headerLen += header_shift;
    }
    dataFinal = asn_build_header(dataPtr, &dummyLen, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), dummyLen);
    if (dataFinal == NULL) {
	return NULL;
    }
    if (dataFinal < dataHeader) {
	bcopy(dataHeader, dataFinal, data - dataHeader);
	data -= dataHeader - dataFinal;
    }
    return data;
}


void
erpcd_dbmErrorTrap (errCode)
    int errCode;
{
    u_char *buf_start, *buf = NULL;
    u_char *out_varlist, *out_end, *out_final;
    int len = BUFSIZE;
    int	trap_name_len = XYL_TRAP_PREFIX_LEN + 1;
    int length, list_shift, dummyLen;
    char *errMsg;

    if (debug)
	printf("erpcd_dbmErrorTrap = %d\n",errCode);

    buf = (u_char *)malloc((unsigned) BUFSIZE);
    if (!buf) {
	syslog(LOG_ERR,"erpcd: buffer alloc failed");
	return;
    }
    buf_start = buf;

    out_varlist = asn_build_header(buf, &len, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), DUMMYLEN);

    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_DBERRCODE;
    out_end = snmp_build_var_op(out_varlist, trap_prefix, &trap_name_len, ASN_INTEGER, 
		sizeof(int), &errCode, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_DBERRCODE");
	goto trap_exit;
    }

    if (errCode == ERPCD_TRAP_READ)
	errMsg = trap_read_msg;
    else if (errCode == ERPCD_TRAP_WRITE)
	errMsg = trap_write_msg;
    else
	errMsg = trap_protect_msg;

    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_DBERRMSG;
    out_end = snmp_build_var_op(out_end, trap_prefix, &trap_name_len, ASN_OCTET_STR, 
		strlen(errMsg), errMsg, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_DBERRMSG");
	goto trap_exit;
    }
    /*
     * Because of the assumption above that header lengths would be encoded
     * in one byte, things need to be fixed, now that the actual lengths are 
     * known.     */
    list_shift = 0;
    length = out_end - out_varlist;
    if (length >= 0x80){
	list_shift++;
	if (length > 0xFF)
	    list_shift++;
    }
    if (list_shift){
	/*
	 * Shift packet (from start of varlist to end of packet) by the sum 
	 * of the necessary shift counts.
	 */
        shift_array(out_varlist, length, list_shift);
        /* Now adjust pointers into the packet */
	out_end += list_shift;
	out_varlist += list_shift;
    }

    /* Now rebuild header with the actual lengths */
    dummyLen = out_end - out_varlist;
    buf = buf_start;
    out_final = asn_build_header(buf, &dummyLen, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), dummyLen);
    if (out_final == NULL || out_final > out_varlist) {
	syslog(LOG_ERR,"erpcd: rebuild header failed");
	goto trap_exit;
    }

    if (out_final < out_varlist) {
	bcopy(out_varlist, out_final, out_end - out_varlist);
	out_end -= out_varlist - out_final;
    }
    length = out_end - buf_start;

    erpcdtrap (TRAP_ENTERPRISE, TRAP_DB_ERROR, buf_start, length);

trap_exit:
    free (buf_start);
    return;
}


void
erpcd_suspectAttackTrap (user, attackCode)
    char *user;
    int attackCode;
{
    u_char *buf_start, *buf = NULL;
    u_char *out_varlist, *out_end, *out_final;
    int len = BUFSIZE;
    int	trap_name_len = XYL_TRAP_PREFIX_LEN + 1;
    int length, list_shift, dummyLen, temp_int;

    if (debug)
	printf("erpcd_suspectAttackTrap = %s: %d\n",user,attackCode);

    buf = (u_char *)malloc((unsigned) BUFSIZE);
    if (!buf) {
	syslog(LOG_ERR,"erpcd: buffer alloc failed");
	goto attack_exit;
    }
    buf_start = buf;

    out_varlist = asn_build_header(buf, &len, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), DUMMYLEN);

    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_USERNAME;
    out_end = snmp_build_var_op(out_varlist, trap_prefix, &trap_name_len, ASN_OCTET_STR, 
		strlen(user), user, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_USERNAME");
	goto attack_exit;
    }

    if (port_used != NULL)
	temp_int = port_used->unit;
    else
	temp_int = 0;
    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_PORTINDEX;
    out_end = snmp_build_var_op(out_end, trap_prefix, &trap_name_len, ASN_INTEGER, 
		sizeof(int), &temp_int, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_PORTINDEX");
	goto attack_exit;
    }

    if (port_used != NULL)
	temp_int = port_used->type;
    else
	temp_int = 0;
    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_PORTTYPE;
    out_end = snmp_build_var_op(out_end, trap_prefix, &trap_name_len, ASN_INTEGER, 
		sizeof(int), &temp_int, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_PORTTYPE");
	goto attack_exit;
    }

    if (addr_used != NULL)
	temp_int = *addr_used;
    else
	temp_int = 0;
    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_INETADDR;
    out_end = snmp_build_var_op(out_end, trap_prefix, &trap_name_len, IPADDRESS, 
		sizeof(int), &temp_int, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_INETADDR");
	goto attack_exit;
    }

    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_ATTACKERRCODE;
    out_end = snmp_build_var_op(out_end, trap_prefix, &trap_name_len, ASN_INTEGER, 
		sizeof(int), &attackCode, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_ATTACKERRCODE");
	goto attack_exit;
    }

    trap_prefix[XYL_TRAP_PREFIX_LEN] = SNMPTRAP_ATTACKERRMSG;
    out_end = snmp_build_var_op(out_end, trap_prefix, &trap_name_len,
		ASN_OCTET_STR, strlen(trap_attack_msg), trap_attack_msg, &len);

    if (out_end == NULL){
	syslog(LOG_ERR,"erpcd: build varop failed on SNMPTRAP_ATTACKERRMSG");
	goto attack_exit;
    }

    /*
     * Because of the assumption above that header lengths would be encoded
     * in one byte, things need to be fixed, now that the actual lengths are 
     * known.     */
    list_shift = 0;
    length = out_end - out_varlist;
    if (length >= 0x80){
	list_shift++;
	if (length > 0xFF)
	    list_shift++;
    }
    if (list_shift){
	/*
	 * Shift packet (from start of varlist to end of packet) by the sum 
	 * of the necessary shift counts.
	 */
        shift_array(out_varlist, length, list_shift);
        /* Now adjust pointers into the packet */
	out_end += list_shift;
	out_varlist += list_shift;
    }

    /* Now rebuild header with the actual lengths */
    dummyLen = out_end - out_varlist;
    buf = buf_start;
    out_final = asn_build_header(buf, &dummyLen, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), dummyLen);
    if (out_final == NULL || out_final > out_varlist) {
	syslog(LOG_ERR,"erpcd: rebuild header failed");
	goto attack_exit;
    }

    if (out_final < out_varlist) {
	bcopy(out_varlist, out_final, out_end - out_varlist);
	out_end -= out_varlist - out_final;
    }
    length = out_end - buf_start;

    erpcdtrap (TRAP_ENTERPRISE, TRAP_SUSPECT_ATTACK, buf_start, length);

attack_exit:
    free (buf_start);
    return;
}


/*
 *      buftoargv(char *buf, int *argc, char *argv[])
 *
 *      This routine takes a buffer and splits it up into an argc/argv pair.
 *      The splitting is done in place by changing white space to NULs.
 *      *argv[] is limitted to MAXARGS elements.
 *      Comments (a # following to the \n) are removed.
 *
 *      Weakly handles quoted strings strings. If it starts with one
 *      type of quote (',") then it hunts for that one for the end
 *      quote ignoring the contents of the string.
 */
void
buftoargv(buf, argc, argv)
    register int *argc;
    register char *argv[];
    register char *buf;
{
    *argc = 0;
    argv[0] = NULL;
 
    while (*buf && isspace(*buf))	/* skip initial white space */
	++buf;
 
    /*
     * top of loop; either at end of line or start of a word
     */
    while (*buf && *argc < MAXARGS) {
	if (*buf == '\'') {		/* Single quoted string */
	    buf++;
	    argv[*argc] = buf;
 
	    while (*buf && *buf != '\'')
		buf++;
 
	    *buf++ = '\0';
	}  else if (*buf == '\"') {	/* Double quoted string */
 
	    buf++;
	    argv[*argc] = buf;
 
	    while (*buf && *buf != '\"')
		buf++;
 
	    *buf++ = '\0';
	} else {
 
	    argv[*argc] = buf;
	    /* skip to end of arg */
 
	    while (*buf && *buf != '#' && !isspace(*buf))
		buf++;
 
	    if (*buf == '#')
	    *buf = '\0';
	    if (*buf)
		*buf++ = '\0';
	}

	if (argv[*argc] != buf) {
	    if (++*argc < MAXARGS)
		argv[*argc] = NULL;
	}
	while (*buf && isspace(*buf))
	    buf++;
    }

}


void 
erpcdtrap(generic, specific, encoded, encodedLen)
    int generic;
    int specific;
    char *encoded;
    int encodedLen;
{
    char *buf = NULL;
    int	len;
    int	result;
    time_t clock;
    int	out_length;
    int err;
    int newsock;
    struct sockaddr_in sin;
    int i;
#ifdef TLI
    struct t_unitdata t;
#else
    char t;
#endif

    buf = (char *)malloc((unsigned) BUFSIZE);
    if (!buf) {
	syslog(LOG_ERR,"erpcd: buffer alloc failed");
	return;
    }

    time(&clock);
    clock = clock - erpcd_boottime;
    clock = clock * 100;

    for (i = 0; i < acp_numtraps; i++) {
	out_length = erpcd_build_trap(buf, BUFSIZE, version_id,
		XYL_PROD_LEN, (u_long)myipaddr.s_addr, generic, specific,
		(u_long)clock, encoded, encodedLen, acp_trapinfo[i].snmpCommunity);
	if (out_length == 0) {
	    syslog(LOG_ERR,"erpcd: can't build trap message");
	    goto trapexit;
	}
	if (out_length  >  BUFSIZE) {
	    syslog(LOG_ERR,"erpcd: used too much memory");
	    goto trapexit;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = acp_trapinfo[i].snmpTrapHost.s_addr;
	sin.sin_port = htons(IPPORT_SNMPTRAP);

	if ((newsock = api_open(IPPROTO_UDP, &sin, "erpcdtrap", TRUE)) < 0) {
	  if (debug)
	    printf("erpcd: can't open socket = %d\n",newsock);
	  syslog(LOG_ERR,"erpcd: can't open socket = %d\n",newsock);
	  goto trapexit;
	}

        err = api_sndud (newsock, sizeof(struct sockaddr_in), &sin, &t,
                        buf, out_length, "erpcdtrap",debug);
	if (err) {
	  if (debug)
	    printf("erpcd: error sending = %d\n",errno);
	  syslog(LOG_ERR,"erpcd: error sending = %d\n",errno);
	}

	api_close (newsock);
	newsock = 0;
    }

trapexit:
    if (newsock)
	api_close(newsock);
    if (buf) 
	free(buf);
}



int
erpcd_build_trap(out_data, length, sysOid, sysOidLen, myAddr, trapType, specificType, time, encoded, encodedLen, community)
    register u_char  *out_data;
    int	    length;
    oid	    *sysOid;
    int	    sysOidLen;
    u_long  myAddr;
    int	    trapType;
    int	    specificType;
    u_long  time;
    char    *encoded;
    int	    encodedLen;
    u_char  *community;
{
    long    version = SNMP_VERSION_1;
    int     sidLen = strlen(community);
    int	    dummyLen;
    u_char  *out_auth, *out_header, *out_pdu;
    u_char  *out_end, *out_varlist, *out_final;
    int     auth_shift, pdu_shift;


    out_auth = out_data;
    out_header = snmp_auth_build(out_data, &length, community, 
					&sidLen, &version, length);
    if (out_header == NULL){
	syslog(LOG_ERR,"erpcd: auth build failed");
	return 0;
    }
    out_pdu = asn_build_header(out_header, &length, (u_char)TRP_REQ_MSG, DUMMYLEN);
    if (out_pdu == NULL){
	syslog(LOG_ERR,"erpcd: header build failed");
	return 0;
    }
    out_data = asn_build_objid(out_pdu, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
		(oid *)sysOid, sysOidLen);
    if (out_data == NULL){
	syslog(LOG_ERR,"erpcd: build enterprise failed");
	return 0;
    }
    out_data = asn_build_string(out_data, &length,
		(u_char)(IPADDRESS),
		(u_char *)&myAddr, sizeof(myAddr));
    if (out_data == NULL){
	syslog(LOG_ERR,"erpcd: build agent_addr failed");
	return 0;
    }
    out_data = asn_build_int(out_data, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&trapType, sizeof(trapType));
    if (out_data == NULL){
	syslog(LOG_ERR,"erpcd: build trap_type failed");
	return 0;
    }
    out_data = asn_build_int(out_data, &length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&specificType, sizeof(specificType));
    if (out_data == NULL){
	syslog(LOG_ERR,"erpcd: build specificType failed");
	return 0;
    }
    out_varlist = asn_build_int(out_data, &length,
		(u_char)(TIMETICKS),
		(long *)&time, sizeof(time));
    if (out_varlist == NULL){
	syslog(LOG_ERR,"erpcd: build timestampfailed");
	return 0;
    }

    /* Copy encoded trap variables to end of buffer */
    if (length >= encodedLen)
        bcopy (encoded, out_varlist, encodedLen);
    else {
	syslog(LOG_ERR,"erpcd: not enough room for encoded variables");
	return 0;
    }
    out_end = out_varlist + encodedLen;

    /*
     * Because of the assumption above that header lengths would be encoded
     * in one byte, things need to be fixed, now that the actual lengths are 
     * known.     */
    pdu_shift = 0;
    length = (out_end - out_pdu);
    if (length >= 0x80){
	pdu_shift++;
	if (length > 0xFF)
	    pdu_shift++;
    }
    auth_shift = 0;
    length = (out_end - out_header) + pdu_shift;
    if (length >= 0x80){
	auth_shift++;
	if (length > 0xFF)
	    auth_shift++;
    }

    if (pdu_shift){
	/*
	 * Shift packet (from start of PDU to end of packet) by the sum 
	 * of the necessary shift counts.
	 */
        shift_array(out_pdu, out_end - out_pdu, pdu_shift);
        /* Now adjust pointers into the packet */
	out_end += pdu_shift;
	out_pdu += pdu_shift;
    }

    /* Now rebuild header with the actual lengths */
    dummyLen = out_end - out_pdu;
    out_final = asn_build_header(out_header, &dummyLen, (u_char)TRP_REQ_MSG, dummyLen);
    if (out_final == NULL || out_final > out_pdu) {
	syslog(LOG_ERR,"erpcd: rebuild header trp failed");
	return 0;
    }
    if (out_final < out_pdu) {
	bcopy(out_pdu, out_final, out_end - out_pdu);
	out_end -= out_pdu - out_final;
    }
    if (auth_shift){
	/*
	 * Shift packet (from start of Trap Header to end of packet) by the sum 
	 * of the necessary shift counts.
	 */
        shift_array(out_header, out_end - out_header, auth_shift);
        /* Now adjust pointers into the packet */
	out_end += auth_shift;
	out_header += auth_shift;
    }
    dummyLen = out_end - out_header;
    out_final = snmp_auth_build(out_auth, &dummyLen, community, &sidLen, &version, dummyLen);
    if (out_final == NULL || out_final > out_header) {
	syslog(LOG_ERR,"erpcd: rebuild auth failed");
	return 0;
    }
    if (out_final < out_header) {
	bcopy(out_header, out_final, out_end - out_header);
	out_end -= out_header - out_final;
    }
    return out_end - out_auth;
}


