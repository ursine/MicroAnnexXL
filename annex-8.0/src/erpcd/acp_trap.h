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
 *    %$(description)$%
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 ****************************************************************************
 */


#define SNMP_VERSION_1       0

#define XYL_PREFIX              1, 3, 6, 1, 4, 1
#define XYL_PREFIX_LEN          6
#define XYLOGICS                15
#define XYL_PROD                1
#define XYL_ANNEX               2
 
#define XYL_PROD_PREFIX         XYL_PREFIX, XYLOGICS, XYL_PROD
#define XYL_PROD_PREFIX_LEN     8
#define XYL_PROD_MAGIC          8
#define XYL_PROD_LEN            10
 
#define PROD_ANNEX              1
#define MIB_VERSION             2
#define PROD_OID                3

#define PRODOID_UNKNOWN         1

/* defined types (from the SMI, RFC 1155) */
#define IPADDRESS   (ASN_APPLICATION | 0)
#define COUNTER     (ASN_APPLICATION | 1)
#define GAUGE       (ASN_APPLICATION | 2)
#define TIMETICKS   (ASN_APPLICATION | 3)
#define OPAQUE      (ASN_APPLICATION | 4)

#define TRP_REQ_MSG         (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4)


#define XYL_TRAP_PREFIX         XYL_PREFIX, XYLOGICS, XYL_ANNEX, 10
#define XYL_TRAP_PREFIX_LEN     9
#define SNMP_TRAP_LEN           11

#define IPPORT_SNMPTRAP         162

#define SNMPTRAP_USERNAME	5	/* anxTrapUserName */
#define SNMPTRAP_PORTINDEX	6	/* ansTrapPortIndex */
#define SNMPTRAP_PORTTYPE	7	/* anxTrapPortType */
#define SNMPTRAP_INETADDR	8	/* anxTrapInetAddr */
#define SNMPTRAP_ATTACKERRCODE	9	/* anxTrapAttackErrcode */
#define SNMPTRAP_ATTACKERRMSG	10	/* anxTrapAttackErrmsg */
#define SNMPTRAP_DBERRCODE	11	/* anxTrapDbErrcode */
#define SNMPTRAP_DBERRMSG	12	/* anxTrapDbErrmsg */

#define TRAP_SUSPECT_ATTACK	1
#define TRAP_DB_ERROR		2

#define ERPCD_TRAP_READ		1
#define ERPCD_TRAP_WRITE	2
#define ERPCD_TRAP_PROTECT	3

#define ERPCD_ATTACK_NUMBER_EXCEEDED	1
#define ERPCD_ATTACK_TIME_THRESHOLD	2


/*
 * SNMP trap codes
 */
 
#define TRAP_COLD       0
#define TRAP_WARM       1
#define TRAP_LINK_DOWN  2
#define TRAP_LINK_UP    3
#define TRAP_AUTH       4
#define TRAP_EGPLOSS    5
#define TRAP_ENTERPRISE 6


