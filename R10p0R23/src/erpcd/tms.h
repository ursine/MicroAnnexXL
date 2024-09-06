/*
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.  Unauthorized
 * duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains definitions for data structures shared by
 *	the Annex and the TMS facility in ERPCD, as well as extern
 *	definitions for the external accessible functions.
 *
 * Original Author: Gary Malkin
 * Created on: June 14, 1996
 */

#ifndef _TMS_H_
#define _TMS_H_

/*
 * This crap doesn't belong here; install should do it
 */
#if defined(UNIXWARE) || defined(_WIN32) || defined(LINUX)
#undef USE_NDBM
#else
#define USE_NDBM 1
#endif
/* end crap */

#define TD_NO_MAXU (u_long)0xffffffff	/* No maxusers limit */

typedef struct {
    struct in_addr ras_addr;		/* IP address of RAS */
    off_t   ras_offset;			/* entry's offset into file (temp) */
    u_short ras_count;			/* number of users from this RAS */
} tms_db_ras;				/* flat-file RAS database entry */

typedef struct Ras_link {
    struct Ras_link *next;		/* pointer to next element */
    tms_db_ras entry;			/* actual RAS entry */
} ras_link;				/* RAS entry chain link */

typedef struct {
    char key_domain[TMS_DOMAIN_LEN];	/* the domain part of the ndbm key */
    char key_dnis[TMS_DNIS_LEN];	/* the DNIS part of the ndbm key */
} tms_db_key;

typedef struct Key_link {
    struct Key_link *next;		/* pointer to next element */
    tms_db_key entry;			/* actual database key */
} key_link;				/* database key chain link */

typedef struct {
    /* provisioned information */
    struct in_addr td_te_addr;		/* IP address of Tunnel Endpoint */
    u_char td_hw_type;			/* type of net between GW and CPE */
    u_char td_hw_addr_len;		/* length of HW address */
    u_char td_hw_addr[TMS_HWADDR_LEN];	/* left-justified HW addr */
    u_short td_auth_proto;		/* auth protocol between GW & AS */
    u_short td_acct_proto;		/* accounting proto between GW & AS */
    struct in_addr td_pauth_addr;	/* IP address of primary AS */
    struct in_addr td_sauth_addr;	/* IP address of secondary AS */
    struct in_addr td_pacct_addr;	/* IP address of primary acct server */
    struct in_addr td_sacct_addr;	/* IP address of secondary acct srvr */
    UINT32 td_spi;			/* security protocol index */
    u_char td_ta_type;			/* tunnel authentication type */
    u_char td_ta_mode;			/* tunnel authentication mode */
    u_char td_ta_key[TMS_KEY_LEN];     	/* left-justified authentication key */
    UINT32 td_maxusers;			/* max num of concurrent users */
    /* statistical & operational */
    UINT32 td_grants;			/* total num of grants issued */
    UINT32 td_denies;			/* tot num of maxu denies issued */
    UINT32 td_users;			/* current number of users */
    u_short td_addr_proto;		/* address resolution protocol */
    struct in_addr td_paddr_addr;	/* IP address of primary ad res srv */
    struct in_addr td_saddr_addr;	/* IP address of secondary ad res srv*/
    u_char td_tunnel_type;		/* type of tunnel */
    u_char td_server_loc;		/* location of auth,acct,addr servers*/
    u_char td_passwd[TMS_PASSWD_LEN];	/* L2TP password */
} tms_db_entry;				/* entry in database */

/*
 * external function definitions
 * the tms_req_* and tms_terminate functions reside in erpcd/tms.c
 * the tms_db_* functions reside in erpcd/tms_lib.c
 */
#if __STDC__ == 1
extern int tms_req_init(caddr_t, struct in_addr, char *, char *, char *);
extern int tms_req_term(caddr_t, char *, int);
extern void tms_terminate(struct in_addr);
extern int tms_db_lock(tms_db_key *);
extern int tms_db_unlock(tms_db_key *);
extern int tms_db_add(tms_db_key *, tms_db_entry *);
extern int tms_db_read(tms_db_key *, tms_db_entry *, tms_db_ras *);
extern int tms_db_update(tms_db_key *, tms_db_entry *, tms_db_ras *);
extern int tms_db_rekey(tms_db_key *, tms_db_key *);
extern int tms_db_delete(tms_db_key *);
extern key_link *tms_db_domains(int);
extern ras_link *tms_db_rases(tms_db_key *, int);
extern int tms_db_rasclear(tms_db_key *);
#else
extern int tms_req_init();
extern int tms_req_term();
extern void tms_terminate();
extern int tms_db_lock();
extern int tms_db_unlock();
extern int tms_db_add();
extern int tms_db_read();
extern int tms_db_update();
extern int tms_db_rekey();
extern int tms_db_delete();
extern key_link *tms_db_domains();
extern ras_link *tms_db_rases();
extern int tms_db_rasclear();
#endif

/*
 * tms_dbm and tms_lib return codes
 */
#define E_SUCCESS 0
#define E_SYNTAX  1
#define E_EXISTS  2
#define E_NOEXIST 3
#define E_GENERAL 4
#define E_NOTMSDB 5
#define E_NORASDB 6

#endif /*_TMS_H_*/
