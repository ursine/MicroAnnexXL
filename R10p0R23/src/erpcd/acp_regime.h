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
 * File description:  ACP regime definitions
 *
 * Original Author: Chris Losso		Created on: 5/17/95
 *
 * Revision Control Information:
 *
 * $Id: getacpuser.h,v 1.14 1994/09/14 16:53:25 reeve Exp $
 *
 * This file created by RCS from:
 * $Source: /annex/t1/src/erpcd/RCS/getacpuser.h,v $
 *
 * Revision History:
 *
 * $Log: getacpuser.h,v $
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *  DATE:	$Date: 1994/09/14 16:53:25 $
 *  REVISION:	$Revision: 1.14 $
 *
 ****************************************************************************
 */

#ifndef _ACP_REGIME_H_
#define _ACP_REGIME_H_

#include "acp_policy.h"
#ifndef _WIN32	   /* RADIUS code */
#include <netinet/in.h>
#endif

#define MAX_REGIME_ENTRY 256 /* from acp_regime.c */
#define REGIME_DELS ":\b\t\n" /* FROM ~losso/per_user/read_acp_regime.c */
#define GOT_AUTH       0x01
#define GOT_ACCT       0x02

#define GOT_HOST       0x01
#define GOT_SECRET     0x02
#define GOT_TIMEOUT    0x04
#define GOT_RETRIES    0x08
#define GOT_BACKUP     0x10

struct security_regime *create_regime_list();

struct keywords_func {
 char *keyword;
 int (*action)();
 int len;
 };
 
typedef struct radius_serv{
           struct in_addr auth_server;
           struct in_addr acct_server;
        }Radius_server;
 
typedef struct radius_serverinfo{
           struct in_addr host_address;
           struct in_addr backup_address;
           char shared_secret[16];
           int resp_timeout;
           int retries;
           struct radius_serverinfo *next;
      }Radius_serverinfo;

struct security_regime {
   struct security_regime *next; 
   int  regime_mask;
   union{
      char password_file[PATHSZ];
      Radius_server radius_servers;
   }regime_supplement;
};

extern char regime_file[PATHSZ];     
int  validate_acp_regime_file();
int  get_security_regime();
void release_security_regime();
int verify_acp_regime();
int get_regime_mash();
char *get_regime();
int extract_regime_fields();
void copy_char();
Radius_serverinfo *create_radius_configs();
Radius_serverinfo *get_serverinfo();
extern Radius_server radius_servers;
extern Radius_serverinfo *radius_head; /* erpcd.c */
extern Radius_server *default_servers; /* erpcd.c */


#endif /* _ACP_REGIME_H_ */






