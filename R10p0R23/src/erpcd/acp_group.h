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
 * File description:  ACP group  definitions
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

#ifndef _ACP_GROUP_H_
#define _ACP_GROUP_H_

#include "acp_policy.h"

extern char group_file[PATHSZ];

#define MAX_GROUP_NAME 64
struct group_entry {
   struct group_entry *next;
   char groupname[MAX_GROUP_NAME];
};

 int  create_group_list();    
				
 void release_group_list();
 int is_group_member();
extern int  is_group_listed();

#endif /* _ACP_GROUP_H_ */
