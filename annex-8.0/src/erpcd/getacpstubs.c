/*
 ****************************************************************************
 *
 *        Copyright 1997, Bay Networks, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Bay Networks, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Filename:      getacpstubs.c
 *
 * Module Description: Contains pre- and post- processing routines for
 *                     user profile information (normally found in
 *                     acp_userinfo)
 * 	
 * Design Specification: <filename of Design Spec>
 *
 * Author:        Maryann Geiser
 *
 *
 *****************************************************************************
 */


/*
 *	INCLUDE FILES
 */

#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

/*#include "../inc/port/libannex.h"
#include "../inc/erpc/nerpcd.h"*/
#include "acp.h"
#include "getacpuser.h"

/*
 *	CONSTANT AND MACRO DEFINES
 */

/*
 *	STRUCTURE AND TYPEDEF DEFINITIONS
 */

/*
 *	GLOBAL DATA DECLARATIONS
 */

/*
 *	STATIC DATA DECLARATIONS
 */

/*
 *	Forward Function Definitions
 */



/*
 ****************************************************************************
 *
 * NAME:
 *   pre_open_user_profile_file - preprocessing before opening acp_userinfo file
 *
 * ARGUMENTS:
 *   int pre_open_user_profile_file (char *filename, Token *file_info)
 *        char *filename        - INPUT the name of the file to open
 *        Token *file_info      - INPUT pointer to structure containing file
 *                                information including file descriptor and file name
 *
 * RETURN VALUE:
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_*                     - error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
int
pre_open_user_profile_file (filename, file_info)
    char *filename;
    Token *file_info;
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_close_user_profile_file - preprocessing before closing acp_userinfo file
 *
 * ARGUMENTS:
 *   int pre_close_user_profile_file ()
 *
 * RETURN VALUE:
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_*                     - error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
int
pre_close_user_profile_file ()
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_init_user_profile_file - preprocessing before initializing the internal
 *                                acp_userinfo information
 *
 * ARGUMENTS:
 *   int pre_init_user_profile_file ()
 *
 * RETURN VALUE:
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_*                     - error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */

int
pre_init_user_profile_file ()
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_clear_user_profile_info - preprocessing before clearing internal
 *                                 acp_userinfo information
 *
 * ARGUMENTS:
 *   int pre_clear_user_profile_info ()
 *
 * RETURN VALUE:
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_*                     - error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */

int
pre_clear_user_profile_info ()
{
    return ACPU_ESUCCESS;
}

/*****************************************************************************
 *
 * NAME:
 *   pre_get_user_profile_entry - preprocessing before retrieving this user
 *                                profile information
 *
 * ARGUMENTS:
 *   int pre_get_user_profile_entry (Uprof *up,
 *                     ACP_LSTRING Name, struct environment_spec **env,
 *                     struct gr_file *file_etc)
 *
 *        Uprof *up             - OUTPUT (if needed) userinfo entry structs
 *        ACP_LSTRING Name      - INPUT username
 *        struct environment_spec **env
 *                              - INPUT user's environment information
 *        struct gr_file *file_etc
 *                              - INPUT group file information 
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_ENOUSER               - user not found
 *   ACPU_*                     - other error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
int
pre_get_user_profile_entry (up, Name, env, file_etc)
    Uprof *up;
#ifndef _WIN32
    ACP_LSTRING Name;
#else   /* defined _WIN32 */
	ACP_USTRING Name;
#endif   /* defined _WIN32 */
    struct environment_spec **env;
    struct gr_file *file_etc;
{
    return ACPU_ESUCCESS;
}


/*
 ****************************************************************************
 *
 * NAME:
 *   pre_get_user_access - preprocessing before getting access information by username
 *
 *
 * ARGUMENTS:
 *   int pre_get_user_access(char *username,
 *			char *accesscode,
 *			Access *accessptr,
 *                      struct env_gr_info *envinfo);
 *
 *        char *username        - INPUT pointer to user name
 *        char *accesscode      - INPUT (optional) pointer to requested access code
 *        Access *accessptr     - OUTPUT access information found
 *        struct env_gr_info *envinfo -
 *                              - INPUT environment and group information
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_ENOUSER               - user not found
 *   ACPU_ENOACC		- A access block for 'accesscode' does not exist.
 *   ACPU_*                     - other error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */

int
pre_get_user_access(username, accesscode, accessptr, envinfo)
	char *username;
	char *accesscode;
	Access *accessptr;
        struct env_gr_info *envinfo;
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_get_port_pool - get port pool information by poolname
 *
 *
 * ARGUMENTS:
 *   int pre_get_port_pool(char *poolname, PoolEntry *pool_entry);
 *
 *        char *poolname        - INPUT name of the pool to match
 *        PoolEntry *pool_entry - OUTPUT pool information found
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_ENOUSER               - user not found
 *   ACPU_ENOACP		- user profile database does not exist
 *   ACPU_ENOPOOL   		- A port pool for `poolname' does not exist
 *   ACPU_ENOPOOLENT 		- The named pool has no pool entries
 *   ACPU_*                     - other error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */

int
pre_get_port_pool(poolname, pool_entry)
	char *poolname;
	PoolEntry *pool_entry;
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_get_next_pool_entry - get the next pool entry
 *
 * AGRUMENTS:
 *   int pre_get_next_pool_entry(PoolEntry *pool_entry);
 *
 *        PoolEntry *pool_entry - OUTPUT pool information found
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_ENOUSER               - user not found
 *   ACPU_ENOACP		- user profile database does not exist
 *   ACPU_ENOPOOL   		- A port pool for `poolname' does not exist
 *   ACPU_ENOPOOLENT 		- There are no more pool entries in this pool
 *   ACPU_EBADGEN		- Since the last get_next_pool_entry call, the pools
 *				  database has been changed
 *   ACPU_*                     - other error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */

int
pre_get_next_pool_entry(pool_entry)
	PoolEntry *pool_entry;
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_get_pool_entry_by_addr - get a pool entry
 *
 * AGRUMENTS:
 *   int pre_get_pool_entry_by_addr(char *poolname, u_long hostaddr, 
 *				int portnum);
 *
 *        char *poolname        - INPUT name of a port pool (if NULL, all pools
 *                                are searched)
 *        u_long hostaddr       - INPUT address of an annex in network byte order
 *        int portnum           - INPUT port number to match
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip to post processing
 *                                routine
 *   ACPU_ENOACP		- user profile database does not exist
 *   ACPU_ENOPOOL   		- A port pool for `poolname' does not exist
 *   ACPU_ENOPOOLENT 		- There are no more pool entries in this pool
 *   ACPU_*                     - other error conditions, report and return from normal
 *                                processing (ie do not run post processing routine)
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */

int
pre_get_pool_entry_by_addr(poolname, hostaddr, portnum, ptype)
	char *poolname;
	INT32 hostaddr;
	int portnum,ptype;
{
    return ACPU_ESUCCESS;
}


/*
 ****************************************************************************
 *
 * NAME:
 *   release_uprof - release any allocated memory in Uprof structure after use
 *
 * AGRUMENTS:
 *   void release_uprof (Uprof *up);
 *
 *        Uprof *up             - INPUT userinfo entry structs
 *
 * RETURN VALUE: 
 *   None
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
void
release_uprof (up)
    Uprof *up;
{
    return;
}


/*
 ****************************************************************************
 *
 * NAME:
 *   pre_setacpdialup - open acp_dialup file
 *
 * AGRUMENTS:
 *   None
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip regular processing
 *				  and return success
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
int
pre_setacpdialup()
{
    return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   pre_endacpdualup - close acp_dialup file
 *
 * AGRUMENTS:
 *   None
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip regular processing
 *				  and return success
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
pre_endacpdialup()
{
    return ACPU_ESUCCESS;
}


/*
 ****************************************************************************
 *
 * NAME:
 *   pre_findacpdialup - given user_key and inet_key, return the matching
 *                       information from acp_dialup file
 *
 * AGRUMENTS:
 *   pre_findacpdialup(uname, inet, type, loc, rem, node, port, ptype,
 *                     user_key, inet_key, dialup_flags)
 *
 *       char **uname          - OUTPUT found user name
 *       UINT32 *inet          - OUTPUT found inet address
 *       int type              - INPUT type of address required (IP_ADDRT
 *                               or IPX_ADDRT
 *       UINT32 *loc           - OUTPUT returned local address
 *       UNIT32 *rem           - OUTPUT returned remote address
 *       char *node            - OUTPUT IPX node address
 *       int port              - INPUT incoming port to test against
 *       int ptype             - INPUT incoming port type to test against
 *       char *user_key        - INPUT user name to match
 *       UINT32 inet_key       - INPUT inet address to match
 *       UINT32 *dialup_flags  - OUTPUT flags (used for DHCP)
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS              - function was successful, continue with normal
 *                                processing
 *   ACPU_ESKIP                 - function was successful, skip regular processing
 *				  and return success
 *   None
 * 
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *   None
 *
 * EXCEPTIONS:
 *   None
 *
 * ASSUMPTIONS:
 *   None
 *
 ****************************************************************************
 */
int
pre_findacpdialup(uname, inet, type, loc, rem, node, port, ptype,
                  user_key, inet_key, dialup_flags)
char    **uname;
UINT32  *inet;
int     type;
UINT32  *loc;
UINT32  *rem;
char    *node;
int     port;
int     ptype;
char    *user_key;
UINT32  inet_key;
UINT32  *dialup_flags;
{
    return ACPU_ESUCCESS;
}
