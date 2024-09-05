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
 * File description:
 *
 * This module provides the interface to the acp_group file. This is a new
 * module and is used by acp_policy module. This module provides the
 * functionality to determine if a specified group exists and if the specified
 * user is a member of the specified group. The entry points to this module
 * are the functions is_group_member and is_group.
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
#include <stdio.h>
#include "../inc/config.h"
#ifndef _WIN32
#include <grp.h>
#include <syslog.h>
#else
#include "../inc/rom/syslog.h"
void NTCreateGroupList(struct group_entry **group_list, char *username);
#endif
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "acp_group.h"

/* External data */
extern int debug;

#define GROUP_FIELD_DELIMITERS ":,\t\n "
#define DISALLOW_GROUP '-'

/******************************************************************************
*
* create_group_list
*
* This is function creates a list of groups that have the specified user
* as a member. This function opens the file specified by group_file. This
* function reads entries from the group file until EOF is encountered. If
* the file cannot be opened, then the event is logged (syslog), group_list
* is set to NULL and FALSE is returned.
*
* The group entry is parsed into its components. This implementation is only
* concerned with the group and user list components, the other components are
* discarded. The function is_group_member() is called with the user list and
* the username. d to is_group_member(). If is_group_member() returns TRUE,
* then this function allocates space for the group_entry structure, copies the
* group name to the structure and adds this entry to the group list. If this
* function has been unable to allocate memory for the group_entry structure,
* then this event is logged (syslog), any allocated entries are released,
* group_list is set to NULL and FALSE is returned. This process is repeated
* until EOF is encountered. When EOF is encountered and the group list created,
* then group_list is to the head of the list and TRUE is returned. Otherwise
* group_list is set to NULL and FALSE returned.
*
* Arguments:
* struct group_entry **group_list;
* char *username;
* Return Value:
* TRUE  - The group is valid and the user is associated with the group or
*         user doesn't belong to any groups.
* FALSE - acp_group exists but is not readible. acp_group doesn't exist
*         and so does /etc/group. Also if /etc/group exists but is not
*         readible. M_ALI 8/7/96.
* Side Effects: None.
* Exceptions: If one of the error conditions described in Return Value has
*             occurred, then an error message will be logged.
* Assumptions: None.
******************************************************************************/

int create_group_list(group_list,username)
struct group_entry **group_list;
char                *username;

{
#ifdef _WIN32

	NTCreateGroupList(group_list,username);
	return TRUE;

#else /* _WIN32 */
    FILE   *grp=NULL;
    struct  group_entry *head,          /* group struct for link list */
                        *entry;
    struct  group       *grp_entry;

#if defined (ULTRIX) || defined (FREEBSD) || defined (BSDI)
    struct group *getgrent();           /* host dependent system call for  */
#else                                   /* ultrix, freebsd and bsdi.      */
    struct  group       *fgetgrent();   /* for all other hosts */
#endif

    int     retv = FALSE,field;
    struct  stat buff_stat;


    head = (struct group_entry *)NULL;
    errno = 0;

    /*
     * checking to see if acp_group file exists and
     * can be read.
     */
#if (!(defined (ULTRIX) || defined (FREEBSD) || defined (BSDI)))

    if((stat(group_file, &buff_stat)) == 0)
    {
        if((grp = fopen(group_file, "r")) == NULL)
	{
	    syslog(LOG_CRIT, "erpcd: failed to open acp_group file");
	    return(retv);
	}
    }
    else
#endif
        if ((errno == ENOENT || errno == 0) && (stat (DEFAULT_GROUP, &buff_stat)) == 0)
	{
	    if ((buff_stat.st_mode & S_IRUSR))
	        grp = fopen(DEFAULT_GROUP,"r");

	    else
	    {
	        syslog(LOG_CRIT, "erpcd: failed to open %s", DEFAULT_GROUP);
		return(retv);
	    }
	}

    /* failed to open either file, return false */
    if(grp == NULL)
	return retv;

    retv = TRUE;

    /*
     * Read the group file to the very end. Search every group
     * entry (ie the user list) to see if user's belongs in that
     * group. If user does belong in that group, add that group
     * to the link-list.
     */
#if defined (ULTRIX) || defined (FREEBSD) || defined (BSDI)
    while(grp_entry = getgrent())
#else
    while(grp_entry = fgetgrent(grp))
#endif
    {
        /* If group is disallowed, skip it */
        if (*(grp_entry->gr_name) == DISALLOW_GROUP)
	{
	    if (debug)
	        fprintf(stderr,"create_group_list: Disallowed group\
                            %s\n",grp_entry->gr_name);
	    continue;
	}

	/*
	 * Check to see if the user belongs to this group.
	 */
	if (is_group_member(grp_entry->gr_mem, username))
	{
	    /*
	     * allocate memory for the node in the link list
	     * and save the group name in it.
	     */
	    if (entry = (struct group_entry *)calloc(1,sizeof(struct group_entry)))
	    {
	        strcpy(entry->groupname,grp_entry->gr_name);
		/* If this is not the first entry then link to it */
		if (head)
		{
		    entry->next = head;
		}
		/* Place entry at the head of the list */
		head = entry;

		if (debug)
		    fprintf(stderr,"create_group_list: Added group %s\n",entry->groupname);
	    }
	    /*Unable to create a link list. Return False.*/
	    else
	    {
	        /*
		 * failed to allocate memory; free the link list
		 * and return false.
		 */
	        retv = FALSE;
		syslog(LOG_ERR, "acp_group.c: cannot allocate memory \
                             for the group entry.");
		/* clean out the link list */
		while(head)
		{
		    entry = head;
		    head = head->next;
		    free(entry);
		}
		break;
	    } /* End if calloc OK */
	} /* End if is group member */
    } /* End for all acp_group entries */

    /* save the list if exists */
    if (head)
        *group_list = head;
    else
        *group_list = (struct group_entry *)NULL;

    fclose(grp);
    return(retv);
#endif	/* _WIN32 */
}

/******************************************************************************
*
* release_group_list
*
* This is function releases memory used for a list of groups. The group list
* is traversed and the memory released. This is done until the end of the
* list has been reached.
*
* Arguments:
* struct group_entry *group_list;
* Return Value: None.
* Side Effects: None.
* Exceptions: None.
* Assumptions: None.
******************************************************************************/
void release_group_list(group_list)
struct group_entry **group_list;
{
    struct group_entry *entry,
                       *head;

    /* if group link list exists, free every node */
    if (*group_list)
    {
        head = *group_list;
	/* take this node and free it */
	while(head)
	{
	    entry = head;
	    head = head->next;
	    if (debug)
	        fprintf(stderr,"release_group_list: Delete group %s\n",entry->groupname);
	    free(entry);
	}
	if (debug){
	    if (head == (struct group_entry *)NULL)
	        fprintf(stderr,"release_group_list: Head is null\n");
	    else
	        fprintf(stderr,"release_group_list: Head is not null\n");
	}
	/* initialize the group list. */
	*group_list = (struct group_entry *)NULL;
    }
}

/******************************************************************************
*
* is_group_member
*
* This is function searches the user_list for the specified user.
* The users are parsed from the list and compared with username. If a
* match is found, then TRUE is returned. Otherwise the process is repeated.
* The process is repeated until the end of the user_list is encountered. When
* the end of the user_list is encountered, FALSE is returned.
*
* Arguments:
* char *user_list;
* char *username
* Return Value:
* TRUE  - The group is valid and the user is associated with the group.
* FALSE - Either the group file cannot be opened or the group is invalid
*         or the user name is invalid or the user is not associated with
*         the group.
* Side Effects: None.
* Exceptions: If one of the error conditions described in Return Value has
* occurred, then an error message will be logged (acp_log and syslog).
* Assumptions: None.
******************************************************************************/

int is_group_member(user_list,user)
char **user_list;
char  *user;
{
    char *keeper, *marker;

    if (debug)
        fprintf(stderr,"is_group_member: Looking for %s\n",user);

    if (user_list)
    {
        /* go through the user-list and search for username */
        for(;*user_list;++user_list)
	{
	    /*
	     * allocate memory for username;
	     * copy the name in keeper except for
	     * the spaces.
	     */
	    if ((keeper = (char *)calloc(strlen(*user_list)+1, sizeof(char)))==NULL)
	    {
            syslog(LOG_CRIT, "acp_group.c: is_group_member() out of memory");
		exit(-1);
	    }
	    marker=keeper;
	    /*
	     * if there are spaces in the user-list
	     * in the beginning or the end, strip'em
	     */
	    for (;**user_list!='\0';(*user_list)++)
	    {
	        /*stripping spaces*/
	        if(!isspace(**user_list))
		{
		    *marker=**user_list;
		    marker++;
		}
	    }
	    if (debug)
	        fprintf(stderr,"is_group_member: User %s\n",*user_list);
	    /*
	     * check to see that user matches the name (from the list)
	     * True is returned in case name matches.
	     */
	    if (!strcasecmp(keeper,user))
	    {
	        if (debug)
		    fprintf(stderr,"is_group_member: Found %s\n",*user_list);

		free(keeper);
		/* user belongs in this group */
		return(TRUE);
	    }
	    free(keeper);
	}
    }
    /* no match found in this group. */
    return(FALSE);
}


/******************************************************************************
*
* print_group_list
*
* This is function prints the group list ie groups the user belongs to.
*
* Arguments:
* struct group_entry *list;
* Return Value: None.
* Side Effects: None.
* Exceptions: If one of the error conditions described in Return Value has
* occurred, then an error message will be logged (acp_log and syslog).
* Assumptions: None.
******************************************************************************/

void print_group_list(list)
struct group_entry *list;
{
   int nodes;
   /* print the list */
   for(nodes = 0;list; list = list->next)
       fprintf(stderr,"print_group_list: #%d Group %s\n",++nodes,list->groupname);
}
