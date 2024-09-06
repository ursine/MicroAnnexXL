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
 * File description:  ACP regime  definitions
 * This module provides the interface to the acp_regime file. This is a
 * new module and is used by erpcd and acp_policy modules. The entry
 * points to this module are the exported functions
 * validate_acp_regime_file() and get_security_regime().
 * The internal function verify_acp_regime() is used to support the
 * functionality supplied by the previous functions.
 *
 * Original Author: Chris Losso		Created on: 5/17/95
 *
 * Revision Control Information:
 *
 * $Id:  $
 *
 * This file created by RCS from:
 * $Source:  $
 *
 * Revision History:
 *
 * $Log: $
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *  DATE:	$Date:  $
 *  REVISION:	$Revision:  $
 *
 ****************************************************************************
 */
#include "../inc/config.h"
#include <stdio.h>
#ifdef _WIN32
#include "../inc/rom/syslog.h"
int syslog( int pri, const char *format, ...);
#else
#include <syslog.h>
#endif
#include <ctype.h>
#include "../inc/erpc/nerpcd.h"
#include "acp_regime.h"
#include "acp_policy.h"
#include "environment.h"

extern int create_group_list();
extern UINT32 inet_address();

/* #define DEBUG 1 */
#define WAIT 1
#define DONT_WAIT 0
#define MAX_REGIMES 8

extern char regime_file[PATHSZ];     /* path name of the regime file */
extern int  debug;                   /* debugging for developers. */
int available_regimes = (ACP_AVAILABLE |
			 SAFEWORD_AVAILABLE |
			 KERBEROS_AVAILABLE |
			 NATIVE_AVAILABLE |
			 SECURID_AVAILABLE); /* regime codes. */


/******************************************************************************
 *
 * validate_acp_regime_file()
 *
 * This is function is used to check that the security regimes listed in
 * the acp_regime file are available in the ERPCD image. The file specified
 * in regime_file is opened in read-only mode and the entries read
 * sequentially. The security regimes are extracted from the regime file
 * entry. Then verify_acp_regime is called with the security regime and the
 * return value is checked. If the return value is non-zero, then the next
 * security regime is processed.
 *
 * If the file specified in regime_file cannot be opened or the return value
 * from verify_acp_regime() is zero, then an error message will be logged
 * (syslog) and FALSE is returned.
 *
 * Arguments: None.
 * Return Value:
 * TRUE  - The acp_regime file has passed validation.
 * FALSE - The acp_regime file has failed validation.
 * Side Effects: None.
 * Exceptions: If the file specified in regime_file cannot be opened or
 *             bad  security regime, then an error message will be logged
 *             (stderr and syslog) and FALSE is returned.
 * Assumptions: None.
 *****************************************************************************/

int validate_acp_regime_file()

{
    FILE   *fh;
    int     number_of_fields = 0;
    int     failed = 0;
    char    entry[MAX_REGIME_ENTRY],
            regime_name[MAX_REGIME_ENTRY],
            pu_string[MAX_REGIME_ENTRY],
            passwd_file[MAX_REGIME_ENTRY];  /* storage for entries during parsing */
    struct  environment_values values_p;  /*storage for holding the regime file entries */

    /*
     * Open the regime file for reading. In case
     * of failure just log and get out
     */
    if ((fh = fopen(regime_file,"r")) == (FILE *)NULL)
    {
	if(debug)
           fprintf(stderr,"%s not found\n",regime_file);
	syslog(LOG_ERR,"acp_regime.c:regime_file %s not found\n",regime_file);
	return(FALSE);
    }

    /*
     * Read this file until the end checking for syntax errors
     */
    while(fgets(entry,MAX_REGIME_ENTRY,fh) != NULL)
    {
        bzero(pu_string, sizeof(pu_string));
	bzero(regime_name, sizeof(regime_name));
	bzero(passwd_file, sizeof(passwd_file));

	/*
	 * extract and save profile criteria, regime-name and
	 * password-file from "entry" to "pu_string", "regime_name"
	 * and "passwd_file". This fxn return the number of fields
	 * extracted and parsed.
	 */
	if (debug)printf("acp_regime.c: entry = %s \n", entry);
	number_of_fields = extract_regime_fields(entry, pu_string, regime_name,
						 passwd_file);

	if (debug) {
	    printf("validate_acp_regime_file: entry = %s \n", entry);
	    printf("validate_acp_regime_file: pu_string = %s \n",pu_string);
	    printf("validate_acp_regime_file: regime_name = %s \n", regime_name);
	    printf("validate_acp_regime_file: passwd_file = %s \n", passwd_file);
	    printf("validate_acp_regime_file: number_of_fields = %d\n", number_of_fields);
	}


	/*
	 * If this is the bogus regime, return FALSE.
	 */
	if ( verify_acp_regime(regime_name) == 0)
	{
	    if(debug)
                fprintf(stderr,"Invalid security regime specified: %s\n",regime_name);
	    syslog(LOG_ERR,"erpcd: Invalid security regime specified: %s\n",regime_name);
	    failed = 1;
	}

	/*
	 * If extracted anything from this file,
	 * parse profile-criteria and save in "values_p"
	 * struct.
	 */
	if (number_of_fields)
	{
	    /*
	     * Parse the environment string
	     */
	    if(pu_string[0]!= '\0'){
	      bzero(&values_p, sizeof(struct environment_values));
	      if(env_keyword_routine(pu_string, &values_p) <= 0)  {
		if(debug)
                   fprintf(stderr,"Invalid environment found in regime file: %s\n",pu_string);
	        syslog(LOG_ERR,"erpcd: Invalid environment found in regime file: %s\n",pu_string);
	        failed = 1;
	      }
	    }
	  }
    }

    /* close file and return true. */
    fclose(fh);
    if(failed != 0)
	return (FALSE);
    else
        return(TRUE);
}


/******************************************************************************
 *
 * get_security_regime()
 *
 * This is function is used to validate and retrieve the security regime
 * specified by the environment(profile-criteria), and allocate space
 * for the security regime
 * structure. The file specified in regime_file is opened in read-only mode
 * and the entries read sequentially. The environment string field of the
 * entry is parsed by calling env_keyword_routine(). If this function returns
 * an address of a set of environment values, then the values are tested for
 * a match with the environment specification by calling match_env_options().
 * If a match is found, then the security regime is extracted from the regime
 * file entry. Then verify_acp_regime is called with regime_name and the
 * return value is checked. If the return value is non-zero and the number of
 * fields matched is greater than the previous match, it is added to the
 * security regime structure along with any specified password file. If there
 * is no specified password file and the regime requires a password file
 * (acp, native, kerberos), then the default will be used. The defaults are:
 *			acp - acp_passwd
 *			native (re UNIX) - /etc/passwd
 *			kerberos - /tmp/tkt_erpcd_
 * This is performed until all entries have been exhausted. If no match has
 * been found, then the default security regime (last entry in the acp_regime
 * file) is assumed to always match the environment. So the default security
 * regime will be returned.The address of the security regime structure is
 * stored in regime (environment) and TRUE is returned to the calling function.
 *
 * If the file specified in regime_file cannot be opened or there is no match
 * with the environment specification or verify_acp_regime returns zero, then
 * an error message will be logged (syslog), regime (environment) is set to
 * NULL and FALSE is returned.
 *
 * Arguments:
 * struct environment_spec *env_p; - Information for the current user.
 * Return Value:
 * TRUE - security regime found.
 * FALSE - no regime found.
 * Side Effects: None.
 * Exceptions: If the file specified in regime_file cannot be opened or there
 *             is no match with the environment specification, then an error
 *             message will be logged (acp_log and syslog).
 * Assumptions: None.
 *
 *****************************************************************************/

int get_security_regime(env_p)
struct environment_spec *env_p;
{
    FILE   *fh;
    struct  environment_values values_p;  /*storage for holding the regime file entries */
    struct  security_regime *curr,
                            *prev,
                            *node;        /* pointer for link lists */
    int     FLAG             = 0;
    int     number_of_fields = 0;
    int     regime_mask      = 0;
    int     match            = 0;
    int     entries          = 0;
    /* storage for entries during parsing*/
    char    entry[MAX_REGIME_ENTRY],
            regime_name[MAX_REGIME_ENTRY],
            pu_string[MAX_REGIME_ENTRY],
            passwd_file[MAX_REGIME_ENTRY];
    Radius_server servers;
    prev        = (struct security_regime *)NULL;/* initialize pointers for regime linklist*/
    curr        = (struct security_regime *)NULL;
    node        = (struct security_regime *)NULL;

#define AUTH_SERVER_ADDR regime_supplement.radius_servers.auth_server.s_addr
#define ACCT_SERVER_ADDR regime_supplement.radius_servers.acct_server.s_addr

    /*
     * Open the regime file for reading. if failed to
     * read the file, return an error.
     */
    if ((fh = fopen(regime_file,"r")) == (FILE *)NULL)
    {
	if(debug)
           fprintf(stderr,"%s not found\n",regime_file);
	syslog(LOG_ERR,"acp_regime.c: file %s not found\n",regime_file);
	env_p = (struct environment_spec *)NULL;
	return(FALSE);
    }

    /*
     * Read this file until the end or a match is reached.
     * This block of code takes the line from the regime file
     * and saves it in array "entry". The array "entry" is
     * passed to routine extract_regime_fields() where the
     * profile criteria, regime name and password file info
     * are saved in arrays "pu_string", "regime_name" and
     * "passwd_file" respectively. "pu_string" is passed to
     * fxn env_keyword_routine() where all the specified keywords
     * (in pu_string ) are saved in struct values_p. If "values_p"
     * contains any group info., then create a list of groups
     * (in which user belongs). Match "env_p" with "values_p".
     * If a match is found, that's the regime and password
     * we use for user's authentication.
     */
    while((fgets(entry,MAX_REGIME_ENTRY,fh)) != NULL && !match)
    {
	if (debug)printf("acp_regime.c: entry = %s \n", entry);
        bzero(pu_string, sizeof(pu_string));
	bzero(regime_name, sizeof(regime_name));
	bzero(passwd_file, sizeof(passwd_file));
	bzero(&servers, sizeof(Radius_server));

	/*
	 * extract and save profile criteria, regime-name and
	 * password-file from "entry" to "pu_string", "regime_name"
	 * and "passwd_file". This fxn return the number of fields
	 * extracted and parsed.
	 */
	number_of_fields = extract_regime_fields(entry, pu_string, regime_name,
						 passwd_file, &servers);

	if (debug)
	{
	    printf("acp_regime.c: entry = %s \n", entry);
	    printf("acp_regime.c: pu_string = %s \n",pu_string);
	    printf("acp_regime.c: regime_name = %s \n", regime_name);
	    printf("acp_regime.c: passwd_file = %s \n", passwd_file);
	    printf("number_of_fields: %d\n", number_of_fields);
	  }

	/*
	 * verify the regime found in the regime file.
	 * If this is the bogus regime, return FALSE.
	 * This false is used by the calling fxn to
	 * deny access.
	 */
	if ( verify_acp_regime(regime_name) == 0)
	{
	    if(debug)
               fprintf(stderr,"Security regime %s is not available\n",regime_name);
	    syslog(LOG_ERR,"erpcd: Invalid security regime specified: %s\n",regime_name);
	    return(FALSE);
	}

	/*
	 * If extracted anything from this file,
	 * parse profile-criteria and save in "values_p"
	 * struct.
	 */
	if (number_of_fields)
	{
	    /* clean out the struct */
	    bzero(&values_p, sizeof(struct environment_values));
	   if (debug)
	     printf("CALLING MATCH IN GETSECURITYREGIME \n");

	    /*
	     * save all the keywords' info. (from the
	     * profile criteria) in the struct
	     * "values_p". If successful, form
	     * group lists (if necessary) and
	     * match "values_p" with "env_p".
	     */
	    if(pu_string[0] != '\0'){
	      if(env_keyword_routine(pu_string, &values_p) > 0)
		{
		  if (debug) {
		    printf("acp_regime.c: pu_string = %s \n",pu_string);

		    /*
		     * If there is a group entry in the
		     * profile criteria (which is now saved in the form
		     * of tokens in values_p struct), look up the group
		     * file and create a link list of group to which
		     * this user belongs to.
		     *
		     */
		    if(debug)
		        printf("groupname: %s; env_p: %p\n", values_p.groupname, *env_p);
		  }
		  if(isalpha(values_p.groupname[0]))
		    {
		      /* create a list of groups to which this user belongs */
		      if (create_group_list(&(env_p->group_list), env_p->username)
			  ==FALSE)
			{
			  /* Couldn't create group list, deny access. */
			  if (debug)
			    printf("acp_regime.c: failed to create a group list \
                                                     for the user.\n");
			  return(FALSE);
			}
		    }

		  /*
		   * match the user's environment (env_p) with
		   * "values_p" - profile-criteria. If match is
		   * found, we use this regime and password file
		   * for user's authentication.
		   */
		  match = match_env_options(env_p, &values_p);
		}  /* if(env_keyword_routine(pu_string, &values_p)) */
	      else
	        /* failed to parse, an erroneous keyword. found */
	        return FALSE;
	    }
	     else
		match = TRUE; /*this means that there is no environment
				specification hence user matches this
				entry regardless*/
	    /* print match found, ie regime name and mask */
	    if (debug)
	      {
	        printf("match = %d \n", match);
		printf("get_security_regime: after match_env_options. match \
                     = %d.regime_name = %s. regime_mask = %d \n", match,
		       regime_name, regime_mask);
	      }

	    /*
	     * If match is found, save that regime and password file
	     * in user's environment (env_p). The following code
	     * however, supports the mulitple regime authentication
	     * and creates a link list of regimes. But since we
	     * only use one regime for authentication, no harm done.
	     * TODO: properly "#ifdef" the following chunk of code
	     * such that it is invoked ( in the future) only when
	     * the multiple regime authentication is used. In the meantime
	     * it can be left as it is.
	     */
	    if (match)
	      {
	        /* verify the found regime. */
	        if(regime_mask = verify_acp_regime(regime_name))
		  {
		    if (debug)printf("get_security_regime: regime_mask\
                                                        = %d\n", regime_mask);
		    /* code for creating regime link list */
		    prev = curr;
		    /* create the regime node with regime name and password file */
		    if(node = create_regime_list(&regime_mask, passwd_file, &servers))
		      {
		        if (prev)
			  {
			    prev->next = node;
			    curr = node;
			    node = node->next;

			  }
			else
			  {
			    prev = node;
			    curr = node;
			    env_p->regime = node ;
			  }
		      }
		    /* failed to creaet node, log error. */
		    else
		      {
			if(debug)
		           fprintf(stderr,"Failure to allocate memory.");
			syslog(LOG_ERR,"acp_regime.c: Not enough memory.");
		      }
		  }/* if (regime_mask = verify_acp_regime(regime_name) */
		else
		  {
		    /* bogus regime , log and deny access. */
		    syslog(LOG_ERR,"acp_regime.c: Regime %s not found.",
			   regime_name);
		    if (debug)
		        printf("value of regime struct is %d\n",env_p->regime);

		    /* release the regime link list, on the way out */
		    if(env_p->regime)
		      release_security_regime(env_p->regime);
		    return(FALSE);
		  }/*else , for if regime_mask exists. */
	    }/* if(match) */
	}/*if number_of_fields exists*/

	/*
	 * TODO: Unnecessary comments. These array are on stack and not
	 * "malloced"
	 */
        if (debug)
	{
	    printf("FREEEEEEE for regime_name and passwd_file \n");
	    printf("FREEEEEEE for pu_string \n");
	}
    }/* while loop "while((fgets(entry,MAX_REGIME_ENTRY,fh)) != NULL && !match)" */

    /* close this file */
    fclose(fh);

    /* no matches found, just clean out and deny access.*/
    if (match == 0)
    {
        if (debug)
	    printf("get_security_regime: Getting out of get_security_regime.\
                                      returning FALSE\n match = %d\n", match);
	syslog(LOG_ERR,"acp_regime.c: No environment matches found.");
	if (env_p->regime)
	    release_security_regime(env_p->regime);
	return(FALSE);
    }
    else
    {
        /*
	 * search successful, found a match, return TRUE.
	 * calling fxn uses "env_p" to get regime info.
	 */
        if (debug)
	    printf("get_security_regime: Getting out of get_security_regime.\
                                      returning TRUE\n");
	return(TRUE);
    }
}

/******************************************************************************
 *
 * release_security_regime()
 *
 * This is function releases memory used for the security regime.
 *
 * Arguments:
 * struct security_regime **regime;
 * Return Value: None.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *****************************************************************************/

void release_security_regime(regime)
struct security_regime *regime;
{
    struct security_regime *entry,
                           *head;
    int    i = 0;

    /* If regime exists at all */
    if (regime)
    {
        /* free memory alloc'ed for each and every node. */
        head = regime;
	while(head)
        {
	    entry = head;
	    head = head->next;
	    if (debug)
	    {
	        for(i;((security_keywords[i].mask != entry->regime_mask) && i <= 6);i++);
		fprintf(stderr,"release_security_regime:\
                     Delete security_regime %s\n",security_keywords[i].keyword);
	    }
	    free(entry);
	}
	if (debug)
	{
	    if (head == (struct security_regime *)NULL)
	        fprintf(stderr,"release_group_list: Head is null\n");
	    else
	        fprintf(stderr,"release_group_list: Head is not null\n");
	}
	/* initialize the pointer. */
	regime = (struct security_regime *)NULL;
    }
}

/******************************************************************************
 *
 * verify_acp_regime()
 *
 * This is function tests the validity and availability of the specified
 * security regime. This function is called by validate_acp_regime_file()
 * and get_security_regime(). A list of regime keywords and security regime
 * mask values is maintained by the ERPCD.
 *
 * If the regime specified in regime_name matches one of the regime keywords,
 * then the security regime mask value is checked against the value in the
 * global variable security_regimes_available. If this security regime mask
 * value is in security_regimes_available, then mask value is returned to the
 * calling function.
 *
 * If either test fails, an error message is logged (stderr and syslog) and
 * zero is returned to the calling function.
 *
 * Arguments:
 * char *regime_name;
 * Return Value:
 * Zero is returned if the regime is invalid or not available. Otherwise,
 * the security regime mask value is returned.
 * Side Effects: None.
 * Exceptions: If a test fails, an error message will be logged
 *             (stderr and syslog) and FALSE is returned.
 * Assumptions: None.
 *
 *****************************************************************************/

int verify_acp_regime(regime_name)
char *regime_name;
{
    int mask = 0;

    /*
     * get the regime mask. If it exists
     * regime is valid else regime is
     * invalid .
     */
    mask = get_regime_mask(regime_name);

    /* return the regime mask */
    if (mask > 0)
        return(mask);
    else return(0);
}


/******************************************************************************
 *
 * extract_regime_fields()
 *
 * This is function extracts the profile-criteria(optional), regime and
 * password file (optional) fields from the line ("entry") gotten from the
 * acp_regime file and copies them in "pu_string", "regime_name" and
 * "passwd_file" respectively.
 * Entries from acp_regime file have 3 fields and follow the format below:
 * [profile-criteria]:regime-name[:password-file] or
 * [profile-criteria]:radius:auth_server:acct_server
 * [] indicate optional data.
 *
 * Arguments:
 * char *entry; a line from acp_regime file.
 * char *pu_entry; storage for profile criteria
 * char *regime_name; storage for regime_name
 * char *passwd_file; password file name.
 * Return Value:
 * number of extracted fields.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

int extract_regime_fields(entry, pu_string, regime_name, passwd_file, servers)
char  *entry;
char *pu_string;
char *regime_name;
char *passwd_file;
Radius_server *servers;
{
  char *value;
  int   number_of_fields = 0, entry_length, pu_length;
  char auth_server[80], acct_server[80];
  UINT32 auth_addr=0;
  UINT32 acct_addr=0;

  value = entry;

  bzero(auth_server, 80);
  bzero(acct_server, 80);

  /* save the length of the entry from acp_regime file.*/
  entry_length = strlen(entry);

  /* copy the profile_criteria in pu_string */
  copy_char(value, pu_string);

  /* if copied anything, increment the field number. */
  if(pu_length = strlen(pu_string))
    number_of_fields++;

  /* advance the "entry" pointer. */
  value+=(strlen(pu_string)+1);

  /* erroneous entry , log */
  if(*(entry + pu_length) != ':')
    syslog(LOG_ERR, "erpcd: Invalid line in acp_regime: %s", entry);

  if (debug)
    printf("acp_regime.c: extract_regime_fields. pu_string = %s and value = %s\n", pu_string, value);

  /*
   * pointer value is advanced correctly
   * copy the regime to "regime_name"
   * and proceed.
   */
  if((value - entry) < entry_length)
    copy_char(value, regime_name);

  /* if copied anything, increment the field number. */
  if(strlen(regime_name))
    number_of_fields++;

  /* advance the "entry" pointer. */
  value+=(strlen(regime_name)+1);

  if (debug)
    printf("acp_regime.c: extract_regime_fields. regime_name = %s and value = %s \n", regime_name, value);

  /*
   * pointer value is advanced correctly
   * copy the password-file name to "passwd_file"
   * and proceed.
   */
  if((value - entry) < entry_length){
    if(!strcmp(regime_name, "radius")){
      copy_char(value, auth_server);
      if (strlen(auth_server)) {
          if (auth_addr = inet_address(auth_server))
              servers->auth_server.s_addr = auth_addr;
          number_of_fields++;
      }
      value += strlen(auth_server) + 1;
      if((value - entry) < entry_length) {
          copy_char(value, acct_server);
          if (strlen(acct_server)) {
              if (acct_addr = inet_address(acct_server))
                  servers->acct_server.s_addr = acct_addr;
              number_of_fields++;
          }
          value += strlen(acct_server) + 1;
      }
    }
    else{       /* We get the passwd-file name */
      copy_char(value, passwd_file);
      /* if copied anything, increment the field number. */
      if(strlen(passwd_file))
	number_of_fields++;
      /* advance the "entry" pointer. */
      value+=(strlen(passwd_file)+1);
    }
  }

  if (debug)
    printf("acp_regime.c: extract_regime_fields. passwd_file = %s and value = %s\n", passwd_file, value);

  /* return the number of fields extracted. */
  return(number_of_fields);
}


/******************************************************************************
 *
 * copy_char()
 *
 * This function extracts a token from line gotten from the
 * acp_regime file and copies them in char *token. This token is delimited
 * by a ':', ' ' or a '\0'. Essentially this fxn. copies data from the
 * beginning (where char *entry points to ) to one of the above delimiters.
 * Profile-criteria's time-keyword contain quotes ("), and this
 * routine makes sure that time keyword and data is parsed
 * correctly.
 *
 * Arguments:
 * char *entry; a line from acp_regime file.
 * char *token; storage to which the token should be copied to.
 * Return Value:
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

void copy_char(entry, token)
char *entry;
char *token;
{
    char *marker; /* location in the "entry" */
    char *temp;
    int   flag = DONT_WAIT;
    int   i    = 0;

    /* point to the passed line from acp_regime file */
    temp   = entry;

    /* read chars. from the line b4 exceeding MAX_REGIME_ENTRY */
    for(marker = entry, i=0; i < MAX_REGIME_ENTRY; marker++, i++)
    {
        /* if any one of the delimiter and flag is DONT_WAIT, stop */
        if ((*marker == ':' || isspace(*marker) || *marker == '\0') &&
                                                flag == DONT_WAIT)
            break;

	/*
	 * If first quote, don't terminte and  continue parsing
	 * till second quote is found. if second quote found,
	 * terminate normally (ie on ':', ' ' or '\0').
	 */
	if (*marker == '\"')
	{
	    if (flag == DONT_WAIT)
	        flag = WAIT;
	    else
                flag = DONT_WAIT;
        }
    }

    /* if any data between "entry" and the delimiter,  copy */
    if (i > 0)
    {
        strncpy(token, temp, i);
	token[i] = '\0';
    }
    /* no data */
    else
        token[0] = '\0';

    return;
}


/******************************************************************************
 *
 * create_regime_list()
 *
 * This is function creates a node for the regime-list. It receives two
 * arguements, one regime mask and password file name. This fxn. allocates
 * memory for the node (struct) and saves the two argument in there. If there is no
 * password file name provided, it uses the default values. Default values
 * for the regimes are:
 * Regime Name :  Default Password file name.
 * Acp         :  acp_passwd
 * Native      :  passwd
 * Kerberos    :  ./tmp/tkt_erpcd_
 * Safeword    : none
 * Securid     : none
 * Deny        : none
 * None        : none
 *
 * Once this fxn has saved these values, it set the pointer to next node in
 * the link list to null and return the pointer to newly created node.
 *
 * Node contains an extra field (pointer to next node) since initially the
 * the design supported multiple regimes for authentication. Even though
 * that's not the case anymore, there is practically very little or
 * no over head in using a struct that has an unused field. This is only
 * left in the code for the reasons of extensibility ie supporting multiple
 * regimes.
 *
 * Arguments:
 * int *regime_mask;  regime mask
 * char *passwd_file; name of the password file
 * Return Value:
 * struct security_regime *temp; this struct (node) contains the regime and
 *                                password filename (if applicable)
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

struct security_regime *create_regime_list(regime_mask, passwd_file, servers)
int  *regime_mask;
char *passwd_file;
Radius_server *servers;
{
    struct security_regime *temp;
   int i, full_path = FALSE;
   char *temp_char;


    /*allocate storage for regime mask and password file name. */
    temp = (struct security_regime *)calloc(1,sizeof(struct security_regime));

    /*
     * Upon successful memory allocation,
     * save the regime mask and password file name.
     */
    if (temp)
    {
        if (debug)
	    printf("acp_regime.c: In create_regime_list - regime_mask = %d,  passwd_file = %s\n", *regime_mask, passwd_file);
	/* save regime-mask */
	temp->regime_mask = *regime_mask;

       /* if password filename consists of all printable chars, save it */
       if (isgraph(*passwd_file)) {
           /* check whether full path name was specified */
           temp_char = passwd_file;
           for (i = 0; i < (int)strlen(passwd_file); i++) {
                if (*temp_char == '/') {
                     full_path = TRUE;
                     break;
                }
                temp_char++;
           }
           if (full_path == FALSE)
               /* if no full path name, use the install directory */
	       sprintf(temp->regime_supplement.password_file,"%s/%s",install_dir,passwd_file);
           else
               /* if the acp_regime file contains a full path file name, use it */
	       strcpy(temp->regime_supplement.password_file, passwd_file);
       }
       else
	{
	    switch (*regime_mask)
	    {
	        case ACP_MASK:
	            ACP_PASSWD(temp->regime_supplement.password_file);
		break;

		/* these regimes don't require password files. */
	        case SAFEWORD_MASK:
		case SECURID_MASK:
		case DENY_MASK:
	        case NONE_MASK:
		    strcpy(temp->regime_supplement.password_file, "");
		break;

		case NATIVE_MASK:
		    strcpy(temp->regime_supplement.password_file, "passwd");
		break;

		case KERBEROS_MASK:
		    strcpy(temp->regime_supplement.password_file, "./tmp/tkt_erpcd_");
		break;

               case RADIUS_MASK:
                   temp->AUTH_SERVER_ADDR = servers->auth_server.s_addr;
                   temp->ACCT_SERVER_ADDR = servers->acct_server.s_addr;
                   break;

	        default:
		break;

	    }
	}

	/*
	 * set the pointer to next node to NULL, it is not used though.
	 * TODO: IT WOULD BE NICE 2 '#ifdef' this field depending on
	 * the support for multiple regimes.
	 */
        temp->next = (struct security_regime *)NULL;
    }

    if (debug)
      printf("acp_regime.c: In create_regime_list - new_node's regime_mask = %d, passwd_file = %s\n", temp->regime_mask, temp->regime_supplement.password_file);
    /* return the struct containing the regime and password file info. */
    return(temp);
}
