/*****************************************************************************
 *
 *        Copyright 1990, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description:: acp_dbm_lib.c
 *
 *  database.
 *
 * Detailed Design Specification: security/blacklist-ds/spec.book
 *
 * Original Author: dfox (Design), mchiba (code) Created on: 10/10/95
 *
 * Module Reviewers:
 *	carlson, gmalkin, dfox, mchiba
 *
 * Revision Control Information:
 * $Id: $
 *
 * This file created by RCS from
 * $Source: $
 *
 * Revision History:
 * $Log:$
 * This file is currently under revision by: $Locker: $
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *	DESIGN DETAILS
 *
 *	MODULE INITIALIZATION - 
 *		No initialization required.
 *       
 *	PERFORMANCE CRITICAL FACTORS - 
 *      	Testing for a previous password match may show a noticeable delay
 *          because a hash must be calculated for each check.
 *
 *      RESOURCE USAGE - 
 *		Any malloced space in here must be subsequently freed in here
 *
 *	SIGNAL USAGE -
 *      No signal usage
 *
 *      SPECIAL EXECUTION FLOW -
 *      As this is a library, only calls to standard c library can be made
 *
 * 	SPECIAL ALGORITHMS - 
 *
 ***************************************************************************
 */


/*
 *	INCLUDE FILES
 */

#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
/*#include <sys/bsdtypes.h>*/
#include <sys/stat.h>
#include "acp_policy.h"

#ifdef USE_NDBM
#include <ndbm.h>
#include "acp_dbm_lib.h"
#include "config.h"
/*
 *	CONSTANT AND MACRO DEFINES
 *	- Comment those that are external interfaces 
 */

#ifndef ACP_DBM_FILE
#define ACP_DBM_FILE "acp_dbm"
#endif


/*
 *	STRUCTURE AND TYPEDEF DEFINITIONS
 *	- Comment those that are external interfaces
 */

/*
 *	GLOBAL DATA DECLARATIONS
 */


/*
 *	STATIC DATA DECLARATIONS
 */

/*
 *	Forward Function Definitions
 * 	- Follow ANSI prototype format for ALL functions.
 */


/*****************************************************************************
 *
 * NAME: dbm_store_old_pwd(dbm. user, hash)
 *
 * DESCRIPTION: Stores hash as an old password used by user
 *
 * ARGUMENTS:
 *   DBM *dbm - open dbm
 *   char *user - username
 *   char *hash - hash of old user password
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error, RVWERROR write error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int dbm_store_old_pwd(dbm, user, hash)
    DBM *dbm;
    char *user;
    char *hash;
{
  datum key, content, user_exists;
  ACPUSER_DATA *data;
  short i;
  int rv = 0;

  key.dptr = user;
  key.dsize = strlen(user);
  
  dbm_clearerr(dbm);
  content.dsize = sizeof(ACPUSER_DATA);
  if((data = (ACPUSER_DATA *)malloc(content.dsize)) == NULL){
    errno = ENOMEM;
    return -1;
  }
  content.dptr = (char *)data;
  
  user_exists = dbm_fetch(dbm, key);
  
  if(user_exists.dptr != NULL){
    bcopy(user_exists.dptr, data, user_exists.dsize);
      for(i=STORED_PASS -2; i >= 0; i--) 
	strcpy(data->oldpass[i+1], data->oldpass[i]);
    strcpy(data->oldpass[0], hash);
    rv = dbm_store(dbm, key, content, DBM_REPLACE);
  }
  else {
    if(dbm_error(dbm) == 0){
      bzero(content.dptr, content.dsize);
      strcpy(data->oldpass[0], hash);
      rv = dbm_store(dbm, key, content, DBM_INSERT);
    }
    else{
      free(data);
      errno = EIO;
      rv = RVRERROR;         /*Indicate read error*/
      return rv;
    }
  }

  free(data);
  if(rv == -1)
    rv = RVWERROR;       /*Indicate write error*/
  return(rv);

  

}

/*****************************************************************************
 *
 * NAME: dbm_get_old_pwds(dbm, user, hash)
 *
 * DESCRIPTION: Retrieves the old password for a user and stores it into hash
 *
 * ARGUMENTS:
 *   DBM *dbm - open dbm
 *   char *user - username
 *   char *hash - hash of old user password
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:  hash points to valid memory space
 *
 */

int dbm_get_old_pwds(dbm, user, hash)
     DBM *dbm;
     char *user;
     char *hash;
{

  datum key, user_exists;
  ACPUSER_DATA *data;
  
  key.dptr = user;
  key.dsize = strlen(user);

  dbm_clearerr(dbm);
  user_exists = dbm_fetch(dbm, key);

  if(user_exists.dptr != NULL){
    data = (ACPUSER_DATA *)user_exists.dptr;
    bcopy(data->oldpass, hash, MAX_STORED_PASS * (HASHLEN + 1));
    return RVSUCCESS;
  }


  if(dbm_error(dbm) == 0){
    errno = ENOENT;    /*Indicate user does not exist*/
  }
  else
    errno = EIO;  /*Indicate read error*/
  



  return RVRERROR;
}



/*****************************************************************************
 *
 * NAME: dbm_record_login_failure(dbm, user, maxcon, maxtotal, period)
 *
 * DESCRIPTION: Records a login failure for a user and then checks if the 
 *              user has to be blacklisted.
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *	char *user - username
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error, RVWERROR write error
 *               RVBLACKLIST_MAXTRIES if blacklisted because consecutive tries
 *               exceeded, RVBLACKLIST_OVERTME if blacklisted because maximum
 *               errors over time exceeded
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
int dbm_record_login_failure(dbm, user, maxcon, maxtotal, period)
     DBM *dbm;
     char *user;
     int maxcon;
     int maxtotal;
     time_t period;
{
  datum key, user_exists, content; 
  ACPUSER_DATA *data;
  int rv=-1, i, save_rv;
  u_short set_blacklist = FALSE;

  key.dptr = user;
  key.dsize = strlen(user);

  dbm_clearerr(dbm);
  user_exists = dbm_fetch(dbm, key);

  content.dsize = sizeof(ACPUSER_DATA);
  if((data = (ACPUSER_DATA *)malloc(content.dsize))==NULL){
    errno=ENOMEM;
    return -1;
  }
  content.dptr = (char *)data;

  if(dbm_error(dbm) == 0 || (user_exists.dptr != NULL)){

    /*Record the most recent failure*/
    if(user_exists.dptr != NULL){
      bcopy(user_exists.dptr, data, content.dsize);
      if (data->blacklisted == TRUE) {
	free(data);
	return RVSUCCESS;
      }
      for(i=MAX_FAILURES - 1; i >= 0; i--)    
	data->previous_failures[i+1]=data->previous_failures[i];
    }
  
    else
      bzero((char *)data, content.dsize);

    data->previous_failures[0]=time(NULL);
    data->consecutive_failures++;
    
    /*Calculate the total failures and get the number of consecutive failures*/
    if(data->blacklisted == FALSE){
      if(maxcon != -1){
	if((int)data->consecutive_failures > maxcon) {
	  data->blacklisted = TRUE;
	  save_rv = RVBLACKLIST_MAXTRIES;
	}
      }
      if(maxtotal != -1){
	for(i=1; i< (MAX_FAILURES+1) && (data->previous_failures[i] != 0); i++){
	  if(data->previous_failures[0]-data->previous_failures[i] > period)
	    break;
	}
	if( i > maxtotal) {
	  data->blacklisted = TRUE;
	  save_rv = RVBLACKLIST_OVERTME;
	}
      }
    }

    rv = dbm_store(dbm, key, content, DBM_REPLACE);
    if(rv == -1)
      rv = RVWERROR;       /*Indicate write error*/
    else if (data->blacklisted == TRUE)
      rv = save_rv;
    free(data);
  }
  
  else{
    errno = EIO;
    rv = RVRERROR;         /*Indicate read error*/
  }
  
  return rv;
}


/*****************************************************************************
 *
 * NAME: dbm_verify_login_success(dbm, user)
 *
 * DESCRIPTION: Verifies that the user is not blacklisted and then records a 
 *              login success.
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *	char *user - username
 *
 * RETURN VALUE: RVSUCCESS if user is blacklisted, RVRERROR (no user)/(read eror) 
                 and RVWERROR for write error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int dbm_verify_login_success(dbm, user)
     DBM *dbm;
     char *user;
{

  datum key, user_exists, content;
  ACPUSER_DATA *data ;
  int i, rv= -1;
  
  key.dptr = user;
  key.dsize = strlen(user);
  
  dbm_clearerr(dbm);
  user_exists = dbm_fetch(dbm, key);
  
  if(user_exists.dptr != NULL){
    content.dsize = sizeof(ACPUSER_DATA);
    if((data = (ACPUSER_DATA *)malloc(content.dsize))==NULL){
      errno=ENOMEM;
      return -1;
    }
    content.dptr = (char *)data;
    bcopy(user_exists.dptr, data, user_exists.dsize);

    if(data->blacklisted == TRUE){
      free(data);
      return (FALSE);
    }

    data->consecutive_failures= 0;

    rv = dbm_store(dbm, key, content, DBM_REPLACE);
    free(data);
    if(rv == -1)
      return RVWERROR;       /*Indicate write error*/
    return (TRUE);
  }


  if (dbm_error(dbm) == 0){
    errno = ENOENT;   /*Indicate user does not exist*/
    return rv;
  }
  else{
    errno = EIO;      /*Indicate read error*/
    return rv;
  }

}

/*****************************************************************************
 *
 * NAME: dbm_show_user(dbm, user)
 *
 * DESCRIPTION: Sends info for user to stdout
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *	char *user - username
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error/user does not exist
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:

 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int dbm_show_user(dbm, user)
     DBM *dbm;
     char *user;
{
  datum key, user_exists, content;
  ACPUSER_DATA *data;
  int rv=0, i;
  u_short cons_failures;

  key.dptr = user;
  key.dsize = strlen(user);

  dbm_clearerr(dbm);
  user_exists = dbm_fetch(dbm, key);

  if(user_exists.dptr != NULL){
    content.dsize = sizeof(ACPUSER_DATA);
    if((data = (ACPUSER_DATA *)malloc(content.dsize))==NULL){
      errno = ENOMEM;
      return -1;
    }
    content.dptr = (char *)data;
    bcopy(user_exists.dptr, data, user_exists.dsize);

    printf("User name: %s\n", user);
    
    printf("\tTotal number of consecutive failed login attempts: %d\n", 
	                                           data->consecutive_failures);

    for(i=0; (i < (MAX_FAILURES+1)) && (data->previous_failures[i] != 0); i++)
      printf("\tLogin failure on %s", ctime(&data->previous_failures[i]));
      free(data);
      return rv;
  }


  if (dbm_error(dbm) == 0){
    errno = ENOENT;   /*Indicate user does not exist*/
    rv = RVRERROR;
  }
  else{
    errno = EIO;
    rv = RVRERROR;         /*Indicate read error*/
  }

  return rv;

}

/*****************************************************************************
 *
 * NAME: dbm_show_blacklist(dbm)
 *
 * DESCRIPTION: Sends to stdout a list of blacklisted users
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error/no users exist
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:

 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

int dbm_show_blacklist(dbm)
     DBM *dbm;
{
 
  datum key, user_exists, content;
  ACPUSER_DATA *data;
  int rv=0; 
  char *name;
  u_short blacklist;
 
  dbm_clearerr(dbm);

  for(key = dbm_firstkey(dbm); key.dptr != NULL; key = dbm_nextkey(dbm)){
    user_exists = dbm_fetch(dbm, key);
    if(user_exists.dptr != NULL){
      data = (ACPUSER_DATA *)user_exists.dptr;
      bcopy((char *)&data->blacklisted, (char *)&blacklist, sizeof(u_short));
      if(blacklist != FALSE){
	if ((name = (char *) malloc (key.dsize + 1)) == NULL) {
	  errno = ENOMEM;
	  return(-1);
	}
	strncpy(name, key.dptr, key.dsize);
	name[key.dsize] = '\0';
	printf("Warning: Annex user \"%s\" may be under attack; all logins for this account have been disabled.\n", name);
	free(name);
      }
    }
    else if(dbm_error(dbm) != 0){
      errno = EIO;       /*Indicate read error*/
      rv = RVRERROR;
      return rv;
    }
  }
  printf("\n");
  return rv;
  
}

/*****************************************************************************
 *
 * NAME: dbm_clear_blacklist(dbm, user)
 *
 * DESCRIPTION: Unblacklists a user
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *  char *user - username
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error, RVWERROR write error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:

 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

int dbm_clear_blacklist(dbm, user)
     DBM *dbm;
     char *user;
{
 

  datum key, user_exists, content;
  ACPUSER_DATA *data ;
  int i, rv= -1;
  
  key.dptr = user;
  key.dsize = strlen(user);
  
  dbm_clearerr(dbm);
  user_exists = dbm_fetch(dbm, key);
  
  if(user_exists.dptr != NULL){
    content.dsize = sizeof(ACPUSER_DATA);
    if((data = (ACPUSER_DATA *)malloc(content.dsize))==NULL){
      errno=ENOMEM;
      return -1;
    }
    content.dptr = (char *)data;
    bcopy(user_exists.dptr, data, user_exists.dsize);

    data->blacklisted = FALSE;
    data->consecutive_failures = 0;
    bzero(data->previous_failures, (MAX_FAILURES+1)*sizeof(time_t));

    rv = dbm_store(dbm, key, content, DBM_REPLACE);
    free(data);
    if(rv == -1)
      return RVWERROR;       /*Indicate write error*/
    return FALSE;
  }


  if (dbm_error(dbm) == 0){
    errno = ENOENT;   /*Indicate user does not exist*/
    return rv;
  }
  else{
    errno = EIO;      /*Indicate read error*/
    return rv;
  }
}


/*****************************************************************************
 *
 * NAME: dbm_delete_user(dbm, user)
 *
 * DESCRIPTION: Deletes all info in dbm for a user
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *  char *user - username
 *
 * RETURN VALUE: RVSUCCESS success, RVWERROR write error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:

 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

int dbm_delete_user(dbm, user)
     DBM *dbm;
     char *user;

{
  datum key, user_exists;
  int rv=0;

  key.dptr = user;
  key.dsize = strlen(user);

  user_exists = dbm_fetch(dbm, key);
 
  if(user_exists.dptr != NULL)
    rv = dbm_delete(dbm, key);
  
  else{
    if (dbm_error(dbm) == 0){
      errno = ENOENT;   /*Indicate user does not exist*/
      return RVRERROR;
    }
    else{
      errno = EIO;      /*Indicate read error*/
      return RVRERROR;
    }
  }
 
  
 if(rv == -1)
   rv = RVWERROR;  /*Indicate write error */
 return rv;

}


/*****************************************************************************
 *
 * NAME: dbm_list_users(dbm)
 *
 * DESCRIPTION: Lists all users that have info stored in dbm
 *
 * ARGUMENTS:
 *  DBM *dbm - open dbm
 *
 * RETURN VALUE: RVSUCCESS success, RVRERROR read error/ no user exists
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:

 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

int dbm_list_users(dbm)
     DBM *dbm;
{

  datum key;
  int rv=0;
  char *name;
  u_short exist_flag = FALSE;
  
  printf("List of users currently present in the %s:\n", ACP_DBM_FILE);
  dbm_clearerr(dbm);

  for(key=dbm_firstkey(dbm); key.dptr != NULL; key=dbm_nextkey(dbm)){
    exist_flag = TRUE;
    if((name = (char *) malloc (key.dsize + 1))==NULL){
      errno=ENOMEM;
      return -1;
    }
    bzero(name, key.dsize);
    strncpy(name, key.dptr, key.dsize);
    name[key.dsize] = '\0';
    printf("\t%s\n", name);
    free(name);
  }

  if(exist_flag == FALSE){
    if(dbm_error(dbm)== 0){
      errno = ENOENT;
      rv = RVRERROR;
    }
    else {
      errno=EIO;
      rv = RVRERROR;
    }
  }
  return rv;
}



/*****************************************************************************
 *
 * NAME: dbm_lock_acp_dbm()
 *
 * DESCRIPTION: Stores hash as an old password used by user
 *
 * ARGUMENTS:
 * 
 * RETURN VALUE: RVSUCCESS lock , RVRERROR file previously locked, RVWERROR system error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int dbm_lock_acp_dbm()
{
  int fd=-1;
  char dbm_lock_name[PATHSZ];

  ACP_DBM_LOCK(dbm_lock_name);
  fd = open(dbm_lock_name, (O_EXCL | O_CREAT | O_RDWR), 0600);
 
  if(fd == -1){
     if(errno == EEXIST)
        return -1;
     
     else if(errno != EEXIST)
        return -2;
  }

  close(fd);
  
  return RVSUCCESS;
}



/*****************************************************************************
 *
 * NAME: dbm_unlock_acp_dbm()
 *
 * DESCRIPTION: Stores hash as an old password used by user
 *
 * ARGUMENTS:
 * 
 * RETURN VALUE:
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int dbm_unlock_acp_dbm()
{
  char dbm_lock_name[PATHSZ];

  ACP_DBM_LOCK(dbm_lock_name);
  remove(dbm_lock_name);
}

/*****************************************************************************
** NAME: print_error(user, rv) 
** 
** DESCRIPTION: prints the errors encountered
**
** ARGUMENTS: 
       char *user - user name
       int rv - error return value (not errno)
**
** RETURN VALUE: none
**
** RESOURCE HANDLING:
**
** SIDE EFFECTS:
**
** ASSUMPTIONS:
*****************************************************************************/
void print_error(user, rv)
     char *user;
     int rv;
{
  extern char *myname;

  if((rv == -1) && errno == EIO)
    printf("%s: Error reading from %s\n", myname, ACP_DBM_FILE);
  
  else if((rv == -1) && errno == ENOENT)
    printf("%s: No such user name found in the acp_dbm database: \"%s\"\n", myname, user);
  
  else if((rv == -1) && errno == ENOMEM)
    printf("%s: Could not allocate dynamic memory from the heap\n", myname);

  else if(rv == -2)
    printf("%s: Error writing to %s\n", myname, ACP_DBM_FILE);
}

#endif /* USE_NDBM */
