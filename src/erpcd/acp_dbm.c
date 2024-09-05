#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "acp_policy.h"
#include "../inc/port/install_dir.h"
#include "../inc/vers.h"

#ifdef USE_NDBM
#include <ndbm.h>
#include "acp_dbm_lib.h"
#include "comdefs.h"

int handle_arguments();
DBM *open_dbm();
DBM *lock_and_open_dbm();
static void unlock_database();

#ifndef INSTALL_DIR
#define INSTALL_DIR "/etc"
#endif

char *install_dir = INSTALL_DIR;
char *myname;

#endif /* USE_NDBM */

main(argc, argv)
     int argc;
     char **argv;
{
#ifdef UNIXWARE
   printf("acp_dbm is unsupported on this platform\n");
   exit(0);
#endif
#ifdef USE_NDBM
  DBM *dbm;

  char str[80]; 
  int rv=0, i;
  u_short set_lock_flag = FALSE;
  struct stat *stats;

  myname = *argv++;

  if(getuid()!=0 && geteuid() != 0){
    printf("You need root privileges to run the acp_dbm utility\n");
    exit(1);
  }

  if(argc > 3 ){
    printf("Usage: acp_dbm [-s user][-c user][-d user][-lv]\n");
    exit(1);
  }

  if((stats = (struct stat *)malloc(sizeof(struct stat))) == NULL){
    errno = ENOMEM;
    print_error(NULL, -1);
    exit(1);
  }

  ACP_DBM_DIR(str);
  if (stat(str, stats) == -1) {
    perror(str);
    free(stats);
    exit(1);
  }
  else if(stats->st_mode != ROOT_RDWR){ 
    printf("Wrong permissions on file: %s\n", str);
    free(stats);
    exit(1);
  }

  ACP_DBM_PAGE(str);
  if (stat(str, stats) == -1) {
    perror(str);
    free(stats);
    exit(1);
  }

  else if(stats->st_mode != ROOT_RDWR){ 
    printf("Wrong permissions on file: %s\n", str);
    free(stats);
    exit(1);
  }

  free(stats);

  dbm = open_dbm();

  if((rv = dbm_show_blacklist(dbm)) != 0)
    print_error(argv[1], rv);

  if(argc == 1){
    dbm_close(dbm);
    exit(1);
  }
 
  dbm_close(dbm);
  rv=handle_arguments(argc, argv, dbm);
  if(rv == -1)
     exit (1);
  exit(0);
  
#else /* USE_NDBM */
  printf("dbm option turned off\n");
  exit(0);
#endif /* USE_NDBM */  
}

#ifdef USE_NDBM
/*****************************************************************************
** NAME: handle_arguments(argc, argv, dbm)
**
** DESCRIPTION: handles the command line switches
**
** ARGUMENTS:
       int argc - number of command line parameters
       char *argv[] - pointer to command line strings
       DBM *dbm - open dbm
**
** RETURN VALUE: -1 on error;
**
** RESOURCE HANDLING:
**
** SIDE EFFECTS:
**
** ASSUMPTIONS:
*****************************************************************************/
int
handle_arguments(argc, argv)
     int argc;
     char *argv[];
     
{
  char *cp = argv[0], str[80], hash[MAX_STORED_PASS][HASHLEN +1];
  int rv=0, i;
  DBM *dbm=NULL;

  if (strcmp(cp,"-l") == 0 || strcmp(cp,"-v") == 0) {
    if(argc !=2){
      printf("Usage: acp_dbm [-s user][-c user][-d user][-lv]\n");
      return -1;
    }
    if (strcmp(cp,"-v") == 0) {
      printf("acp_dbm host tool version %s, released %s\n",
	     VERSION,RELDATE);
      return 0;
    }
    dbm = open_dbm();
    rv= dbm_list_users(dbm);
    if(rv == -1){ 
      if(errno == EIO)
	print_error(argv[1], rv);
      else
	printf("No users present currently in the database\n");
    }
    dbm_close(dbm);
    return 0;
  }
  else{
    if (cp[0] == '-' && argv[1] != '\0'){
      *++cp;
      if((*cp == 's') || (*cp == 'c') || (*cp == 'd') || (*cp == 'p')){
	dbm = lock_and_open_dbm();
	if (dbm == NULL)
	   exit(-1);
	switch (*cp) {
	case 's': rv=dbm_show_user(dbm, argv[1]);
	          break;
	  
	case 'c': rv=dbm_clear_blacklist(dbm, argv[1]);
	          break;
	  
	case 'd': rv=dbm_delete_user(dbm, argv[1]);
		  if(!rv)
		     printf("Record for %s has been deleted\n", argv[1]);
	          break;

	case 'p': 
#ifdef DEBUG_P		
		rv=dbm_get_old_pwds(dbm, argv[1], hash);
	          if(rv == 0){
	            printf("The passwords for user: %s\n", argv[1]);
		    for(i=0; i < STORED_PASS; i++) 
	 	        printf("%d) %s\n", i+1, hash[i]);
                  } 
#else 
		   printf("This option has not been turned ON\n");
#endif
	};
	unlock_database(dbm);
	if(rv !=0)
	  print_error(argv[1], rv);
	return 0;
      }
    }
    else {
      if (strcmp(cp,"help") != 0)
	fprintf(stderr, "Illegal switch:  \"%s\"\n", cp);
    }
    printf("Usage: acp_dbm [-s user][-c user][-d user][-lv]\n");
    return -1;
  }
}


/*****************************************************************************
** NAME: lock_and_open_dbm()
**
** DESCRIPTION: checks if the acp_dbm database is locked and if not it then 
                locks it and returns a pointer to the open database.
**
** ARGUMENTS:
**
** RETURN VALUE:  open database pointer
**
** RESOURCE HANDLING:
**
** SIDE EFFECTS:
**
** ASSUMPTIONS:
*****************************************************************************/
DBM *lock_and_open_dbm()
{
  int i, rv=0;
  char str[80];
  DBM *dbm;
  

  for( i=0; i<5; i++){
    if((rv = dbm_lock_acp_dbm()) == -1)
      sleep(1);
    else 
      break;
  }

  if(rv == -1 ){
    printf("acp_dbm:File locked by another process\n");
    return (NULL);
  }
  else {
    if(rv == -2){
      perror(NULL);
      return (NULL);
    }
  }
  dbm=open_dbm();
  return dbm;
}

/*****************************************************************************
** NAME: open_dbm
**  
** DESCRIPTION: Opens the database and returns any errors
**
** ARGUMENTS: none
**
** RETURN VALUE: pointer to open database
**
** RESOURCE HANDLING:
**
** SIDE EFFECTS:
**
** ASSUMPTIONS:
*****************************************************************************/
DBM *open_dbm()
{
  char str[80];
  DBM *dbm;
  
  sprintf(str, "%s/", install_dir);
  strcat(str, ACP_DBM_FILE);
  dbm = dbm_open(str, O_RDWR, 0600);

  if(dbm != NULL)
    return dbm;

  else{
    printf("acp_dbm:Error reading from acp_dbm database\n");
    dbm_unlock_acp_dbm();
    return (NULL);
  }

}

/*****************************************************************************
** NAME: unlock_database(dbm)
**
** DESCRIPTION: Closes the database and then unlocks the database
**
** ARGUMENTS: 
      DBM *dbm-pointer to open database 
**
** RETURN VALUE: none
**
** RESOURCE HANDLING:
**
** SIDE EFFECTS:
**
** ASSUMPTIONS:
*****************************************************************************/
static void unlock_database(dbm)
     DBM *dbm;
{

  dbm_close(dbm);
  dbm_unlock_acp_dbm();

}

#endif /* USE_NDBM */







