/*
 *****************************************************************************
 *
 *        Copyright 1989, 1990 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 * 	Password-changing utility program.
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 * Module Reviewers:
 *
 *	%$(reviewers)$%
 *
 *****************************************************************************
 */


/*
 * Enter a password in the password file.
 * This program should be suid with an owner
 * with write permission on ACP_PASSWD.
 */


/*
 *	Include Files
 */
#include "../inc/config.h"
#include "../inc/port/port.h"
#include "../inc/vers.h"
#include "comdefs.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <pwd.h>

#include <errno.h>
#include <ctype.h>
#include "../inc/port/install_dir.h"
#include <sys/types.h>

#include "../libannex/srpc.h"
#include "../inc/port/install_dir.h"
#include "acp_policy.h"

#ifdef USE_NDBM
#include <ndbm.h>
#include "acp_dbm_lib.h"
#endif

#ifdef USESHADOW
#ifdef NATIVESHADOW
#include <shadow.h>
#else
#include <ashadow.h>
#endif
#endif

char	*strcpy();
char	*crypt();
char	*getpass();
char	*getlogin();

char *change_password(),*test_password();

int	debug = 0;	/* global needed for functions in env_parser.c */

extern int errno;

#ifndef INSTALL_DIR
#define INSTALL_DIR "/etc"
#endif
char *install_dir = INSTALL_DIR;

char *myname;

#ifdef USE_NDBM
static DBM *open_dbm();
static void unlock_database();
#endif

static int
alldigits(str)
char *str;
{
    while (*str != '\0')
	if (!isdigit(*str))
	    return 0;
	else
	    str++;
    return 1;
}

static void
usage()
{
    fprintf(stderr,"Usage:\n\t%s [-s<dir>] [-v] [userid]\n\n",myname);
    fprintf(stderr,"\t-s<dir>\t\t- use alternate security directory.\n");
    fprintf(stderr,"\t-v\t\t- display software version number and exit.\n");
/*    fprintf(stderr,"\t-S\t\t- display status of password.\n"); */
    fprintf(stderr,"\t[userid]\t- user-name or number.\n");
    exit(1);
}

int
main(argc, argv)
int argc;
char **argv;
{

#ifdef USE_NDBM
    DBM *dbm;
#endif

    char *cp,chr;
    char *uname = NULL;
    int showstatus = 0, unum, usenumber = 0, uid, i;
    char pwbuf[16],old_password[16],user_name[LEN_USERNAME], oldbuf[16];
    struct passwd *pwd;
    int sawillegal,insist, rv =0;
    struct stat sbuf;


    myname = *argv++;
    argc--;
    while (argc > 0) {
	if ((cp = *argv++) == NULL)
	    break;
	argc--;
	if (*cp == '\0')
	    continue;
	if (*cp == '-') {
	    if (*++cp == '\0') {
		fprintf(stderr,
		    "%s:  Illegal switch format.\n",
		    myname);
		usage();
	    }
	    chr = *cp++;
	    switch (chr) {
	    case 's':
		if (*cp == '\0') {
		    if (argc <= 0 || (cp = *argv) == NULL) {
			fprintf(stderr,"Argument required for -s.\n");
			usage();
		    }
		}
		if (stat(cp,&sbuf) < 0)
		    perror(cp);
		else if ((sbuf.st_mode&S_IFMT) != S_IFDIR)
		    fprintf(stderr,"Bad file mode: %s:  %o.\n",cp,
			sbuf.st_mode);
		else {
		    install_dir = cp;
		    break;
		}
		exit(1);
	    case 'S':
		showstatus = 1;
		break;
	    case 'v':
		printf("ch_passwd host tool version %s, released %s\n",
		       VERSION,RELDATE);
		exit(0);
		break;
	    default:
		fprintf(stderr,"%s:  Unknown switch -- %c.\n",
		    myname,chr);
		usage();
	    }
	} else if (uname == NULL)
	    uname = cp;
	else {
	    fprintf(stderr,"%s:  More than one user name given.\n",
		myname);
	    usage();
	}
    }

#ifndef NATIVEPASSWD
    ACP_PASSWD(passwd_name);

    ACP_PTMP(ptmp_name);

    ACP_LOCKFILE(lock_name);
#else
    ACP_NATIVEPASSWD(passwd_name);
    ACP_NATIVEPTMP(ptmp_name);
    ACP_NATIVELOCKFILE(lock_name);
#endif /* !NATIVEPASSWD */
    
#ifndef NATIVESHADOW
    ACP_SHADOW(shadow_name);
    ACP_STMP(stmp_name);
#else
    ACP_NATIVESHADOW(shadow_name);
    ACP_NATIVESTMP(stmp_name);
#endif /* !NATIVESHADOW */

    uid = getuid();

    if (uname == NULL) {
	if ((uname = getlogin()) == NULL) {
	    unum = uid;
	    usenumber = 1;
	}
    } else if (alldigits(uname)) {
	unum = atoi(uname);
	usenumber = 1;
    }

    if (!showstatus && usenumber && uid != 0 && uid != unum) {
	fprintf(stderr,
	    "%s:  permission to change password for UID %d denied.\n",
	    myname,unum);
	exit(1);
    }

    sawillegal = 0;
    setacppw(NULL);   
    while ((pwd = getacppw()) != NULL) {
	if (usenumber && unum != pwd->pw_uid)
	    continue;
	if (!usenumber && strcmp(uname,pwd->pw_name) != 0)
	    continue;
	if (showstatus) {
	/* Not implemented yet */
	    continue;
	}
	if (uid != 0 && uid != pwd->pw_uid) {
	    sawillegal = 1;
	    continue;
	}
	break;
    }
    endacppw();

    if (showstatus)
	return 0;

    if (pwd != NULL) {
	strncpy(user_name,pwd->pw_name,sizeof(user_name));
	strncpy(old_password,pwd->pw_passwd,sizeof(old_password));
#ifdef USESHADOW
	if (strcmp(old_password,"x") == 0) {
	  struct spwd *shp;

	    setacpsp();
	    while ((shp = getacpsp()) != NULL) {
		if (strcmp(shp->sp_namp,user_name) != 0)
		    continue;
		if ((uid != 0) && (shp->sp_lstchg != 0) &&
		    (shp->sp_lstchg != -1) && (shp->sp_min != -1) &&
		    DAY_NOW < shp->sp_lstchg + shp->sp_min) {
		    fprintf(stderr,
			"%s:  cannot change password for %ld days.\n",
			myname,shp->sp_lstchg+shp->sp_min-DAY_NOW);
		    exit(1);
		}
		strncpy(old_password,shp->sp_pwdp,sizeof(old_password));
		break;
	    }
	    endacpsp();
	    if (shp == NULL)
		pwd = NULL;
	}
#endif
    }

    if (pwd == NULL) {
	if (sawillegal) {
	    fprintf(stderr,
		"%s:  permission to change password for %s denied.\n",
		myname,uname);
	} else if (usenumber)
	    fprintf(stderr,
		"%s:  UID %d not found in password file.\n",
		myname,unum);
	else
	    fprintf(stderr,
		"%s:  user %s not found in password file.\n",
		myname,uname);
	exit(1);
    }

    if (usenumber)
	printf("Changing password for UID %d (%s).\n",unum,
	    pwd->pw_name);
    else
	printf("Changing password for %s.\n",uname);

    if (old_password[0] != '\0' && uid != 0) {
	strcpy(oldbuf,getpass("Old password:  "));
	strcpy(pwbuf,crypt(oldbuf,old_password));
	if (strcmp(pwbuf,old_password) != 0) {
	    printf("Sorry.\n");
	    exit(1);
	}
    }

    for (i=0;i<3;i++) {
	strcpy(pwbuf,getpass("New password:  "));
	if (pwbuf[0] == '\0') {
	    printf("Password unchanged.\n");
	    exit(1);
	}
	if ((cp = test_password(pwbuf)) != NULL) {
	    printf(cp);
	    continue;
	}
#ifdef USE_NDBM
	if(!strcmp(oldbuf, pwbuf) || 
	   (rv=matches_password(pwd->pw_name, pwbuf))==TRUE)
#else
	if (!strcmp(oldbuf, pwbuf))
#endif
	{
	  printf(ACP_MATCH_FOUND);
	  continue;
	}
	else{
	  if(rv == -1)
	    exit(1);
	}
	if (strcmp(pwbuf,getpass("Retype new password:  ")) != 0) {
	    printf("Passwords don't match -- try again.\n");
	    continue;
	}
	break;
    }

    if (i == 3) { /* user is a moron -- kick him out */
      printf(ACP_PASS_UNCHANGED);
      return 0;
    }
    if ((cp = change_password(user_name,old_password,pwbuf)) != NULL) {
      if (*cp == ' ')
	fprintf(stderr,"%s:  %s",myname,cp+1);
      else
	perror(cp);
      return 1;
    }
#ifdef USE_NDBM
    if(STORED_PASS > 0){
      dbm = open_dbm();
      rv = dbm_store_old_pwd(dbm, user_name, old_password);
      if(rv != 0)
	print_error(user_name, rv);
      unlock_database(dbm);
    }
#endif
    return 0;
  }

#ifdef USE_NDBM
/* Waits for the use of the acp_dbm and then returns a pointer to the open 
   dbm database*/

static DBM *open_dbm()
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
    printf("ch_passwd:File locked by another process\n");
    exit(1);
  }
  else {
    if(rv == -2){
      perror(NULL);
      exit(1);
    }
  }
  
  sprintf(str, "%s/", install_dir);
  strcat(str, ACP_DBM_FILE);
  dbm = dbm_open(str, (O_RDWR | O_CREAT ), 0600);

  if(dbm != NULL)
    return dbm;

  else{
    printf("ch_passwd:Error reading from acp_dbm database\n");
    unlock_database(dbm);
    exit(1);
  }
}

/* Closes the database and then breaks the lock*/
static void unlock_database(dbm)
     DBM *dbm;
{

  dbm_close(dbm);
  dbm_unlock_acp_dbm();

}


/* Matches password entered with the users previous history of passwords*/ 

static int matches_password(user, new)
     char *user;
     char *new;
{

  
  DBM *dbm;
  int rv, i;
  char *pw, old_password[MAX_STORED_PASS][HASHLEN+1], str[80], new_usr_pwd[13];
  struct stat *stats;
  

  if((stats = (struct stat *)malloc(sizeof(struct stat))) == NULL){
    if (debug)
      printf("%p", stats);
    errno = ENOMEM;
    return -1;
  }

  ACP_DBM_DIR(str);
  if (stat(str, stats) == -1) {
    if (errno != ENOENT) {
      printf("Error reading from acp_dbm\n");
      free(stats);
      exit(1);
    }
  }
  else if(stats->st_mode != ROOT_RDWR){ 
    printf("Wrong permissions on file: %s\n", str);
    free(stats);
    exit(1);
  }

  ACP_DBM_PAGE(str);
  if (stat(str, stats) == -1) {
    if (errno != ENOENT) {
      printf("Error reading from acp_dbm\n");
      free(stats);
      exit(1);
    }
  }
  else if(stats->st_mode != ROOT_RDWR){ 
    printf("Wrong permissions on file: %s\n", str);
    free(stats);
    exit(1);
  }
  free(stats);

  dbm = open_dbm();

  if(dbm != NULL){
    rv=dbm_get_old_pwds(dbm, user, (char*)old_password);  
    unlock_database(dbm);

    if(rv == 0){
      for(i=0; i<STORED_PASS && old_password[i][0] != '\0'; i++){
        pw = crypt(new, old_password[i]);
        if(strncmp(pw, old_password[i], 13)==0){
          return TRUE;
        }
      }
      return FALSE;
    }
    else {
      if(errno == EIO){
        print_error(user, rv);
        return -1;
      }
    }
    return FALSE;
  }
}

#endif /* USE_NDBM */
