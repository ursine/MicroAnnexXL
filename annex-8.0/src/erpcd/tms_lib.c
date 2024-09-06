/*
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.  Unauthorized
 * duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains the source code for the TMS database API.
 *	The Design Specification, in Frame, for this code is in
 *	specifications/udas/tunnel-mgr_ds/spec.book
 *
 * Original Author: Gary Malkin
 * Created on: June 14, 1996
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../inc/config.h"
#include "../inc/port/port.h"
#include "../inc/port/install_dir.h"

#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "../inc/erpc/acp_tms.h"
#include "tms.h"

/* This include needs to come after tms.h, which sets USE_NDBM! */
#ifdef USE_NDBM
#include <ndbm.h>
#endif

#ifdef SGI
#include <time.h>
#endif

/*
 * defines
 */
#define TMS_DATABASE "tms-database"	/* ndbm database name */
#define RETRY_TIME 100000		/* microseconds */
#define PID_LEN 8			/* do not mess with this */

#define LOCKNAME_LEN   sizeof(INSTALL_DIR)+9+TMS_DOMAIN_LEN+TMS_DNIS_LEN+5
#define TMS_DBNAME_LEN sizeof(INSTALL_DIR)+5+sizeof(TMS_DATABASE)+1
#define RAS_DBNAME_LEN sizeof(INSTALL_DIR)+9+TMS_DOMAIN_LEN+TMS_DNIS_LEN+4
#define Make_lockname(buf,key) sprintf((buf), "%s/tms/tms-%.64s%.20s-lck", \
				       INSTALL_DIR, \
				       (key)->key_domain, (key)->key_dnis)
#define Make_tms_dbname(buf) sprintf((buf), "%s/tms/%s", \
				     INSTALL_DIR, TMS_DATABASE)
#define Make_ras_dbname(buf,key) sprintf((buf), "%s/tms/tms-%.64s%.20s-db", \
					 INSTALL_DIR, \
					 (key)->key_domain, (key)->key_dnis)

/*
 * externs
 */
extern int debug;		/* defined in erpcd.c and tms_dbm.c */
#if !defined(FREEBSD) && !defined(BSDI) && !defined(LINUX)
extern char *sys_errlist[];	/* errno strings */
#endif

/************************************************************
 *
 * Name:
 *	tms_db_lock
 *
 * Description:
 *	This function creates a lock file for a record.  If
 *	the lock cannot be obtained, an error is returned.
 *
 * Inputs:
 *	key - pointer to key (used to create lock name)
 *
 * Outputs:
 *	0   - file locked
 *	pid - filed locked; pid's lock broken
 *	-1  - file system error
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_lock(key)
  tms_db_key *key;
{
#ifdef USE_NDBM
  char lockfile[LOCKNAME_LEN];
  char old_lockpid[PID_LEN+2], new_lockpid[PID_LEN];
  int  fd, rc, brokeflag = 0;

  /*
   * quick programmer's sanity check
   */
  if (debug) {
    if (PID_LEN != 8)
      printf("CONSISTANCY WARNING ** PID_LEN != 8 ** check printfs\n");
  }

  /*
   * create the lockfile name
   */
  Make_lockname(lockfile, key);
  old_lockpid[0] = '\0';

  /*
   * attempt to create the lock file
   */
  while (1) {
    if (debug)
      printf("<D> tms_db_lock: creating \"%s\" ... ", lockfile);

    if ((fd = open(lockfile, (O_EXCL | O_CREAT | O_RDWR), 0600)) == -1) {
      if (errno != EEXIST) {
	if (debug)
	  printf("fail 1 - %s\n", sys_errlist[errno]);
	return(-1);				/* general failure creating */
      }

      if ((fd = open(lockfile, O_RDWR, 0)) == -1) {
	if (errno == ENOENT) {
	  if (debug)
	    printf("was locked\n");
	  continue;				/* retry right away */
	}
	if (debug)
	  printf("fail 2 - %s\n", sys_errlist[errno]);
	return(-1);				/* general failure opening */
      }
      rc = read(fd, new_lockpid, PID_LEN);
      close(fd);

      if (rc != PID_LEN) {
	if (debug)
	  printf("bad locker PID\n");
	return(-1);
      }

      if (bcmp(old_lockpid, new_lockpid, PID_LEN) == 0) {
	if (debug)
	  printf("breaking lock %.8s\n", new_lockpid);
	brokeflag = 1;
	remove(lockfile);
	continue;				/* retry right away */
      }
      else {
	if (debug)
	  printf("held by %.8s; will retry\n", new_lockpid);
	bcopy(new_lockpid, old_lockpid, PID_LEN);
#ifdef SGI
	{
	timespec_t rqt;
	rqt.tv_sec = 0;
	rqt.tv_nsec = RETRY_TIME * 1000;
	nanosleep(&rqt, NULL);
	}
#elif defined(HP) || defined(SCO) || defined(SCO5)
	sleep(1);		/* very gross, but there's no choice */
#else
	usleep(RETRY_TIME);
#endif
	continue;
      }	
    } /*if*/

    break;
  } /*while*/

  /*
   * put our PID into the file and be done
   */
  sprintf(new_lockpid, "%08x", getpid());
  rc = write(fd, new_lockpid, PID_LEN);
  close(fd);
  if (rc != PID_LEN) {
    if (debug)
      printf("fail 3 - %s\n", sys_errlist[errno]);
    return(-1);
  }
  else
    if (debug)
      printf("success - pid=%08x\n", getpid());

  if (brokeflag) {
    old_lockpid[PID_LEN] = '\0';
    return((int)strtol(old_lockpid, NULL, 16));
  }

  return(0);
#else /* USE_NDBM */
  return(-1);				/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_unlock
 *
 * Description:
 *	This function removes a lock file for a record.  If
 *	the lock had been broken, an indication is returned.
 *
 * Inputs:
 *	key - pointer to key (used to create lock name)
 *
 * Outputs:
 *	0   - file unlocked
 *	pid - lock broken; now held by pid
 *	-1  - lock broken; no longer held
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_unlock(key)
  tms_db_key *key;
{
#ifdef USE_NDBM
  char lockfile[LOCKNAME_LEN];
  char lockpid[PID_LEN+2];
  int  fd, rc;

  /*
   * create the lockfile name
   */
  Make_lockname(lockfile, key);

  /*
   * attempt to open the lock file
   */
  if (debug)
    printf("<D> tms_db_unlock: unlocking \"%s\" ... ", lockfile);

  if ((fd = open(lockfile, O_RDWR, 0)) == -1) {
    if (errno == ENOENT) {
      if (debug)
	printf("was unlocked\n");
      return(-1);
    }
    if (debug)
      printf("fail - %s\n", sys_errlist[errno]);
    return(0);
  }

  /*
   * read the PID out of the lock file
   */
  rc = read(fd, lockpid, PID_LEN);
  close(fd);

  if (rc != PID_LEN) {
    if (debug)
      printf("bad locker PID\n");
    return(0);
  }

  /*
   * check that we are still the owner of the lock
   */
  lockpid[PID_LEN] = '\0';
  rc = (int)strtol(lockpid, NULL, 16);
  if (rc != getpid()) {
    if (debug)
      printf("broken by %s\n", lockpid);
    return(rc);
  }

  /*
   * release the lock and be done
   */
  remove(lockfile);
  if (debug)
    printf("success\n");
  return(0);
#else /* USE_NDBM */
  return(0);
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_add
 *
 * Description:
 *	This function adds a record to the database.
 *
 * Inputs:
 *	key  - pointer to key
 *	data - pointer to data
 *
 * Outputs:
 *	defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_add(key, data)
  tms_db_key *key;
  tms_db_entry *data;
{
#ifdef USE_NDBM
  char	tms_dbname[TMS_DBNAME_LEN];
  char	ras_dbname[RAS_DBNAME_LEN];
  DBM	*dbp;
  datum	keyd, datad;
  int	fd, rc;

  /*
   * create RAS database file for this domain
   */
  Make_ras_dbname(ras_dbname, key);
  if ((fd = open(ras_dbname, (O_EXCL | O_CREAT | O_RDWR), 0600)) == -1) {
    if (errno == EEXIST) {
      if (debug)
	printf("<D> tms_db_add: RAS db \"%s\" exists\n", ras_dbname);
      return(E_EXISTS);
    }
    if (debug)
      printf("<D> tms_db_add: error creating RAS db \"%s\" - %s\n",
	     ras_dbname, sys_errlist[errno]);
    return(E_GENERAL);
  }

  close(fd);
  if (debug)
    printf("<D> tms_db_add: created RAS db \"%s\"\n", ras_dbname);

  /*
   * create database name and open the database
   */
  Make_tms_dbname(tms_dbname);
  if ((dbp = dbm_open(tms_dbname, (O_CREAT | O_RDWR), 0600)) == NULL) {
    if (debug)
      printf("<D> tms_db_add: error opening db \"%s\" - %s\n",
	     tms_dbname, sys_errlist[errno]);
    if (errno == ENOENT)
      return(E_NOTMSDB);
    else
      return(E_GENERAL);
  }
  else
    if (debug)
      printf("<D> tms_db_add: opened db \"%s\"\n", tms_dbname);

  /*
   * prepare the datum elements and ready the database
   */
  keyd.dptr = (char *)key;
  keyd.dsize = sizeof(*key);
  datad.dptr = (char *)data;
  datad.dsize = sizeof(*data);
  dbm_clearerr(dbp);

  /*
   * add the new record
   */
  if (debug)
    printf("<D> tms_db_add: adding \"%.64s/%.20s\" ... ",
	   key->key_domain, key->key_dnis);
  errno = 0;
  rc = dbm_store(dbp, keyd, datad, DBM_INSERT);
  switch (rc) {
  case 0:
    if (debug)
      printf("success\n");
    rc = E_SUCCESS;
    break;
  case 1:
    if (debug)
      printf("entry exists\n");
    rc = E_EXISTS;
    break;
  default:
    if (debug)
      printf("fail - %s\n", sys_errlist[errno]);
    rc = E_GENERAL;
    break;
  }

  /*
   * close the database and be done
   */
  dbm_close(dbp);
  return(rc);
#else /* USE_NDBM */
  return(E_GENERAL);			/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_read
 *
 * Description:
 *	This function reads a record from the database.
 *
 * Inputs:
 *	key    - pointer to key
 *	buffer - pointer to data buffer
 *	ras    - pointer to RAS entry (may be NULL)
 *
 * Outputs:
 *	defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_read(key, buffer, ras)
  tms_db_key *key;
  tms_db_entry *buffer;
  tms_db_ras *ras;
{
#ifdef USE_NDBM
  char	tms_dbname[TMS_DBNAME_LEN];
  char  ras_dbname[RAS_DBNAME_LEN];
  DBM	*dbp;
  datum	keyd, datad;
  int	rc;

  /*
   * create database name and open the database
   */
  Make_tms_dbname(tms_dbname);
  if ((dbp = dbm_open(tms_dbname, O_RDWR, 0600)) == NULL) {
    if (debug)
      printf("<D> tms_db_read: error opening db \"%s\" - %s\n",
	     tms_dbname, sys_errlist[errno]);
    if (errno == ENOENT)
      return(E_NOTMSDB);
    else
      return(E_GENERAL);
  }
  else
    if (debug)
      printf("<D> tms_db_read: opened db \"%s\"\n", tms_dbname);

  /*
   * prepare the key datum element and ready the database
   */
  keyd.dptr = (char *)key;
  keyd.dsize = sizeof(*key);
  dbm_clearerr(dbp);

  /*
   * read the record
   */
  if (debug)
    printf("<D> tms_db_read: reading \"%.64s/%.20s\" ... ",
	   key->key_domain, key->key_dnis);
  datad = dbm_fetch(dbp, keyd);
  if (datad.dptr != NULL) {			/* got a record */
    if (datad.dsize != sizeof(*buffer)) {
      if (debug)
	printf("expected %d bytes, got %d\n", sizeof(*buffer), datad.dsize);
      rc = E_GENERAL;
    }
    else {
      if (debug)
	printf("success\n");
      bcopy(datad.dptr, buffer, sizeof(*buffer));
      rc = E_SUCCESS;
    }
  }
  else {					/* did not get a record */
    if ((rc = dbm_error(dbp)) == 0) {
      if (debug)
	printf("does not exist\n");
      rc = E_NOEXIST;
    }
    else {
      if (debug)
	printf("fail - rc=%d", rc);
      rc = E_GENERAL;
    }
  }

  /*
   * close the database
   */
  dbm_close(dbp);

  /*
   * get requested RAS entry, if any
   */
  if (ras && (rc == E_SUCCESS)) {
    tms_db_ras rasbuff;
    int fd;
    register i;

    if (debug)
      printf("<D> tms_db_read: looking for RAS %s\n",inet_ntoa(ras->ras_addr));

    Make_ras_dbname(ras_dbname, key);
    if ((fd = open(ras_dbname, O_RDWR, 0600)) == -1) {
      if (debug)
	printf("<D> tms_db_read: error opening RAS db \"%s\" - %s\n",
	       ras_dbname, sys_errlist[errno]);
      if (errno == ENOENT)
	return(E_NORASDB);
      else
	return(E_GENERAL);
    }
    if (debug)
      printf("<D> tms_db_read: opened RAS db \"%s\"\n", ras_dbname);

    ras->ras_offset = -1;	/* no match and no empty slot */
    for (i = 0;; i++) {
      if ((rc = read(fd, (char *)(&rasbuff), sizeof(*ras))) != sizeof(*ras)) {
	switch (rc) {
	case -1:
	  if (debug)
	    printf("<D> tms_db_read: error reading - %s\n",sys_errlist[errno]);
	  rc = E_GENERAL;
	  goto read_close;
	case 0:
	  if (debug)
	    printf("<D> tms_db_read: RAS not found - OK\n");
	  ras->ras_count = 0;
	  rc = E_SUCCESS;
	  goto read_close;
	default:
	  if (debug)
	    printf("<D> tms_db_read: expected %d bytes, got %d\n",
		   sizeof(*ras), rc);
	  rc = E_GENERAL;
	  goto read_close;
	}
      } /*if*/

      if (rasbuff.ras_addr.s_addr == 0L) {
	ras->ras_offset = i * sizeof(*ras);	/* found empty slot */
	continue;
      }

      if (ras->ras_addr.s_addr == rasbuff.ras_addr.s_addr) {
	if (debug)
	  printf("<D> tms_db_read: RAS found\n");
	ras->ras_offset = i * sizeof(*ras);
	ras->ras_count = rasbuff.ras_count;
	rc = E_SUCCESS;
	break;
      }
    } /*for*/

read_close:
    close(fd);
  } /*if*/

  return(rc);
#else /* USE_NDBM */
  return(E_GENERAL);				/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_update
 *
 * Description:
 *	This function updates a record in the database.
 *
 * Inputs:
 *	key  - pointer to key
 *	data - pointer to data
 *	ras  - pointer to RAS entry (may be NULL)
 *
 * Outputs:
 *	defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_update(key, data, ras)
  tms_db_key *key;
  tms_db_entry *data;
  tms_db_ras *ras;
{
#ifdef USE_NDBM
  char	tms_dbname[TMS_DBNAME_LEN];
  char  ras_dbname[RAS_DBNAME_LEN];
  DBM	*dbp;
  datum	keyd, datad;
  int	rc;

  /*
   * create database name and open the database
   */
  Make_tms_dbname(tms_dbname);
  if ((dbp = dbm_open(tms_dbname, O_RDWR, 0600)) == NULL) {
    if (debug)
      printf("<D> tms_db_update: error opening db \"%s\" - %s\n",
	     tms_dbname, sys_errlist[errno]);
    if (errno == ENOENT)
      return(E_NOTMSDB);
    else
      return(E_GENERAL);
  }
  else
    if (debug)
      printf("<D> tms_db_update: opened db \"%s\"\n", tms_dbname);

  /*
   * prepare the datum elements and ready the database
   */
  keyd.dptr = (char *)key;
  keyd.dsize = sizeof(*key);
  datad.dptr = (char *)data;
  datad.dsize = sizeof(*data);
  dbm_clearerr(dbp);

  /*
   * update the record
   */
  if (debug)
    printf("<D> tms_db_update: updating \"%.64s/%.20s\" ... ",
	   key->key_domain, key->key_dnis);
  errno = 0;
  rc = dbm_store(dbp, keyd, datad, DBM_REPLACE);
  switch (rc) {
  case 0:
    if (debug)
      printf("success\n");
    rc = E_SUCCESS;
    break;
  default:
    if (debug)
      printf("fail - %s\n", sys_errlist[errno]);
    rc = E_GENERAL;
    break;
  }

  /*
   * close the database
   */
  dbm_close(dbp);

  /*
   * update requested RAS entry, if any
   */
  if (ras && (rc == E_SUCCESS)) {
    tms_db_ras rasbuff;
    int fd;

    if (debug)
      printf("<D> tms_db_update: updating RAS %s at %d\n",
	     inet_ntoa(ras->ras_addr), ras->ras_offset);

    Make_ras_dbname(ras_dbname, key);
    if ((fd = open(ras_dbname, O_RDWR, 0600)) == -1) {
      if (debug)
	printf("<D> tms_db_update: error opening RAS db \"%s\" - %s\n",
	       ras_dbname, sys_errlist[errno]);
      if (errno == ENOENT)
	return(E_NORASDB);
      else
	return(E_GENERAL);
    }
    if (debug)
      printf("<D> tms_db_update: opened RAS db \"%s\"\n", ras_dbname);

    if (ras->ras_offset == -1)
      rc = lseek(fd, 0, SEEK_END);
    else
      rc = lseek(fd, ras->ras_offset, SEEK_SET);
    if (rc == -1) {
      if (debug)
	printf("<D> tms_db_update: error seeking to %d - %s\n",
	       ras->ras_offset, sys_errlist[errno]);
      rc = E_GENERAL;
      goto update_close;
    }
    if (debug)
      printf("<D> tms_db_update: seeked to %d\n", ras->ras_offset);

    if ((rc = write(fd, (char *)ras, sizeof(*ras))) != sizeof(*ras)) {
      if (rc == -1) {
	if (debug)
	  printf("<D> tms_db_update: error writing - %s\n",sys_errlist[errno]);
	rc = E_GENERAL;
	goto update_close;
      }
      if (debug)
	printf("<D> tms_db_update: error writing - rc=%d\n", rc);
      rc = E_GENERAL;
      goto update_close;
    }
    rc = E_SUCCESS;

update_close:
    close(fd);
  } /*if*/

  return(rc);
#else /* USE_NDBM */
  return(E_GENERAL);				/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_rekey
 *
 * Description:
 *	This function changes the domain/DNIS (key) of an
 *	entry in the database.
 *
 * Inputs:
 *	oldkey - pointer to existing key
 *	newkey - pointer to replacement key
 *
 * Outputs:
 *	defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_rekey(oldkey, newkey)
  tms_db_key *oldkey;
  tms_db_key *newkey;
{
#ifdef USE_NDBM
  char	tms_dbname[TMS_DBNAME_LEN];
  char  ras_old_dbname[RAS_DBNAME_LEN];
  char  ras_new_dbname[RAS_DBNAME_LEN];
  DBM	*dbp;
  datum	oldkeyd, newkeyd, datad;
  char	temp[sizeof(tms_db_entry)];
  int	rc;

  /*
   * create database name and open the database
   */
  Make_tms_dbname(tms_dbname);
  if ((dbp = dbm_open(tms_dbname, O_RDWR, 0600)) == NULL) {
    if (debug)
      printf("<D> tms_db_rekey: error opening db \"%s\" - %s\n",
	     tms_dbname, sys_errlist[errno]);
    if (errno == ENOENT)
      return(E_NOTMSDB);
    else
      return(E_GENERAL);
  }
  else
    if (debug)
      printf("<D> tms_db_rekey: opened db \"%s\"\n", tms_dbname);

  /*
   * prepare the key datum elements and ready the database
   */
  oldkeyd.dptr = (char *)oldkey;
  oldkeyd.dsize = sizeof(*oldkey);
  newkeyd.dptr = (char *)newkey;
  newkeyd.dsize = sizeof(*newkey);
  dbm_clearerr(dbp);

  /*
   * read the record under the old key
   */
  if (debug)
    printf("<D> tms_db_rekey: reading \"%.64s/%.20s\" ... ",
	   oldkey->key_domain, oldkey->key_dnis);
  datad = dbm_fetch(dbp, oldkeyd);
  if ((datad.dptr != NULL) && (datad.dsize == sizeof(temp))){ /* got record? */
    if (debug)
      printf("success\n");
    bcopy(datad.dptr, temp, sizeof(temp));	/* because ndbm has a bug */
    datad.dptr = temp;
    rc = E_SUCCESS;
  }
  else {					/* did not get a record */
    if ((rc = dbm_error(dbp)) == 0) {
      if (debug)
	printf("does not exist\n");
      rc = E_NOEXIST;
    }
    else {
      if (debug)
	printf("fail - rc=%d", rc);
      rc = E_GENERAL;
    }
  }
  if (rc != E_SUCCESS)
    goto rekey_close;

  /*
   * add the record under the new key
   */
  if (debug)
    printf("<D> tms_db_rekey: adding \"%.64s/%.20s\" ... ",
	   newkey->key_domain, newkey->key_dnis);
  errno = 0;
  rc = dbm_store(dbp, newkeyd, datad, DBM_INSERT);
  switch (rc) {
  case 0:
    if (debug)
      printf("success\n");
    rc = E_SUCCESS;
    break;
  case 1:
    if (debug)
      printf("entry exists\n");
    rc = E_EXISTS;
    break;
  default:
    if (debug)
      printf("fail - %s\n", sys_errlist[errno]);
    rc = E_GENERAL;
    break;
  }
  if (rc != E_SUCCESS)
    goto rekey_close;

  /*
   * delete the record under the old key
   */
  if (dbm_delete(dbp, oldkeyd) == 0) {
    if (debug)
      printf("<D> tms_db_rekey: deleted \"%.64s/%.20s\"\n",
	     oldkey->key_domain, oldkey->key_dnis);
    rc = E_SUCCESS;
  }
  else {
    if (debug)
      printf("<D> tms_db_rekey: error deleting \"%.64s/%.20s\" - %s\n",
	     oldkey->key_domain, oldkey->key_dnis, sys_errlist[errno]);
    rc = E_GENERAL;
    goto rekey_close;
  }

  /*
   * rename the RAS database file
   */
  Make_ras_dbname(ras_old_dbname, oldkey);
  Make_ras_dbname(ras_new_dbname, newkey);
  if (rename(ras_old_dbname, ras_new_dbname) != 0) {
    if (debug)
      printf("<D> tms_db_rekey: error renaming RAS db - %s\n",
	     sys_errlist[errno]);
    if (errno == ENOENT)
      rc = E_NORASDB;
    else
      rc = E_GENERAL;
  }
  else
    rc = E_SUCCESS;

  /*
   * close the database
   */
rekey_close:
  dbm_close(dbp);
  return(rc);
#else /* USE_NDBM */
  return(E_GENERAL);				/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_delete
 *
 * Description:
 *	This function deletes a record from the database.
 *
 * Inputs:
 *	key - pointer to key
 *
 * Outputs:
 *	defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
tms_db_delete(key)
  tms_db_key *key;
{
#ifdef USE_NDBM
  char	tms_dbname[TMS_DBNAME_LEN];
  char  ras_dbname[RAS_DBNAME_LEN];
  DBM	*dbp;
  datum	keyd, datad;
  int	rc;

  /*
   * create database name and open the database
   */
  Make_tms_dbname(tms_dbname);
  if ((dbp = dbm_open(tms_dbname, O_RDWR, 0600)) == NULL) {
    if (debug)
      printf("<D> tms_db_delete: error opening db \"%s\" - %s\n",
	     tms_dbname, sys_errlist[errno]);
    if (errno == ENOENT)
      return(E_NOTMSDB);
    else
      return(E_GENERAL);
  }
  else
    if (debug)
      printf("<D> tms_db_delete: opened db \"%s\"\n", tms_dbname);

  /*
   * prepare the key datum element and ready the database
   */
  keyd.dptr = (char *)key;
  keyd.dsize = sizeof(*key);
  dbm_clearerr(dbp);

  /*
   * delete the record
   */
  if (debug)
    printf("<D> tms_db_delete: deleting \"%.64s/%.20s\" ... ",
	   key->key_domain, key->key_dnis);
  datad = dbm_fetch(dbp, keyd);
  if (datad.dptr != NULL) {			/* entry exists */
    if (dbm_delete(dbp, keyd) == 0) {
      if (debug)
	printf("success\n");
      rc = E_SUCCESS;
    }
    else {
      if (debug) {
	rc = dbm_error(dbp);
	printf("fail - dbe=%d\n", rc);
      }
      rc = E_GENERAL;
    }
  }
  else {					/* entry does not exist */
    if ((rc = dbm_error(dbp)) == 0) {
      if (debug)
	printf("does not exist\n");
      rc = E_NOEXIST;
    }
    else {
      if (debug)
	printf("fail - rc=%d", rc);
      rc = E_GENERAL;
    }
  }

  /*
   * close the database, zap the RAS database, and be done
   */
  dbm_close(dbp);
  if (rc == E_SUCCESS) {
    Make_ras_dbname(ras_dbname, key);
    remove(ras_dbname);
    if (debug)
      printf("<D> tms_db_delete: removed RAS db \"%s\"\n", ras_dbname);
  }
  else {
    if (debug)
      printf("<D> tms_db_delete: did not remove RAS db\n");
  }
  return(rc);
#else /* USE_NDBM */
  return(E_GENERAL);				/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_domains
 *
 * Description:
 *	This function returns a linked-list of database
 *	domain/dnis pairs (keys).
 *
 * Inputs:
 *	order - sort list by domain if non-zero
 *
 * Outputs:
 *	success    - pointer to first linked-list element
 *	no entries - NULL
 *	error	   - -1
 *
 * Notes:
 *	The elements in the list must be freed by the caller.
 *
 ************************************************************/

key_link *
tms_db_domains(order)
  int order;
{
#ifdef USE_NDBM
  char	tms_dbname[TMS_DBNAME_LEN];
  DBM	*dbp;
  datum	keyd;
  key_link *rootp = NULL, *prevp, *currp;
  int	rc;

  /*
   * create database name and open the database
   */
  Make_tms_dbname(tms_dbname);
  if ((dbp = dbm_open(tms_dbname, O_RDWR, 0600)) == NULL) {
    if (debug)
      printf("<D> tms_db_domains: error opening db \"%s\" - %s\n",
	     tms_dbname, sys_errlist[errno]);
    return((key_link *)(-1));
  }
  else
    if (debug)
      printf("<D> tms_db_domains: opened db \"%s\"\n", tms_dbname);

  /*
   * ready the database
   */
  dbm_clearerr(dbp);

  /*
   * run the database to create the linked-list
   */
  for (keyd = dbm_firstkey(dbp); keyd.dptr != NULL; keyd = dbm_nextkey(dbp)) {
    if ((currp = (key_link *)malloc(sizeof(key_link))) == NULL) {
      if (debug)
	printf("<D> tms_db_domains: insufficient memory\n");
      goto domain_cleanup;
    }

    bcopy(keyd.dptr, (char *)(&currp->entry), keyd.dsize);

    if (order && rootp) {		/* do an insertion sort */
      register i;

      for (prevp = (key_link *)(&rootp); prevp->next; prevp = prevp->next) {
	for (i = 0; i < keyd.dsize; i++)
	  if (*((char*)keyd.dptr+i) != *((char *)(&prevp->next->entry)+i))
	    break;
	if (*((char*)keyd.dptr+i) < *((char *)(&prevp->next->entry)+i))
	  break;
      }
      currp->next = prevp->next;
      prevp->next = currp;
    }
    else {
      currp->next = rootp;
      rootp = currp;
    }
  } /*for*/

  /*
   * make sure we reached the end and didn't get an error
   */
  if ((rc = dbm_error(dbp)) != 0) {
    if (debug)
      printf("<D> tms_db_domains: error running db - %s (rc=%d)\n",
	     sys_errlist[errno], rc);
domain_cleanup:
    while (rootp) {		/* clean up any we got before the error */
      prevp = rootp;
      rootp = rootp->next;
      free(prevp);
    }
    rootp = (key_link *)(-1);
  }

  /*
   * close the database and be done
   */
  dbm_close(dbp);
  return(rootp);
#else /* USE_NDBM */
  return((key_link *)(-1));	/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_rases
 *
 * Description:
 *	This function returns a linked-list of RAS addresses
 *	and user counts for the specified domain/dnis pair (key).
 *
 * Inputs:
 *	key   - pointer to key
 *	order - sort list by domain if non-zero
 *
 * Outputs:
 *	success    - pointer to first linked-list element
 *	no entries - NULL
 *	error	   - -1
 *
 * Notes:
 *	The elements in the list must be freed by the caller.
 *	Empty slots (IP address == 0) are not returned.
 *
 ************************************************************/

ras_link *
tms_db_rases(key, order)
  tms_db_key *key;
  int order;
{
#ifdef USE_NDBM
  char  ras_dbname[RAS_DBNAME_LEN];
  ras_link *rootp = NULL, *prevp, *currp;
  int	fd, rc;

  /*
   * open RAS database file for this domain
   */
  Make_ras_dbname(ras_dbname, key);
  if ((fd = open(ras_dbname, O_RDWR, 0600)) == -1) {
    if (debug)
      printf("<D> tms_db_rases: error opening RAS db \"%s\" - %s\n",
	     ras_dbname, sys_errlist[errno]);
    return((ras_link *)(-1));
  }
  if (debug)
    printf("<D> tms_db_rases: opened RAS db \"%s\"\n", ras_dbname);

  /*
   * read the database to create the linked-list
   */
  while (1) {
    if ((currp = (ras_link *)malloc(sizeof(ras_link))) == NULL) {
      if (debug)
	printf("<D> tms_db_rases: insufficient memory\n");
      break;
    }

    rc = read(fd, (char *)(&currp->entry), sizeof(currp->entry));
    if (rc != sizeof(currp->entry)) {
      free(currp);
      if (rc == 0)
	goto ras_close;
      if (rc == -1) {
	if (debug)
	  printf("<D> tms_db_rases: error reading - %s\n", sys_errlist[errno]);
	break;
      }
      if (debug)
	printf("<D> tms_db_rases: expected %d bytes, got %d\n",
	       sizeof(currp->entry), rc);
      break;
    }

    if (currp->entry.ras_addr.s_addr == 0L) {
      free(currp);			/* don't return empty slots */
      continue;
    }

    if (order && rootp) {		/* do an insertion sort */
      for (prevp = (ras_link *)(&rootp); prevp->next; prevp = prevp->next) {
	if (ntohl(currp->entry.ras_addr.s_addr) <
	    ntohl(prevp->next->entry.ras_addr.s_addr)){
	  currp->next = prevp->next;
	  prevp->next = currp;
	  break;
	}
      }
      if (prevp->next == NULL) {	/* add to end of list */
	currp->next = prevp->next;
	prevp->next = currp;
      }
    }
    else {
      currp->next = rootp;
      rootp = currp;
    }
  } /*while*/

  /*
   * if we're here, we broke out of the while due to an error
   */
  while (rootp) {		/* clean up any we got before the error */
    prevp = rootp;
    rootp = rootp->next;
    free(prevp);
  }
  rootp = (ras_link *)(-1);

  /*
   * close the database and be done
   */
ras_close:
  close(fd);
  return(rootp);
#else /* USE_NDBM */
  return((ras_link *)(-1));	/* general failure */
#endif /* USE_NDBM */
}

/************************************************************
 *
 * Name:
 *	tms_db_rasclear
 *
 * Description:
 *	This function clears the RAS address and user count
 *	information for the specified domain/dnis (key).
 *
 * Inputs:
 *	key - pointer to key
 *
 * Outputs:
 *	defined in tms.h
 *
 * Notes:
 *	The file must be emptied, not deleted; otherwise, the
 *	add, read, modify and delete functions will get errors.
 *
 ************************************************************/

int
tms_db_rasclear(key)
  tms_db_key *key;
{
#ifdef USE_NDBM
  char  ras_dbname[RAS_DBNAME_LEN];
  int	fd;

  /*
   * open RAS database file for this domain
   */
  Make_ras_dbname(ras_dbname, key);
  if ((fd = open(ras_dbname, (O_TRUNC | O_RDWR), 0600)) == -1) {
    if (debug)
      printf("<D> tms_db_rasclear: error opening RAS db \"%s\" - %s\n",
	     ras_dbname, sys_errlist[errno]);
    if (errno == ENOENT)
      return(E_NORASDB);
    else
      return(E_GENERAL);
  }
  if (debug)
    printf("<D> tms_db_rasclear: truncated RAS db \"%s\"\n", ras_dbname);

  /*
   * close (the O_TRUNC did the work) and be done
   */
  close(fd);
  return(E_SUCCESS);
#else /* USE_NDBM */
  return(E_GENERAL);				/* general failure */
#endif /* USE_NDBM */
}
