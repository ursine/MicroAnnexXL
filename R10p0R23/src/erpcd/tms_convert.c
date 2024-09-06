/*
 *        Copyright 1997, Bay Networks.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Bay Networks.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.  Unauthorized
 * duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains the source code for the TMS database conversion
 *	utility.  It will find the most recent version of the database in
 *	use, and create the latest version (which the latest ERPCD uses).
 *
 * Original Author: Gary Malkin
 * Created on: April 16, 1997
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../inc/vers.h"
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
#include "acp_policy.h"		/* For def'n of PATHSZ */

/* This include needs to come after tms.h, which sets USE_NDBM! */
#ifdef USE_NDBM
#include <ndbm.h>
#endif


/*
 * defines
 */
#define TMS_DATABASE "tms-database"	/* old ndbm database name */
#define TMS_ROOTDIR  "tms"		/* TMS directory name */
#define OLD_DOMAIN_LEN 48


/*
 * externs
 */
int debug = 0;				/* tms_lib needs this */

#if !defined(FREEBSD) && !defined(BSDI)
extern char *sys_errlist[];		/* errno strings */
#endif


#ifndef USE_NDBM
main()
{
  fprintf(stderr, "DBM is not enabled, so TMS is not available\n");
  exit(0);
}
#else


main(argc, argv)
int argc;
char **argv;
{
  char	buffer[PATHSZ + 1];
  char	tms_dirname[PATHSZ + 1];
  struct stat statbuf;
  DBM	*dbp;
  datum	keyd, datad;
  tms_db_key key;
  tms_db_entry entry;
  int	rc;
  int   ret;

  /*
   * create old database name and open the database
   */
  sprintf(buffer, "%s/%s", INSTALL_DIR, TMS_DATABASE);
  sprintf(tms_dirname, "%s/%s", INSTALL_DIR, TMS_ROOTDIR);

  if ((dbp = dbm_open(buffer, O_RDONLY, 0600)) == NULL) {
    fprintf(stderr, "Error opening db \"%s\" - %s\n",
	    buffer, sys_errlist[errno]);
    exit(errno);
  }

  /*
   * ready the database
   */
  dbm_clearerr(dbp);
  bzero(key.key_domain, TMS_DOMAIN_LEN);

  /*
   * run the database to create the linked-list
   */
  for (keyd = dbm_firstkey(dbp); keyd.dptr != NULL; keyd = dbm_nextkey(dbp)) {

    bcopy(keyd.dptr, key.key_domain, OLD_DOMAIN_LEN);
    bcopy(keyd.dptr+OLD_DOMAIN_LEN, key.key_dnis, TMS_DNIS_LEN);

    /*
     * read the record
     */
    datad = dbm_fetch(dbp, keyd);
    if (datad.dptr == NULL) {			/* did not get a record */
      fprintf(stderr, "Empty record for %.48s/%.20s\nConversion incomplete\n",
	      key.key_domain, key.key_dnis);
      exit(1);
    }

    /*
     * create the new record
     */
    bcopy(datad.dptr, (char *)&entry, datad.dsize);
    entry.td_addr_proto = 0;		/* no default addr resolution proto */
    entry.td_paddr_addr.s_addr = 0L;	/* no default primary addr res srvr */
    entry.td_saddr_addr.s_addr = 0L;	/* no default secondary addr res srvr*/
    entry.td_tunnel_type = TG_TUTYPE_DVS;
    if (entry.td_auth_proto == TG_AUTHP_ACP)
      entry.td_server_loc = TG_SRVLOC_LOCAL;
    else
      entry.td_server_loc = TG_SRVLOC_REMOTE;
    bzero(entry.td_passwd, sizeof(entry.td_passwd));

    /*
     * add the new record to the new database
     */
    if ((rc = tms_db_add(&key, &entry)) != E_SUCCESS) {
      fprintf(stderr, "Error %d adding %.48s/%.20s\nConversion incomplete\n",
	      rc, key.key_domain, key.key_dnis);
      exit(rc);
    }
  } /*for*/

  /*
   * make sure we reached the end and didn't get an error
   */
  if ((rc = dbm_error(dbp)) != 0) {
    fprintf(stderr, "Error running db - %s (rc=%d)\nConversion incomplete\n",
	     sys_errlist[errno], rc);
    exit(rc);
  }

  /*
   * close the database
   */
  dbm_close(dbp);

  /* Create the database directory if necessary */
  if((ret = stat(tms_dirname, &statbuf)) && (errno == ENOENT)) {
	if(mkdir(tms_dirname, 0755)) {
		fprintf(stderr, "Error creating database directory %s.\n",
			tms_dirname);
		perror("mkdir");
		exit(1);
	}
  } else if(ret) {
		fprintf(stderr, "Error looking for database directory %s.\n",
			tms_dirname);
		perror("stat");
		exit(1);
  } else if(!S_ISDIR(statbuf.st_mode)) 
		fprintf(stderr, "Error - %s is not a directory.\n",
			tms_dirname, ret, errno);
	
  /*
   * handle the RAS database files
   */
  sprintf(buffer, "%s %s/tms-*-db %s/%s",
	  (((argc == 2) && (strcmp(*argv, "-m") == 0)) ? "mv" : "cp"),
	  INSTALL_DIR, INSTALL_DIR, TMS_ROOTDIR);
  if ((rc = system(buffer)) != 0)
    fprintf(stderr, "Error %s RAS database files\nConvert incomplete\n",
	    ((*buffer == 'm') ? "moving" : "copying"));
  else
    printf("Convert completed successfully\n");

  return(rc);
}
#endif
