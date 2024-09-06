/*****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Filename: session_dbunx.c
 *
 * Module Description: Unix specific session database functions
 * 	
 * Design Specification: RADIUS Authorization
 *
 * Author: Dave Mitton, Jeff Koniszewski
 *
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *	DESIGN DETAILS
 *
 *	MODULE INITIALIZATION - 
 *	The session db is allocated and initialized on demand by child
 *      processes forked to handle a request.
 *      All children map in only the base memory and the blocks associated 
 *      with the annex specified in their request.
 *       
 *	PERFORMANCE CRITICAL FACTORS - 
 *      This implementation optimizes the performance by storing mappings 
 *      and search results within a process.
 *
 *      RESOURCE USAGE - 
 *		
 *
 *	SIGNAL USAGE -
.
 *
 *      SPECIAL EXECUTION FLOW - 

 *
 * 	SPECIAL ALGORITHMS - 
 *
 ***************************************************************************
 */

/*JKJK GENERAL POSIX ISSUE, keys for memory need to be strings, 9 chars max */

/*
 *	INCLUDE FILES
 */

#include "../inc/config.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "acp.h"
#include "../libannex/api_if.h"
#include "../inc/erpc/nerpcd.h"

#include "radius.h"
#include "environment.h"
#include "session_db.h"

/* This header senses and sets the mode of shared memory */
/* and also instantiates the external interface */
#define DEFINE_HERE
#include "session_db_i.h"
#undef DEFINE_HERE
/*
 *	CONSTANT AND MACRO DEFINES
 *
 */

#define SHM_NAME "/radiusses.shm"       /* section name */
#define SEM_NAME "/radiuswrt.sem"		/* semaphore name */

#define SHM_PATH "acp_regime"           /* key base name - must be an existent file */

#define RETRY_TIME 100000  /* micro seconds */
#define RETRY_MAX  50

static char	appname[] = "RADIUS sesdb";		/* component name for error logging	*/

static int annex_count = 0;  /* number of annexes supported in table */
u_short socket_num = 0;   /* socket number erpcd is running on */


/*
 *	STRUCTURE AND TYPEDEF DEFINITIONS
 *	
 */
typedef long Align;				/* for record alignment calcs */

/*
 *	GLOBAL DATA DECLARATIONS
 */

#ifdef SHMIMP_POSIX
struct sesdb_hdr *shm_start;    /* address of beginning of region */
int shm_size;           /* size of the region */

#else  /*  SHMIMP_SYSV */

key_t sem_key = 0;          /* semaphore key */
int Asemid;		/* Access semaphore id */

union semun ctlinit;	/* arg struct for semctl */
						/* sembuf elements: index, op, flag */
struct sembuf sopwait = {0,-1, SEM_UNDO};	/* wait for semaphore */
struct sembuf soppost = {0, 1, SEM_UNDO};	/* set value to available */


/* This base memory structure is mapped in per process */
SDBBASEMEMCONTROL basemem;

/* This array of blocks is mapped in per process for the Annex generating the request */

SDBRECMEMCONTROL annexmem[SDB_MAX_BLOCKS];


#endif	


/*
 *	STATIC DATA DECLARATIONS
 */

extern int debug;

/*
 *	Forward Function Definitions
 * 	
 */

static int map_in_annex_sdb _((UINT32 nasaddr));
static int map_in _((key_t key, int mem_flag, int mem_loc, int anx_idx));
static int find_sdb_record _((NASPROFILE *nprofile, SESPROFILE *profile, SESREC **rtnrec, int match));
static SESREC * new_sdb_record _((UINT32 nasaddr));
static ANNEXENTRY * lookup_annex _((UINT32 nasaddr, int mem_flag));
static SESREC * update_next_free _((int check));
static int wait_sdb_semaphore _(());
static void post_sdb_semaphore _(());
static key_t newkey _((UINT32 nasaddr, int idx, key_t keyin));


/*****************************************************************************
 *
 * NAME: sesdb_init_db
 *
 * DESCRIPTION: 
 *	Releases any old memory and semaphores
 *      Creates memory semaphore
 *
 * ARGUMENTS:
 *  none
 *
 * RETURN VALUE:
 *    SESDB_SUCCESS or errno (semaphore errno)
 *
 * RESOURCE HANDLING:
 *
 * 
 * SIDE EFFECTS:
 *	
 *            
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *       
 */

int
sesdb_init_db(annexmax, tcpport)
int annexmax;
u_short tcpport;
{

  struct sesdb_hdr *baseptr;
  key_t key;
  int retry = 0;
  int rc;

  if (sem_key){
    /* We've been here already */
    return(SDB_SUCCESS);
  }

  if (debug> 2) {
    printf("%s: init_db entry \n", appname);
  }

  /* save limit on number of annexes */
  annex_count = annexmax;

  /* save socket */
  socket_num = tcpport;

  /* close any preexisting SDB */
  sesdb_close_db();
	
  /* map in the base block */

  /* starting key */
#ifdef SHMIMP_POSIX
  /* JKJK NEEDS INFO FOR POSIX */
#else  /* SHMIP_SYSV */
  key = 1996;
#endif
  
  /* try keys until memory is available */
  retry = 0;
  while (retry < SDB_MAX_KEYS){
    rc = map_in(key, SDB_CREATE_BASE, SDB_BASE_MAP, 0);
    if (rc == SDB_SUCCESS){
      /* sucess */
      break;
    }
    else if (rc == EEXIST){
      /* tried create, some else is using this key, try again */
      key += 111;
      ++retry;
      continue;
    }
    else {
      /* failed to allocate the memory */
      if (debug > 1) 
	printf("%s: Failed base memory allocation, shared memory error = %d \n", appname, rc);
      return(SDB_FAILED);
    }
    
  } /* end while */

  if (retry == SDB_MAX_KEYS){
    /* failed to allocate the memory */
    basemem.key = 0;
    basemem.memid = -1;
    if (debug > 1) 
      printf("%s: Failed base memory allocation, all keys used. \n", appname);
    return(SDB_FAILED);
  }

  if (debug > 8) 
    printf("%s: Base memory id %d created. \n",appname, basemem.memid);


  /* create the Access semaphore */
#ifdef SHMIMP_POSIX
  if (sem_init(&shm_start->Asem, 1,1) == -1) {
#ifdef USE_SYSLOG
    syslog(LOG_CRIT, "%s: Create semaphore, sem_init error %d. No database access.", appname, errno);
#endif
    if (debug)
	perror("SDB:sem_init failed");
    return(errno);
  }
#else  /* SHMIMP_SYSV */
  /* Get the key for the semaphore */
  sem_key = 4321;

  retry = 0;
  while (retry < SDB_MAX_KEYS){
    if ((Asemid = semget(sem_key, 1, (IPC_CREAT|IPC_EXCL|0600))) == -1) {
      if(errno == EEXIST){
	/* try another key */
	++sem_key;
    ++retry;
	continue;
      }
      else {
#ifdef USE_SYSLOG
	syslog(LOG_CRIT, "%s: Create semaphore, semget error %d. No database access.", appname, errno);
#endif
	if(debug)
	  perror("SDB:semget failed");
	/* JKJK FREE BASE MEMORY ?? */
	return errno;
      }
    }
    ctlinit.val = 1;
    if (semctl(Asemid, 0, SETVAL, ctlinit) == -1) {
#ifdef USE_SYSLOG
      syslog(LOG_CRIT, "%s: Set semaphore, semctl error %d. No database access.", appname, errno);
#endif
      if (debug)
	perror("SDB:semctl failed");
      /* JKJK FREE BASE MEMORY ?? */
      return errno;
    }
    break;
  }

  if (retry == SDB_MAX_KEYS) {
      if (debug > 1) 
          printf("%s: Failed to get a semaphore, all keys used. \n", appname);
      return(SDB_FAILED);
  }

  /* save for cleanup */
  baseptr = (struct sesdb_hdr *)basemem.startmem;
  baseptr->Asemid = Asemid;

  if (debug > 8) 
    printf("%s: Semaphore id %d created.\n",appname, Asemid);

#endif
    

  /* unmap the base memory, we don't need it in the parent anymore */
  shmdt((char *)basemem.startmem);
  basemem.startmem = (struct sesdb_hdr *)NULL;

  if (debug> 2) {
    printf("%s: init_db exit \n",appname);
  }
    
  return SDB_SUCCESS;
}
 

/*****************************************************************************
 *
 * NAME: sesdb_nas_reboot
 *
 * DESCRIPTION: 
 *	Clear records on a NAS which has just rebooted
 *
 * ARGUMENTS:
 *  nasaddr - address of NAS that just rebooted
 *
 * RETURN VALUE:
 *	none
 *
 * RESOURCE HANDLING:
 *
 * 
 * SIDE EFFECTS:
 *	(e.g. changes to shared data structres,
 *            unfriendly termination of another task.)
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	 No significant events occur on this Annex before 
 *       initialization is complete.
 */
void
sesdb_nas_reboot(nasaddr)
UINT32 nasaddr;
{
  SESREC *rptr;
  int mem_idx, rec_idx;
  int available = 0;

  /* map in memory for the annex into this process */
  map_in_annex_sdb(nasaddr);
  
  /* clear each memory block */
  for(mem_idx = 0; mem_idx < SDB_MAX_BLOCKS; ++mem_idx){
    if (annexmem[mem_idx].key == 0)
      /* No memory allocated, skip this block */
      continue;
    
    /* clear all records */
    rptr = annexmem[mem_idx].startmem;
    for (rec_idx = 0; rec_idx < SDB_REC_COUNT; ++rec_idx){
      bzero((char *)rptr, sizeof(SESREC)); 
      ++rptr;
    }
    available += SDB_REC_COUNT;
  }

  /* reset the number of available records for the annex */
  if(available && basemem.anxsel)
    basemem.anxsel->available = available;

  return;
}


/*****************************************************************************
 *
 * NAME: sesdb_new_record
 *
 * DESCRIPTION: 
 *	create a new record, and save the attribute block
 *
 * ARGUMENTS:
 *  nprofile - pointer to NAS IP address and port
 *         port should be  (UINT32)port_number + ((UINT32)port_type << 16)
 *  profile - pointer to the user profile to be stored
 *  attributes - pointer to radius message
 *
 * RETURN VALUE:
 *	SDB_SUCCESS - Success; record created, info added
 *      SDB_FAILED - Error occured, no record created
 *
 * RESOURCE HANDLING:
 *	This function allocates(if necessary) and initializes the record.
 *      It sets the SDB_INUSE bit in the status field of the record
 *      and copies the profile (into the current profile) and attributes.
 *      If another record exists on the port, the current profile info is 
 *      moved to the stale profile of the record and the staletime is set
 *      and the SDB_HASSTALE bit is set in the status field.
 *      Any old stale information is lost.
 *	It does update the freelist pointer accordingly.
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 */

int
sesdb_new_record(nprofile, profile, attributes)
NASPROFILE *nprofile;
SESPROFILE *profile;
u_char *attributes;
{
  SESREC *rptr = NULL;
  short tb,len;
  int rc;
  int retry;
  
  if (debug> 2) {
    printf("%s: new_record for [%s] %d '%s' \n", appname, 
	   inet_ntoa(*(struct in_addr *)&nprofile->nasaddr), 
	   nprofile->nasport, profile->username);
  }
  
  /* check attribute length here because, */
  /* undoing the allocation of the record is a pain */
  if ((attributes != NULL) && (*attributes == PW_AUTHENTICATION_ACK)){
    bcopy(attributes+2, &tb, 2);
    len = ntohs(tb);
    if(len > ATTRIB_SIZE){
      /* too big */
      if (debug > 1)
	printf ("%s :length of attributes, %d, greater than %d maximum. \n", appname, len, ATTRIB_SIZE);
      return(SDB_FAILED);
    }
  }

  /* map in EXISTING memory for the annex into this process */
  /* Annex blocks are NOT allocated, and the entry in */
  /* the base table is NOT created by this call */
  map_in_annex_sdb(nprofile->nasaddr);

  if(!basemem.startmem)
    return(SDB_FAILED);

  /* Loop controls waiting for record not in Use */
  retry = 0;
  while(1){
    if (wait_sdb_semaphore() == SDB_FAILED)
      return(SDB_FAILED);
  
    if(basemem.anxsel){
      /* There is an entry in the base table for this annex */
      /* Is there an existing record ON THIS PORT? */
      /* The search always feeds in the results of the last search */
      rc = find_sdb_record(nprofile, profile, &rptr, SDB_FINDPORT);
    }
  
    if (rptr){
      if(++retry == SDB_MAX_INUSE){
#ifdef USE_SYSLOG
	syslog(LOG_WARNING, "%s: Creating new record, freed stuck in use record.", appname);
#endif
	/* it's stuck */
	--rptr->Use;
      }

      if(rptr->Use){
	/* The record is in use, wait until its available */
	/* JKJK MAX RETRY?? */
	post_sdb_semaphore();
	sleep(1);
	continue;
      }

      /* There is an existing session, not in Use */
      /* Stale the old information */
      rptr->status |= SDB_HASSTALE;
      rptr->staletime = profile->starttime;
      bcopy(&rptr->current, &rptr->stale, sizeof(SESPROFILE));
      break;
    }
    else {
      /* No existing session, this call will allocate annex  */
      /* memory if needed */
      rptr = new_sdb_record(nprofile->nasaddr);
      if(rptr == NULL){
	if (debug > 1)
	  printf ("%s :New SDB record allocation failed. \n", appname);
	post_sdb_semaphore();
	return(SDB_FAILED);
      }
      /* nasport copied in */
      rptr->nasport = nprofile->nasport;
      break;
    }
      
  }
  
  /* copy in the new profile */
  bcopy(profile, &rptr->current, sizeof(SESPROFILE));      

  /* copy attributes into the record */
  if ((attributes != NULL) && (*attributes == PW_AUTHENTICATION_ACK)){
    bcopy(attributes, rptr->attributes, len);
  }
      
  post_sdb_semaphore();

  if (debug > 2)
    printf("%s: new_record success exit\n", appname);
  
  return (SDB_SUCCESS);
}

/*****************************************************************************
 *
 * NAME: sesdb_find_record
 *
 * DESCRIPTION: 
 *	Find a record in the database
 *
 * ARGUMENTS:
 *  nprofile - pointer to NAS IP address and port
 *         port should be  (UINT32)port_number + ((UINT32)port_type << 16)
 *  profile - pointer to the user profile to be matched
 *  rtnprofile - ptr to ptr to current or stale profile matched, rtn NULL if port match
 *  rtnattrib -  ptr to ptr to attributes if current profile matched
 *  rtnrecord -  ptr to ptr to matched record 
 *                          (arguement for sesdb_release_record)
 *  fflag - SDB_FINDANY(0)       = NAS,Port, User match Current or Stale record
 *                  (returns first match: checks current first, then stale )
 *          SDB_FINDPORT(1)      = NAS,Port only match
 *          SDB_FINDACTIVEUSER(2)= NAS,Port,User match, check Current record only
 *	    SDB_FINDSTALEUSER(3) = NAS,Port,User match, check Stale record only
 * RETURN VALUE: Type of match found
 *	SDB_PORT_MATCH, SDB_CURRENT_MATCH, SDB_STALE_MATCH, SDB_NO_MATCH
 *
 * RESOURCE HANDLING:
 *	ANY CALL TO THIS FUNCTION WILL LOCK THE MATCHING RECORD UNTIL 
 *      THE CALLER FOLLOWS UP WITH A sesdb_release_record CALL. THE CALLER 
 *      SHOULD NOT MAKE ANY OTHER sesdb_ CALLS UNTIL THE RECORD IS RELEASED.
 * 
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *      only one record will port match,
 *	Always check the current profile and then the stale profile. 
 */

int
sesdb_find_record(nprofile, profile, rtnprofile, rtnattrib, rtnrecord, fflag)
NASPROFILE *nprofile;
SESPROFILE *profile;
SESPROFILE **rtnprofile;
u_char **rtnattrib;
SESREC **rtnrecord;
int fflag; 
{
  ANNEXENTRY *anxtbl;
  SESREC *rptr = NULL;
  int rc;
  /* JKJKthe next two lines may be removed after checked in code is shown to stable */
  int lastblock, lastrec;
  ANNEXENTRY aentry;

  if (debug> 2) {
    printf("%s: find_record for [%s] %d '%s'  flg=%i\n", appname, 
	   inet_ntoa(*(struct in_addr *)&nprofile->nasaddr), 
	   nprofile->nasport, profile->username, fflag);
  }

  /* map in memory for the annex into this process */
  rc = map_in_annex_sdb(nprofile->nasaddr);

  /* success?? */
  if (rc == SDB_FAILED)
    /* No memory = no match */
    return(SDB_NO_MATCH);

  if (wait_sdb_semaphore() == SDB_FAILED)
    return(SDB_NO_MATCH);

  /* Optimize find by checking the last found for this annex */
  /* If it matches, we're done, otherwise, the find routine checks */
  /* all the records for a match anyway. */
  if(basemem.anxsel && (basemem.anxsel->nasaddr == nprofile->nasaddr)){
    anxtbl = basemem.anxsel;
    if((anxtbl->lastfindblock != -1) && (anxtbl->lastfindrec != -1)){
      /* JKJKthe next three lines may be removed after checked in code is shown to stable */
      lastblock = anxtbl->lastfindblock;
      lastrec = anxtbl->lastfindrec;
      bcopy(anxtbl, &aentry, sizeof(ANNEXENTRY));
      rptr = annexmem[anxtbl->lastfindblock].startmem;
      rptr += (anxtbl->lastfindrec);
    }
  }

  /* Is there an existing record for this profile? */
  rc = find_sdb_record(nprofile, profile, &rptr, fflag);

  if(rc != SDB_NO_MATCH) {
    /* found a match */
    /* bump Use counter */
    ++rptr->Use;
    /* safe to release the semaphore now */
    post_sdb_semaphore();
    if(rtnattrib)
      *rtnattrib = NULL;
    if (rc == SDB_CURRENT_MATCH){
      /* return the current profile and attributes */
      *rtnprofile = &rptr->current;
      if(rtnattrib)
	*rtnattrib = &rptr->attributes[0];
    }
    else if (rc == SDB_STALE_MATCH){
      /* return the stale profile */
      *rtnprofile = &rptr->stale;
    }
    else {
      /* NULL profile on port match */
      *rtnprofile = NULL;
    }
    /* return the record pointer, needed for sesdb_release_record */
    *rtnrecord = rptr;
  }
  else {
    /* Failed search, clear all return info */
    /* release the semaphore now */
    post_sdb_semaphore();
    *rtnprofile = NULL;
    if (rtnattrib)
      *rtnattrib = NULL;
    *rtnrecord = NULL;
  }

  if (debug > 2)
    printf("%s: find_record exit\n", appname);

  return rc;
}




/*****************************************************************************
 *
 * NAME: sesdb_release_record
 *
 * DESCRIPTION: 
 *	releases a record found by sesdb_find_record
 *
 * ARGUMENTS:
 *  rptr - pointer to record to release
 *
 * RETURN VALUE:
 *	SDB_SUCCESS, SDB_FAILED
 *
 * RESOURCE HANDLING:
 *   	
 * 
 * SIDE EFFECTS:
*
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	 
 */



int
sesdb_release_record(rptr)
SESREC *rptr;
{

  /* check pointer */
  if (rptr == NULL)
    return(SDB_FAILED);

  if (debug> 2) {
    printf("%s: release_record entry \n",appname);
  }

  /* The memory should be mapped in from the sdb_find_record call */
  if (!annexmem[0].key)
    /* No memory */
    return(SDB_FAILED);

  if (wait_sdb_semaphore() == SDB_FAILED)
    return(SDB_FAILED);

  --rptr->Use;

  post_sdb_semaphore();

  if (debug > 2)
    printf("%s: release_record exit\n", appname);

  return(SDB_SUCCESS);
}

/*****************************************************************************
 *
 * NAME: sesdb_del_record
 *
 * DESCRIPTION: 
 *	delete a record from the db
 *
 * ARGUMENTS:
 *  nprofile - pointer to NAS IP address and port
 *         port should be  (UINT32)port_number + ((UINT32)port_type << 16)
 *  profile - pointer to the user profile to be matched
 *
 * RETURN VALUE:
 *	SDB_SUCCESS, SDB_FAILED
 *
 * RESOURCE HANDLING:
 *   records are deleted by clearing the sdb->status SDB_INUSE bit	
 * 
 * SIDE EFFECTS:
 *   Deleting an active record Deletes the stale, the record is cleared
 *   Deleting a stale record, clears the SDB_HASSTALE bit in the status field
 *      and clears the stale profile 
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	 
 */

int 
sesdb_del_record(nprofile, profile)
NASPROFILE *nprofile;
SESPROFILE *profile;
{
  SESREC *rptr = NULL;
  ANNEXENTRY *anxtbl;
  int rc;
  int retry;
  /* JKJKthe next two lines may be removed after checked in code is shown to stable */
  int lastblock, lastrec;
  ANNEXENTRY aentry;

  if (debug> 2) {
    printf("%s: del_record for [%s] %d '%s' \n", appname, 
	   inet_ntoa(*(struct in_addr *)&nprofile->nasaddr), 
	   nprofile->nasport, profile->username);
  }

  /* map in memory for the annex into this process */
  rc = map_in_annex_sdb(nprofile->nasaddr);

  /* success?? */
  if (rc == SDB_FAILED){
    /* No memory = no match */
    return(SDB_FAILED);
  }

  retry = 0;
  while(1){
    if (wait_sdb_semaphore() == SDB_FAILED){
      return(SDB_FAILED);
    }

    /* Optimize delete by checking the last found for this annex */
    /* If it matches, we're done, otherwise, the find routine checks */
    /* all the records for a match anyway. */
    /* This is for the first pass only */
    if(!retry && basemem.anxsel && (basemem.anxsel->nasaddr == nprofile->nasaddr)){
      anxtbl = basemem.anxsel;
      if((anxtbl->lastfindblock != -1) && (anxtbl->lastfindrec != -1)){
	/* JKJKthe next three lines may be removed after checked in code is shown to stable */
	lastblock = anxtbl->lastfindblock;
	lastrec = anxtbl->lastfindrec;
	bcopy(anxtbl, &aentry, sizeof(ANNEXENTRY));
	rptr = annexmem[anxtbl->lastfindblock].startmem;
	rptr += (anxtbl->lastfindrec);
      }
    }

    /* Is there an existing record for this profile? */
    /* The search always feeds in the results of the last search */
    rc = find_sdb_record(nprofile, profile, &rptr, SDB_FINDANY);

    if(rc != SDB_NO_MATCH) {
      /* check match of in use */
      if((rptr->Use) && (++retry == SDB_MAX_INUSE)){
#ifdef USE_SYSLOG
	syslog(LOG_WARNING, "%s: Deleting record, freed stuck in use record.", appname);
#endif
	/* stuck */
	--rptr->Use;
      }
      if (rptr->Use){
	/* The record is in use, wait until its available */
	/* JKJK MAX RETRY?? */
	post_sdb_semaphore();
	sleep(1);
	continue;
      }
      else
	break;
    }
    else {
      /* no match, can process */
      break;
    }
  }

  /* if is a stale match, just clear the stale area */
  if(rc == SDB_STALE_MATCH){
    /* clear the status bit */
    rptr->status &= ~SDB_HASSTALE;
    rptr->staletime = 0;
    bzero((char *)&rptr->stale, sizeof(SESPROFILE)); 
  }
  else if (rc == SDB_CURRENT_MATCH){
    /* Current match, Blow it all away */
    bzero((char *)rptr, sizeof(SESREC));
    /* bump the available record count for the annex */
    ++basemem.anxsel->available;
    update_next_free(SDB_CHECK_FIND);
  }
      
  post_sdb_semaphore();

  if (debug > 2)
    printf("%s: del_record exit\n", appname);

  if(rc == SDB_NO_MATCH)
    return(SDB_FAILED);
  else
    return(SDB_SUCCESS);
}


/*****************************************************************************
 *
 * NAME: sesdb_close_db
 *
 * DESCRIPTION: 
 *	Close the data base
 *
 * ARGUMENTS:
 *  none
 *
 * RETURN VALUE:
 *	none, failure is not an option ;-)
 *
 * RESOURCE HANDLING:
 *  deletes the semaphore
 *  unlinks/detachs/destroys all annex memory regions and the base region
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	 as erpcd is 
 *      not exited in a controlled manner this is called as part of the init
 */

void 
sesdb_close_db()
{
  struct sesdb_hdr *baseptr;
  ANNEXENTRY *anxtbl;
  int memid;
  key_t key;
  int i, j;
  int shm_size;
  int shm_id;
  struct sesdb_hdr *shm_start;
  int retry;
  char teststr[10];

  /* map in the base memory */
  if(basemem.key)
    map_in(basemem.key, SDB_NO_CREATE_MEM, SDB_BASE_MAP, 0);
  else {
    /* Try to remove any previously existing SDB */
#ifdef SHMIMP_POSIX

    /* JKJK NEEDS TWEEKING FOR POSIX, needs names */
    /* JKJK CALCULATE KEY AS IN map_in FUNCTION */

#else  /* SHMIP_SYSV */
    /* map in any existing base */
    key = 1996;
    shm_size = sizeof (struct sesdb_hdr) + (sizeof(ANNEXENTRY) * annex_count);

    retry = 0;
    while(++retry < SDB_MAX_KEYS){
      shm_id = shmget(key, shm_size, (0600));
      if (shm_id == -1) {
          if (errno == ENOSPC) {
#ifdef USE_SYSLOG
              syslog(LOG_WARNING, "%s: Map base memory failed, shmat error %d. Database cleanup fails.",
                     appname, errno);
#endif
              if (debug)
                  perror("SDB:shmget failure");
              return;
          }
	/* no luck, try the next */
	key += 111;
	continue;
      }
      else {
	/* got an ID, is it SDB */
	/* map memory and remember start pointer */
	shm_start = (void *) shmat(shm_id, (void *)NULL, 0);
	if (shm_start == (void *)-1) {
#ifdef USE_SYSLOG
	  syslog(LOG_WARNING, "%s: Map base memory failed, shmat error %d. Database cleanup fails.", appname, errno);
#endif
	  if (debug)
	    perror("SDB:shmat failure");
	  return;
	}
	sprintf(teststr, "SDB%d", socket_num);
	if (!strcmp(shm_start, teststr)){
	  /* SDB match */
	  break;
	}
	else{
	  /* not SDB, unmap and try again */
	    shmdt((char *)shm_start);	  
	  key += 111;
	  continue;
	}
      }
    }

    /* Unsuccessfully did the shmget */
    if (retry == SDB_MAX_KEYS) {
        if (debug > 1)
            printf("sesdb_close_db failure, max retries.  Database cleanup fails.");
#ifdef USE_SYSLOG
        syslog(LOG_CRIT, "%s: Map base memory failed, max retries.  Database cleanup fails.",
               appname);
#endif
        key = 0;
        shm_start = (void *)-1;
    }
    
    basemem.key = key;
    basemem.memid = shm_id;
    basemem.startmem = (struct sesdb_hdr *)shm_start;
    basemem.anxsel = NULL;
#endif
  }

  if(basemem.memid == -1)
    /* no base, no other memory either */
    return;
  else {
    baseptr = (struct sesdb_hdr *)basemem.startmem;
    anxtbl = baseptr->annex_table;
    /* get the semaphore ID for cleanup */
    Asemid = baseptr->Asemid;
  }

  for(i = 0; i < annex_count; ++i){
    if (anxtbl[i].nasaddr){
      /* It's ALIVE, KILL IT */
      for(j = 0; j < SDB_MAX_BLOCKS; ++j){
	/* JKJK THIS IS BRUTAL, NO CHECK IF ANY RECORD IS IN USE */
	/* PROBLEM, HOW TO ONLY REMOVE REGION IF NOT IN USE BUT */
	/* PREVENT NEW USERS FROM STARTING UP */
#ifdef SMHIMP_POSIX
	/* JKJK NEEDS SAME TYPE OF STUFF AS SYS V */
	(void)shm_unlink(SHM_NAME);		       /* unlink shm area */
	(void)shm_unmap((void *)shm_start, shm_size);  /* destroy the region */
	
#else /* SHMIMP_SYSV */
	if (anxtbl[i].memkey[j]){
	  if (anxtbl[i].memkey[j] == annexmem[j].key){
	    /* This annex has been mapped into this process */
	    /* detach the region */
	    shmdt((char *)annexmem[j].startmem);
	    shm_id = annexmem[j].memid;
	  }
	  else {
	    /* Not mapped in */
	    /* need the ID for this region */
	    shm_size = sizeof(SESREC) * SDB_REC_COUNT;
            shm_id = shmget(anxtbl[i].memkey[j], shm_size, 0600);
          if (shm_id == -1) {
              if (errno == ENOSPC) {
#ifdef USE_SYSLOG
                  syslog(LOG_WARNING, "%s: Map base memory failed, shmat error %d. Database cleanup fails.",
                         appname, errno);
#endif
                  if (debug)
                      perror("SDB:shmget failure");
                  return;
              }
          }
	  }
	  /* remove the region */ 
	  shmctl(shm_id, IPC_RMID, NULL);
	}
#endif
      }
    }
  }

#ifdef SMHIMP_POSIX
  /* JKJK NEEDS SAME TYPE OF STUFF AS SYS V */
  (void)shm_unlink(SHM_NAME);		       /* unlink shm area */
  (void)shm_unmap((void *)shm_start, shm_size);  /* destroy the region */
#else /* SHMIMP_SYSV */
  /* unmap and remove the base region */ 
  shmdt((char *)basemem.startmem);
  shmctl(basemem.memid, IPC_RMID, NULL);
#endif

  /* destroy semaphore */
#ifdef SMHIMP_POSIX
  /* JKJK SHOULD CHECK IF EXISTS BEFORE DELETE ?? */
  (void)sem_destroy(&shm_start->Asem);
#else /* SHMIMP_SYSV */
  if(Asemid)
    semctl(Asemid, 0, IPC_RMID, NULL);
  Asemid = 0;
  sem_key = 0;
#endif

  /* Clear all reference structures */
  bzero(&basemem, sizeof(SDBBASEMEMCONTROL));
  basemem.memid = -1;
  for(i = 0; i < SDB_MAX_BLOCKS; ++i){
    bzero((char *)&annexmem[i], sizeof(SDBRECMEMCONTROL));
  }

  return;
}


/*****************************************************************************
 *
 * NAME: sesdb_connect
 *
 * DESCRIPTION: 
 *	Flag annex disconnect/reconnect
 *         if down, save the current time in the base table discon_time entry
 *         if up, set base table discon_time entry to 0
 *
 * ARGUMENTS:
 *  UINT32 nasaddr - IP address of the annex
 *  int  status - SDB_CONNECTION_DOWN, SDB_CONNECTION_UP
 *
 * RETURN VALUE:
 *	none
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

void 
sesdb_connect(nasaddr, status)
UINT32 nasaddr;
int status;
{
  ANNEXENTRY *anxtbl;

  /* map in EXISTING memory for the annex into this process */
  /* Annex blocks are NOT allocated, and the entry in */
  /* the base table is NOT created by this call */
  map_in_annex_sdb(nasaddr);

  if(!basemem.startmem)
    return;

  /* find the table entry */
  anxtbl = lookup_annex(nasaddr, SDB_NO_CREATE_MEM);
  if(anxtbl == NULL){
    /* The table entry should have been created */
    /*    when Base memory was mapped in */
    if (debug > 1) 
      printf("%s: No entry in annex table \n", appname);
    return;
  }
  if (status == SDB_CONNECTION_DOWN)
    anxtbl->discon_time = time(NULL);
  else if (status == SDB_CONNECTION_UP)
    anxtbl->discon_time = 0;

  return;
}


/*****************************************************************************
 *
 * NAME: find_sdb_record
 *
 * DESCRIPTION: locates a matching record in the SDB
 *     
 *
 * ARGUMENTS:
 *    
 *  
 *
 * RETURN VALUE:
 *	  SDB_PORT_MATCH, SDB_CURRENT_MATCH, SDB_STALE_MATCH, SDB_NO_MATCH 
 *
 * RESOURCE HANDLING:
 *	
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static int find_sdb_record(nprofile, profile, rtnrec, match)
NASPROFILE *nprofile;
SESPROFILE *profile;
SESREC **rtnrec;
int match;
{
  SESREC *recptr;
  int i,j;

  /* The memory is already mapped in */

  /* If rtnrec points to a record, check it first */
  if (*rtnrec){
    recptr = *rtnrec;
    if ((recptr->status & SDB_INUSE) && (recptr->nasport == nprofile->nasport)){
      if (match == SDB_FINDPORT){
	return(SDB_PORT_MATCH);
      }
      else {
	/* check current user */
	if ((match != SDB_FINDSTALEUSER) && !strcmp(recptr->current.username, profile->username))
	  return(SDB_CURRENT_MATCH);
	if((match != SDB_FINDACTIVEUSER) && (recptr->status & SDB_HASSTALE) &&
	   (!strcmp(recptr->stale.username, profile->username)))
	  return(SDB_STALE_MATCH);
      }
    }
  }
  /* Old record no longer matches, restart the search */
  *rtnrec = NULL;
  basemem.anxsel->lastfindblock = -1;
  basemem.anxsel->lastfindrec = -1;

  /* check each block of memory, each INUSE record, current and stale */
  for (i = 0; i < SDB_MAX_BLOCKS; ++i) {
    if (annexmem[i].key == 0){
      /* block not mapped, all done */
      break;
    }
    recptr = annexmem[i].startmem;
    for(j = 0; j < SDB_REC_COUNT; ++j) {
      if (!(recptr->status & SDB_INUSE) || (recptr->nasport != nprofile->nasport)){
	/* Not in use or wrong port, check next */
	++recptr;
	continue;
      }

      /* save return info as if everythings OK */
      *rtnrec = recptr;
      basemem.anxsel->lastfindblock = i;
      basemem.anxsel->lastfindrec = j;

      /* Port match! If all we check is the port, return now */
      if (match == SDB_FINDPORT){
	return(SDB_PORT_MATCH);
      }
      /* if not checking stale only, check the current user */
      if ((match != SDB_FINDSTALEUSER) && 
	  !strcmp(recptr->current.username, profile->username)){
	/* same current user */
	return(SDB_CURRENT_MATCH);
      }
      /* if not checking current only, check the stale user */
      if((match != SDB_FINDACTIVEUSER) && recptr->status & SDB_HASSTALE){
	if (!strcmp(recptr->stale.username, profile->username)){
	  /* same user */
	  return(SDB_STALE_MATCH);
	}
      }
      /* No match, there should not be another entry with this port, so we're done */
      /* Clear the returned match info */
      *rtnrec = NULL;
      basemem.anxsel->lastfindblock = -1;
      basemem.anxsel->lastfindrec = -1;
      
      return(SDB_NO_MATCH);
    } /* for each record */
  } /* for each memory block */

  /* No matches found for this annex */
  return(SDB_NO_MATCH);
}

/*****************************************************************************
 *
 * NAME: new_sdb_record
 *
 * DESCRIPTION: Allocates a new record, if necessary, adds new annex memory 
 *    block.
 *     
 *
 * ARGUMENTS: none
 *  
 *
 * RETURN VALUE: pointer to the allocated record
 *	   
 *
 * RESOURCE HANDLING:
 *	Sets the INUSE bit in the record status field
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	The available annex memory is already mapped in.
 *      
 */

static SESREC * new_sdb_record(nasaddr) 
UINT32 nasaddr;
{
  ANNEXENTRY *anxtbl;
  key_t key;
  SESREC *rptr;
  int rc, retry;

  /* find the table entry */
  anxtbl = lookup_annex(nasaddr, SDB_CREATE_ANNEX);
  if(anxtbl == NULL){
    /* The table entry should have been created */
    /*    when Base memory was mapped in */
    if (debug > 1) 
      printf("%s: No entry in annex table \n", appname);
    return((SESREC *)NULL);
  }

  /* are any free records available? */
  if (anxtbl->available == 0){
    /* No, can a new block be allocated? */
    if(anxtbl->allocated < SDB_MAX_BLOCKS){
      key = 0;
      retry = 0;
      key = newkey(nasaddr, anxtbl->allocated, key);
      if (key == 0) {
          /* Unable to generate a unique key */
          return((SESREC *)NULL);
      }
      while (++retry < SDB_MAX_INUSE) {
	/* loop until a block is allocated */
	/* yes, generate a key */
	rc = map_in(key, SDB_CREATE_ANNEX, SDB_ANNEX_MAP, anxtbl->allocated);
	if (rc == SDB_SUCCESS){
	  /* sucess */
	  break;
	}
	else if (rc == EEXIST){
	  /* some else is using this key, try again */
	  ++key;
	  continue;
	}
	else {
	  /* failed to allocate the memory */
	  if (debug > 1) 
	    printf("%s: Failed record allocation, shared memory error = %d \n", appname, rc);
	  return((SESREC *)NULL);
	}
      }
      
      if (retry == SDB_MAX_INUSE) {
          if (debug > 1) 
              printf("%s: Failed record allocation, shared memory error = %d \n", appname, rc);
          return((SESREC *)NULL);
      }

      /* save the allocated blocks key */
      anxtbl->memkey[anxtbl->allocated] = key;
      /* set the next free to the first in this block */
      anxtbl->freeblock = anxtbl->allocated;
      anxtbl->freerec = 0;
      ++anxtbl->allocated;
      anxtbl->available += SDB_REC_COUNT;
    }
    else {
      /* max blocks, fatal error, no more room */
      if (debug > 1) 
	printf("%s: Maximum blocks in annex table \n", appname);
      return((SESREC *)NULL);
    }
  }

  /* Now assured of available records, check the next free locator */ 
  /* if available, update next free, and return */
  if((anxtbl->freerec != -1) && (annexmem[anxtbl->freeblock].startmem)){
    rptr = annexmem[anxtbl->freeblock].startmem;
    rptr += (anxtbl->freerec);
    if (!(rptr->status & SDB_INUSE)){
      bzero((char *)rptr, sizeof(SESREC));
      rptr->status |= SDB_INUSE;
      --anxtbl->available;
      /* setup the next free record */
      update_next_free(NULL);
      return(rptr);
    }
  }

  /* not available, find next free (1), update next free (2), return (1)*/
  rptr = update_next_free(NULL);
  if(rptr == NULL){
      if (debug > 1) 
          printf("%s: No free records \n", appname);
      return((SESREC *)NULL);
  }
  else {
      /* update fields */
      rptr->status |= SDB_INUSE;
      --anxtbl->available;
  }
  /* setup next free record */
  update_next_free(NULL);
  /* return the record found */
  return(rptr);
}

/*****************************************************************************
 *
 * NAME: lookup_annex
 *
 * DESCRIPTION: Find the annex in the annex table. If the mem_flag is 
 *     SDB_CREATE_BASE or SDB_CREATE_ANNEX allocate an entry in the 
 *     annex table for this annex.
 *     
 *
 * ARGUMENTS: nasaddr - the IP address of the annex
 *  
 *
 * RETURN VALUE:
 *	  pointer to an entry in the annex table, NULL if annex IP address
 *         not matched
 *
 * RESOURCE HANDLING:
 *	
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 * Base memory is already mapped in     
 */

static ANNEXENTRY * lookup_annex(nasaddr, mem_flag)
UINT32 nasaddr;
int mem_flag;
{
  struct sesdb_hdr *baseptr;
  ANNEXENTRY *anxtbl;
  ANNEXENTRY *nextopen = NULL;
  time_t cur_time;
  int shm_size;
  int shm_id;
  int i, j;

  
  if(!basemem.startmem)
    /* no base, no other memory either */
    return(NULL);
  else if(basemem.anxsel && (basemem.anxsel->nasaddr == nasaddr)){
    /* been here before, use the last lookup */
    return(basemem.anxsel);
  }
  else{
    /* start a lookup */
    baseptr = (struct sesdb_hdr *)basemem.startmem;
    anxtbl = baseptr->annex_table;
  }

  cur_time = time(NULL);
  for(i = 0; i < annex_count; ++i){
    if (anxtbl[i].nasaddr == nasaddr){
      /* Got it */
      /* save table entry ptr for easy access */
      basemem.anxsel = &anxtbl[i];
      /* if it's been asked for, it's in use */
      anxtbl[i].discon_time = 0;
      return(&anxtbl[i]);
    }
    else if(!nextopen && !anxtbl[i].nasaddr){
      nextopen = &anxtbl[i];
    }
    /* check the entry for long disconnect */
    if(anxtbl[i].nasaddr && anxtbl[i].discon_time && 
       (cur_time - anxtbl[i].discon_time > SDB_MAX_DISCONNECT)){
      /* Annex has been disconnected quite a while, drop it */
      for(j = 0; j < SDB_MAX_BLOCKS; ++j){
#ifdef SMHIMP_POSIX
	/* JKJK NEEDS SAME TYPE OF STUFF AS SYS V */
	(void)shm_unlink(SHM_NAME);		       /* unlink shm area */
	(void)shm_unmap((void *)shm_start, shm_size);  /* destroy the region */
	
#else /* SHMIMP_SYSV */
	if (anxtbl[i].memkey[j]){
	  /* need the ID for this region */
	  shm_size = sizeof(SESREC) * SDB_REC_COUNT;
	  shm_id = shmget(anxtbl[i].memkey[j], shm_size, 0600);
      if (shm_id == -1) {
          if (errno == ENOSPC) {
              if (debug)
                  perror("SDB:shmget failure");
              return(NULL);
          }
      }
	}
	/* remove the region */ 
	shmctl(shm_id, IPC_RMID, NULL);
#endif
      }
      bzero((char *)&anxtbl[i], sizeof(ANNEXENTRY));
      if(!nextopen){
	/* next available in the table */
	nextopen = &anxtbl[i];
      }
    }
  }

  if ((mem_flag == SDB_CREATE_ANNEX) && (nextopen)){
    /* Need to create an entry */

    /* Initialize the record */
    bzero((char *)nextopen, sizeof(ANNEXENTRY));
    nextopen->nasaddr = nasaddr;
    nextopen->freeblock = -1;
    nextopen->freerec = -1;
    nextopen->lastfindblock = -1;
    nextopen->lastfindrec = -1;

    /* Save for access w/o lookup */
    basemem.anxsel = nextopen;

    return(nextopen);
  }

  /* No match and none available */
  basemem.anxsel = NULL;
  return(NULL);
}

/*****************************************************************************
 *
 * NAME: update_next_free
 *
 * DESCRIPTION: sets the next free pointer to the next available record
 *      This is recorded in block/record index manner so it can be located  
 *      across processes.
 *     
 *
 * ARGUMENTS: none
 *  
 *
 * RETURN VALUE:
 *	  0 = OK, -1 = failed 
 *
 * RESOURCE HANDLING:
 *	
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static SESREC * update_next_free(check)
int check;
{

  SESREC *rptr;
  ANNEXENTRY *anxtbl;
  int i,j;
  

  if(!basemem.anxsel){
    if (debug > 1) 
      printf("%s: Can't update free, no annex table entry \n", appname);
    return((SESREC *)NULL);
  }
  anxtbl = basemem.anxsel;

  /* Use the results from the last find? (used by del record) */
  if((check == SDB_CHECK_FIND) && (anxtbl->lastfindblock != -1) && (anxtbl->lastfindrec != -1)){
    /* if the last found block and record is less than the current next free, use last found */ 
    if ((anxtbl->freeblock == -1) || (anxtbl->freerec == -1) ||
	(anxtbl->lastfindblock < anxtbl->freeblock) ||
	((anxtbl->lastfindblock == anxtbl->freeblock) && 
	 (anxtbl->lastfindrec < anxtbl->freerec))){
      /* need to generate a pointer and verify record not in use */
      rptr = annexmem[anxtbl->lastfindblock].startmem;
      rptr += (anxtbl->lastfindrec);
      if (!(rptr->status & SDB_INUSE)){
	/* use the last find */
	anxtbl->freeblock = anxtbl->lastfindblock;
	anxtbl->freerec = anxtbl->lastfindrec;
	return(rptr);
      }
    }
  } 

  /* Plow through them until a free one is found */
  rptr = NULL;

  /* check each block of memory for not INUSE record */
  for (i = 0; i < SDB_MAX_BLOCKS; ++i) {
    if (annexmem[i].key == 0){
      /* block not mapped, all done */
      break;
    }
    rptr = annexmem[i].startmem;
    for(j = 0; j < SDB_REC_COUNT; ++j) {
      if(!(rptr->status & SDB_INUSE)){
	anxtbl->freeblock = i;
	anxtbl->freerec = j;
	return(rptr);
      }
      ++rptr;
    }
  }

  /* Couldn't get one now */
  /* That's OK, when we really need it, we'll allocate new memory */
  anxtbl->freeblock = -1;
  anxtbl->freerec = -1;
  return(NULL);
}


/*****************************************************************************
 *
 * NAME: wait_sdb_semaphore
 *
 * DESCRIPTION: waits for semaphore access
 *     
 *
 * ARGUMENTS: none
 *  
 *
 * RETURN VALUE:
 *	  0 = OK, -1 = failed 
 *
 * RESOURCE HANDLING:
 *	
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static int wait_sdb_semaphore() {
    int rc;
    int retry;
    
    for (retry = 0; retry < RETRY_MAX; retry++) {
        rc = SDB_SUCCESS;
        errno = 0;
        
        /* wait for access semaphore */
#ifdef SHMIMP_POSIX
        rc = sem_wait(&shm_start->Asem);
#else  /* SHMIMP_SYSV */
        rc = semop(Asemid, &sopwait, 1);
#endif
 
        if (rc == -1) {
            if (errno == EINTR) {
#if defined(HP) || defined(SCO) || defined(SCO5)
                sleep(1);               /* very gross, but there's no choice */
#else
                usleep(RETRY_TIME);
#endif
                continue;
            }

#ifdef USE_SYSLOG
            syslog(LOG_WARNING, "%s: Get semaphore failed, semop error %d.", appname, errno);
#endif
            if (debug)
                perror ("SDB:get semaphore failebd");
            return(SDB_FAILED);
        }
        
        return (SDB_SUCCESS);
    }
    
    /* Hit max retries */
    return(SDB_FAILED);
}


/*****************************************************************************
 *
 * NAME: post_sdb_semaphore
 *
 * DESCRIPTION: Releases the Access semaphore
 *     
 *
 * ARGUMENTS:none
 *  
 *
 * RETURN VALUE:
 *	none
 *
 * RESOURCE HANDLING:
 *	
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static void post_sdb_semaphore() {
    int rc;
    int retry;
  
    for (retry = 0; retry < RETRY_MAX; retry++) {
        rc = SDB_SUCCESS; /* OK */
        errno = 0;
      
#ifdef SHMIMP_POSIX
        rc = sem_post(&shm_start->Asem);     /* post write semaphore */
#else /* SHMIMP_SYSV */
        rc = semop(Asemid, &soppost, 1);
#endif
        if (rc == -1) {
            if (errno == EINTR) {
#if defined(HP) || defined(SCO) || defined(SCO5)
                sleep(1);               /* very gross, but there's no choice */
#else
                usleep(RETRY_TIME);
#endif
                continue;
            }
            
            break;
        }
        
        if (debug > 2) {
            printf("      ...semaphore released \n");
        }
        
        return;
    }
    
    /* Hit max retries */
#ifdef USE_SYSLOG
    syslog(LOG_CRIT, "%s: Post semaphore failed, semop error %d.", appname, errno);
#endif
}

/*****************************************************************************
 *
 * NAME: map_in_annex_sdb
 *
 * DESCRIPTION: Maps in the memory for the base region and the specified annex. 
 *  If it has already been mapped in for this process, nothing else is needed.
 *     
 *
 * ARGUMENTS:
 *  nasaddr - IP address of the annex, for lookup in the annex table
 *
 * RETURN VALUE:
 *	SDB_SUCCESS, SDB_FAILED
 *
 * RESOURCE HANDLING:
 *	can allocate shared memory blocks 
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static int map_in_annex_sdb(nasaddr)
UINT32 nasaddr;
{
  ANNEXENTRY *anxtbl;
  int i;
  int mapped_cnt = 0;
  int rc;
  int retry = 0;

  if(!basemem.key)
    /* base memory not allocated in init */
    return(SDB_FAILED);

  /* The basemem structure key and ID are already initialized. */
  /* If not mapped into this process, attach the base block */
  if(!basemem.startmem){
    rc = map_in(basemem.key, SDB_NO_CREATE_MEM, SDB_BASE_MAP, 0);
    if (rc != SDB_SUCCESS){
      /* failed to map in the base memory */
      if (debug > 1) 
	printf("%s: Failed base memory map, shared memory error = %d \n", appname, rc);
      return(SDB_FAILED);
    }
  }
    
  /* get the information for this annex */
  anxtbl = lookup_annex(nasaddr, SDB_NO_CREATE_MEM);
  if (anxtbl == NULL){
    /* no entries for this annex */
    return(SDB_FAILED);
  }

  /* Map in each block */
  for(i = 0; i < SDB_MAX_BLOCKS; ++i){
    /* is there a key, and has it been mapped in for this process already?? */
    if (anxtbl->memkey[i] && (anxtbl->memkey[i] != annexmem[i].key)){
      rc = map_in(anxtbl->memkey[i], SDB_NO_CREATE_MEM, SDB_ANNEX_MAP, i);
      if(rc != SDB_SUCCESS){
	/* couldn't map in memory, try next block */
	/* JKJK SHOULD CONSIDER MAP FAILURE AS FATAL FOR WHOLE ANNEX??, OTHERWISE HOLES IN THE DB */
	if (debug > 1) 
	  printf("%s: Failed annex block %d map, shared memory error = %d \n", appname, i, rc);
	annexmem[i].key = (key_t)0;
	annexmem[i].memid = -1;
	annexmem[i].startmem = (SESREC *)NULL;
	continue;
      }
    }
    else if(!anxtbl->memkey[i]){
      /* no key, mark annex memory block unused */
      annexmem[i].key = (key_t)0;
      annexmem[i].memid = -1;
      annexmem[i].startmem = (SESREC *)NULL;
    }
  }
  return(SDB_SUCCESS);
}

/*****************************************************************************
 *
 * NAME: map_in
 *
 * DESCRIPTION: Actual shared memory calls for mapping in memory. Fills in the 
 * appropriate memory control structure (key, memid, startmem).
 *  
 *     
 *
 * ARGUMENTS:
 *  key - key for the memory area to be mapped in
 *  mem_flag - if the base or annex memory does not exist,
 *             SDB_CREATE_BASE or SDB_CREATE_ANNEX = create it.
 *             SDB_NO_CREATE_MEM = do not create it
 *  mem_loc  - SDB_BASE_MAP = this is the base memory block
 *             SDB_ANNEX_MAP = this is an annex memory block
 *  anx_idx  - index of the annex memory block
 *  mask     - if not 0, do not print shmget errors
 *
 * RETURN VALUE:
 *	SDB_SUCCESS, SDB_FAILED
 *
 * RESOURCE HANDLING:
 *	can allocate shared memory blocks 
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static int 
map_in (key, mem_flag, mem_loc, anx_idx)
key_t key;
int mem_flag;
int mem_loc;
int anx_idx;
{

  int shm_id;
  int shm_size;
  void *shm_start;
  struct sesdb_hdr *baseptr;
  char em[80];

#ifdef SHMIMP_POSIX
/* JKJK NEEDS WORK */
  /* open or create (mem_flag) the region and size it */
  if ((mem_flag == SDB_CREATE_BASE) || (mem_flag == SDB_CREATE_ANNEX))
    shm_id = shm_open(SHM_NAME, O_RDWR, S_IRWXU);
  else
    /* JKJK NEED ARGUEMENTS FOR OPEN, NO CREATE */
    shm_id = shm_open(SHM_NAME, O_RDWR, S_IRWXU);

  if (shm_id == -1) {
#ifdef USE_SYSLOG
    syslog(LOG_CRIT, "%s: Open shared memory failed, shm_open error %d. No database access.", appname, errno);
#endif
    if (debug)  
      perror("SDB:shm_open failed:");
    return errno;
  }
  if (ftruncate(shm_id, MYSHMSIZE) < 0) { 
#ifdef USE_SYSLOG
    syslog(LOG_CRIT, "%s: Set shared memory size failed, ftruncate error %d. No database access.", appname, errno);
#endif
    if (debug)
      perror("SDB:ftruncate failed:");            
    return errno;
  }
  
  /* map memory and remember start pointer */
  if ((shm_start = 
       (void *)mmap(0, shm_size, (PROT_READ|PROT_WRITE), MAP_SHARED, 
				shm_id, (long)0)) == (caddr_t)-1) {
#ifdef USE_SYSLOG
    syslog(LOG_WARNING, "%s: Map shared memory failed, mmap error %d", appname, errno);
#endif
    if(debug)
      perror("SDB:mmap failed:");
    return errno;
  }
#else  /* SHMIP_SYSV */
  /* open or create (mem_flag) the region */
  /* size the memory */
  if (mem_loc == SDB_BASE_MAP){
    shm_size = sizeof (struct sesdb_hdr) + (sizeof(ANNEXENTRY) * annex_count);
  }
  else if (mem_loc == SDB_ANNEX_MAP){
    shm_size = sizeof(SESREC) * SDB_REC_COUNT;
  }
  if ((mem_flag == SDB_CREATE_BASE) || (mem_flag == SDB_CREATE_ANNEX)){
    /* Create the memory, exclusively for erpcd */
    shm_id = shmget(key, shm_size, (IPC_CREAT|IPC_EXCL|0600));
    /* If EEXIST, caller will have to handle by issuing a new key JKJK */
    if (shm_id == -1) {
      if(errno != EEXIST){
	if(mem_flag == SDB_CREATE_BASE){
#ifdef USE_SYSLOG
	  syslog(LOG_CRIT, "%s: Create base shared memory failed, shmget error %d. No database access.", appname, errno);
#endif
	  if (debug)
	    perror("SDB:shmget failure creating base");
	}
	else {
#ifdef USE_SYSLOG
	  syslog(LOG_CRIT, "%s: Create annex shared memory failed, shmget error %d. No database access.", appname, errno);
#endif
	  if (debug)
	    perror("SDB:shmget failure creating annex");
	}
      }
      return errno;
    }
  }
  else {
    if(mem_loc == SDB_ANNEX_MAP){
      /* Get erpcd memory ID for this annex */
      shm_id = shmget(key, shm_size, (0600));
      if (shm_id == -1) {
#ifdef USE_SYSLOG
	syslog(LOG_WARNING, "%s: Get shared memory key %d failed, shmget error %d", appname, key, errno);
#endif
	if (debug){
	  sprintf(em, "SDB:shmget failure getting annex key %d.\n", key);
	  perror(em);
	}
	return errno;
      }
    }
    else{
      /* base memory ID is always available after created */
      shm_id = basemem.memid;
    }
  }

  /* map memory and remember start pointer */
  shm_start = (void *) shmat(shm_id, (void *)NULL, 0);
  if (shm_start == (void *)-1) {
#ifdef USE_SYSLOG
    syslog(LOG_WARNING, "%s: Map shared memory failed, shmat error %d, memory ID %d", appname, errno, shm_id);
#endif
    if (debug)
      perror("SDB:shmat failure");
    return errno;
  }

#endif

  if (mem_loc == SDB_BASE_MAP){
    if ((mem_flag == SDB_CREATE_BASE)){
      /* Created the base memory, do special setup */
      baseptr = (struct sesdb_hdr *)shm_start;
      /* init the signature field */
      sprintf(baseptr->signature, "SDB%d", socket_num);
      /* save the semaphore key for cleanup */
#ifdef SHMIMP_POSIX
      /* JKJK NEED STUFF HERE */
#else
      /* save the key and ID on creation */
      /* all forked processes will inherit it */
      basemem.key = key;
      basemem.memid = shm_id;
#endif
    }

    /* save info in the base control */
    basemem.startmem = (struct sesdb_hdr *)shm_start;
    basemem.anxsel = NULL;
  }
  else if (mem_loc == SDB_ANNEX_MAP){
    /* save info in the annex control */
    annexmem[anx_idx].key = key;
    annexmem[anx_idx].memid = shm_id;
    annexmem[anx_idx].startmem = (SESREC *)shm_start;
  }

  return(SDB_SUCCESS);

}



#ifdef SHMIMP_POSIX
/*****************************************************************************
 *
 * NAME: newkey
 *
 * DESCRIPTION: Generates a key string  to be used to identify a shared memory 
 * block. The key string is of the form "SDB_n_m", where n is the annex index
 * (0 -> n_max) and m is the index (0 -> m_max) of the block being allocated. 
 * Ex. SDB_3_2 is for the 4th annex in the list (0,1,2,3), and the 3rd block 
 * for that annex (0,1,2).
 *     
 *
 * ARGUMENTS:
 *   annex - in
 *
 * RETURN VALUE:
 *     
 *
 * RESOURCE HANDLING:
 *	 
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static int newkey(nasaddr, idx, keyin, shm_name)
int annex;
int block;
char *shm_name;
{
  sprintf(shm_name, "%s_%d_%d", "SDB", annex, block);
}

#else  /* SHMIMP_SYSV */


/*****************************************************************************
 *
 * NAME: newkey
 *
 * DESCRIPTION: Generates a integer key to be used to identify a shared memory 
 * block. Also verifies that the key is not used in this program. If a suggested
 * key is passed in, the key is checked and returned if not in use.
 *  
 *     
 *
 * ARGUMENTS:
 *   nasaddr - IP address os annex, used as base for the key
 *   idx - which annex block the key is for, used to figure an offset
 *   keyin - suggested key value
 *
 * RETURN VALUE:
 *     key, 0 if failed
 *
 * RESOURCE HANDLING:
 *	 
 *  
 * 
 * SIDE EFFECTS:
 *	
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *	
 *      
 */

static key_t newkey(nasaddr, idx, keyin)
UINT32 nasaddr;
int idx;
key_t keyin;
{
 
  struct sesdb_hdr *baseptr;
  ANNEXENTRY *anxtbl;
  int i, j, rc;
  key_t key;

  baseptr = (struct sesdb_hdr *)basemem.startmem;

  /* use suggestion or seed the key */
  if (!keyin)
    key = (key_t)((nasaddr & 0x00ffffff) + (idx * 100));
  else
    key = keyin;

  rc = 0;
  /* Check all allocated blocks for key in use */
  while (rc == 0){

    anxtbl = baseptr->annex_table;

    rc = 1;
    for(i = 0; i < annex_count; ++i){
      if (anxtbl[i].nasaddr){
	/* Annex entry in use, check it */
	for(j = 0; j < SDB_MAX_BLOCKS; ++j){
	  if (anxtbl[i].memkey[j] && (anxtbl[i].memkey[j] == key)){
	    /* This key is in use already */
	    rc = 0;
	    ++key;
	    break; /* inner for */
	  }
	}
      }
      else {
	/* check the next annex */
	continue;
      }
      if (rc == 0){
	/* key in use, stop checking */
	break; /* outer for */
      }
    }
  }
  
  /* No match, unique key */
  return(key);
}
#endif


