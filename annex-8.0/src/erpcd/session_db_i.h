/*****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Filename: session_db_i.h  
 *
 * Module Description: Session database internal definitions
 * 	
 * Design Specification: RADIUS Authorization
 *
 * Author: Dave Mitton
 *
 *
 *****************************************************************************
 */

#include <unistd.h>
#include <sys/types.h>

#if 0
/* #if defined (_POSIX_SHARED_MEMORY_OBJECTS) && defined (_POSIX_SEMAPHORES) */
#define SHMIMP_POSIX         /* remember what type we're going to use */
#include <sys/mman.h>  
#include <semaphore.h>
#else 
/* can we test for this somehow? currently will not work on BSD only systems */
/* #undef _POSIX_C_SOURCE /* don't fool the headers */
#define SHMIMP_SYSV				/* system v only */
#include <sys/ipc.h>
#include <sys/shm.h>
#ifdef LINUX
#define _I386_BITOPS_H   /* prevent buggy header include */
#endif
#include <sys/sem.h>
#endif

 
/* conditional extern stuff */
#undef EXTERN
#ifdef DEFINE_HERE 
#define EXTERN 
#else
#define EXTERN  extern
#endif

/* conditional prototypes */
#ifdef _
#undef _
#if ((_STDC_ == 1) && (USE_PROTOTYPE == 1))
#define _(x)    x
#else
#define _(x)    ()
#endif
#endif

/* union semun is already defined on SunOS, LINUX, FreeBSD and SGI Irix */
#if (!defined(SUN) || defined(SYS_V)) && !defined(LINUX) \
    && !defined(FREEBSD) && !defined(SGI) && !defined(BSDI)
typedef union semun {
    int val;
    struct semid_ds *buf;
    ushort *array;
};
#endif

/* internal session db interface between generic and system specific */

#define SDB_RECORD_SIZE             1536	/* Always allocate in even nos*/
#define SDB_MAX_BLOCKS              4		/* blocks per annex */
#define SDB_REC_COUNT               32		/* records per block */
/* #define SDB_MAX_ATR_SIZE          1024 */
#define SDB_MAX_KEYS                 10
#define SDB_MAX_INUSE               15

/* Memory control */
#define SDB_CREATE_BASE             1
#define SDB_CREATE_ANNEX            2
#define SDB_NO_CREATE_MEM           3
#define SDB_BASE_MAP                1
#define SDB_ANNEX_MAP               2
/* Update last free control */
#define SDB_CHECK_FIND              1

/* connection status */
#define SDB_CONNECTION_DOWN         1
#define SDB_CONNECTION_UP           2
#define SDB_MAX_DISCONNECT          1800    /* 30 minutes */

typedef struct profilenas {
  UINT32 nasaddr;       /* Annex IP address */
  UINT32 nasport;               /* Annex port type & unit */
} NASPROFILE;

/* try to get each record to be 1024+512 bytes */
#define ATTRIB_SIZE SDB_RECORD_SIZE-sizeof(int)-sizeof(int)-sizeof(UINT32)-sizeof(time_t)-sizeof(SESPROFILE)-sizeof(SESPROFILE)

typedef struct sesdbrec {
    int		    status;     /* status bits {INUSE, HASSTALE} */
    int             Use;        /* Active readers counter */
    UINT32	    nasport;    /* Annex port type & unit */
    time_t          staletime;  /* time when staled */
    SESPROFILE      current;    /* Current session profile */
    SESPROFILE      stale;      /* Stale session profile */
    u_char          attributes[ATTRIB_SIZE];   /* JKJK SIZE THIS BETTER RADIUS attributes received */
} SESREC;

/* Annex Table */
typedef struct annex_entry {
  UINT32 nasaddr;
  key_t memkey[SDB_MAX_BLOCKS];
  int allocated;
  int available;
  time_t discon_time;
  int freeblock;      /* Init as -1 */
  int freerec;      /* Init as -1 */
  int lastfindblock;      /* Init as -1 */
  int lastfindrec;      /* Init as -1 */
}ANNEXENTRY;

typedef struct bmemcontrol {
  key_t key;
  int memid;
  struct sesdb_hdr *startmem;
  /*only used by base memory table */
  /* Used by the update free to easily find the next free record */
  ANNEXENTRY *anxsel; /* points to annex table entry currently in use, NULL not in use */
} SDBBASEMEMCONTROL;

typedef struct rmemcontrol {
  key_t key;
  int memid;
  SESREC *startmem;
} SDBRECMEMCONTROL;

/* Base memory section header */
struct sesdb_hdr {
  char signature[10];
  int Asemid; /* semaphore key */
#ifdef SHMIMP_POSIX
    sem_t wsem;       /* writer semaphore */
#else /* SHMIMP_SYSV */
    int	wsem;		/* writer semaphore stand-in */
#endif
  /* playing a little game here. This table size is defined */
  /* on init. Just define the first element here and allocate */
  /* the needed memeory when we know how big it is */
    ANNEXENTRY annex_table[1];
} BASE;


/* Interface Function Definitions */

EXTERN int sesdb_init_db _((int annexmax, u_short tcpport));
EXTERN void sesdb_nas_reboot _((UINT32 nasaddr));
EXTERN int sesdb_new_record _((NASPROFILE *nprofile, SESPROFILE *profile, char *attributes));
EXTERN int sesdb_find_record _((NASPROFILE *nprofile, SESPROFILE *profile, SESPROFILE **rtnprofile, char **rtnattrib, SESREC **rtnrec, int fflag));
EXTERN int sesdb_release_record _((SESREC *rptr));
EXTERN int sesdb_del_record _((NASPROFILE *nprofile, SESPROFILE *profile));
EXTERN void sesdb_close_db();
EXTERN void sesdb_connect _((UINT32 nasaddr, int status));
