/*****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Filename: session_db.h  
 *
 * Module Description: Session database definitions
 * 	
 * Design Specification: RADIUS Authorization
 *
 * Author: Dave Mitton
 *
 *
 *****************************************************************************
 */

/*
 *	CONSTANT AND MACRO DEFINES
 *	
 */
#define BAY_TYPE_FILTER             1

#define SDB_SUCCESS                  0
#define SDB_NEW_OK                   0
#define SDB_IGNORE		     1
#define SDB_NOTRADIUS        2
#define SDB_FAILED		    -1
#define SDB_ATTRIBUTE_TOO_LARGE     -2

/* Select type of match */
#define SDB_FINDANY                  0
#define SDB_FINDPORT                 1
#define SDB_FINDACTIVEUSER	     2
#define SDB_FINDSTALEUSER	     3
/* Type of match result */
#define SDB_NO_MATCH                0
#define SDB_CURRENT_MATCH           1
#define SDB_STALE_MATCH             2
#define SDB_PORT_MATCH              3

#undef EXTERN
#ifdef DEFINE_HERE 
#define EXTERN 
#else
#define EXTERN  extern
#endif

#ifdef _
#undef _
#if ((_STDC_ == 1) && (USE_PROTOTYPE == 1))
#define _(x)    x
#else
#define _(x)    ()
#endif
#endif

/*
 *	STRUCTURE AND TYPEDEF DEFINITIONS
 *	
 */
#define SDB_INUSE       0x01	/* record is active session */
#define SDB_ISLOGGEDIN	0x02	/* session is logged in */
#define SDB_HASSTALE    0x08	/* stale session on this port */
#define SDB_USERNAME_SZ   128    /* size of username field */
#define SDB_RADIUS_CLASS_SZ   128    /* size of RADIUS class field */
#define SDB_CALLINF_SZ	32	/* size of call numbers field */


typedef struct profileses {
    u_char          username[SDB_USERNAME_SZ];   /* User name */
    u_char          class[SDB_RADIUS_CLASS_SZ];  /* Class atrib */
    u_char          caller[SDB_CALLINF_SZ];	/* caller number */
    u_char          called[SDB_CALLINF_SZ];	/* Called number */
    time_t          starttime;  /* start of session time stamp */
    struct in_addr  srvaddr;    /* acct server address */
    struct in_addr  ataddr;     /* authorized target address */
    UINT32          sesid;	    /* session id */ 
    u_short         iservice;   /* initial acp service type */
    u_short         aport;      /* authorized tcp port number */
    u_short         actses;     /* active session count */
    u_short         totses;     /* total session count */
    u_char          aservice;   /* authorized radius service */
    u_char          aprotocol;  /* authorized radius protocol */
} SESPROFILE;


/*
 *	Interface Function Definitions
 * 	
 */

EXTERN int ses_open_db _((int numannex, u_short tcpport));
EXTERN void ses_nas_reboot _((UINT32 nasaddr));
EXTERN void ses_nas_down _((UINT32 nasaddr));
EXTERN int ses_new _((struct environment_spec *envp, char *atlistp, struct arq_profile *opt_info));
EXTERN int ses_lookup _((struct environment_spec *envp, struct profileses **sesp, int sflag));
EXTERN int ses_update _((struct environment_spec *envp, struct profileses **sesp, int sflag, int uflag));
EXTERN int ses_get_attribute _((struct environment_spec *envp, struct radius_attribute *attrib, int *offset));
EXTERN int ses_login _((struct environment_spec *envp, struct profileses **sesp,UINT32 logid));
EXTERN int ses_logout _((struct environment_spec *envp, struct profileses **sesp, int event, UINT32 logid));
EXTERN void ses_delete _((struct environment_spec *envp, struct profileses *sesp));
EXTERN void ses_close_db();

