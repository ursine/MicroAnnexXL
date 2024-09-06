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
 * File description:  ACP user profile Support routines
 *
 * Original Author: Richard G. Bockenek		Created on: 2/22/93
 *
 ****************************************************************************
 */





/*
 ****************************************************************************
 *
 *
 *				NOTES
 *
 *
 * Lexical Analysis
 *
 *   An ACP token is a string ending in any of the following separators:
 *   " \t,{}\\\r\n"
 *
 *   The '\' quote character does the usual thing.  A single '\' is removed
 *   from the token and the next character is not.  Two consecutive quotes
 *   results in a single '\' in the token.  Tokens can span input lines by 
 *   quoting the EOL characters '\r' or '\n'.  Note, however, that the EOL
 *   itself is discarded and *not* included in the token string.  The '#'
 *   comment character causes the profile reader to discard all characters 
 *   to the end of the line, including any continuation lines.  The reason {
 *   and } are included is to allow users to take advantage of editor
 *   block-sensitivity.
 *
 *
 * Parsing
 *
 *   The ACP parser views its input as a token stream with no constraints
 *   on typographical format.  This stream is read sequentually until the 
 *   end of file is reached.  Each token is fed through an FSM-based parser
 *   which generates an action and a state transition.
 *
 *   Within constructed objects (user, access and atzone), command/argument
 *   pairs may arrive in any order or be omitted entirely.  Also command 
 *   names need not be prohibited for use as argument values -- the parser 
 *   distinquishes commands from arguments based on state.
 *
 *   Well-formed user records are compiled into user profile structs and
 *   added to the database.  Parser warnings are issued if a syntactically
 *   correct but otherwise dubious or duplicate user record is encountered.
 *   Parser errors are issued if a syntax error is encountered.  In the case
 *   of error, the parser continues compiling in order to report additional
 *   errors, but a database is not generated.
 *
 *
 * Notes on the following parser FSM:
 *
 *   - The token <other> means any token not listed as an expected token
 *     in the given state.
 *
 *   - The next state <same> means no state transition.
 *
 *   - The next state <pop> means the state previous to the current.
 *
 *   - The initial state is Idle.
 *
 *
 * FSM
 *
 *	STATE   TOKEN	   NEXT-STATE	DESCRIPTION OF ACTION
 *
 *	Idle    user	   User		Start a new user profile record,
 *					the next token is the username.
 *
 *		pool	   Pool		Start a new port pool record,
 *					the next token is the poolname.
 *
 *              %include   filename     Open up an included file and continue
 *
 *		<other>	   Recover	Start error recovery
 *
 *      User	accesscode Acc		Start a new accesscode record,
 *					the next token is the access code
 *
 *		at_callback <same>	The following token is an at
 *					callback number
 *
 *		at_passwd   <same>	The following token is an ARAP
 *					password
 *
 *		at_zone    Zone		Start a new atzone record
 *
 *		at_connect_time <same>	The following token is the connect
 *					time in minutes.
 *
 *		blacklist  <same>	The following token is blacklist
 *					`max value'
 *
 *		climask    Climask	Start a new cli mask record
 *
 *		clicmd     Clicmd	Start a new cli cmd record
 *
 *		filter     Filter	Start a new filter definition
 *
 *		route      Route	Start a static route definition
 *
 *		local_address <same>	The following token is the local
 *					IP address of the slip or ppp link.
 *
 *              mp_max_links            The following token is the maximum
 *                                      number of links within an MP bundle.
 *
 *		remote_address <same>	The following token is the remote
 *					IP address of the slip or ppp link.
 *
 *		subnet_mask <same>	The following token is the subnet
 *					mask of the interface.
 *
 *              %include   filename     Open up an included file and continue
 *
 *		end	   <pop>	End of user record
 *
 *		<other>	   Recover	Start error recovery
 *
 *	Access	in_pool	   <same>	The following token is an input
 *					pool name
 *
 *		out_pool   <same>	The following token is an output
 *					pool name
 *
 *		phone_no   <same>	The following token is a callback
 *					number
 *
 *		job	   Job		Start of job record
 *
 *              %include   filename     Open up an included file and continue
 *              
 *		end	   <pop>	End of access record
 *
 *		<other>	   Recover	Start error recovery
 *
 *	Job	end	   <pop>	End of job record
 *
 *		<other>    <same>	Job token
 *
 *	Zone	end	   <pop>	End of at zone
 *
 *		<other>	   <same>	Zone token
 *
 *	Climask	end	   <pop>	End of climask state
 *
 *		<other>	   <same>	cli mask token
 *
 *	Clicmd	end	   <pop>	End of clicmd state
 *
 *		<other>	   <same>	cli cmd token
 *
 *	Filter	end	   <pop>	End of filter state
 *
 *		<other>	   <same>	cli cmd token
 *
 *              %include   filename     Open up and included file and continue
 *
 *	Route	end	   <pop>	End of route state
 *
 *              %include   filename     Open up and included file and continue
 *
 *		<other>	   <same>	cli cmd token
 *
 *      Pool	ports	   Portset	Start of new port set record
 *
 *		annex     <same>	The next token is a hostname or
 *					host ip address in `dot' notation
 *
 *              %include   filename     Open up and included file and continue
 *
 *		end	   <pop>	End of pool record
 *
 *		<other>	   Recover	Start error recovery
 *
 *	Portset end	   <pop>	End of port set
 *
 *              %include   filename     Open up and included file and continue
 *
 *		<other>    <same>	Port number or range
 *
 *	Recover end	   <pop>	End of recovery state
 *
 *		<other>	   <same>	Ignored
 *
 *   Note that commands are case insensitive.  Note additionally that in
 *   each state commands can be abbreviated to the shorted unambiguous
 *   initial string in their name.
 *
 *
 * Database Additions and Searches
 *
 *   The ACP user profiler uses the standard hash-table support routines
 *   hcreate(3C) and hsearch(3C).  These routines are based on Knuth 6.4
 *   Algorithm D.  They are not necessarily the most efficient, but they
 *   are reliable and supported in virtually all POSIX compliant user 
 *   development environments.
 *
 *
 * Implementation Notes
 *
 *   The implementation of the database add/find routines do not use the
 *   hcreate/hsearch routines due to severe limitations in these routines.
 *   Viz, they support only one static database whereas we have currently
 *   to support user and port pool databases, and many others in the
 *   future unless nobody wants to extend this code, which seems to be the
 *   ad hoc way things are implemented around here.
 *
 ****************************************************************************
 */

/*
 * included headers
 */
#include "../inc/config.h"
#include "../inc/port/port.h"
#include <sys/types.h>

#ifndef _WIN32
#include <grp.h>
#include <sys/param.h>
#include <sys/file.h>
#include <strings.h>
#include <netdb.h>
#include <syslog.h>
#else
#include "../inc/rom/syslog.h"
#endif /* !_WIN32 */

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <search.h>
#include <memory.h>
#include <sys/stat.h>
#include <string.h>

#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "getacpuser.h"
#include "acp_group.h"
#include "acp_policy.h"
#include "environment.h"

/*
 * Routines for creating group lists for group= entries in 
 * userinfo database.
 */

static int create_group_list_4_env();
static int is_group_member_4_env();
int extract_ports();

#ifdef _WIN32
void NTCreateGroupList();
#endif

/*
 * global vars.
 */
static int database_count = 0; /*userinfo database count*/

/*
 * Class member function forward references
 */
static	int	token_new();
static	int	token_open();
static	int	token_close();
static	int	token_read();
static	char	*token_get();
static	int	database_new();
static	int	database_add();
static	int	database_find();
static	void	database_free();
static	int	parser_event();
static	int	stack_new();
static	int	stack_push();
static	int	stack_pop();
static  void	errlog();

static	int	get_user_profile();
static	int	get_user_profile_by_env();

void		release_cmd_list();

/*
 * action routine forward references -- by state
 */
static	int user_begin(), pool_begin(), idle_error();
static	int access_begin(), climask_begin(), deny_user(), 
               clicmd_begin(), blacklist(), 
		filter_begin(), route_begin(),
            atzone_begin(),atpasswd(), atconnect_time(), atcallback(),
		local_addr(), remote_addr(), subnet_mask(),
		dyndial_passwd(), chap_secret(), mp_max_links(),
		max_logon_time(), user_end(), user_error();
static	int phone_no(), in_pool_name(), out_pool_name(), job_begin(),
		access_end(), access_error();
static	int zone_end(), zone();
static  int nve_begin(), nve_filter(), nve_include(), nve_exclude(), nve_end();
static	int job_end(), job();
static	int climask_end(), climask();
static	int clicmd_end(), clicmd();
static	int filter_end(), filter();
static	int route_end(), route();
static	int portnum(), portset(), hostname(), pool_end(), pool_error();
static	int portset_end(), portmem();
static	int recover_end(), recover();
static  int open_include_file();

/*
 * action routine vectors -- by state
 */
static  ifp idle_fn[]	= { open_include_file, user_begin, pool_begin, idle_error };

static	ifp user_fn[]	= { open_include_file, access_begin, climask_begin, 
                            deny_user,
			    clicmd_begin, filter_begin, route_begin,
			    blacklist,atzone_begin, 
			    atpasswd, atconnect_time,
			    atcallback, local_addr, remote_addr,
			    subnet_mask, nve_begin, dyndial_passwd, 
			    chap_secret, mp_max_links, max_logon_time,
			    user_end, user_error };

static	ifp access_fn[]	= { open_include_file, phone_no, in_pool_name, 
                            out_pool_name, job_begin,
			    access_end, access_error };
static	ifp job_fn[]	= { job_end, job };
static	ifp zone_fn[]	= { zone_end, zone };
static	ifp nve_fn[]	= { open_include_file, nve_include, nve_exclude, nve_end, nve_filter };
static	ifp climask_fn[]= { climask_end, climask };
static	ifp clicmd_fn[] = { clicmd_end, clicmd };
static	ifp filter_fn[] = { open_include_file, filter_end, filter };
static	ifp route_fn[] = { open_include_file, route_end, route };
static	ifp pool_fn[]	= { open_include_file, portnum, portset, hostname, pool_end,
				pool_error };
static	ifp port_fn[]	= { open_include_file, portset_end, portmem };
static	ifp recover_fn[]= { recover_end, recover };
static	ifp include_fn[]= { open_include_file };
/*
 * keywords -- by state
 */
static	char *idle_kw[]	= { "%include", "user", "pool" };

static	char *user_kw[] = {	
	"%include", "accesscode",	"climask", "deny", "clicmd", 
	"filter", "route", "blacklist", 
	"at_zone", 	"at_passwd",	"at_connect_time", 
	"at_callback",	"local_address","remote_address",
	"subnet_mask",	"at_nve_filter","dyndial_passwd", 
	"chap_secret",	"mp_max_links", "max_logon", "end" };

static	char *access_kw[]= { "%include", "phone_no", "in_pool_name", 
                             "out_pool_name", "job", "end" };
static	char *zone_kw[]	= { "end" };
static	char *nve_kw[]	= { "%include", "include", "exclude", "end" };
static	char *job_kw[]	= { "end" };
static	char *climask_kw[] = { "end" };
static	char *clicmd_kw[] = { "end" };
static	char *filter_kw[] = { "%include", "end" };
static	char *route_kw[] = { "%include", "end" };
static	char *pool_kw[]	= { "%include", "ports", "__place_holder__", "annex", "end" };
static	char *port_kw[]	= { "%include", "end" } ;
static	char *recover_kw[] = { "end" };
static	char *include_kw[] = { "__place_holder__" };

/*
 * parse vector size -- by state
 */
#define MAX_IDLE	(sizeof(idle_kw) / sizeof(char *))
#define MAX_USER	(sizeof(user_kw) / sizeof(char *))
#define MAX_ACCESS	(sizeof(access_kw) / sizeof(char *))
#define MAX_ZONE	(sizeof(zone_kw) / sizeof(char *))
#define MAX_NVE		(sizeof(nve_kw) / sizeof(char *))
#define MAX_JOB		(sizeof(job_kw) / sizeof(char *))
#define MAX_CLIMASK	(sizeof(climask_kw) / sizeof(char *))
#define MAX_CLICMD	(sizeof(clicmd_kw) / sizeof(char *))
#define MAX_FILTER	(sizeof(filter_kw) / sizeof(char *))
#define MAX_ROUTE	(sizeof(route_kw) / sizeof(char *))
#define MAX_POOL	(sizeof(pool_kw) / sizeof(char *))
#define MAX_PORT	(sizeof(port_kw) / sizeof(char *))
#define MAX_RECOVER	(sizeof(recover_kw) / sizeof(char *))
#define MAX_INCLUDE	(sizeof(include_kw) / sizeof(char *))


#define MAX_LOGON     1440        /* in minutes (comes out to be 24 Hr) */

/*
 * parser state table
 */

static	ParserEntry parse_table[] = {
	{ MAX_IDLE,	idle_kw,	idle_fn		},
	{ MAX_USER,	user_kw,	user_fn		},
	{ MAX_ACCESS,	access_kw,	access_fn	},
	{ MAX_ZONE,	zone_kw,	zone_fn		},
	{ MAX_JOB,	job_kw,		job_fn		},
	{ MAX_NVE,	nve_kw,		nve_fn		},
	{ MAX_CLIMASK,  climask_kw,	climask_fn	},
	{ MAX_CLICMD,   clicmd_kw,	clicmd_fn	},
	{ MAX_FILTER,   filter_kw,	filter_fn	},
	{ MAX_ROUTE,    route_kw,	route_fn	},
	{ MAX_POOL,	pool_kw,	pool_fn		},
	{ MAX_PORT,	port_kw,	port_fn		},
	{ MAX_RECOVER,	recover_kw,	recover_fn	},
	{ MAX_INCLUDE,	include_kw,	include_fn	}
        };

static Uprof	*uprof;			/* Current user profile */
static int	illegal_uprof;		/* user profile is legal */
static int	print_user_name = 0;	/* record name is not printed */
static unsigned	print_mode = 0;		/* print mode (-u option) */
static Access	*current_access;
static Pool	*pool;
static PoolEntry *pool_entry;
static char	*severity[] = { "unspecified", "fatal", "error", "warning" };

/*
 * Objects
 */
static	Database	users;
static	Database	pools;
static	Stack		state;
static	Token		token, sub_token;
static	Token		*active_token;

/*
 * Defines to indicate the type of database being acted upon by database_free
 */
#define NO_DATABASE   0
#define USER_DATABASE 1
#define POOL_DATABASE 2

#define Mlint (print_mode & M_LINT)
#define Mdebug (print_mode & M_DEBUG)

/* #define DEBUG_ORA 1 */


/*
 ****************************************************************************
 *
 * NAME:
 *   open_user_profile_file - open the ACP user profile file
 *
 * SYNOPSIS:
 *   int open_user_profile_file(const char *filename)
 *
 * DESCRIPTION:
 *
 * EXCEPTIONS:
 *
 ****************************************************************************
 */
int
open_user_profile_file (filename)
	char *filename;
{
	int status;

	status = pre_open_user_profile_file (filename, &token);
	if (status == ACPU_ESUCCESS) {
	    if (token_new(&token, &sub_token, filename) != ACPU_ESUCCESS) {
		errlog(Warning, "Could not initialize Token");
		print_mode = 0;
		return(ACPU_ERROR);
	    }
	}

	else if (status == ACPU_ESKIP)
	    status = ACPU_ESUCCESS;

	return (status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *   close_user_profile_file - close the ACP user profile file
 *
 * SYNOPSIS:
 *   int close_user_profile_file()
 *
 * DESCRIPTION:
 *
 * EXCEPTIONS:
 *
 ****************************************************************************
 */
int
close_user_profile_file ()
{
	int status;

	status = pre_close_user_profile_file();
	if (status == ACPU_ESUCCESS) {
	    if ((status = token_close(&token)) != ACPU_ESUCCESS)
		return (status);
	}

	else if (status == ACPU_ESKIP)
	    status = ACPU_ESUCCESS;

	return (status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   initialize_user_profile_file - read the ACP user profile file into memory
 *
 *
 * SYNOPSIS:
 *
 *   int initialize_user_profile_file(unsigned mode);
 *
 *
 * DESCRIPTION:
 *
 *   initialize_user_profile_file creates an in-core database of user profiles by
 *   reading user profile records from `filename'.  If `filename'
 *   is NULL, then stdin is used.  `Mode' is a bit mask interpreted as follows:
 *
 *   Symbol  Bit  Value  Description
 *
 *   M_INCR              CURRENTLY UNIMPLEMENTED
 *            1     1    the existing database is incrementally updated with
 *                       user profiles in `filename'.
 *
 *                  0    the current database is discarded and a new
 *	    	   	 database is generated from scratch.
 *
 *   M_LINT   2     1	 `filename' is syntax checked only and database
 *			 generation is suppressed (overrides M_INCR).
 *
 *   M_TEE               CURRENTLY UNIMPLEMENTED
 *            4	    1	 the user profiles are printed on stdout as they
 *                       are added to database.
 *
 *   M_DEBUG  8     1    print debug info on stdout.  Works only if this
 *			 file is compiled with -DDEBUG.
 *
 *
 *   initialize_user_profile_file returns ACPU_ESUCCESS on success and error codes
 *   on error conditions.
 *
 *
 * EXCEPTIONS:
 *
 *   Upon detecting an operational error, such as not enought memory or
 *   file oper error, initialize_user_profile_file prints a message on stderr and 
 *   returns an error code to caller.
 *
 *   Upon detecting an parsing error, initialize_user_profile_file prints a
 *   message on stderr.  The message contains the filename, line number,
 *   severity and description.  If severity is Error, then database
 *   generation is suppressed but the parser continues in order to detect
 *   and report additional syntax errors.  If severity is Warning, the
 *   parser prints the message but adds the user profile to the database.
 *   If the warning condition warrants, the user should fix the acp
 *   user profile source and rehup the profile reader.
 *
 *
 ****************************************************************************
 */

int
initialize_user_profile_file(mode)
	unsigned mode;
{
    char *word = NULL;
    int status = ACPU_ESUCCESS;

    print_mode = mode;	/* it makes life much easier */
    active_token = &token;

    if ((status = pre_init_user_profile_file ()) == ACPU_ESUCCESS) {

	/*
	 * make new objects
	 */
	if (Mdebug)
		printf("initialize_user_profile_file: making objects\n");
	if (database_new(&users, sizeof(Uprof)) != ACPU_ESUCCESS) {
		errlog(Fatal, "Insufficient memory for Uprofs");
		print_mode = 0;
		return(ACPU_ERROR);
	}
	if (database_new(&pools, sizeof(Pool)) != ACPU_ESUCCESS) {
		errlog(Fatal, "Insufficient memory for Pools");
		print_mode = 0;
		return(ACPU_ERROR);
	}
	if (stack_new(&state, Idle) != ACPU_ESUCCESS) {
		errlog(Fatal, "Could not initialize Stack");
		print_mode = 0;
		return(ACPU_ERROR);
	}

	/*
	 * main loop
	 */
main_loop:
	while (word = token_get(active_token)) {
		if (Mdebug)
			printf("initialize_user_profile_file: got token \"%s\"\n", word);
		status = parser_event(word);
		if (Mdebug)
			printf("initialize_user_profile_file: parse status %d\n", status);
		if (status != ACPU_ESUCCESS)
			break;
	}
	if (Mlint) {
		if (status == ACPU_ESUCCESS) {
			printf("initialize_user_profile_file: parsed %d users\n",
			       database_entries(&users));
                        if(sub_token.t_fp) {
                           token_free(&sub_token);
                           bzero((caddr_t)&sub_token, sizeof(Token));
                           active_token = &token;
                           goto main_loop;
                        }
                }
		else
			printf("initialize_user_profile_file: parse failed\n");
		print_mode = 0;
		return(ACPU_ERROR);
	}

	if (status == ACPU_ESUCCESS) {
            if(sub_token.t_fp) {
               token_free(&sub_token);
               bzero((caddr_t)&sub_token, sizeof(Token));
               active_token = &token;
               goto main_loop;
            }
	    database_ready(&users);
	    database_ready(&pools);
	} else {
	    database_free(&users,USER_DATABASE);
	    database_free(&pools,POOL_DATABASE);
	}

	/*
	 * done with this object
	 */
	token_free(&token);
        if(sub_token.t_fp) 
           token_free(&sub_token);
    }

    else if (status == ACPU_ESKIP)
	status = ACPU_ESUCCESS;

    print_mode = 0;

    return(status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   clear_user_profile_info - clear out the old ACP user profile info
 *
 *
 * SYNOPSIS:
 *
 *   #include "acp_uprof.h"
 *
 *   void clear_user_profile_info();
 *
 *
 * DESCRIPTION:
 *
 *   Clears the old user profile information in preparation for re-reading
 *   the database. Called on SIGUSR1. 
 *
 *
 *
 ****************************************************************************
 */

void
clear_user_profile_info()
{
    int         status;
    Uprof	*up, *up_prev;
    Access	*acc, *acc_prev;
    struct	_phone	*ph, *ph_prev;

    Pool	*pool, *pool_prev;
    PoolEntry	*pe, *pe_prev;

    status = pre_clear_user_profile_info();
    if (status == ACPU_ESUCCESS) {
        /* users.db_list and pools.db_list are declared to be of type
         * DatabaseEntry, but they are in reality Uprof and Pool structs,
         * both of whom have DatabaseEntry structs as their first members,
         * so they can be manipulated by database_add() etc. as DatabaseEntry
         * structs.
         */
        up = (Uprof *)users.db_list;
        while (up != NULL)
        {
	    acc = up->up_accesslist;
	    while (acc != NULL)
	    {
	        ph = acc->ac_phone_list;
	        while (ph != NULL)
	        {
		    ph_prev = ph;
		    ph = ph->next;
		    ph_prev->next = NULL;
		    free(ph_prev);
	        }
	        acc_prev = acc;
	        acc = acc->ac_next;
	        acc_prev->ac_next = NULL;
	        free(acc_prev);
	    }
	    	
	    if (up->up_cmd_list)
	      release_cmd_list(up->up_cmd_list);

	    if (up->up_filter_list)
	      release_cmd_list(up->up_filter_list);

	    if (up->up_route_list)
	      release_cmd_list(up->up_route_list);
	
	    if (up->up_values_p)
	      free(up->up_values_p);
			
	    up_prev = up;
	    up = (Uprof *)up->up_de.de_next;
	    up_prev->up_de.de_next = NULL;
	    bzero(up_prev, sizeof(Uprof));
       	    free(up_prev);
        }

        pool = (Pool *)pools.db_list;
        while (pool != NULL)
        {
	    pe = pool->po_list;
	    while (pe != NULL)
	    {
	        pe_prev = pe;
	        pe = pe->pe_next;
	        pe_prev->pe_next = NULL;
	        free(pe_prev);
	    }
	    pool_prev = pool;
	    pool = (Pool *)pool->po_de.de_next;
	    pool_prev->po_de.de_next = NULL;
	    free(pool_prev);
        }
    }

    database_count = 0;
}

/*****************************************************************************
 *
 * NAME: get_user_profile_entry
 *
 * DESCRIPTION: Returns the first matched entry for a user from the userinfo
 *              database.
 *              This routine makes two calls to userinfo database. Both
 *              calls search the database linearly from the very beginning.
 *              First call (get_user_profile) searches the database for  
 *              pre per-user entries such as:
 *
 * user net-surfer
 *    at_passwd xyz 
 *    at_zone 38net 39net end
 *    chat_secret surf1
 * end
 *
 *              where as the 2nd call (get_user_profile_by_env) looks
 *              for entries with the per-user profile criteria.  For eg.
 *
 * user username=net-surfer;time="Saturday";annex=whatever
 *    climask telnet, who end
 *    at_zone 38net 39net end
 *    chap_secret surf1
 * end
 *
 *              Whichever entry is first in the database, it is used for
 *              user's connection environment.  If the first call returns
 *              with success, the 2nd call uses the entry index no. of the
 *              entry found.  This makes sure that 2nd call doesn't go beyond
 *              the first match found (by the first call) and saves on frivolous
 *              lookups. If the first call is unsuccessful, 2nd calls gets a
 *              very large entry index no. and searches the entire database for
 *              user's entry.
 *
 * ARGUMENTS:
 *   Uprof          *up                     - OUTPUT userinfo entry structs
 *   ACP_LSTRING    Name                    - INPUT username
 *   struct         environment_spec **env  - INPUT user's environment information
 *   struct         gr_file *file_etc       - INPUT group file information 
 *						   
 *
 * RETURN VALUE: 
 *   ACPU_ESUCCESS if successful
 *   ACPU_ENOUSER  on failure
 * 
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
int
get_user_profile_entry(up, Name, env, file_etc)

Uprof             *up;			     /*userinfo entry struct*/
#ifndef _WIN32
    ACP_LSTRING Name;						/*username */
#else   /* defined _WIN32 */
	ACP_USTRING Name;
#endif   /* defined _WIN32 */
struct            environment_spec **env;    /*user's environment information*/
struct            gr_file *file_etc;         /*group file information */

{
    int    status;
    int    error = -1;
    int    error_by_env = -1;
    Uprof  up_call1, up_call2;

    status = pre_get_user_profile_entry (up, Name, env, file_etc);
    if (status == ACPU_ESUCCESS) {
        bzero (&up_call1, sizeof(Uprof));
        bzero (&up_call2, sizeof(Uprof));

        error = get_user_profile(Name, &up_call1);
        if (error == ACPU_ESUCCESS) {
            file_etc->count = up_call1.up_de.de_entry_num;
	    error_by_env    = get_user_profile_by_env(env, &up_call2, file_etc);
        }
        else {
            file_etc->count = 0xfffffff;
	    error_by_env    = get_user_profile_by_env(env, &up_call2, file_etc);
        }
        file_etc->count = 0;

        if(error == ACPU_ESUCCESS || error_by_env == ACPU_ESUCCESS)
            status = ACPU_ESUCCESS;
        else 
            status = ACPU_ENOUSER;

        /*
         * Choosing the first match of the two
         * calls. Both calls could be successful
         * since the database is read from the very
         * beginning.
         * "error" is the error value from the first call.
         * "error_by_env" is the error value from the 2nd call.
         * Copy information from the successful entry. If no
         * success, return ACPU_ENOUSER
         */
        if ((error_by_env == ACPU_ESUCCESS) &&
            ((error == ACPU_ESUCCESS)||(error == ACPU_ENOUSER)))
            bcopy (&up_call2, up, sizeof(Uprof));
        else if (error == ACPU_ESUCCESS)
            bcopy (&up_call1, up, sizeof(Uprof));
    }

    else if (status == ACPU_ESKIP)
	status = ACPU_ESUCCESS;

    return (status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   get_user_profile - get user profile information by username
 *
 * SYNOPSIS:
 *   static int get_user_profile(const char *username, Uprof *profile);
 *
 * DESCRIPTION:
 *   Get_user_profile returns user profile information for a specified
 *   user.  `Username' is the search key.  The user profile data is copied
 *   into the uprof structure provided in `profile'.
 *
 *   Get_user_profile returns an integer value interpreted as follows:
 *
 *   ACPU_ESUCCESS	Normal return, username found.
 *
 *   ACPU_ENOACP	The user profile database does not exist.
 *
 *   ACPU_EINPROG	The user profile database is in the process of being update,
 *			try again later.
 *
 *   ACPU_ENOUSER	A user profile for `username' does not exist.
 *
 ****************************************************************************
 */

static int
get_user_profile(username, uprof)
	char *username;
	Uprof *uprof;
{
	/*
	 * check if database exists
	 */
	if ((database_flags(&users) & DF_OPEN) == 0)
		return ACPU_ENOACP;

	/*
	 * check if database is ready
	 */
	if ((database_flags(&users) & DF_READY) == 0)
		return ACPU_EINPROG;

	/*
	 * search database for username
	 */
	if (database_find(&users, username, uprof) != ACPU_ESUCCESS)
		return ACPU_ENOUSER;

	/*
	 * normal return
	 */
	return ACPU_ESUCCESS;
}

/*
 ****************************************************************************
 *
 * NAME:
 *   get_user_profile_by_env - get user profile information by username
 *
 *
 * SYNOPSIS:
 *   int get_user_profile_by_env(struct environment_spec **env_p,
 *			Uprof *entry, struct gr_file *file_info);
 *
 * DESCRIPTION:
 *
 *   get_user_profile_by_env returns user profile information for a specified
 *   user which matches the environment description provided in `env_p'.
 *
 *   Get_user_profile returns an integer value interpreted as follows:
 *
 *   ACPU_ESUCCESS	Normal return, match found.
 *
 *   ACPU_ENOUSER	A user profile matching the environment does not exist
 *
 ****************************************************************************
 */
static int
get_user_profile_by_env(env_p,entry, file_info)
	struct environment_spec **env_p;
	Uprof *entry;
        struct gr_file *file_info;
{
        struct environment_spec *temp=*env_p;
	struct environment_values *user_temp=NULL;
	DatabaseEntry *target;
	int i = 1;
	int list_already_created = FALSE;

	for (target = users.db_list;
	     target && i < file_info->count;
	     i++, target = target->de_next) {
	  if (!(((Uprof *)target)->up_values_p))
	    continue;
	  
	  if(isalpha(((Uprof *)target)->up_values_p->groupname[0])) {
	    if (!list_already_created) {
	      if(create_group_list_4_env(&(temp->group_list),
					 temp->username, file_info) == FALSE) {
		/* Failed to create a group list */
		/* deny access    */
		return(ACPU_ENOUSER);
	      }
	    }
	    list_already_created = TRUE;
	  }
	  user_temp = (struct environment_values *)malloc(sizeof(struct environment_values)); 
	  bzero(user_temp, sizeof(struct environment_values));
	  bcopy(((Uprof *)target)->up_values_p, user_temp, 
                                      sizeof(struct environment_values));
	  if (match_env_options(*env_p, user_temp)) {
	    bcopy((caddr_t)target, (caddr_t)entry, users.db_sizeof);
	    file_info->count = i;
	    free(user_temp);
	    return(ACPU_ESUCCESS);
	  }
	   free(user_temp);
	}
	return(ACPU_ENOUSER);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   get_user_access - get access information by username
 *
 *
 * SYNOPSIS:
 *
 *   #include "acp_uprof.h"
 *
 *   int get_user_access(const char *username,
 *			const char *accesscode,
 *			Access *accessptr);
 *                      struct env_gr_info *envinfo);
 *
 *
 * DESCRIPTION:
 *
 *   Get_user_access returns user access information for a specified
 *   user and access.  `Username' is the search key for the user profile
 *   and `accesscode' is the search key for an access code defined within
 *   the user profile.  The user access data is copied into the access
 *   structure provided in `access'.
 *
 *   Get_user_access returns an integer value interpreted as follows:
 *
 *   ACPU_ESUCCESS	Normal return, access code found.
 *
 *   ACPU_ENOACP	The user profile database does not exist.
 *
 *   ACPU_EINPROG	The user profile database is in the process of being update,
 *		try again later.
 *
 *   ACPU_ENOUSER	A user profile for `username' does not exist.
 *
 *   ACPU_ENOACC	A access block for 'accesscode' does not exist.
 *
 ****************************************************************************
 */

int
get_user_access(username, accesscode, accessptr, envinfo)
	char *username;
	char *accesscode;
	Access *accessptr;
        struct env_gr_info *envinfo;
{
    Uprof uprof;
    Access *acp = NULL;
    int status;

    bzero (&uprof, sizeof(Uprof));

    /*
     * search database for user
     */
    if((status = get_user_profile_entry(&uprof, username, envinfo->env, envinfo->gr_info))
            != ACPU_ESUCCESS) {
	release_uprof(&uprof);
    	return (status);
    }

    if ((status = pre_get_user_access (username, accesscode, accessptr, envinfo)) 
	    != ACPU_ESUCCESS) {
	if (status == ACPU_ESKIP)
	    status = ACPU_ESUCCESS;
	release_uprof(&uprof);
	return (status);
    }

    /*
     * if pointer to access code is null, do not return
     * the access code, just check if there is one defined.
     * return ACPU_ENOACC if no access codes are defined.
     */
    if (accesscode == 0) {
        if(uprof.up_accesslist == 0)
    	    /* no access codes defined */
    	    status = ACPU_ENOACC;
        else
    	    /* access codes are defined but pointer is null */
    	    status = ACPU_EACCESSCODE;
	release_uprof(&uprof);
	return(status);
    }

    /*
     * search accesscode list for access code
     */
    for (acp = uprof.up_accesslist; acp; acp = acp->ac_next) {
    	if (!strcmp(acp->ac_code, accesscode))
    		break;
    }
    if (!acp)
    	status = ACPU_ENOACC;
    if ((acp != NULL) && (accessptr != NULL) && (status == ACPU_ESUCCESS))
	bcopy((caddr_t)acp, (caddr_t)accessptr, sizeof(Access));
    release_uprof(&uprof);
    return (status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   get_port_pool - get port pool information by poolname
 *
 *
 * SYNOPSIS:
 *
 *   #include "acp_uprof.h"
 *
 *   int get_port_pool(const char *poolname, PoolEntry *pool_entry);
 *
 *
 * DESCRIPTION:
 *
 *   Get_port_pool returns port pool information for a specified
 *   poolname. `Poolname' is the search key for the port pool.
 *   The pool data is copied into the pool structure provided in
 *   `pool_entry'.
 *
 *   Get_port_pool returns an integer value interpreted as follows:
 *
 *   ACPU_ESUCCESS	Normal return, port pool found.
 *
 *   ACPU_ENOACP	The user profile database does not exist.
 *
 *   ACPU_EINPROG	The user profile database is in the process of being update,
 *		try again later.
 *
 *   ACPU_ENOPOOL    A port pool for `poolname' does not exist.
 *
 *   ACPU_ENOPOOLENT  The named pool has no pool entries.
 *
 ****************************************************************************
 */

int
get_port_pool(poolname, pool_entry)
	char *poolname;
	PoolEntry *pool_entry;
{
    Pool pool;
    int status;

    if ((status = pre_get_port_pool(poolname, pool_entry)) != ACPU_ESUCCESS) {
	if (status == ACPU_ESKIP)
	    status = ACPU_ESUCCESS;
	return (status);
    }

    /*
     * check if database exists
     */
    if ((database_flags(&pools) & DF_OPEN) == 0)
    	status = ACPU_ENOACP;

    /*
     * check if database is ready
     */
    else if ((database_flags(&pools) & DF_READY) == 0)
    	status = ACPU_EINPROG;

    /*
     * search database for username
     */
    else if (database_find(&pools, poolname, &pool) != ACPU_ESUCCESS)
    	status = ACPU_ENOPOOL;

    /*
     * check for first pool entry
     */
    else if (pool.po_count == 0)
    	status = ACPU_ENOPOOLENT;

    bcopy((caddr_t)pool.po_list, (caddr_t)pool_entry, sizeof(PoolEntry));
    return (status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   get_next_pool_entry - get the next pool entry
 *
 *
 * SYNOPSIS:
 *
 *   #include "acp_uprof.h"
 *
 *   int get_next_pool_entry(PoolEntry *pool_entry);
 *
 *
 * DESCRIPTION:
 *
 *   Get_next_pool_entry returns pool information for the next pool entry
 *   in a poolname. `pool_entry' is the address of a pool entry returned by
 *   a call to get_port_pool or get_next_pool_entry.  The pool data is copied
 *   into the pool structure provided in `pool_entry'.
 *
 *   Get_port_pool returns an integer value interpreted as follows:
 *
 *   ACPU_ESUCCESS	Normal return, port pool found.
 *
 *   ACPU_ENOACP	The user profile database does not exist.
 *
 *   ACPU_EINPROG	The user profile database is in the process of being update,
 *		try again later.
 *
 *   ACPU_EBADGEN	Since the last get_next_pool_entry call, the pools database
 *		has been changed.
 *   ACPU_ENOPOOL    A port pool for `poolname' does not exist.
 *
 *   ACPU_ENOPOOLENT  There are no more pool entries in this pool.
 *
 ****************************************************************************
 */

int
get_next_pool_entry(pool_entry)
	PoolEntry *pool_entry;
{
    PoolEntry *next_entry = pool_entry->pe_next;
    int status;

    if ((status = pre_get_next_pool_entry(pool_entry)) != ACPU_ESUCCESS) {
	if (status == ACPU_ESKIP)
	    status = ACPU_ESUCCESS;
	return (status);
    }

    /*
     * check if database exists
     */
    if ((database_flags(&pools) & DF_OPEN) == 0)
    	status = ACPU_ENOACP;

    /*
     * check if database is ready
     */
    else if ((database_flags(&pools) & DF_READY) == 0)
    	status = ACPU_EINPROG;

    /*
     * check database generation to make sure
     * that it hasn't been re-cached since last 
     * get_next_pool_entry call.
     */
    else if (pool_entry->pe_gen != pools.db_gen)
    	status = ACPU_EBADGEN;

    /*
     * check for next pool entry
     */
    else if (next_entry == 0) {
      status = ACPU_ENOPOOLENT;
      return (status);
    }

    bcopy((caddr_t)next_entry, (caddr_t)pool_entry, sizeof(PoolEntry));
    return (status);
}

/*
 ****************************************************************************
 *
 * NAME:
 *
 *   get_pool_entry_by_addr - get a pool entry
 *
 *
 * SYNOPSIS:
 *
 *   #include "acp_uprof.h"
 *
 *   int get_pool_entry_by_addr(const char *poolname, const u_long hostaddr, 
 *				const int portnum);
 *
 *
 * DESCRIPTION:
 *
 *   `Poolname' is the name of a port pool.  If NULL, all pools in the pools
 *   database are searched.  `Hostaddr' is the address of the Annex in network
 *   byte order.  `Portnum' is a port number of a serial port.
 *
 *   Get_pool_entry_by_addr returns an integer value interpreted as follows:
 *
 *   ACPU_ESUCCESS	Normal return, port pool found.
 *
 *   ACPU_ENOACP	The user profile database does not exist.
 *
 *   ACPU_EINPROG	The user profile database is in the process of being update,
 *		try again later.
 *
 *   ACPU_ENOPOOL    A port pool for `poolname' does not exist.
 *
 *   ACPU_ENOPOOLENT  There are no more pool entries in this pool.
 *
 ****************************************************************************
 */

int
get_pool_entry_by_addr(poolname, hostaddr, portnum, ptype)
	char *poolname;
	INT32 hostaddr;
	int portnum,ptype;
{
    Pool *pool;
    PoolEntry *pool_entry;
    int n = (portnum - 1)/8;
    int bmask = 1 << ((portnum-1) % 8);
    int status;

    if ((status = pre_get_pool_entry_by_addr(poolname, hostaddr, portnum, ptype))
	    != ACPU_ESUCCESS) {
	if (status == ACPU_ESKIP)
	    status = ACPU_ESUCCESS;
	return (status);
    }

    /*
     * check if database exists
     */
    if ((database_flags(&pools) & DF_OPEN) == 0)
    	status = ACPU_ENOACP;

    /*
     * check if database is ready
     */
    else if ((database_flags(&pools) & DF_READY) == 0)
    	status = ACPU_EINPROG;

    /*
     * Do range check on the port number.
     * On Annex3's port MAX_SERIAL_PORTS+1 is the first vcli port number.
     * pe_portmap[] is MAX_SERIAL_PORTS-bit wide and must not be exceeded.
     */
    else if (portnum > MAX_PORTS)
    	status = ACPU_ENOPOOLENT;

    /*
     * search pools database for pool entry
     */
    else {
      status=ACPU_ENOPOOLENT;
      for (pool = (Pool*)pools.db_list; pool; pool = (Pool*)pool->po_next) {


    	/*
    	 * restrict search to named pool
    	 */
    	if (poolname && strcmp(poolname, pool->po_poolname))
    		continue;

    	/*
    	 * search pool entries on this pool for match
    	 */

    	for (pool_entry = pool->po_list; pool_entry;
	     pool_entry = pool_entry->pe_next) {
	  if ((hostaddr == pool_entry->pe_hostaddr) &&
	      (pool_entry->pe_ports[ptype][n] & bmask)) {
	    status = ACPU_ESUCCESS;
	    break;
	  }
	}
      }
    } /* end else */
    if (status == ACPU_ESUCCESS)
        return ACPU_ESUCCESS;
    else
	return ACPU_ENOPOOLENT;
}

/*
 ****************************************************************************
 *
 *	class member functions
 *
 ****************************************************************************
 */

static int
token_new(this, sub_this, filename)
	Token *this, *sub_this;
	char *filename;
{
	bzero((caddr_t)this, sizeof(Token));
	bzero((caddr_t)sub_this, sizeof(Token));
	if (token_open(this, filename) == ACPU_ERROR)
		return ACPU_ERROR;
	return token_read(this);
}

static int
token_open(this, filename)
	Token *this;
	char *filename;
{
	if (filename) {
		strncpy(this->t_filename,filename,
			sizeof(this->t_filename)-1);
		this->t_filename[sizeof(this->t_filename)-1] = '\0';
		if ((this->t_fp = fopen(filename, "r")) == NULL)
			return ACPU_ERROR;
	} else {
		strcpy(this->t_filename, "stdin");
		this->t_fp = stdin;
	}
	return ACPU_ESUCCESS;
}

static int
token_close(this)
	Token *this;
{
	if (this->t_fp != NULL) {
	    if (fclose (this->t_fp))
		return ACPU_ERROR;
	}
	return ACPU_ESUCCESS;
}

static int
token_read(this)
	Token *this;
{
	register char *bp = this->t_buf;
	register int len = sizeof this->t_buf, i = 0;

  again:
	this->t_buf[0] = '\0';
	this->t_bp = this->t_buf;
	while (i < len) {
		if (!fgets(bp, len - i, this->t_fp))
			return ACPU_ERROR;
	        this->t_line++;
		i += strlen(bp) - 1;
		if (i == 0)
			goto again;
		if (!(memchr("\n\r", this->t_buf[i], 2) && 
		      this->t_buf[i-1] == '\\'))
			return ACPU_ESUCCESS;
		bp = &this->t_buf[--i];
	}
	errlog(Error, "line too long");
	return ACPU_ERROR;
}

static char *
token_get(this)
	Token *this;
{
	register char *start, *middle, *end;
	char temp[TOKBUFLEN + 1];
	int current_state = state.s_stack[state.s_index];

	/*
	 * return ungotten word, if any
	 */
	if (this->t_ungotten) {
		start = this->t_ungotten;
		this->t_ungotten = NULL;
		return start;
	}

more:
	/*
	 * read more if real or virtual eol
	 */
	if (*this->t_bp == '\0' || *this->t_bp == '#') {
		if (token_read(this) != ACPU_ESUCCESS)
			return NULL;
		goto more;
	}
	start = this->t_bp + strspn(this->t_bp, SEPARATORS);
	if (*start == '\0' || *start == '#') {
		if (token_read(this) != ACPU_ESUCCESS)
			return NULL;
		goto more;
	}

        /* We want to start at the beginning backslash if first char is
           a backslash */
        if((start > this->t_bp) && ((*(start-1)) == '\\'))
          start -= 1;

	/*
	 * find token end
	 */
	middle = start;
again:
	/* When looking for the end of the token, we need to
	 * look not only for separator characters, but quote
	 * characters, which we must handle specially. 
	 */
	end = middle + strcspn(middle, SEPARATORS_W_QUOTES);

	/* If we got a quote character, skip up to the closing
	 * quote and move forward.
	 */  
	/* Be certain to check that the
	 * preceding character was not a backslash, quoting the
	 * quote.  This involves looking back *two* characters,
	 * as the backslash might itself be quoted!
	 */
	if (*end == '\"') {
		int close_found = FALSE;
		int x = 1;
		int nquotes = 0;

		/* Loop to look for closing quote - we must be certain
		 * the quote we find is not a quoted quote within a 
		 * string.
		 */
		while (1) {
			/* Find the closing quote */
			if ((end = (char *)strchr(end+1, '\"')) == NULL) {
				errlog(Error, "Unclosed quote in token");
				return NULL;
			} 

			/* Make sure it's not a quoted quote by counting
			 * up the number of contiguous backslashes that
			 * immediately precede it.  If it's an odd number,
			 * one of them goes with the quote character.
			 */
			for (x = 1, nquotes = 0; 
		    	    ((end - x) >= start) && (*(end - x) == '\\'); x++) 
				nquotes++;

			/* Reset "middle" to point to the character following
			 * the quote.
			 */
			middle = end + 1;
		
			/* If it's an even number of quotes, this quote
			 * wasn't quoted.  Get out.  Otherwise, we go
			 * through the loop again, looking for the next quote.
			 */	
			if(!(nquotes % 2)) 
				break;
		}

		/* Finished processing the quote - go back and get
	 	 * the rest of the token.
		 */
		goto again;

	} else if (*end == '\\') {
                int c;
	        if (isxdigit(*(end+1)) && isxdigit(*(end+2))) {
		   strncpy(temp, end+1, 2);
                   temp[2] = '\0';  /* null terminate */
		   c = strtol(temp,0,16);
		   if (c == 0) {
		     errlog(Error, "Illegal embedded NULL(\\00)");
                     return NULL;
                   }
                   *temp = (unsigned char)c;
	           strcpy(temp+1, end+3);
                   strcpy(end, temp);
                   middle = end +1;
                   goto again;
                }
		strcpy(temp, end+1);
		strcpy(end, temp);
		middle = end + 1;
		goto again;
	}

	/*
	 * if last token in buf, 
	 *   set bp to point to '\0' so that next
	 *   call to token_get does a token_read;
	 * else
	 *   set bp to point 1 char past end of token;
	 */
	this->t_bp = (*end == '\0' || *end == '#') ? end : end + 1;

	/*
	 * terminate token
	 */
	*end = '\0';

	/* disallow wildcard prefixes in username.  This should be remmoved 
	   later and then put in to the apt. place*/
	if((current_state == Idle) && strchr(start, '*') &&(!strchr(start, '='))){
	   errlog(Error, "* is invalid as username in non-profile entries");
	   return NULL;
	}
	return (*start ? start : NULL);
}

static int
parser_event(word)
	char *word;
{
	int i, j, status;
	int s = state.s_stack[state.s_index];
	ParserEntry *pe = &parse_table[s - 1];
	int n = pe->pe_num_events;
	char **keywords = pe->pe_keywords;
	int (**fns)() = pe->pe_funcs;

	if (Mdebug)
		fprintf(stderr, "parser_event: passed \"%s\" in state %d\n",
			word, s);

	for (i = 0; i < n; i++) {
		if (strncasecmp(keywords[i], word, strlen(word)) == 0)
			break;
	}

	for (j = i + 1; j < n; j++) {
		if (strncasecmp(keywords[j], word, strlen(word)) == 0)
			break;
	}

	if (j < n) {
		if (Mlint)
			fprintf(stderr,
				"%s: line %d: error: \"%s\" is ambiguous\n",
				active_token->t_filename, active_token->t_line,
				word);
		return(stack_push(&state, Recover));
	}

	/*
	 * If keyword, pass action routine the next word (ie,
	 * the argument) else pass action routine this word.
	 */
	if (i < n)
		word = token_get(active_token);
	if (Mdebug)
		fprintf(stderr, "parser_event: passing \"%s\" to handler\n",
			(word == NULL)?"NULL":word);
	status = (*fns[i])(word);
	return status;
}

static int
database_new(this, entry_len)
	Database *this;
	int entry_len;
{
	int gen = this->db_gen;

	bzero((caddr_t)this, sizeof(Database));
	this->db_flags = DF_OPEN;
	this->db_sizeof = entry_len;
	this->db_listp = &this->db_list;
	this->db_gen = gen + 1;
	return ACPU_ESUCCESS;
}

static int
database_add(this, new_entry)
	Database *this;
	DatabaseEntry *new_entry;
{
	*this->db_listp = new_entry;
	this->db_listp = &new_entry->de_next;
	this->db_entries++;
	return ACPU_ESUCCESS;	
}

static int
database_find(this, key, entry)
	Database *this;
	char *key;
	DatabaseEntry *entry;
{
	DatabaseEntry *target;

	for (target = this->db_list; target; target = target->de_next)
		if (!strcmp(key, target->de_key))
			break;

	if (!target)
		return ACPU_ERROR;
	bcopy((caddr_t)target, (caddr_t)entry, this->db_sizeof);
	return ACPU_ESUCCESS;
}


static void
database_free(this,db_type)
	Database *this;
        int db_type;
{
	DatabaseEntry *curr, *next;

	next = this->db_list;
	while (curr = next) {
		next = curr->de_next;
		/* Free anything from user environment and clicmd list */
                if (db_type == USER_DATABASE)
                {
			if (((Uprof *)curr)->up_cmd_list)
			   release_cmd_list(((Uprof *)curr)->up_cmd_list);

        		if (((Uprof *)curr)->up_filter_list)
			   release_cmd_list(((Uprof *)curr)->up_filter_list);

		        if (((Uprof *)curr)->up_route_list)
			   release_cmd_list(((Uprof *)curr)->up_route_list);

			if (((Uprof *)curr)->up_values_p)
		           free(((Uprof *)curr)->up_values_p);
			
                }
		free(curr);
	}
	(void)database_new(this, this->db_sizeof);
}

static int
stack_new(this, init_entry)
	Stack *this;
	int init_entry;
{
	bzero((caddr_t)this, sizeof(Stack));
	this->s_stack[0] = init_entry;
	return ACPU_ESUCCESS;
}

static int
stack_push(this, new_entry)
	Stack *this;
	int new_entry;
{
	if (this->s_index >= MAXSTKENT)
		return ACPU_ERROR;		/* stack overflow */
	this->s_stack[++this->s_index] = new_entry;
	return ACPU_ESUCCESS;
}

static int
stack_pop(this)
	Stack *this;
{
	if (this->s_index < 1)
		return ACPU_ERROR;		/* stack underflow */
	this->s_stack[this->s_index--];
	return ACPU_ESUCCESS;
}

static void
errlog(level, msg)
Severity level;
char *msg;
{
	int syslev;
	char buf[256];

	switch (level) {
	case Warning:
		syslev = LOG_WARNING;
		break;
	case Error:
		syslev = LOG_ERR;
		break;
	default:
		if (Mlint)
			fprintf(stderr, "errlog: *** bad level coded ***\n");
	case Fatal:
		syslev = LOG_CRIT;
		break;
	}

	if (Mlint)
		fprintf(stderr, "%s: line %d: %s: %s %s\n",
		        (active_token) ? active_token->t_filename : "",
		        (active_token) ? active_token->t_line : 0,
			severity[(int)level], msg,
			(print_user_name && uprof) ? uprof->up_username : "");
	else
	{
		sprintf(buf, "%s: line %d: %s: %s %s\n",
		       (active_token) ? active_token->t_filename : "",
		       (active_token) ? active_token->t_line : 0,
		       severity[(int)level], msg,
		       (print_user_name && uprof) ? uprof->up_username : "");
		syslog(syslev, buf);
	}
}

/*
 *****************************************************************************
 *
 * parse table action routines
 *
 *****************************************************************************
 */

static int
user_begin(word)
char *word;
{
	int env_parse = 0;
	char *temp=NULL;
    ACP_USTRING check_word;

	if (Mdebug)
	  fprintf(stderr, "user_begin: called with \"%s\"\n", word);

	if (word == NULL) {
	  errlog(Error, "user_begin: called with no username");
	  return(ACPU_ERROR);
	}

	if ((uprof = (Uprof *)malloc(sizeof(Uprof))) == NULL) {
	  errlog(Fatal, "user_begin: insufficient memory");
	  return(ACPU_ERROR);
	}

        bzero(uprof, sizeof(Uprof));
	strncpy(check_word, word, ACP_MAXUSTRING);
	check_word[ACP_MAXUSTRING] = '\0';
	temp = check_word;
	/* if profile criteria keyword, we just use count, spr 6259 */
	/* tokens screw everything up. */
	if (strstr(word, "="))sprintf(temp, "%d", database_count+1);
	fill_field(&temp, uprof->up_username, ACP_MAXUSTRING + 1);
	if (database_find(&users, uprof->up_username, uprof) == ACPU_ESUCCESS) {
	  print_user_name = 1;
	  errlog(Warning, "record exists for user");
	  print_user_name = 0;
	  bzero(uprof, sizeof(Uprof));
	  illegal_uprof = 1;
	}
	else
	  print_user_name = illegal_uprof = 0;

	database_count++;

	uprof->up_de.de_entry_num = database_count;
        /* Check if this is an environment string */
        while (strstr(word, "=")) {
           if (uprof->up_values_p == (struct environment_values *)NULL) {
	      uprof->up_values_p =
		(struct environment_values *)malloc(sizeof(struct environment_values));
              if (uprof->up_values_p == (struct environment_values *)NULL) {
		 /* print_user_name = 1; */
		 errlog(Warning, "insufficient memory for environment");
	         print_user_name = 0;
	         bzero(uprof, sizeof(Uprof));
	         illegal_uprof = 1;
	         break;
	      }
	      else {
		bzero(uprof->up_values_p, sizeof(struct environment_values));
	      }
	   }

           /* Parse the environemt string */
           if (env_keyword_routine(word,uprof->up_values_p) == TRUE) {
	      /* Get the next token (maybe environment token) */
	      if ((word = token_get(active_token)) == NULL)
                 break;
              else
                 env_parse = 1;
	   }
	   else {
	      /* Parsing failed setup for cleanup */
	      /* print_user_name = 1; */
	      errlog(Warning, "failed parsing environment");
	      print_user_name = 0;
	      bzero(uprof, sizeof(Uprof));
	      illegal_uprof = 1;
	      break;
	   }
        }

        if (env_parse) {
	   /* Push the unused token back on the stream */
	   token_unget(active_token, word);
        }

	return stack_push(&state, User);
}

static int
pool_begin(word)
char *word;
{
	if ((pool = (Pool *)malloc(sizeof(Pool))) == NULL) {
		errlog(Fatal, "not enough memory for pool");
		return ACPU_ERROR;
	}
	bzero(pool, sizeof(Pool));
	pool->po_listp = &pool->po_list;
	if (strlen(word) > NAMLEN) {
		errlog(Warning, "poolname truncated to 64 characters");
		word[NAMLEN] = '\0';
	}
	strcpy(pool->po_poolname, word);
	pool_entry = (PoolEntry *)malloc(sizeof(PoolEntry));
	if (!pool_entry) {
		errlog(Fatal, "not enough memory for pool entry");
		return ACPU_ERROR;
	}
	bzero(pool_entry, sizeof(PoolEntry));
	pool_entry->pe_gen = pools.db_gen;
	return stack_push(&state, Portpool);
}

static int
idle_error(word)
	char *word;
{
	errlog(Warning, "expected \"user\"");
	return stack_push(&state, Recover);
}

static int
access_begin(word)
	char *word;
{
	register Access **acpp;

	acpp = &uprof->up_accesslist;
	while (current_access = *acpp) {
		*acpp = current_access;
		acpp = &current_access->ac_next;
	}
	current_access = (Access *)malloc(sizeof(Access));
	if (!current_access) {
		errlog(Fatal, "not enough memory");
		return ACPU_ERROR;
	}
	bzero(current_access, sizeof(Access));
	*acpp = current_access;
	if (strlen(word) > NAMLEN) {
		errlog(Warning, "accesscode truncated to 64 characters");
		word[NAMLEN] = '\0';
	}
	strcpy(current_access->ac_code, word);
	return stack_push(&state, Acc);
}

static int
climask_begin(word)
	char *word;
{
	if (Mdebug)
		fprintf(stderr, "climask_begin: entered\n");

	if (uprof->up_climask) {
		errlog(Error, "multiply defined climask");
		return stack_push(&state, Recover);
	}
	climask(word);
	return stack_push(&state, Climask);
}

static int
climask(word)
	char *word;
{
	register i, j;

	/* NOTE, these must be in the same order as the MASK_* definitions */
	static char *cli_names[] = {
		"bg", "call", "fg", "hangup", "help",
		"hosts", "jobs", "kill", "netstat", "rlogin",
		"stats","stty", "telnet", "who", "lock",
		"su", "slip", "connect", "services", "ppp",
		"arap", "ipx", "dec", "lat", "ping", "none"
	};

#define	MAXCLINAM	(sizeof(cli_names) / sizeof (char *))

	if (Mdebug)
		fprintf(stderr, "climask: entered\n");
	
	for (i = 0; i < MAXCLINAM; i++) {
		if (!strncasecmp(cli_names[i], word, strlen(word)))
			break;
	}
	for (j = i + 1; j < MAXCLINAM; j++) {
		if (!strncasecmp(cli_names[j], word, strlen(word)))
			break;
	}
	if (i == MAXCLINAM) {
		errlog(Warning, "unsupported cli command name found");
		return stack_push(&state, Recover);
	}
	else if (j < MAXCLINAM) {
		errlog(Warning, "ambiguous cli command name found");
		return stack_push(&state, Recover);
	}
	else if (i == MAXCLINAM -1)
		uprof->up_climask = MASK_NONE;
	else 
		uprof->up_climask |= 1 << i;
	return ACPU_ESUCCESS;
}

static int
climask_end(word)
	char *word;
{
	if (Mdebug)
		fprintf(stderr, "climask_end: entered\n");

	token_unget(active_token, word);
	return stack_pop(&state);
}

static int
deny_user(word)
     char *word;
{
	if (Mdebug)
		fprintf(stderr, "deny_user: entered\n");

       token_unget(active_token, word);
       uprof->up_deny = TRUE;
       return ACPU_ESUCCESS;
}



/**********************************************************************
 *
 *  The release_cmd_list function is used to release clicmd, filter
 *  and route lists from the Uprof structure
 *
 **********************************************************************/

void
release_cmd_list(head_p)
struct cli_cmd_list *head_p;
{
	struct cli_cmd_list *entry_p;

	while(head_p)
	{
		entry_p = head_p;
		head_p  = head_p->next;
		free(entry_p);
	}
}


/**********************************************************************
 *
 *  The clicmd_begin, clicmd, and clicmd_end functions parse a
 *  clicmd entry in acp_userinfo
 *
 */

static int
clicmd_begin(word)
  char *word;
{
  register struct cli_cmd_list *entp;
  struct cli_cmd_list *new_entp;

  if (Mdebug)
    fprintf(stderr, "clicmd_begin: entered\n");

  new_entp = (struct cli_cmd_list *)malloc(sizeof(struct cli_cmd_list));
  if ((new_entp == NULL) || (strlen(word) > MAX_CLI_CMD)) {
    errlog(Error, "cannot allocate space for clicmd entry");
    return(stack_push(&state, Recover));	/* Clear out the list */
  }

  bzero(new_entp, sizeof(struct cli_cmd_list));
  new_entp->next = NULL;
  if (strcmp("...", word) != 0)		/* look for special indicator */
    strcpy(new_entp->clicmd, word);	/* this must be a real command */
  else
    *new_entp->clicmd = '\0';		/* indicates not to kill the cli */

  if (uprof->up_cmd_list == NULL)
    uprof->up_cmd_list = new_entp;
  else {
    for (entp = uprof->up_cmd_list; entp->next != NULL; entp = entp->next);
    entp->next = new_entp;
  }

  return(stack_push(&state, Clicmd));
}

static int
clicmd(word)
  char *word;
{
  register struct cli_cmd_list *entp;

  if (Mdebug)
    fprintf(stderr, "clicmd: entered\n");

  for (entp = uprof->up_cmd_list; entp->next != NULL; entp = entp->next);
  if ((strlen(entp->clicmd) + strlen(word) + 2) > MAX_CLI_CMD) {
    errlog(Error, "clicmd \"%20s ...\" - length greater than %d\n",
	   entp->clicmd, MAX_CLI_CMD);
    return(stack_push(&state, Recover));	/* Clear out the list ??? */
  }

  strcat(entp->clicmd, " ");
  strcat(entp->clicmd, word);

  return(ACPU_ESUCCESS);
}

static int
clicmd_end(word)
	char *word;
{
  if (Mdebug)
    fprintf(stderr, "clicmd_end: entered\n");

  token_unget(active_token, word);
  return stack_pop(&state);
}

/**********************************************************************
 *
 *  The filter_begin, filter, and filter_end functions parse a
 *  filter entry in acp_userinfo
 *
 */

static int
filter_begin(word)
  char *word;
{
  register struct cli_cmd_list *entp;
  struct cli_cmd_list *new_entp;

  if (Mdebug)
    fprintf(stderr, "filter_begin: entered\n");

  new_entp = (struct cli_cmd_list *)malloc(sizeof(struct cli_cmd_list));
  if ((new_entp == NULL) || (strlen(word) > MAX_CLI_CMD)) {
    errlog(Error, "cannot allocate space for filter entry");
    return(stack_push(&state, Recover));	/* Clear out the list */
  }

  bzero(new_entp, sizeof(struct cli_cmd_list));
  new_entp->next = NULL;
  strcpy(new_entp->clicmd, word);

  if (uprof->up_filter_list == NULL)
    uprof->up_filter_list = new_entp;
  else {
    for (entp = uprof->up_filter_list; entp->next != NULL; entp = entp->next);
    entp->next = new_entp;
  }

  return(stack_push(&state, Filter));
}

static int
filter(word)
  char *word;
{
  register struct cli_cmd_list *entp;

  if (Mdebug)
    fprintf(stderr, "filter: entered\n");

  for (entp = uprof->up_filter_list; entp->next != NULL; entp = entp->next);
  if ((strlen(entp->clicmd) + strlen(word) + 2) > MAX_CLI_CMD) {
    errlog(Error, "filter \"%20s ...\" - length greater than %d\n",
	   entp->clicmd, MAX_CLI_CMD);
    return(stack_push(&state, Recover));	/* Clear out the list ??? */
  }

  strcat(entp->clicmd, " ");
  strcat(entp->clicmd, word);

  return(ACPU_ESUCCESS);
}

static int
filter_end(word)
	char *word;
{
  if (Mdebug)
    fprintf(stderr, "filter_end: entered\n");

  token_unget(active_token, word);
  return stack_pop(&state);
}

/**********************************************************************
 *
 *  The route_begin, route, and route_end functions parse a
 *  route entry in acp_userinfo
 *
 */

static int
route_begin(word)
  char *word;
{
  register struct cli_cmd_list *entp;
  struct cli_cmd_list *new_entp;

  if (Mdebug)
    fprintf(stderr, "route_begin: entered\n");

  new_entp = (struct cli_cmd_list *)malloc(sizeof(struct cli_cmd_list));
  if ((new_entp == NULL) || (strlen(word) > MAX_CLI_CMD)) {
    errlog(Error, "cannot allocate space for route entry");
    return(stack_push(&state, Recover));	/* Clear out the list */
  }

  bzero(new_entp, sizeof(struct cli_cmd_list));
  new_entp->next = NULL;
  strcpy(new_entp->clicmd, word);

  if (uprof->up_route_list == NULL)
    uprof->up_route_list = new_entp;
  else {
    for (entp = uprof->up_route_list; entp->next != NULL; entp = entp->next);
    entp->next = new_entp;
  }

  return(stack_push(&state, Route));
}

static int
route(word)
  char *word;
{
  register struct cli_cmd_list *entp;

  if (Mdebug)
    fprintf(stderr, "route: entered\n");

  for (entp = uprof->up_route_list; entp->next != NULL; entp = entp->next);
  if ((strlen(entp->clicmd) + strlen(word) + 2) > MAX_CLI_CMD) {
    errlog(Error, "route \"%20s ...\" - length greater than %d\n",
	   entp->clicmd, MAX_CLI_CMD);
    return(stack_push(&state, Recover));	/* Clear out the list */
  }

  strcat(entp->clicmd, " ");
  strcat(entp->clicmd, word);

  return(ACPU_ESUCCESS);
}

static int
route_end(word)
  char *word;
{
  if (Mdebug)
    fprintf(stderr, "route_end: entered\n");

  token_unget(active_token, word);
  return stack_pop(&state);
}

static int
blacklist(word)
	char *word;
{
	int n;

	if (Mdebug)
		fprintf(stderr, "blacklist: entered\n");

	n = atoi(word);
	if (n > 0)
		uprof->up_blacklist = n;
	else
		errlog(Warning, "expected blacklist arg > 0");
	return ACPU_ESUCCESS;
}

static int
user_error(word)
char *word;
{
	errlog(Error, "expected user keyword");
	/*return stack_push(&state, Recover);*/
	return ACPU_ERROR;
}

static int
atzone_begin(word)
	char *word;
{
	token_unget(active_token, word);
	uprof->up_at.at_zones = 0;
	return stack_push(&state, Zone);
}

static int
atpasswd(word)
	char *word;
{
	register i, n = strlen(word);
	char c;

	for (i = 0; i < n; i++) {
		c = word[i];
		if (c == ' ') {
			errlog(Warning, "illegal blank in at_passwd");
			illegal_uprof = 1;
			return ACPU_ESUCCESS;
		}
		if (!isalnum(c) && !ispunct(c)) {
			errlog(Warning, "illegal character in at_passwd");
			illegal_uprof = 1;
			return ACPU_ESUCCESS;
		}
	}
	if (n > PWDLEN) {
		errlog(Warning, "passwd truncated to 8 characters");
		illegal_uprof = 1;
		word[PWDLEN] = '\0';
		n = PWDLEN;
	}
	strcpy(uprof->up_at.at_passwd, word);
	return ACPU_ESUCCESS;
}

static int
dyndial_passwd(word)
	char *word;
{
	register i, n = strlen(word);
	char c;

	for (i = 0; i < n; i++) {
		c = word[i];
		if (c == ' ') {
			errlog(Warning, "illegal blank in dyndial_passwd");
			return ACPU_ESUCCESS;
		}
		if (!isalnum(c) && !ispunct(c)) {
			errlog(Warning, "illegal character in dyndial_passwd");
			return ACPU_ESUCCESS;
		}
	}
	if (n >= ACP_MAXSTRING) {
		errlog(Warning, "dyndial passwd truncated to 31 characters");
		word[ACP_MAXSTRING] = '\0';
		n = ACP_MAXSTRING - 1;
	}
	strcpy(uprof->user_index, word);
	return ACPU_ESUCCESS;
}


static int
chap_secret(word)
        char *word;
{
        register i, n = strlen(word);
        char c;

        for (i = 0; i < n; i++) {
                c = word[i];
                if (c == ' ') {
                        errlog(Warning, "illegal blank in chap_secret");
                        return ACPU_ESUCCESS;
                }
                if (!isalnum(c) && !ispunct(c)) {
                        errlog(Warning, "illegal character in chap_secret");
                        return ACPU_ESUCCESS;
                }
        }
        if (n >= ACP_MAXSTRING) {
                errlog(Warning, "chap secret truncated to 31 characters");
                word[ACP_MAXSTRING] = '\0';
                n = ACP_MAXSTRING - 1;
        }
        strcpy(uprof->up_secret, word);
        return ACPU_ESUCCESS;
}

static int
  max_logon_time(word)
    char *word;
{
       uprof->up_max_logon = atoi(word);
       /* -1 value means log this user off immediately. */
       if (((uprof->up_max_logon < 0) && (uprof->up_max_logon != -1)) ||
           (uprof->up_max_logon > MAX_LOGON) || (uprof->up_max_logon == 0)){
         errlog(Warning,"Illegal max_logon argument");
         return stack_push(&state, Recover);
       }
       else
         return ACPU_ESUCCESS;
     }

static int
atconnect_time(word)
char *word;
{
	register int n;
	int i;
	int max = strlen(word);
	char *p = word;

	for(i=0; i<max; i++)
	    if(isdigit(*p++) == FALSE)
		{
		errlog(Warning, "illegal at_connect_time argument");
		illegal_uprof = 1;
		return ACPU_ESUCCESS;
		}

	n = atoi(word);
	if (n < 0) {
		errlog(Warning, "illegal at_connect_time argument");
		illegal_uprof = 1;
	  }
	uprof->up_at.at_connect_time = n;
	return ACPU_ESUCCESS;
}

static int
atcallback(word)
	char *word;
{
	if (strlen(word) > DIALEN) {
		errlog(Warning, "phone num truncated to 32 characters");
		illegal_uprof = 1;
		word[DIALEN] = '\0';
	}
	strcpy(uprof->up_at.at_callback, word);
	return ACPU_ESUCCESS;
}

static int
local_addr(word)
char *word;
{
	struct hostent *hostent;

	uprof->up_local_addr = inet_addr(word);
	if (uprof->up_local_addr == -1) {
		if ((hostent = gethostbyname(word)) == 0) {
			errlog(Warning, "unknown local hostname");
			return stack_push(&state, Recover);
		}
		bcopy(hostent->h_addr, &uprof->up_local_addr,
			hostent->h_length);
	}
	return ACPU_ESUCCESS;
}

static int
mp_max_links(word)
char *word;
{
	register int n;
	int i;
	int max = strlen(word);
	char *p = word;

	for(i=0; i<max; i++)
	    if(isdigit(*p++) == FALSE)
		{
		errlog(Warning, "illegal mp_max_links argument");
		illegal_uprof = 1;
		return ACPU_ESUCCESS;
		}

	n = atoi(word);
	if (n < 0) {
		errlog(Warning, "illegal mp_max_links argument");
		illegal_uprof = 1;
	  }
	uprof->up_mp_max_links = n;
	return ACPU_ESUCCESS;
}

static int
remote_addr(word)
char *word;
{
	struct hostent *hostent;

	uprof->up_remote_addr = inet_addr(word);
	if (uprof->up_remote_addr == -1) {
		if ((hostent = gethostbyname(word)) == 0) {
			errlog(Warning, "unknown remote hostname");
			return stack_push(&state, Recover);
		}
		bcopy(hostent->h_addr, &uprof->up_remote_addr,
			hostent->h_length);
	}
	return ACPU_ESUCCESS;
}

static int
subnet_mask(word)
char *word;
{
	struct hostent *hostent;

	uprof->up_subnet_mask = inet_addr(word);
	if (uprof->up_subnet_mask == -1) {
		if ((hostent = gethostbyname(word)) == 0) {
			errlog(Warning, "unknown subnet mask");
			return stack_push(&state, Recover);
		}
		bcopy(hostent->h_addr, &uprof->up_subnet_mask,
			hostent->h_length);
	}
	return ACPU_ESUCCESS;
}

static int
user_end(word)
char *word;
{
	char *env_print_values();

	token_unget(active_token, word);
	if (illegal_uprof == 0) {
	  if (Mlint) {
	    if(uprof->up_values_p != (struct environment_values *) 0)
		(void) fprintf(stderr, "Security profile criteria %s added\n",
			env_print_values(uprof->up_values_p));
	    else
	    	(void) fprintf(stderr, "user %s added\n", uprof->up_username);
	  }
	  database_add(&users, uprof);
	}
	else {
	  print_user_name = 1;
	  errlog(Warning, "record not loaded for user");
	  print_user_name = 0;
	  free(uprof);
	  uprof = (Uprof *) 0;
	}
	illegal_uprof = 0;
	return stack_pop(&state);
}


static int
phone_no(word)
	char *word;
{

#define ca_phone_list   current_access->ac_phone_list
#define ca_phone        current_access->ac_phone_list->ac_phone
#define ca_code         current_access->ac_code

	int is_ipx = !strcmp(ca_code, IPX_ACCESS_CODE_TOK);
	struct _phone **ll_head_ptr = 0;
	char	*phone_ptr = 0;


	if (strlen(word) > DIALEN) {
		errlog(Warning, "phone no truncated to 32 characters");
		word[DIALEN] = '\0';
	}

	if (!ca_phone_list) {
		ll_head_ptr = &ca_phone_list;
	}
	else {
	    if (is_ipx) {

		/*
		 * For ipx, go to the back of the list.
		 */
		struct _phone *mark, *last;
		for (mark = ca_phone_list; 
			mark; mark = mark->next) {
			last = mark;
		}
		phone_ptr = last->ac_phone;
		ll_head_ptr = &(last->next);

		/*
		 * If the last phone number is the
		 * charge_back token, then this 
		 * phone number just read is 
		 * meaningless.
		 */

		if (phone_ptr && !strcmp(phone_ptr, 
				IPX_CHARGE_BACK_TOK))
			return ACPU_ESUCCESS;
	    }
	    else {

		/*
		 * For cli dialback security, there's
		 * only one phone number in the list,
		 * i.e. at the head.
		 */
		phone_ptr = ca_phone;
	    }
        }

	if (ll_head_ptr) {
		(*ll_head_ptr) =(struct _phone *)malloc(sizeof(struct _phone));
		if (!(*ll_head_ptr)) {
			errlog(Fatal, "not enough memory");
                        return ACPU_ERROR;
                }
		bzero(*ll_head_ptr, sizeof(struct _phone));
		phone_ptr = (*ll_head_ptr)->ac_phone;
        }
	strcpy(phone_ptr, word);
	return ACPU_ESUCCESS;
}


static int
in_pool_name(word)
	char *word;
{
	if (strlen(word) > NAMLEN) {
		errlog(Warning, "pool name no truncated to 64 characters");
		word[NAMLEN] = '\0';
	}
	strcpy(current_access->ac_inpool, word);
	return ACPU_ESUCCESS;
}

static int
out_pool_name(word)
	char *word;
{
	if (strlen(word) > NAMLEN) {
		errlog(Warning, "poll name truncated to 64 characters");
		word[NAMLEN] = '\0';
	}
	strcpy(current_access->ac_outpool, word);
	return ACPU_ESUCCESS;
}

static int
job_begin(word)
	char *word;
{
	Acjob *acjob = &current_access->ac_job;

	if (acjob->j_length) {
		errlog(Error, "multiply defined jobs");
		return stack_push(&state, Recover);
	}
	acjob->j_length = strlen(word);
	if (acjob->j_length > JOBLEN) {
		errlog(Error, "job string too long");
		return stack_push(&state, Recover);
	}
	strcpy(acjob->j_string, word);
	acjob->j_count = 1;
	return stack_push(&state, Job);
}

static int
job(word)
	char *word;
{
	Acjob *acjob = &current_access->ac_job;
	int i = strlen(word);

	if ((i + acjob->j_length + 1) > JOBLEN) {
		errlog(Error, "job string too long");
		return stack_push(&state, Recover);
	}
	acjob->j_string[acjob->j_length++] = ' ';
	strcpy(&acjob->j_string[acjob->j_length], word);
	acjob->j_length += i;
	acjob->j_count++;
	return ACPU_ESUCCESS;
}

static int
job_end(word)
char *word;
{
	token_unget(active_token, word);
	return stack_pop(&state);
}

static int
access_end(word)
        char *word;
{
        token_unget(active_token, word);

#ifdef  DEBUG_PHONE_LIST
        {
            struct _phone *x;
            if ((x = current_access->ac_phone_list)) {
                printf("Phone numbers for accescode %s:\n\t",
                        ca_code);
                for (;x; x = x->next) {
                        printf("%s  ", x->ac_phone);
                }
                printf("\n");
            }
        }
#endif
	return stack_pop(&state);

}

static int
access_error(word)
	char *word;
{
	errlog(Error, "expected access keyword");
	return stack_push(&state, Recover);
}

static int
zone_end(word)
	char *word;
{
	token_unget(active_token, word);
	return stack_pop(&state);
}

static int
zone(word)
	char *word;
{
	At *atp = &uprof->up_at;
	register int i, n = strlen(word);
	char c;

	for (i = 0; i < n; i++) {
		c = word[i];
#if 0
		if (c == ' ') {
			errlog(Warning, "illegal blank in zone");
			return ACPU_ESUCCESS;
		}
#endif
		if (!isalnum(c) && !ispunct(c) && !isspace(c)) {
			errlog(Warning, "illegal character in zone");
			illegal_uprof = 1;
			return ACPU_ESUCCESS;
		}
	}
	if (n > ZONLEN) {
		errlog(Warning, "zone truncated to 33 characters");
		illegal_uprof = 1;
		word[ZONLEN] = '\0';
		n = ZONLEN;
	}
	if (atp->at_zone_combined + 1 + n  > MAXNUMZON) {
		errlog(Warning, "too many at_zone characters, ignored");
		illegal_uprof = 1;
	  }
	else {
		atp->at_zonelist[atp->at_zone_combined++] = (u_char)n;
		strcpy(&atp->at_zonelist[atp->at_zone_combined],word);
		atp->at_zone_combined += n;
		atp->at_zones++;
	}
	return ACPU_ESUCCESS;
}

static int
portnum(word)
char *word;
{
	if (pool_entry->pe_flags & PF_PORT) {
		if ((pool_entry->pe_flags & PF_ADDR) == 0)
			errlog(Warning, "unspecified address identifier");
		*pool->po_listp = pool_entry;
		pool->po_listp = &pool_entry->pe_next;
		pool_entry = (PoolEntry *)malloc(sizeof(PoolEntry));
		if (!pool_entry) {
			errlog(Fatal, "not enough memory for pool entry");
			return ACPU_ERROR;
		}
	        bzero(pool_entry, sizeof(PoolEntry));
		pool_entry->pe_gen = pools.db_gen;
		pool->po_count++;
	}
	return portmem(word);
}

#define PORTS    1
#define HOSTNAME 2
#define ERROR_STATE    3
#define DONE     4

static int
portmem(word)
char *word;
{
	char *cp=0, *pp=0;
	char buffp[ACP_MAXSTRING];
	int done=FALSE;
	int rv=TRUE;
	int state=PORTS;
	pool_entry->pe_flags |= PF_PORT;
	
	/*
	 * This fxn. gets a pool port string of following 
	 * syntax:
	 *
	 * pool-port       := <port-string><hostname>
	 * port-string     := <port><port-expr>
	 * port-expr       := {} | ,[ <port-string> | <port-range> ]
	 * port-range      := <port><port-range-expr>
	 * port-range-expr := -<port-string>
	 * hostname        := @<ip>
	 * ip              := #.#.#.# | name
	 * port            := annex port#s 
	 *
	 * <port-string> is parsed by calling extract_ports()
	 * fxn. in env_parser.c file. <ip> is parsed by calling
	 * hostname() .
	 */
	while(!done) {
	   switch(state) {

	     /* parse <port-string> */
	   case PORTS:
	     strncpy(buffp, word, strcspn(word, "@"));  /* copy <port-string> to buff */
	     buffp[strcspn(word, "@")]='\0';
	     pp = buffp;
	     cp=strstr(word, "@");

	     /* call extract_port_list() to parse <port-string> */
	     if(rv = extract_port_list(&pp,pool_entry->pe_ports))
	       state = HOSTNAME;
	     else 
	       state = ERROR_STATE;
	     break;

	     /* parse <hostname> */
	   case HOSTNAME:
	     if (*cp != '@') {
	       state = ERROR_STATE;
	       break;
	     }
	     *cp++ = '\0';

	     /* call hostname() to parse <ip> */
	     if (hostname(cp) != ACPU_ESUCCESS)
	       state = ERROR_STATE;
	     else state = DONE;
	     break;
	     
	     /* error out */
	   case ERROR_STATE:
	     done = TRUE;
	     rv = ACPU_ERROR;
	     break;
	     
	     /* end parsing */
	   case DONE:
	   default:
	     done = TRUE;
	     rv = ACPU_ESUCCESS;
	     break;
	   }
	 }

	if (*cp)
	  return stack_pop(&state);
	return(rv);
}

static int
portset(word)
char *word;
{
	token_unget(active_token, word);
	if (pool_entry->pe_flags & PF_PORT) {
		if ((pool_entry->pe_flags & PF_ADDR) == 0)
			errlog(Warning, "unspecified Annex identifier");
		*pool->po_listp = pool_entry;
		pool->po_listp = &pool_entry->pe_next;
		pool_entry = (PoolEntry *)malloc(sizeof(PoolEntry));
		if (!pool_entry) {
			errlog(Fatal, "not enough memory for pool entry");
			return ACPU_ERROR;
		}
	        bzero(pool_entry, sizeof(PoolEntry));
		pool_entry->pe_gen = pools.db_gen;
		pool->po_count++;
	}
	return stack_push(&state, Portset);
}

static int
portset_end(word)
char *word;
{
	token_unget(active_token, word);
	return stack_pop(&state);
}

static int
pool_end(word)
char *word;
{
	token_unget(active_token, word);
	*pool->po_listp = pool_entry;
	pool->po_listp = &pool_entry->pe_next;
	pool->po_count++;
	database_add(&pools, pool);
	return stack_pop(&state);
}

static int
pool_error(word)
char *word;
{
	errlog(Warning, "expected pool keyword");
	return stack_push(&state, Recover);
}

static int
hostname(word)
char *word;
{
	struct hostent *hostent;

	if (pool_entry->pe_flags & PF_ADDR) {
		if ((pool_entry->pe_flags & PF_PORT) == 0)
			errlog(Warning, "unspecified port identifier");
		*pool->po_listp = pool_entry;
		pool->po_listp = &pool_entry->pe_next;
		pool_entry = (PoolEntry *)malloc(sizeof(PoolEntry));
		if (!pool_entry) {
			errlog(Fatal, "not enough memory for pool entry");
			return ACPU_ERROR;
		}
	        bzero(pool_entry, sizeof(PoolEntry));
		pool_entry->pe_gen = pools.db_gen;
		pool->po_count++;
	}
	pool_entry->pe_flags |= PF_ADDR;
	if (strlen(word) > NAMLEN) {
		errlog(Warning, "truncating hostname to 64 characters");
		word[NAMLEN] = '\0';
	}
	strcpy(pool_entry->pe_hostname, word);
	pool_entry->pe_hostaddr = inet_addr(word);
	if (pool_entry->pe_hostaddr == -1) {
		if ((hostent = gethostbyname(word)) == 0) {
			errlog(Warning, "unknown hostname");
			return stack_push(&state, Recover);
		}
		bcopy(hostent->h_addr, &pool_entry->pe_hostaddr,
			hostent->h_length);
	}
	return ACPU_ESUCCESS;
}

static int
recover_end(word)
	char *word;
{
	token_unget(active_token, word);
	return stack_pop(&state);
}

static int
recover(word)
	char *word;
{
	return ACPU_ESUCCESS;
}

static  int
nve_begin(word) 
	char *word;
{
	token_unget(active_token, word);
	return stack_push(&state, Nve);
}

static int
test_nve( word , len)
	char *word;
	int len;
{
        int wild = 0;
	int esc = 0;
        char *p = word;

        if (len == 0) {
	    errlog(Error, "Zero length entity");
 	    return ( ACPU_ERROR );
        }

	if (len > ZONLEN) {
		errlog(Warning, "Entity truncated to 32 characters");
		word[ZONLEN] = '\0';
		len = ZONLEN;
		return ACPU_ERROR;
	}
        while ( len ) {
		if ( *p == '*' ) 
			wild++;
          	if ( wild > 1 ) {
	    		errlog(Error, "Too Many wildcards in NVE");
 			return(ACPU_ERROR);
          	}
                p++;
		len--;
	}
	return (ACPU_ESUCCESS);
}
static  int
nve_filter(word) 
	char *word;
{
	int n;
        int indx;
        char *p;
	At *atp = &uprof->up_at;
	
        indx = atp->at_nve_combined;
        if ((p =  (char *)index ( word, ':')) == (char *)0) {
          errlog(Error, "Missing colon (:) in NVE filter");
	  illegal_uprof = 1;
          return(ACPU_ESUCCESS);
        } else {
          n = p - word;
          if (test_nve(word, n) == ACPU_ERROR) {
	    illegal_uprof = 1;
	    return(ACPU_ESUCCESS);
	  }
	  atp->at_nve[indx++] = (char)n;
	  strncpy(&atp->at_nve[indx],word, n);
	  indx += n;
          word = p+1;
       }
       if ((p = (char *)index(word, '@')) == (char *)0) {
          errlog(Error, "Missing at sign (@) in NVE filter");
	  illegal_uprof = 1;
          return(ACPU_ESUCCESS);
       } else {
          n = p - word;
          if (test_nve(word , n) == ACPU_ERROR) {
	    illegal_uprof = 1;
	    return(ACPU_ESUCCESS);
	  }
	  atp->at_nve[indx++] = (char)n;
	  strncpy(&atp->at_nve[indx],word, n);
	  indx += n;
          word = p+1;
       }

       if (*word) {
          n = strlen ( word );
          if (test_nve(word, n ) == ACPU_ERROR) {
	    illegal_uprof = 1;
	    return(ACPU_ESUCCESS);
	  }
	  atp->at_nve[indx++] = (char)n;
	  strncpy(&atp->at_nve[indx],word, n);
	  indx += n;
	  atp->at_nve_combined = indx;
	  atp->at_nves += 3;
       } else {
          errlog(Error, "Missing zone in NVE filter");
	  illegal_uprof = 1;
          return(ACPU_ESUCCESS);
       }
          
	if (atp->at_nve_combined + 1 + n  > MAXNUMNVE) {
	  atp->at_nve_combined = MAXNUMNVE;
	  errlog(Warning, "Too many at_nve_filter characters, ignored");
	  illegal_uprof = 1;
        }

	return ACPU_ESUCCESS;
}
static  int
nve_include(word) 
	char *word;
{
	token_unget(active_token, word);
	return ACPU_ESUCCESS;
}
static  int
nve_exclude(word)
	char *word;
{
	At *atp = &uprof->up_at;
	atp -> at_nve_exclude = 1;
	token_unget(active_token, word);
	return ACPU_ESUCCESS;
}

static  int
nve_end(word) 
	char *word;
{
	At *atp = &uprof->up_at;
	
	token_unget(active_token, word);
        if ((atp -> at_nves == 0) || ((atp -> at_nves % 3) != 0)) {
	   atp -> at_nves = 0;
	   atp -> at_nve_combined = 0;
	   atp -> at_nve_exclude = 0;
	   return stack_pop(&state);
        }
	return stack_pop(&state);
}




#define GROUP_FIELD_DELIMITERS ":,\t\n "
#define DISALLOW_GROUP '-'

/******************************************************************************
*
* create_group_list_4_env
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

static int 
create_group_list_4_env(group_list,username, file_info)
struct group_entry **group_list;
char                *username;
struct        gr_file *file_info;
{
#ifdef _WIN32

	NTCreateGroupList(group_list,username);
	return TRUE;

#else /* _WIN32 */
   FILE   *grp;
   struct  group_entry *head, 
                       *entry;
   struct  group       *grp_entry;
#if defined (ULTRIX) || defined (FREEBSD) || defined (BSDI)
   struct group *getgrent();
#else
   struct  group       *fgetgrent();
#endif

   int     retv = FALSE,field;
   struct  stat buff_stat;


   head = (struct group_entry *)NULL;
   errno = 0;

   /* checking to see if acp_group */
   /* exists M_ALI 8/7/95.         */

#if (!(defined (ULTRIX) || defined (FREEBSD) || defined (BSDI)))
   if ((stat(file_info->group_f, &buff_stat)) == 0)
   {
        if((grp = fopen(file_info->group_f, "r")) == NULL){
          syslog(LOG_CRIT, "erpcd: failed to open acp_group file");
          return(retv);
     }

   }

   /* since acp_group doesn't exist, */
   /* /etc/group must exist. else it */
   /* is an error  M_ALI 8/7/95      */

   else 
#endif
if ((errno == ENOENT || errno==0) && (stat (DEFAULT_GROUP, &buff_stat)) == 0)
   {
       if ((buff_stat.st_mode & S_IRUSR))
          grp = fopen(DEFAULT_GROUP,"r");
       else
       {
          syslog(LOG_CRIT, "erpcd: failed to open %s", DEFAULT_GROUP);
          return(retv);
        }
  }

   /* Both acp_group and /etc/group  */
   /* are not available. This is an  */
   /* error. retv=FALSE M_ALI 8/7/95 */
      
   if(grp == NULL){
        syslog(LOG_CRIT, "erpcd: failed to open either of the group files");
        return retv;
    }

   /* retv can only be FALSE when there   */
   /* is an error calloc'ng. M_ALI 8/7/95 */

   retv = TRUE;

   /* get a line from the group file */
#if defined (ULTRIX) || defined (FREEBSD) || defined (BSDI)
   setgrent();
   while(grp_entry = getgrent())
#else
   while((grp_entry = fgetgrent(grp)))
#endif
   {                              
       /* Get the group name */                                         
      if (*(grp_entry->gr_name) == DISALLOW_GROUP)
         continue;

      if (is_group_member_4_env(grp_entry->gr_mem, username)) {
         if (entry = (struct group_entry *)malloc(sizeof(struct group_entry))){
	    bzero(entry, sizeof(struct group_entry));
            strcpy(entry->groupname,grp_entry->gr_name);

            /* Place entry at the head of the list */
	    entry->next = head;
	    head = entry;
         }
	 
         else {		/* Unable to create a link list - return FALSE */
	    retv = FALSE;
	    syslog(LOG_ERR,"acp_group.c: insufficient memory for group entry");
            while(head) {
               entry = head;
               head = head->next;
               free(entry); 
            }
            break;
         } /* End if malloc OK */
      } /* End if is group member */
   } /* End for all acp_group entries */

   *group_list = head;
   fclose(grp);
   return(retv);
#endif	/* _WIN32 */
}


/******************************************************************************
*
* is_group_member_4_env
*
* This is function searches for the user_list for the specified user.
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

static int
is_group_member_4_env(user_list,user)
char **user_list;
char  *user;
{
   for(; *user_list; user_list++)
      if (strcasecmp(*user_list, user) == 0)
	 return(TRUE);

   return(FALSE);
}


static int
open_include_file(word)
        char *word;
{
	char temp_name[256];
	int status;
 
        if(sub_token.t_fp) {
        /* not allowed to nest include files */
          errlog (Error, "Include files cannot be nested - Ignored");
          return ACPU_ESUCCESS;
        }
 
        sprintf(temp_name,"%s/%s",install_dir,word);
        if ((status = token_open(&sub_token, temp_name)) != ACPU_ESUCCESS)
                return (status);
        active_token = &sub_token;
        return token_read(active_token);
}
