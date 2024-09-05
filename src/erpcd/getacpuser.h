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
 * File description:  ACP user profile definitions
 *
 * Original Author: Richard G. Bockenek		Created on: 2/22/93
 *
 ****************************************************************************
 */

#ifndef _GETACPUSER_H_
#define _GETACPUSER_H_

#define	ACPU_ESUCCESS		0
#define ACPU_ESKIP              1
#define ACPU_ENOACP		2
#define ACPU_EINPROG		3
#define ACPU_EBADGEN		4
#define ACPU_ENOUSER		5
#define ACPU_ENOACC		6
#define ACPU_ENOPOOL		7
#define ACPU_ENOPOOLENT		8
#define ACPU_EACCESSCODE	9
#define ACPU_ERROR		10

#define M_INCR		1
#define M_LINT		2
#define M_TEE		4
#define M_DEBUG		8

#define UNAMLEN		128
#define NAMLEN		63
#define DIALEN		31
#define JOBLEN		79
#define PWDLEN		8
#define ZONLEN		32

#define MAX_SERIAL_PORTS      72            /* allow for ANNEX 3 */

#ifndef MAX_PORTS
#define MAX_PORTS 128
#endif

#define TOKBUFLEN	2048
#define MAXNUMZON	524
#define MAXNUMNVE	990		/* 10 * 99 */
#define MAXSTKENT	8
#define MAX_CLI_CMD     80

#define SEPARATORS	" \t\r\n\f\\"
#define SEPARATORS_W_QUOTES	" \t\r\n\f\\\""

typedef int (*ifp)();	/* integer function pointer */
typedef enum { Unspecified = 0, Fatal, Error, Warning } Severity;
typedef enum { Idle = 1, User, Acc, Zone, Job, Nve, Climask,
		Clicmd, Filter, Route, Portpool, Portset, Recover } State;

struct cli_cmd_list {
   struct cli_cmd_list *next;
   char clicmd[MAX_CLI_CMD];
};

struct gr_file { 
  char *group_f;
  char *default_f;
  int   count;
}; 

struct env_gr_info {
  struct gr_file *gr_info;
  struct environment_spec **env;
};

typedef struct _database_entry {
        long    de_entry_num;/*keep the serialnum. of the records. M_ALI 10/8/95*/
	struct _database_entry	*de_next;
	char			de_key[UNAMLEN + 1];
} DatabaseEntry, *DatabaseEntryP;

typedef struct _acjob {
	struct _acjob	*j_next;
	int		j_count;
	char		j_string[JOBLEN + 1];
	int		j_length;
} Acjob;

struct _phone {
	char            ac_phone[DIALEN + 1];
	struct _phone   *next;
};


typedef struct _access {
	struct _access	*ac_next;
	char            ac_code[NAMLEN + 1];
	struct _phone	*ac_phone_list;
	char            ac_inpool[NAMLEN + 1];
	char            ac_outpool[NAMLEN + 1];
	Acjob           ac_job;
} Access, *AccessP;

typedef struct {
	int       	at_zones;
	int		at_zone_combined;
	char		at_zonelist[MAXNUMZON];
	char      	at_passwd[PWDLEN + 1];
	int       	at_nves;
	int		at_nve_combined;
	int		at_nve_exclude;
	char 		at_nve[MAXNUMNVE+1];
	int		at_connect_time;
	char      	at_callback[DIALEN + 1];
} At, *Atp;

typedef struct _uprof {
	DatabaseEntry	           up_de;
#define up_entry_num              up_de.de_entry_num
#define up_next		           up_de.de_next
#define up_username	           up_de.de_key
	Access		          *up_accesslist;
	INT32		           up_climask;
        struct cli_cmd_list       *up_cmd_list;
	struct cli_cmd_list       *up_filter_list;
        struct cli_cmd_list       *up_route_list;
        struct environment_values *up_values_p;
	int		           up_blacklist;
	int                        up_deny; /* if true deny this user*/
	UINT32		           up_local_addr;
	UINT32		           up_remote_addr;
	UINT32		           up_subnet_mask;
	At		           up_at;
	ACP_STRING	           user_index;
	ACP_STRING	           up_secret;
	int                        up_mp_max_links;	/* mp_max_links */
        int                        up_max_logon;
} Uprof, *UprofP;

typedef struct _pool_entry {
	struct _pool_entry *pe_next;
	int		pe_flags;
#define PF_PORT		1
#define PF_ADDR		2
	char		pe_hostname[NAMLEN + 1];
	INT32		pe_hostaddr;
	char		pe_ports[DEV_MAX][MAX_PORTS/8];
	int		pe_gen;
} PoolEntry, *PoolEntryP;

typedef struct _pool {
	DatabaseEntry	po_de;
#define po_next		po_de.de_next
#define po_poolname	po_de.de_key
	PoolEntry	*po_list;
	PoolEntry	**po_listp;
	int		po_count;
} Pool, *PoolP;

typedef struct {
	int		t_line;
	char		*t_bp;
	FILE		*t_fp;
	char		*t_ungotten;
	char		t_filename[NAMLEN + 1];
	char		t_buf[TOKBUFLEN + 1];
} Token;

typedef struct {
	int		s_index;
	int		s_stack[MAXSTKENT + 1];
} Stack;

typedef struct {
	int		pe_num_events;
	char		**pe_keywords;
	ifp		*pe_funcs;
} ParserEntry;

typedef struct {
	int	        db_flags;
#define	DF_OPEN		1
#define DF_READY	2
	DatabaseEntry	*db_list;
	DatabaseEntry	**db_listp;
	int		db_entries;
	int		db_sizeof;
	int		db_gen;
} Database;

/*
 * Services provided
 */

int get_user_access();
int get_port_pool();
int get_next_pool_entry();
int get_pool_entry_by_addr();

/*
 * inline functions
 */
#define token_unget(this, word)	((this)->t_ungotten = word)
#define token_free(this)	fclose((this)->t_fp)
#define database_ready(this)	((this)->db_flags |= DF_READY)
#define database_entries(this)	(this)->db_entries
#define database_flags(this)	(this)->db_flags
#define stack_current(this)	(this)->s_stack[(this)->s_index]

#endif /* _GETACPUSER_H_ */


/*
 * Prototype functions
 */
int pre_open_user_profile_file();
int pre_close_user_profile_file();
int pre_init_user_profile_file();
int pre_clear_user_profile_info();
int pre_get_user_profile_entry();
int pre_get_user_access();
int pre_get_port_pool();
int pre_get_next_pool_entry();
int pre_get_pool_entry_by_addr();
int extract_port_list();
int pre_setacpdialup();
int pre_endacpdialup();
int pre_findacpdialup();
void release_uprof();
void clear_user_profile_info();



