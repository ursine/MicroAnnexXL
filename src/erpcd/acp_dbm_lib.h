#ifdef USE_NDBM

#ifndef  MAX_STORED_PASS
#define MAX_STORED_PASS 12
#endif

#ifndef MAX_FAILURES
#define MAX_FAILURES 20
#endif

#define HASHLEN 13
#define TRUE 1
#define FALSE 0

#ifdef IUNIX
#include <sys/bsdtypes.h>
#endif

#define RVSUCCESS 0
#define RVRERROR -1
#define RVWERROR -2
#define RVBLACKLIST_MAXTRIES 1
#define RVBLACKLIST_OVERTME  2

/* the following is the format of records in the acp_dbm.pag/acp_dbm.dir
   database.  If you change the array lengths here, you MUST start from
   scratch and erase your current acp_dbm database OR write a utility to
   read in records in the old format, and write them in the new format */

typedef struct acpuser_data {
    char oldpass[MAX_STORED_PASS][HASHLEN+1];
    u_short blacklisted;
    u_short consecutive_failures;
    time_t previous_failures[MAX_FAILURES+1];
} ACPUSER_DATA;


#define ACP_DBM_FILE "acp_dbm"


extern int dbm_store_old_pwd();
extern int dbm_get_old_pwds();
extern int dbm_record_login_failure();
extern int dbm_verify_login_success();
extern int dbm_show_user();
extern int dbm_show_blacklist();
extern int dbm_clear_blacklist();
extern int dbm_delete_user();
extern int dbm_list_users();
extern int dbm_lock_acp_dbm();
extern int dbm_unlock_acp_dbm();

#endif /* USE_NDBM */

