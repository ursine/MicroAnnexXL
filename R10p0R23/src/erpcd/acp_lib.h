/*****************************************************************************
This file contains all the necessary declarations for the acp_lib.c
*****************************************************************************/

#ifndef _ACP_LIB_H_
#define _ACP_LIB_H_

#define MAX_CMD_LINE 80

#ifndef _WIN32		/* is this needed at all? */
struct annex_status_return {
  int errno;
}; 
#endif /* not _WIN32 */

struct filter_list {
  struct filter_list *next;
  char filter[MAX_CMD_LINE];
};

int construct_filter();
int get_time_stamp();
int acp_add_filter();
#endif  /* _ACP_LIB_H_*/


