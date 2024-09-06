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

#ifndef _ENVIRONMENT_H_
#define _ENVIRONMENT_H_
#include <time.h>

int match_env_options();
struct environment_spec *create_env();
void releave_env();
int env_keyword_routine();
int get_keyword_pointer();
int match_keyword();
int extract_annex_data();
int extract_group_date();
int extract_port_date();
void set_port();
void set_port_range();
int extract_protocol_data();
int extract_regime_date();
int extract_time_data();
int extract_username_data();
int fill_field();
int match_ports();
int get_keyword_mask();
int get_protocol_mask();
int get_regime_mask();
int dos_convert_time();
int match_time();
int best_env_match();


#define MAX_ENV_STRING	1024	/* Array size for largest env strings */
#define MAX_OPTION 64
#define MAX_ENV_USERNAME_SIZE 129

#ifndef MAX_PORTS
#define MAX_PORTS 128
#endif

struct environment_spec {
   char username[MAX_ENV_USERNAME_SIZE];
   struct group_entry *group_list;
   UINT32 annex;
   int port,ptype;
   int protocol;
   struct security_regime *regime;
   struct tm time;
   EndpDesc endpoint;      /* endpoint discriminator */
};

struct environment_values {
   char username[MAX_ENV_USERNAME_SIZE];
   char groupname[MAX_OPTION];
   char annex[MAX_OPTION];
   char port_is_set;
   char ports[DEV_MAX][MAX_PORTS/8];
   int protocol;
   int regime;
   int time_format;
   struct tm start_time;
   struct tm end_time;
   EndpDesc endpoint;      /* endpoint decrimator */
};

struct keyword_data
{
   char  *keyword;
   int    mask;
   int    len;
};

extern struct keyword_data security_keywords[];

/* Values returned by best_env_match() */
#define EQUAL_ENVS   0
#define ENV_1_BETTER 1
#define ENV_2_BETTER 2

/* Value returned by match_env_options() */
#define NO_MATCHES        0

/**extern struct environment_spec *create_env();**/
/*extern void   release_env();
extern int    env_parser();
extern int    get_regime_mask();
extern int    best_env_match();
extern int    match_env_options();**/
/**COMMENTING OUT THE EXTERN DECL'S 6/14/95 . MA **/


#endif /* _ENVIRONMENT_H_ */
