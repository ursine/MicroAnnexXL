/*
 *****************************************************************************
 *
 * Copyright 1992 by Information Systems Laboratory, Inc, Concord, MA
 *
 *			 All Rights Reserved.
 *
 * Permission to use and modify this software and its documentation without
 * fee is granted, provided that the above copyright notice appear in all
 * source material and supporting documentation.
 *
 * ISL MAKES NO WARRANTY OF ANY KIND WITH REGARD TO THIS SOFTWARE, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.  ISL SHALL NOT BE LIABLE FOR ERRORS CONTAINED
 * HEREIN OR DIRECT, INDIRECT, SPECIAL, INCIDENTIAL OR CONSEQUENTIAL DAMAGES
 * IN CONNECTION WITH THE FURNISHING, PERFORMANCE, OR USE OF THIS MATERIAL.
 *
 *        Copyright 1989,1990 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * File description:  Pick lint from an ACP User Profile file
 *
 * Original Author: Richard G. Bockenek		Created on: 2/22/93
 *
 ****************************************************************************
 */

/*
 ****************************************************************************
 *
 *	compile:	cc -o lint acplint.c getacpuser.c
 *
 ****************************************************************************
 */
#include "../inc/config.h"
#include "../inc/port/port.h"
#include "../inc/vers.h"
#include <stdio.h>
#include "../inc/erpc/acp_const.h"
#include "../inc/erpc/nerpcd.h"
#include "getacpuser.h"
#include "environment.h"

extern int optind;
extern char *optarg;

#ifndef INSTALL_DIR
#define INSTALL_DIR "/etc"
#endif
 
char *install_dir = INSTALL_DIR;
int debug = 0;

#ifdef ORACLE
extern char ora_user[ACP_MAXLSTRING];
#endif

void uprof_dump();
 
char *err_text[] = {
    "ACPU_ESUCCESS",
    "ACPU_ESKIP",
    "ACPU_ENOACP",
    "ACPU_EINPROG",
    "ACPU_EBADGEN",
    "ACPU_ENOUSER",
    "ACPU_ENOACC",
    "ACPU_ENOPOOL",
    "ACPU_ENOPOOLENT",
    "ACPU_EACCESSCODE",
    "ACPU_ERROR"
};

struct gr_file file_info = {"/etc/acp_group", "/etc/group",0};

main(argc, argv)
int argc;
char *argv[];
{
	char *filename = NULL;
	char buf[BUFSIZ], username[BUFSIZ], accesscode[BUFSIZ];
	int mode = 0, status, i;
	int opt, flags = 0;
	Uprof uprof;
	Access access;
	static void usage();
	struct environment_spec env, *env_p = &env;


	/*
	 * Process options
	 */
	while ((opt = getopt(argc, argv, "dltu:vO:")) != EOF) {
		switch (opt) {
		case 'd':
			mode |= M_DEBUG;
			break;
		case 'l':
			mode |= M_LINT;
			break;
		case 't':
			mode |= M_TEE;
			break;
		case 'u':
			flags = 1;	
			bcopy (optarg, username, strlen(optarg));
			printf("username = %s\n",username);
			break;
		case 'v':
			printf("acplint host tool version %s, released %s\n",
			       VERSION,RELDATE);
			exit(0);
			break;
#ifdef ORACLE
		case 'O':
			strcpy (ora_user, optarg);
			printf("using user/pass = %s\n",ora_user);
			break;
#endif
		default:
			usage();
			exit(0);
		}
	}

	/*
	 * Open and read database
	 */
	status = open_user_profile_file (argv[optind]);
	if (status != ACPU_ESUCCESS) {
	    printf("open_user_profile failed\n");
	    exit(0);
	}
	status = initialize_user_profile_file(mode);
	if (status != ACPU_ESUCCESS) {
	    printf("initialize_user_profile failed\n");
	    exit(0);
	}


	if (flags) {
	    bzero (&env, sizeof(struct environment_spec));
	    bcopy (username, env.username, strlen(username));
	    status = get_user_profile_entry (&uprof, username, &env_p, &file_info);
	    if (status != ACPU_ESUCCESS) {
		printf("get_user_profile failed (%s) on username %s\n",
                                          err_text[status],username);
	    }
	    else {
		uprof_dump(&uprof);
		release_uprof(&uprof);
	    }
	}

	/*
	 * done
	 */
	close_user_profile_file();
	exit(0);

}

static void
usage()
{
	printf("Usage: acplint [-v -d -l -t -u username -O user/pswd] [filename]...\n");
}


void
uprof_dump (uprof)
Uprof *uprof;
{
    struct cli_cmd_list *cli_cmd;

    printf(" up_username \t\t= \"%s\"\n",uprof->up_username);
    printf(" up_entry_num \t\t= %d\n",uprof->up_entry_num);
    if (uprof->up_accesslist) {
	Access *acc;
	struct _phone *phone;
	Acjob *job;

	printf(" up_accesslist:\n");
	for (acc = uprof->up_accesslist; acc; acc = acc->ac_next) {
	    printf("\tac_code \t= \"%s\"\n",acc->ac_code);
	    printf("\tac_inpool \t= \"%s\"\n",acc->ac_inpool);
	    printf("\tac_outpool \t= \"%s\"\n",acc->ac_outpool);
	    for (phone = acc->ac_phone_list; phone; phone = phone->next)
		printf("\tphone \t\t= \"%s\"\n",phone->ac_phone);
	    for (job = &acc->ac_job; job; job = job->j_next) {
		printf("\tjob count \t= %d\n",job->j_count);
		printf("\tjob string \t= \"%s\"\n",job->j_string);
		printf("\tjob length \t= %d\n",job->j_length);
	    }
	}
    }
    else
	printf(" up_accesslist \t\t= NULL\n");
    printf(" up_climask \t\t= 0x%x\n",uprof->up_climask);
    printf(" up_cmd_list \t\t= \"%s\"\n",(uprof->up_cmd_list == NULL)?"":
                                   (uprof->up_cmd_list->clicmd == NULL)?"":
                                   uprof->up_cmd_list->clicmd);
    cli_cmd = uprof->up_cmd_list;
    while (cli_cmd &&
           ((cli_cmd = cli_cmd->next)!= NULL) && (*cli_cmd->clicmd != NULL))
	printf("\t\t\t= \"%s\"\n",cli_cmd->clicmd);
    printf(" up_filter_list \t= \"%s\"\n",(uprof->up_filter_list == NULL)?"":
                                   (uprof->up_filter_list->clicmd == NULL)?"":
                                   uprof->up_filter_list->clicmd);
    cli_cmd = uprof->up_filter_list;
    while (cli_cmd &&
           ((cli_cmd = cli_cmd->next)!= NULL) && (*cli_cmd->clicmd != NULL))
	printf("\t\t\t= \"%s\"\n",cli_cmd->clicmd);
    printf(" up_route_list \t\t= \"%s\"\n",(uprof->up_route_list == NULL)?"":
                                   (uprof->up_route_list->clicmd == NULL)?"":
                                   uprof->up_route_list->clicmd);
    cli_cmd = uprof->up_route_list;
    while (cli_cmd &&
           ((cli_cmd = cli_cmd->next)!= NULL) && (*cli_cmd->clicmd != NULL))
	printf("\t\t\t= \"%s\"\n",cli_cmd->clicmd);
    printf(" up_blacklist \t\t= %d\n",uprof->up_blacklist);
    printf(" up_deny \t\t= %d\n",uprof->up_deny);
    printf(" up_local_addr \t\t= 0x%x\n",uprof->up_local_addr);
    printf(" up_remote_addr \t= 0x%x\n",uprof->up_remote_addr);
    printf(" up_subnet_mask \t= 0x%x\n",uprof->up_subnet_mask);
    printf(" user_index \t\t= \"%s\"\n",uprof->user_index);
    printf(" up_secret \t\t= \"%s\"\n",uprof->up_secret);
    printf(" up_mp_max_links \t= %d\n",uprof->up_mp_max_links);
    printf(" up_max_logon \t\t= %d\n",uprof->up_max_logon);
    if (uprof->up_values_p) {
        printf(" environment:\n\tusername\t= \"%s\"\n",uprof->up_values_p->username);
        printf("\tgroupname\t= \"%s\"\n",uprof->up_values_p->groupname);
        printf("\tannex\t\t= \"%s\"\n",uprof->up_values_p->annex);
	if (uprof->up_values_p->port_is_set)
            printf("\tports\t\t= 0x%x\n",uprof->up_values_p->ports);
        printf("\tprotocol\t= %d\n",uprof->up_values_p->protocol);
        printf("\tregime\t\t= %d\n",uprof->up_values_p->regime);
    }
    else
	printf(" environment \t\t= NULL\n");
    printf(" at_zones \t\t= %d\n",uprof->up_at.at_zones);
    printf(" at_zone_combined \t= %d\n",uprof->up_at.at_zone_combined);
    printf(" at_zonelist \t\t= \"%s\"\n",uprof->up_at.at_zonelist);
    printf(" at_passwd \t\t= \"%s\"\n",uprof->up_at.at_passwd);
    printf(" at_nves \t\t= %d\n",uprof->up_at.at_nves);
    printf(" at_nve_combined \t= %d\n",uprof->up_at.at_nve_combined);
    printf(" at_nve_exclude \t= %d\n",uprof->up_at.at_nve_exclude);
    printf(" at_nve \t\t= \"%s\"\n",uprof->up_at.at_nve);
    printf(" at_connect_time \t= %d\n",uprof->up_at.at_connect_time);
    printf(" at_callback \t\t= \"%s\"\n",uprof->up_at.at_callback);

}


/* end of file */
