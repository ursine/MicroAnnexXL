/*
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.  Unauthorized
 * duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains the source code for the TMS database manager
 *	utility.  The Design Specification, in Frame, for this code is in
 *	specifications/udas/tunnel-mgr_ds/spec.book
 *
 * Original Author: Gary Malkin
 * Created on: June 14, 1996
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../inc/vers.h"
#include "../inc/config.h"
#include "../inc/port/port.h"
#include "../inc/port/install_dir.h"

#include <ctype.h>
#include <string.h>

#include "../inc/erpc/acp_tms.h"
#include "tms.h"

#ifdef USE_NDBM

/*
 * global definitions
 */
#define HELPFILE "tms-dbm.hlp"	/* name of  installed help file */

int debug = 0;			/* print debug info (also used in tms_lib.c) */
static int quiet = 0;		/* do not print any messages */

static tms_db_key key;		/* storage for database key */
static tms_db_entry entry;	/* storage for database entry */

/*
 * NOTE: The order of the entries in each of these arrays is important
 *	 They must match the values assigned in inc/erpc/acp_tms.h
 */
static char *hw_type[] = {"none", "sl", "ppp", "fr"};
static char *auth_proto[] = {"none", "acp", "radius"};
static char *acct_proto[] = {"none", "radius"};
static char *tun_auth_type[] = {"none", "kmd5-128"};
static char *tun_auth_mode[] = {"none", "pref-suff"};
static char *addr_proto[] = {"none", "dhcp"};
static char *tun_type[] = {"none", "unknown", "l2tp", "dvs"};
static char *server_loc[] = {"none", "local", "remote"};

/*
 * add/modify parameter values
 */
#define KW_TE		0x00000001	/* tunnel endpoint IP address */
#define KW_MAXU		0x00000002	/* maximum users */
#define KW_HWTYPE	0x00000004	/* hardware type */
#define KW_HWADDR	0x00000008	/* hardware address */
#define KW_HWALEN	0x00000010	/* hardware address length */
#define KW_PAUTH	0x00000020	/* primary authentication server */
#define KW_SAUTH	0x00000040	/* secondary authentication server */
#define KW_PACCT	0x00000080	/* primary accounting server */
#define KW_SACCT	0x00000100	/* secondary accounting server */
#define KW_AUTHP	0x00000200	/* authentication protocol */
#define KW_ACCTP	0x00000400	/* accounting protocol */
#define KW_SPI		0x00000800	/* security protocol index */
#define KW_TATYPE	0x00001000	/* tunnel authentication type */
#define KW_TAMODE	0x00002000	/* tunnel authentication mode */
#define KW_TAKEY	0x00004000	/* tunnel authentication key */
#define KW_ADDRP	0x00008000	/* address resolution protocol */
#define KW_PADDR	0x00010000	/* primary addr res server */
#define KW_SADDR	0x00020000	/* secondary addr res server */
#define KW_TUTYPE	0x00040000	/* tunnel type */
#define KW_SRVLOC	0x00080000	/* location of servers */
#define KW_PASSWD	0x00100000	/* L2TP password */

static UINT32 add_req = KW_TE | KW_MAXU | KW_PAUTH | KW_AUTHP;

/*
 * macros
 */
#define Check(x) ((**argv == 'a') || (**argv == (x)))

/*
 * forward function definitions
 */
static int f_add(), f_mod(), f_del(), f_rekey(), f_list(),
	   f_show(), f_clear(), f_rem(), f_help();

#if __STDC__ == 1
static int parse_key(int *, char ***);
static int parse_addmod(int, char **, int);
static int parse_keyword(int *, char ***, char **, char **);
#else
static int parse_key();
static int parse_addmod();
static int parse_keyword();
#endif

/*
 * command table
 */
static struct cmd_entry {
  char command[8];
  int (*function)();
  char *helpstr;
} cmd_table[] = {{"add", f_add, "H_ADD\n"}, {"modify", f_mod, "H_MOD\n"},
		 {"delete", f_del, "H_DEL\n"}, {"rekey", f_rekey, "H_REKEY\n"},
		 {"list", f_list, "H_LIST\n"}, {"show", f_show, "H_SHOW\n"},
		 {"clear", f_clear, "H_CLEAR\n"}, {"remove", f_rem, "H_REM\n"},
		 {"help", f_help, "H_HELP\n"}, {"?", f_help, "H_HELP\n"}};

#endif /* USE_NDBM */

/************************************************************
 *
 * Name:
 *	main
 *
 * Description:
 *	This is the main function of the tms_dbm utility.  It
 *	accepts the user's command line and calls the appropriate
 *	command handler.
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

int
main(argc, argv)
  int  argc;
  char **argv;
{
#ifdef USE_NDBM

  int cmdlen;
  tms_db_key *keyp = &key;
  tms_db_entry *entryp = &entry;
  register i;

  /*
   * quick programmer's sanity checks
   */
  if (debug) {
    if (TMS_DOMAIN_LEN != 64)
      printf("CONSISTANCY WARNING ** TMS_DOMAIN_LEN != 64 ** check printfs\n");
    if (TMS_DNIS_LEN != 20)
      printf("CONSISTANCY WARNING ** TMS_DNIS_LEN != 20 ** check printfs\n");
    if (TMS_PASSWD_LEN != 16)
      printf("CONSISTANCY WARNING ** TMS_PASSWD_LEN != 16 ** check printfs\n");
  }

  if (argc == 1)
    goto usage;
  argc--;			/* skip over command name */
  argv++;

  for (; argc; argc--, argv++) {
    cmdlen = strlen(*argv);

    if (**argv == '-') {	/* handle command line options */
      if (cmdlen == 1) {
	if (!quiet) {
	  fprintf(stderr, "No switch specified\n");
	  goto usage;
	}
	else
	  exit(1);
      }

      for (i = 1; i < cmdlen; i++) {
	switch ((*argv)[i]) {
	case 'D':		/* undocumented switch */
	  if (quiet)
	    exit(1);
	  debug = 1;		/* set the debug mode flag */
	  continue;
	case 'Q':
	  if (debug)
	    exit(1);
	  quiet = 1;		/* set the quiet mode flag */
	  continue;
	case 'v':
	  printf("TMS database management tool version %s, released %s\n",
		 VERSION, RELDATE);
	  exit(0);
	default:
	  if (!quiet)
	    fprintf(stderr, "Unknown switch -%c\n", (*argv)[i]);
	  exit(1);
	}
      }

      continue;
    } /*if '-'*/

    /*
     * search the command table for the command using minimum uniqueness
     */
    for (i = 0; i < sizeof(cmd_table)/sizeof(struct cmd_entry); i++) {
      if (strncasecmp(*argv, cmd_table[i].command, cmdlen) == 0) {
	register j;

	for (j = i+1; j < sizeof(cmd_table)/sizeof(struct cmd_entry); j++) {
	  if (strncasecmp(*argv, cmd_table[j].command, cmdlen) == 0) {
	    if (!quiet)
	      fprintf(stderr, "Ambiguous command \"%s\"\n", *argv);
	    goto usage;
	  }
	}

	break;
      }
    }

    if (i == sizeof(cmd_table)/sizeof(struct cmd_entry)) {
      if (!quiet)
	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
      goto usage;
    }
    if (debug)
      printf("<D> main: matched command \"%s\" against \"%s\"\n", *argv,
	     cmd_table[i].command);

    break;
  } /*for argc*/

  /*
   * call the handler for the command with the remaining arguments and be done
   */
  bzero(keyp, sizeof(*keyp));
  bzero(entryp, sizeof(*entryp));
  argc--;
  argv++;
  return((cmd_table[i].function)(argc, argv));

  /*
   * print usage for syntax errors
   */
usage:
  if (!quiet)
    fprintf(stderr, "usage: tms_dbm [-Qv] command [parameters]\n\
       Q - quiet mode; return error codes but do not print error messages\n\
       v - display the version number and release data, then exit\n\
       commands: add, modify, delete, rekey, list, show, clear, remove, help\n");
#else /* USE_NDBM */
  fprintf(stderr, "DBM is not enabled, so TMS is not available\n");
#endif /* USE_NDBM */
  exit(1);
}

#ifdef USE_NDBM

/************************************************************
 *
 * Name:
 *	f_add
 *
 * Description:
 *	This function adds a new entry to the database.  The
 *	command syntax is: domain dnis (keyword=value)*
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	Since we lock by key, and since we're adding a record
 *	with a new key, there is nothing to lock; so we dont.
 *
 ************************************************************/

static int
f_add(argc, argv)
  int  argc;
  char **argv;
{
  int errno;

  /*
   * parse the domain and dnis, then fill in the key
   */
  if ((errno = parse_key(&argc, &argv)) != 0)
    return(errno);

  /*
   * parse the provisioning parameters, then fill in the entry
   */
  if ((errno = parse_addmod(argc, argv, 1)) != 0)
    return(errno);

  /*
   * add the database entry
   */
  errno = tms_db_add(&key, &entry);
  if (quiet)
    return(errno);

  switch (errno) {
  case E_SUCCESS:
    printf("New entry added\n");
    break;
  case E_EXISTS:
    fprintf(stderr,
	    "Entry already exists for domain \"%.64s\" and dnis \"%.20s\"\n",
	    key.key_domain, key.key_dnis);
    break;
  case E_GENERAL:
    fprintf(stderr, "An error occurred adding entry to database\n");
    break;
  case E_NOTMSDB:
    fprintf(stderr, "Could not find TMS database\n");
    break;
  default:
    fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_add() rc=%d\n",
	    errno);
  case E_SYNTAX:
    break;
  }
  return(errno);
}

/************************************************************
 *
 * Name:
 *	f_mod
 *
 * Description:
 *	This function modifies an entry in the database.  The
 *	command syntax is: domain dnis (keyword=value)*
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
f_mod(argc, argv)
  int  argc;
  char **argv;
{
  int errno, errno2;

  /*
   * parse the domain and dnis, then fill in the key
   */
  if ((errno = parse_key(&argc, &argv)) != 0)
    return(errno);

  /*
   * lock the database entry
   */
  errno = tms_db_lock(&key);
  if (errno) {
    if (errno = -1) {
      if (!quiet)
	fprintf(stderr, "An error occurred locking database record\n");
      return(E_GENERAL);
    }
    if (!quiet)
      fprintf(stderr, "Lock held by %08x broken\n", errno);
  }
  else {
    if (debug)
      printf("<D> f_mod: locked entry OK\n");
  }

  /*
   * read the database entry
   */
  errno = tms_db_read(&key, &entry, NULL);
  switch (errno) {
  case E_SUCCESS:
    if (debug)
      printf("<D> f_mod: read entry OK\n");
    break;
  case E_NOEXIST:
    if (!quiet)
      fprintf(stderr, "No entry for domain \"%.64s\" and dnis \"%.20s\"\n",
	      key.key_domain, key.key_dnis);
    goto mod_unlock;
  case E_GENERAL:
    if (!quiet)
      fprintf(stderr, "An error occurred reading entry from database\n");
    goto mod_unlock;
  case E_NOTMSDB:
    if (!quiet)
      fprintf(stderr, "Could not find TMS database\n");
    goto mod_unlock;
  default:
    if (!quiet)
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_read() rc=%d\n",
	      errno);
    goto mod_unlock;
  }

  /*
   * parse the provisioning parameters, then fill in the entry
   */
  if ((errno = parse_addmod(argc, argv, 0)) != 0)
    goto mod_unlock;

  /*
   * update the database entry
   */
  errno = tms_db_update(&key, &entry, NULL);
  if (!quiet) {
    switch (errno) {
    case E_SUCCESS:
      printf("Entry updated\n");
      break;
    case E_NOTMSDB:
      if (debug)
	printf("<D> f_mod: database vanished mid-command\n");
    case E_GENERAL:
      fprintf(stderr, "An error occurred updating entry in database\n");
      break;
    default:
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_update() rc=%d\n",
	      errno);
      break;
    }
  }

  /*
   * unlock the database entry
   */
mod_unlock:
  errno2 = tms_db_unlock(&key);
  if (errno2) {
    if (!quiet) {
      fprintf(stderr, "Lock was broken");
      if (errno2 != -1)
	fprintf(stderr, " by %08x", errno);
      putc('\n', stderr);
    }
  }
  else {
    if (debug)
      printf("<D> f_mod: unlocked entry OK\n");
  }

  return(errno);
}

/************************************************************
 *
 * Name:
 *	f_del
 *
 * Description:
 *	This function deleted a database entry.  The
 *	syntax is: domain dnis
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
f_del(argc, argv)
  int  argc;
  char **argv;
{
  int errno, errno2;

  /*
   * parse the domain and dnis, then fill in the key
   */
  if ((errno = parse_key(&argc, &argv)) != 0)
    return(errno);

  /*
   * lock the database entry
   */
  errno = tms_db_lock(&key);
  if (errno) {
    if (errno = -1) {
      if (!quiet)
	fprintf(stderr, "An error occurred locking database record\n");
      return(E_GENERAL);
    }
    if (!quiet)
      fprintf(stderr, "Lock held by %08x broken\n", errno);
  }
  else {
    if (debug)
      printf("<D> f_del: locked entry OK\n");
  }

  /*
   * delete the database entry
   */
  errno = tms_db_delete(&key);
  if (!quiet) {
    switch (errno) {
    case E_SUCCESS:
      printf("Entry deleted\n");
      break;
    case E_NOEXIST:
      fprintf(stderr, "Entry does not exist\n");
      break;
    case E_GENERAL:
      fprintf(stderr, "An error occurred deleting entry from database\n");
      break;
    case E_NOTMSDB:
      fprintf(stderr, "Could not find TMS database\n");
      break;
    default:
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_delete() rc=%d\n",
	      errno);
      break;
    }
  }

  /*
   * unlock the deleted database entry
   */
  errno2 = tms_db_unlock(&key);
  if (errno2) {
    if (!quiet) {
      fprintf(stderr, "Lock was broken");
      if (errno2 != -1)
	fprintf(stderr, " by %08x", errno);
      putc('\n', stderr);
    }
  }
  else {
    if (debug)
      printf("<D> f_del: unlocked entry OK\n");
  }

  return(errno);
}

/************************************************************
 *
 * Name:
 *	f_rekey
 *
 * Description:
 *	This function changes a database entries key.  The
 *	syntax is: domain dnis domain=new_domain dnis=new_dnis
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
f_rekey(argc, argv)
  int  argc;
  char **argv;
{
  tms_db_key new_key;
  char *kbuffp, *vbuffp;
  int klen, vlen;
  int errno, errno2;

  /*
   * parse the domain and dnis, then fill in the key
   */
  if ((errno = parse_key(&argc, &argv)) != 0)
    return(errno);

  /*
   * parse the new key value(s)
   */
  if ((argc < 1) || (argc > 2)) {
    if (!quiet)
      fprintf(stderr, "Invalid number of parameters\n");
    return(E_SYNTAX);
  }

  bzero((char *)(&new_key), sizeof(new_key));

  while (argc) {
    if ((errno = parse_keyword(&argc, &argv, &kbuffp, &vbuffp)) != 0)
      return(E_SYNTAX);
    if ((klen = strlen(kbuffp)) < 2) {
      if (!quiet)
	fprintf(stderr, "Invalid or ambiguous keyword \"%s\"\n", kbuffp);
      return(E_SYNTAX);
    }

    if (strncasecmp(kbuffp, "domain", klen) == 0) {
      vlen = strlen(vbuffp);
      if ((vlen < 1) || (vlen > TMS_DOMAIN_LEN)) {
	if (!quiet)
	  fprintf(stderr, "Invalid domain name length %d\n", vlen);
	return(E_SYNTAX);
      }
      bcopy(vbuffp, new_key.key_domain, vlen);
      if (debug)
	printf("<D> f_rekey: new domain \"%s\" OK\n", new_key.key_domain);
    }
    else if (strncasecmp(kbuffp, "dnis", klen) == 0) {
      vlen = strlen(vbuffp);
      if ((vlen < 1) || (vlen > TMS_DNIS_LEN)) {
	if (!quiet)
	  fprintf(stderr, "Invalid DNIS name length %d\n", vlen);
	return(E_SYNTAX);
      }
      bcopy(vbuffp, new_key.key_dnis, vlen);
      if (debug)
	printf("<D> f_rekey: new dnis \"%s\" OK\n", new_key.key_dnis);
    }
    else {
      if (!quiet)
	fprintf(stderr, "Unknown keyword \"%s\"\n", kbuffp);
      return(E_SYNTAX);
    }
  } /*while*/

  /*
   * update the new key field(s)
   */
  if (new_key.key_domain[0] == '\0')
    bcopy(key.key_domain, new_key.key_domain, TMS_DOMAIN_LEN);
  if (new_key.key_dnis[0] == '\0')
    bcopy(key.key_dnis, new_key.key_dnis, TMS_DNIS_LEN);

  /*
   * lock the database entry
   */
  errno = tms_db_lock(&key);
  if (errno) {
    if (errno = -1) {
      if (!quiet)
	fprintf(stderr, "An error occurred locking database record\n");
      return(E_GENERAL);
    }
    if (!quiet)
      fprintf(stderr, "Lock held by %08x broken\n", errno);
  }
  else {
    if (debug)
      printf("<D> f_rekey: locked entry OK\n");
  }

  /*
   * rekey the database entry
   */
  errno = tms_db_rekey(&key, &new_key);
  switch (errno) {
  case E_SUCCESS:
    if (!quiet)
      printf("Domain/DNIS \"%.64s/%.20s\" is now \"%.64s/%.20s\"\n",
	     key.key_domain,key.key_dnis, new_key.key_domain,new_key.key_dnis);
    break;
  case E_EXISTS:
    if (!quiet)
      fprintf(stderr,
	      "Entry already exists for domain \"%.64s\" and dnis \"%.20s\"\n",
	      new_key.key_domain, new_key.key_dnis);
    break;
  case E_NOEXIST:
    if (!quiet)
      fprintf(stderr, "Entry does not exist\n");
    break;
  case E_GENERAL:
    if (!quiet)
      fprintf(stderr, "An error occurred rekeying entry in database\n");
    break;
  case E_NOTMSDB:
    if (!quiet)
      fprintf(stderr, "Could not find TMS database\n");
    break;
  default:
    if (!quiet)
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_rekey() rc=%d\n",
	      errno);
    break;
  }

  /*
   * unlock the deleted database entry
   */
  errno2 = tms_db_unlock(&key);
  if (errno2) {
    if (!quiet) {
      fprintf(stderr, "Lock was broken");
      if (errno2 != -1)
	fprintf(stderr, " by %08x", errno);
      putc('\n', stderr);
    }
  }
  else {
    if (debug)
      printf("<D> f_rekey: unlocked entry OK\n");
  }

  return(errno);
}

/************************************************************
 *
 * Name:
 *	f_list
 *
 * Description:
 *	This function lists the domain/DNIS pairs (keys) in
 *	the database.
 *
 * Inputs:
 *	None used
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	Since this is an output-generating command, setting
 *	the quiet flag is considered a syntax error.
 *
 ************************************************************/

static int
f_list(argc, argv)
  int  argc;
  char **argv;
{
  register key_link *klp;
  key_link *old_klp;

  if (quiet)
    return(E_SYNTAX);

  /*
   * check the parameter, if any
   */
  if (argc && (strncasecmp(*argv, "ordered", strlen(*argv)) != 0)) {
    fprintf(stderr, "Unknown argument \"%s\"\n", *argv);
    return(E_SYNTAX);
  }

  klp = tms_db_domains(argc);
  if (klp == NULL) {
    printf("\nThere are no entries in the database\n");
    return(E_SUCCESS);
  }
  if (klp == (key_link *)(-1L)) {
    fprintf(stderr, "\nAn error occurred reading database\n");
    return(E_GENERAL);
  }

  while (klp) {
    printf("%-64.64s %-.20s\n", klp->entry.key_domain, klp->entry.key_dnis);
    old_klp = klp;
    klp = klp->next;
    free(old_klp);
  }

  return(E_SUCCESS);
}

/************************************************************
 *
 * Name:
 *	f_show
 *
 * Description:
 *	This function displays information in the database.  The
 *	syntax is: domain dnis {config | ordered | rases | stats | all}
 *	where all implies ordered.
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	Since this is an output-generating command, setting
 *	the quiet flag is considered a syntax error.
 *
 ************************************************************/

static int
f_show(argc, argv)
  int  argc;
  char **argv;
{
  register ras_link *rlp;
  ras_link *old_rlp;
  register i;
  int errno, errno2;

  if (quiet)
    return(E_SYNTAX);

  /*
   * parse the domain and dnis, then fill in the key
   */
  if ((errno = parse_key(&argc, &argv)) != 0)
    return(errno);

  /*
   * Basic error check of argument
   */
  if (argc != 1) {
    fprintf(stderr, "Invalid number of arguments\n");
    return(E_SYNTAX);
  }
  **argv |= ' ';	/* make it lower case */
  if (strchr("acors", **argv) == NULL) {
    fprintf(stderr, "Unknown argument \"%s\"\n", *argv);
    return(E_SYNTAX);
  }

  /*
   * read the database entry
   */
  errno = tms_db_read(&key, &entry, NULL);
  if (errno) {
    switch (errno) {
    case E_NOEXIST:
      fprintf(stderr, "No entry for domain \"%.64s\" and dnis \"%.20s\"\n",
	      key.key_domain, key.key_dnis);
      break;
    case E_GENERAL:
      fprintf(stderr, "An error occurred reading entry from database\n");
      break;
    case E_NOTMSDB:
      fprintf(stderr, "Could not find TMS database\n");
      break;
    default:
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_read() rc=%d\n",
	      errno);
      break;
    }
    return(errno);
  }
  else
    if (debug)
      printf("<D> f_show: read entry OK\n");

  /*
   * show config information
   */
  if (Check('c')) {
    printf("\nTunnel Endpoint Address: %s   Tunnel Type: %s   Max users: ",
	   inet_ntoa(entry.td_te_addr), tun_type[entry.td_tunnel_type]);
    if (entry.td_maxusers == TD_NO_MAXU)
      printf("unlimited\n");
    else
      printf("%u\n", entry.td_maxusers);

    printf("Hardware Type: %s   Address: 0", hw_type[entry.td_hw_type]);
    if (entry.td_hw_addr_len != 0)
      putchar('x');
    for (i = 0; i < entry.td_hw_addr_len; i++)
      printf("%02x", entry.td_hw_addr[i]);
    switch (entry.td_hw_addr_len) {
    case 1:
      printf(" (%d)\n", entry.td_hw_addr[0]);
      break;
    case 2: {
      u_short svalue;
      bcopy(entry.td_hw_addr, (u_char *)(&svalue), 2);
      svalue = ntohs(svalue);
      printf(" (%u)\n", svalue);
      break;
    }
    case 4: {
      INT32 value;
      bcopy(entry.td_hw_addr, (u_char *)(&value), 4);
      value = ntohl(value);
      printf(" (%d)\n", value);
      break;
    }
    default:
      printf(" (%u octets)\n", entry.td_hw_addr_len);
      break;
    }

    printf("Protocol - Authentication: %s   Accounting: %s   Addressing: %s\n",
	   auth_proto[entry.td_auth_proto], acct_proto[entry.td_acct_proto],
	   addr_proto[entry.td_addr_proto]);

    printf("Servers' location: %s\n", server_loc[entry.td_server_loc]);

    printf("Authentication Servers - Primary: %s   ",
	   inet_ntoa(entry.td_pauth_addr));
    printf("Secondary: %s\n", inet_ntoa(entry.td_sauth_addr));

    printf("Accounting Servers - Primary: %s   ",
	   inet_ntoa(entry.td_pacct_addr));
    printf("Secondary: %s\n", inet_ntoa(entry.td_sacct_addr));

    printf("Addressing Servers - Primary: %s   ",
	   inet_ntoa(entry.td_paddr_addr));
    printf("Secondary: %s\n", inet_ntoa(entry.td_saddr_addr));

    printf("Password: \"%.16s\"\n", entry.td_passwd);

    printf("Tunnel Authentication - SPI: %lu   Type: %s   Mode: %s\n  Key: 0x",
	   entry.td_spi, tun_auth_type[entry.td_ta_type],
	   tun_auth_mode[entry.td_ta_mode]);
    for (i = 0; i < TMS_KEY_LEN; i++)
      printf("%02x", entry.td_ta_key[i]);
    putchar('\n');
  }

  /*
   * show stats information
   */
  if (Check('s')) {
    printf("\nGrants: %lu   Denies: %lu\n", entry.td_grants, entry.td_denies);
    printf("Active Users: %lu out of ", entry.td_users);
    if (entry.td_maxusers == TD_NO_MAXU)
      printf("unlimited\n");
    else
      printf("%lu\n", entry.td_maxusers);
  }

  /*
   * show RAS information (sorted)
   */
  if (Check('o')) {
    rlp = tms_db_rases(&key, 1);
    goto show_rases;
  }

  /*
   * show RAS information (unsorted)
   */
  if (Check('r')) {
    rlp = tms_db_rases(&key, 0);
    goto show_rases;
  }

  return(E_SUCCESS);		/* don't fall into the common show code */

  /*
   * show RAS information returned from database routine
   */
show_rases:
  if (rlp == NULL) {
    printf("\nThere are no RASes for this domain/DNIS\n");
    return(E_SUCCESS);
  }
  if (rlp == (ras_link *)(-1L)) {
    fprintf(stderr, "\nAn error occurred reading RAS database\n");
    return(E_GENERAL);
  }

  for (i = 0; rlp; i++) {
    if (i % 4 == 0)
      putchar('\n');
    else
      printf("  ");
    printf("%15s=%-2u", inet_ntoa(rlp->entry.ras_addr),rlp->entry.ras_count);
    old_rlp = rlp;
    rlp = rlp->next;
    free(old_rlp);
  }
  putchar('\n');

  return(E_SUCCESS);
}

/************************************************************
 *
 * Name:
 *	f_clear
 *
 * Description:
 *	This function clears operational and statistical
 *	information from the database.  The syntax is:
 *	domain dnis {users | stats | all}
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
f_clear(argc, argv)
  int  argc;
  char **argv;
{
  int errno, errno2;

  /*
   * parse the domain and dnis, then fill in the key
   */
  if ((errno = parse_key(&argc, &argv)) != 0)
    return(errno);

  /*
   * Basic error check of argument
   */
  if (argc != 1) {
    if (!quiet)
      fprintf(stderr, "Invalid number of arguments\n");
    return(E_SYNTAX);
  }
  **argv |= ' ';	/* make it lower case */
  if (strchr("ars", **argv) == NULL) {
    if (!quiet)
      fprintf(stderr, "Unknown argument \"%s\"\n", *argv);
    return(E_SYNTAX);
  }

  /*
   * lock the record
   */
  errno = tms_db_lock(&key);
  if (errno) {
    if (errno = -1) {
      if (!quiet)
	fprintf(stderr,"An error occurred locking database record\n");
      return(E_GENERAL);
    }
    if (!quiet)
      fprintf(stderr, "Lock held by %08x broken\n", errno);
  }
  else {
    if (debug)
      printf("<D> f_clear: locked entry OK\n");
  }

  /*
   * read the record
   */
  errno = tms_db_read(&key, &entry, NULL);
  switch (errno) {
  case E_SUCCESS:
    if (debug)
      printf("<D> f_clear: read entry OK\n");
    break;
  case E_NOEXIST:
    if (!quiet)
      fprintf(stderr, "No entry for domain \"%.64s\" and dnis \"%.20s\"\n",
	      key.key_domain, key.key_dnis);
    goto clear_unlock;
  case E_GENERAL:
    if (!quiet)
      fprintf(stderr, "An error occurred reading entry from database\n");
    goto clear_unlock;
  case E_NOTMSDB:
    if (!quiet)
      fprintf(stderr, "Could not find TMS database\n");
    goto clear_unlock;
  default:
    if (!quiet)
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_read() rc=%d\n",
	      errno);
    goto clear_unlock;
  }

  /*
   * clear the information
   */
  if (Check('s')) {
    entry.td_grants = 0;
    entry.td_denies = 0;
    if (debug)
      printf("<D> f_clear: cleared stats\n");
  }

  if (Check('r')) {		/* We must do this here because it must be */
    entry.td_users = 0;		/*  done before tms_db_update() is called. */
    if (debug)
      printf("<D> f_clear: cleared total user count\n");
  }

  /*
   * update the record
   */
  errno = tms_db_update(&key, &entry, NULL);
  switch (errno) {
  case E_SUCCESS:
    if (!quiet && Check('s'))
      printf("Stats cleared\n");
    break;
  case E_NOTMSDB:
    if (debug)
      printf("<D> f_clear: database vanished mid-command\n");
  case E_GENERAL:
    if (!quiet)
      fprintf(stderr, "An error occurred updating entry in database\n");
    goto clear_unlock;
  default:
    if (!quiet)
      fprintf(stderr, "INTERNAL PROGRAMMING ERROR - tms_db_update() rc=%d\n",
	      errno);
    goto clear_unlock;
  }

  /*
   * clear RAS user counts
   */
  if (Check('r')) {
    if ((errno = tms_db_rasclear(&key)) == E_SUCCESS) {
      if (!quiet)
	printf("RAS entries and user counts cleared\n");
    }
    else {
      if (!quiet)
	fprintf(stderr, "An error occurred clearing RAS database\n");
    }
  }

  /*
   * unlock the record
   */
clear_unlock:
  errno2 = tms_db_unlock(&key);
  if (errno2) {
    if (!quiet) {
      fprintf(stderr, "Lock was broken");
      if (errno2 != -1)
	fprintf(stderr, " by %08x", errno);
      putc('\n', stderr);
    }
  }
  else {
    if (debug)
      printf("<D> f_clear: unlocked entry OK\n");
  }

  return(errno);
}

/************************************************************
 *
 * Name:
 *	f_rem
 *
 * Description:
 *	This function removes a RAS from the database.  It would
 *	be used if the administrator took a RAS out of service.
 *	Not only is the RAS removed from all database entries,
 *	but the total user counts are properly decremented.
 *
 * Inputs:
 *	rasid - IP address of RAS to be removed
 *
 * Outputs:
 *	Defined in tms.h
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
f_rem(argc, argv)
  int  argc;
  char **argv;
{
  static char failmsg[] = "Remove failed for \"%.64s/%.20s\" - could not %s\n";

  register key_link *klp;
  key_link *old_klp;
  tms_db_entry entry;
  tms_db_ras ras;
  struct in_addr rasid;
  int errno;

  if (argc != 1) {
    if (!quiet)
      fprintf(stderr, "Invalid number of arguments\n");
    return(E_SYNTAX);
  }

  /*
   * convert the RAS IP address
   */
  rasid.s_addr = inet_addr(*argv);
  if ((*((char *)(&rasid.s_addr)) == 0) ||
      ((*((char *)(&rasid.s_addr)) & 0xe0) == 0xe0)) {
    if (!quiet)
      fprintf(stderr, "Invalid RAS address \"%s\"\n", *argv);
    return(E_SYNTAX);
  }

  if (debug)
    printf("<D> f_rem: rasid=%s\n", inet_ntoa(rasid));

  /*
   * get the list of entries
   * an error probably means that TMS is not in use, so simply return
   * for each entry in the list:
   *	lock the entry
   *	read the entry
   *	if the RAS has a count, decrement the count and update the entry
   *	zero the RAS address
   *	unlock the entry
   *	delete the list element
   */
  if ((klp = tms_db_domains(0)) == (key_link *)(-1)) {
    if (debug)
      printf("<D> f_rem: tms_db_domains() returned -1\n");
    return;
  }

  while (klp) {
  /* lock entry */
    if ((errno = tms_db_lock(&klp->entry)) != 0) {
      if (errno = -1) {
	if (!quiet)
	  fprintf(stderr, failmsg, klp->entry.key_domain, klp->entry.key_dnis,
		  "lock");
	continue;
      }
      if (debug)
	printf("<D> f_rem: broke lock \"%.64s/%.20s\" held by %08x\n",
	       klp->entry.key_domain, klp->entry.key_dnis, errno);
    }

  /* read entry */
    bzero((char *)(&ras), sizeof(ras));
    ras.ras_addr.s_addr = rasid.s_addr;
    if ((errno = tms_db_read(&klp->entry, &entry, &ras)) != E_SUCCESS) {
      if (!quiet)
	fprintf(stderr, failmsg, klp->entry.key_domain, klp->entry.key_dnis,
		"read");
      goto term_unlock;
    }

  /* check entry's offset (-1 means the entry didn't exist) */
    if (ras.ras_offset == -1)
      goto term_unlock;

  /* update entry */
    entry.td_users -= ras.ras_count;
    ras.ras_addr.s_addr = 0L;
    ras.ras_count = 0;
    if ((errno = tms_db_update(&klp->entry, &entry, &ras)) != E_SUCCESS) {
      if (!quiet)
	fprintf(stderr, failmsg, klp->entry.key_domain, klp->entry.key_dnis,
		"update");
      goto term_unlock;
    }

  /* unlock entry */
term_unlock:
    if ((errno = tms_db_unlock(&klp->entry)) != 0) {
      if (debug) {
	printf("<D> f_rem: lock \"%.64s/%.20s\" was broken",
	       klp->entry.key_domain, klp->entry.key_dnis);
	if (errno != -1)
	  printf(" by %08x", errno);
	putchar('\n');
      }
    }

  /* delete list entry */
    old_klp = klp;
    klp = klp->next;
    free(old_klp);
  } /*while*/

  if (!quiet)
    printf("RAS %s removed from database\n", *argv);
  return(E_SUCCESS);
}

/************************************************************
 *
 * Name:
 *	f_help
 *
 * Description:
 *	This function provides syntactic help for this utility.
 *
 * Inputs:
 *	Standard argc and argv.
 *
 * Outputs:
 *	E_SUCCESS
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
f_help(argc, argv)
  int  argc;
  char **argv;
{
  char helpfile[sizeof(INSTALL_DIR)+1+sizeof(HELPFILE)+1];
  char buffer[80];
  FILE *fd;
  int cmdlen, printing = 0;
  register i, j;

  if (argc == 0) {
    printf("usage: tms_dbm help [command]\n\
       Specifying a command will describe its syntax.  Valid commands are:\n\
       add, modify, delete, rekey, list, show, clear, remove, and help.\n");
    return(E_SUCCESS);
  }

  /*
   * search the command table for the command using minimum uniqueness
   */
  cmdlen = strlen(*argv);
  for (i = 0; i < sizeof(cmd_table)/sizeof(struct cmd_entry); i++) {
    if (strncasecmp(*argv, cmd_table[i].command, cmdlen) == 0) {
      for (j = i+1; j < sizeof(cmd_table)/sizeof(struct cmd_entry); j++) {
	if (strncasecmp(*argv, cmd_table[j].command, cmdlen) == 0) {
	  printf("Ambiguous command \"%s\"   Try \"help help\"\n", *argv);
	  return(E_SUCCESS);
	}
      }
      break;
    }
  }
  if (i == sizeof(cmd_table)/sizeof(struct cmd_entry)) {
    printf("Unknown command \"%s\"   Try \"help help\"\n", *argv);
    return(E_SUCCESS);
  }

  /*
   * display help for the specified command
   */
  sprintf(helpfile, "%s/%s", INSTALL_DIR, HELPFILE);
  if ((fd = fopen(helpfile, "r")) == NULL) {
    printf("Sorry, but helpfile \"%s\" could not be read\n", helpfile);
    return(E_SUCCESS);
  }

  while (1) {
    if (fgets(buffer, sizeof(buffer), fd) == NULL) {
      printf("\nSorry, but there is an error in helpfile \"%s\"\n",
	     helpfile);
      goto help_close;
    }

    if (printing)
      if (strcmp(buffer, "H_END\n") == 0)
	goto help_close;
      else
	fputs(buffer, stdout);
    else
      if (strcmp(buffer, cmd_table[i].helpstr) == 0)
	printing = 1;
  }

help_close:
  fclose(fd);
  return(E_SUCCESS);
}

/************************************************************
 *
 * Name:
 *	parse_key
 *
 * Description:
 *	This function parses the domain and DNIS parameters
 *	on an input line and fills in the global key structure.
 *
 * Inputs:
 *	argcp - pointer to standard argc
 *	argvp - pointer to standard argv
 *
 * Outputs:
 *	E_SUCCESS
 *	E_SYNTAX
 *
 * Notes:
 *	The values of argc and argv in the calling function
 *	are updated to point past the domain and DNIS parameters.
 *
 ************************************************************/

static int
parse_key(argcp, argvp)
  int  *argcp;
  char ***argvp;
{
  int modflag = 0;
  register char *dp;
  register i;

  if (*argcp < 2) {
    if (!quiet)
      fprintf(stderr, "Missing%sDNIS\n", ((*argcp) ? " " : " domain and "));
    return(E_SYNTAX);
  }

  /*
   * copy the domain name while error checking and shifting to lower case
   */
  if (strlen(**argvp) > TMS_DOMAIN_LEN) {
    if (!quiet)
      fprintf(stderr, "Domain name length greater than %d\n", TMS_DOMAIN_LEN);
    return(E_SYNTAX);
  }
  for (i = 0, dp = **argvp; *dp && (i < TMS_DOMAIN_LEN); i++, dp++) {
    if (*dp == '/') {
      if (!quiet)
	fprintf(stderr, "Invalid character '/' in domain name\n");
      return(E_SYNTAX);
    }
    if (isalpha(*dp) && isupper(*dp)) {
      modflag++;
      key.key_domain[i] = *dp + ' ';	/* make lower case */
      continue;
    }
    key.key_domain[i] = *dp;
  }
  if (modflag) {
    if (!quiet)
      printf("%d characters in the domain name were changed to lower case\n",
	     modflag);
    modflag = 0;
  }

  (*argcp)--;
  (*argvp)++;

  /*
   * copy the DNIS
   */
  if (strlen(**argvp) > TMS_DNIS_LEN) {
    if (!quiet)
      fprintf(stderr, "DNIS length greater than %d\n", TMS_DNIS_LEN);
    return(E_SYNTAX);
  }
  for (i = 0, dp = **argvp; *dp && (i < TMS_DNIS_LEN); i++, dp++) {
    if (!(isdigit(*dp))) {
      if (!quiet)
	fprintf(stderr, "Invalid character '%c' in DNIS\n", *dp);
      return(E_SYNTAX);
    }
    key.key_dnis[i] = *dp;
  }

  (*argcp)--;
  (*argvp)++;

  if (debug)
    printf("<D> parse_key: \"%.64s/%.20s\"\n", key.key_domain, key.key_dnis);
  return(E_SUCCESS);
}

/************************************************************
 *
 * Name:
 *	parse_addmod
 *
 * Description:
 *	This function parses the add and modify keyword
 *	parameters on an input line and fills in the global
 *	entry structure.
 *
 * Inputs:
 *	argc - standard argc
 *	argv - standard argv
 *	adding - add/modify flag
 *
 * Outputs:
 *	E_SUCCESS
 *	E_SYNTAX
 *
 * Notes:
 *	None
 *
 ************************************************************/

static int
parse_addmod(argc, argv, adding)
  int  argc;
  char **argv;
  int  adding;
{
  char ctoh();
  static char inv_val[] = "Invalid %s value \"%s\"\n";

  static struct kw_entry {
    char keyword[8];
    UINT32 kw_value;
  } kw_table[] = { {"te", KW_TE}, {"ha", KW_TE}, {"maxu", KW_MAXU},
		   {"hwtype", KW_HWTYPE},
		   {"hwaddr", KW_HWADDR}, {"hwalen", KW_HWALEN},
		   {"pauth", KW_PAUTH}, {"sauth", KW_SAUTH},
		   {"pacct", KW_PACCT}, {"sacct", KW_SACCT},
		   {"authp", KW_AUTHP}, {"acctp", KW_ACCTP},
		   {"spi", KW_SPI}, {"tatype", KW_TATYPE},
		   {"tamode", KW_TAMODE}, {"takey", KW_TAKEY},
		   {"addrp", KW_ADDRP}, {"passwd", KW_PASSWD},
		   {"paddr", KW_PADDR}, {"saddr", KW_SADDR},
		   {"tutype", KW_TUTYPE}, {"srvloc", KW_SRVLOC} };

  char *kwp, *valp;
  int kwlen, vallen;
  UINT32 kwmask = 0;
  register i;

  /*
   * handle each keyword/value pair in the command line
   */
  while (argc) {
    if ((i = parse_keyword(&argc, &argv, &kwp, &valp) != E_SUCCESS))
      return(i);
    kwlen = strlen(kwp);
    vallen = strlen(valp);

    /*
     * search the keyword table for the keyword using minimum uniqueness
     */
    for (i = 0; i < sizeof(kw_table)/sizeof(struct kw_entry); i++) {
      if (strncasecmp(kwp, kw_table[i].keyword, kwlen) == 0) {
	register j;

	for (j = i+1; j < sizeof(kw_table)/sizeof(struct kw_entry); j++) {
	  if (strncasecmp(kwp, kw_table[j].keyword, kwlen) == 0) {
	    if (!quiet)
	      fprintf(stderr, "Ambiguous keyword \"%s\"\n", kwp);
	    return(E_SYNTAX);
	  }
	}

	break;
      }
    }

    if (i == sizeof(kw_table)/sizeof(struct kw_entry)) {
      if (!quiet)
	fprintf(stderr, "Unknown keyword \"%s\"\n", kwp);
      return(E_SYNTAX);
    }
    if (debug)
      printf("<D> parse_addmod: matched keyword \"%s\" against \"%s\"\n",
	     kwp, kw_table[i].keyword);

    /*
     * check for duplicate keyword
     */
    if (kwmask & kw_table[i].kw_value) {
      if (!quiet)
	fprintf(stderr, "Invalid duplicate keyword \"%s\"\n", kwp);
      return(E_SYNTAX);
    }
    kwmask |= kw_table[i].kw_value;	/* remember this keyword was used */

    /*
     * handle the keyword/value pair
     */
    switch (kw_table[i].kw_value) {
    case KW_TE:				/* home address */
      entry.td_te_addr.s_addr = inet_addr(valp);
      if ((*((char *)(&entry.td_te_addr.s_addr)) == 0) ||
	  ((*((char *)(&entry.td_te_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "HA", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: ha = %s\n", inet_ntoa(entry.td_te_addr));
      break;

    case KW_MAXU:			/* maximum users */
      if (strncasecmp(valp, "unlimited", vallen) == 0) {
	entry.td_maxusers = TD_NO_MAXU;
	if (debug)
	  printf("<D> parse_addmod: maxu = unlimited\n");
	break;
      }

      entry.td_maxusers = atol(valp);
      if ((entry.td_maxusers == 0) && (strncmp(valp, "0000", vallen) != 0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "MAXU", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: maxu = %u\n", entry.td_maxusers);
      break;

    case KW_HWTYPE:			/* hardware type */
      for (i = 0; i < sizeof(hw_type)/sizeof(char *); i++)
	if (strncasecmp(valp, hw_type[i], vallen) == 0)
	  break;
      if (i == sizeof(hw_type)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "HWTYPE", valp);
	return(E_SYNTAX);
      }
      entry.td_hw_type = i;
      if (debug)
	printf("<D> parse_addmod: hwtype = %s (%u)\n", hw_type[i], i);
      break;

    case KW_HWADDR: {			/* hardware address */
      int asclen;

      if ((asclen = strlen(valp)) > (TMS_HWADDR_LEN * 2)) {
	if (!quiet)
	  fprintf(stderr, "HWADDR too long\n");
	return(E_SYNTAX);
      }

      if (!adding)
	bzero(entry.td_hw_addr, TMS_HWADDR_LEN);

      if ((*valp == '0') && ((*(valp+1) == 'X') ||(*(valp+1) == 'x'))) {
	register asc = 0, digit;

	asc = 2;
	valp += 2;
	digit = asclen % 2;  /* if ASCII is odd length; prepend 0 pad nibble */

	for (; asc < asclen; asc++, valp++) {
	  if (isxdigit(*valp)) {
	    if (digit % 2 == 0)
	      entry.td_hw_addr[digit/2] = ctoh(*valp) << 4; /* high nibble */
	    else
	      entry.td_hw_addr[digit/2] |= ctoh(*valp);	  /* low nibble */
	    digit++;					  /* next byte */
	  }
	  else {
	    if (!quiet)
	      fprintf(stderr, "Invalid HWADDR character '%c'\n", *valp);
	    return(E_SYNTAX);
	  }
	}

	if (entry.td_hw_addr_len == 0)
	  entry.td_hw_addr_len = (asclen - 1) / 2;
      }
      else {
	INT32 value;

	value = atol(valp);
	if ((value == 0) && (strncmp(valp, "0000", asclen) != 0)) {
	  if (!quiet)
	    fprintf(stderr, "Invalid HWADDR\n");
	  return(E_SYNTAX);
	}

	if (value < 256) {
	  entry.td_hw_addr[0] = (u_char)value;
	  if (entry.td_hw_addr_len == 0)
	    entry.td_hw_addr_len = 1;
	}
	else if (value < 65536) {
	  u_short svalue = (u_short)htons((u_short)value);
	  bcopy((u_char *)(&svalue), entry.td_hw_addr, 2);
	  if (entry.td_hw_addr_len == 0)
	    entry.td_hw_addr_len = 2;
	}
	else {
	  value = htonl(value);
	  bcopy((u_char *)(&value), entry.td_hw_addr, 4);
	  if (entry.td_hw_addr_len == 0)
	    entry.td_hw_addr_len = 4;
	}
      }

      if (debug) {
	printf("<D> parse_addmod: hwaddr = 0x");
	for (i = 0; i < TMS_HWADDR_LEN; i++)
	  printf("%02x", entry.td_hw_addr[i]);
	putchar('\n');
      }
      break;
    }

    case KW_HWALEN:			/* hardware address length */
      entry.td_hw_addr_len = atoi(valp);
      if ((entry.td_hw_addr_len == 0 && strncmp(valp, "0000", vallen) != 0) ||
	  (entry.td_hw_addr_len > TMS_HWADDR_LEN)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "HWALEN", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: hwalen = %u\n", entry.td_hw_addr_len);
      break;

    case KW_PAUTH:			/* primary authentication server */
      entry.td_pauth_addr.s_addr = inet_addr(valp);
      if ((*((char *)(&entry.td_pauth_addr.s_addr)) == 0) ||
	  ((*((char *)(&entry.td_pauth_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "PAUTH", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: pauth = %s\n",
	       inet_ntoa(entry.td_pauth_addr));
      break;

    case KW_SAUTH:			/* secondary authentication server */
      entry.td_sauth_addr.s_addr = inet_addr(valp);
      if (((entry.td_sauth_addr.s_addr != 0L) &&
	   (*((char *)(&entry.td_sauth_addr.s_addr)) == 0)) ||
	  ((*((char *)(&entry.td_sauth_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "SAUTH", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: sauth = %s\n",
	       inet_ntoa(entry.td_sauth_addr));
      break;

    case KW_PACCT:			/* primary accounting server */
      entry.td_pacct_addr.s_addr = inet_addr(valp);
      if (((entry.td_pacct_addr.s_addr != 0L) &&
	   (*((char *)(&entry.td_pacct_addr.s_addr)) == 0)) ||
	  ((*((char *)(&entry.td_pacct_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "PACCT", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: pacct = %s\n",
	       inet_ntoa(entry.td_pacct_addr));
      break;

    case KW_SACCT:			/* secondary accounting server */
      entry.td_sacct_addr.s_addr = inet_addr(valp);
      if (((entry.td_sacct_addr.s_addr != 0L) &&
	   (*((char *)(&entry.td_sacct_addr.s_addr))) == 0) ||
	  ((*((char *)(&entry.td_sacct_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "SACCT", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: sacct = %s\n",
	       inet_ntoa(entry.td_sacct_addr));
      break;

    case KW_AUTHP:			/* authentication protocol */
      for (i = 0; i < sizeof(auth_proto)/sizeof(char *); i++)
	if (strncasecmp(valp, auth_proto[i], vallen) == 0)
	  break;
      if (i == sizeof(auth_proto)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "AUTHP", valp);
	return(E_SYNTAX);
      }
      entry.td_auth_proto = i;
      if (debug)
	printf("<D> parse_addmod: authp = %s (%u)\n", auth_proto[i], i);
      break;

    case KW_ACCTP:			/* accounting protocol */
      for (i = 0; i < sizeof(acct_proto)/sizeof(char *); i++)
	if (strncasecmp(valp, acct_proto[i], vallen) == 0)
	  break;
      if (i == sizeof(acct_proto)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "ACCTP", valp);
	return(E_SYNTAX);
      }
      entry.td_acct_proto = i;
      if (debug)
	printf("<D> parse_addmod: acctp = %s (%u)\n", acct_proto[i], i);
      break;

    case KW_SPI:			/* security protocol index */
      entry.td_spi = atol(valp);
      if ((entry.td_spi == 0) && (strncmp(valp, "0000", vallen) != 0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "SPI", valp);
	return(E_SYNTAX);
      }
      if ((entry.td_spi >= 1) && (entry.td_spi <= 255)) {
	if (!quiet)
	  fprintf(stderr, "SPI values between 1 and 255 are reserved\n");
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: spi = %u\n", entry.td_spi);
      break;

    case KW_TATYPE:			/* tunnel authentication type */
      for (i = 0; i < sizeof(tun_auth_type)/sizeof(char *); i++)
	if (strncasecmp(valp, tun_auth_type[i], vallen) == 0)
	  break;
      if (i == sizeof(tun_auth_type)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "TATYPE", valp);
	return(E_SYNTAX);
      }
      entry.td_ta_type = i;
      if (debug)
	printf("<D> parse_addmod: tatype = %s (%u)", tun_auth_type[i], i);
      break;

    case KW_TAMODE:			/* tunnel authentication mode */
      for (i = 0; i < sizeof(tun_auth_mode)/sizeof(char *); i++)
	if (strncasecmp(valp, tun_auth_mode[i], vallen) == 0)
	  break;
      if (i == sizeof(tun_auth_mode)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "TAMODE", valp);
	return(E_SYNTAX);
      }
      entry.td_ta_mode = i;
      if (debug)
	printf("<D> parse_addmod: tamode = %s (%u)", tun_auth_mode[i], i);
      break;

    case KW_TAKEY: {			/* tunnel authentication key */
      int asclen;
      register asc, hex;

      if ((asclen = strlen(valp)) > (TMS_KEY_LEN * 2)) {
	if (!quiet)
	  fprintf(stderr, "TAKEY too long\n");
	return(E_SYNTAX);
      }

      if (!adding)
	bzero(entry.td_ta_key, TMS_KEY_LEN);

      hex = asclen % 2;	    /* if ASCII is odd length; prepend 0 pad nibble */
      for (asc = 0; asc < asclen; asc++, valp++) {
	if (isxdigit(*valp)) {
	  if (hex % 2 == 0)
	    entry.td_ta_key[hex/2] = ctoh(*valp) << 4;	/* high nibble */
	  else
	    entry.td_ta_key[hex/2] |= ctoh(*valp);	/* low nibble */
	  hex++;					/* next byte */
	}
	else {
	  if (!quiet)
	    fprintf(stderr, "Invalid TAKEY character '%c'\n", *valp);
	  return(E_SYNTAX);
	}
      }
      if (debug) {
	printf("<D> parse_addmod: takey = ");
	for (i = 0; i < TMS_KEY_LEN; i++)
	  printf("%02x", entry.td_ta_key[i]);
	putchar('\n');
      }
      break;
    }

    case KW_ADDRP:			/* address resolution protocol */
      for (i = 0; i < sizeof(addr_proto)/sizeof(char *); i++)
	if (strncasecmp(valp, addr_proto[i], vallen) == 0)
	  break;
      if (i == sizeof(addr_proto)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "ADDRP", valp);
	return(E_SYNTAX);
      }
      entry.td_addr_proto = i;
      if (debug)
	printf("<D> parse_addmod: addrp = %s (%u)\n", addr_proto[i], i);
      break;

    case KW_PADDR:			/* primary addr resolution server */
      entry.td_paddr_addr.s_addr = inet_addr(valp);
      if (((entry.td_paddr_addr.s_addr != 0L) &&
	   (*((char *)(&entry.td_paddr_addr.s_addr)) == 0)) ||
	  ((*((char *)(&entry.td_paddr_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "PADDR", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: paddr = %s\n",
	       inet_ntoa(entry.td_paddr_addr));
      break;

    case KW_SADDR:			/* secondary addr resolution server */
      entry.td_saddr_addr.s_addr = inet_addr(valp);
      if (((entry.td_saddr_addr.s_addr != 0L) &&
	   (*((char *)(&entry.td_saddr_addr.s_addr))) == 0) ||
	  ((*((char *)(&entry.td_saddr_addr.s_addr)) & 0xe0) == 0xe0)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "SADDR", valp);
	return(E_SYNTAX);
      }
      if (debug)
	printf("<D> parse_addmod: saddr = %s\n",
	       inet_ntoa(entry.td_saddr_addr));
      break;

    case KW_TUTYPE:			/* tunnel type */
      for (i = 0; i < sizeof(tun_type)/sizeof(char *); i++)
	if (strncasecmp(valp, tun_type[i], vallen) == 0)
	  break;
      if (i == sizeof(tun_type)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "TUTYPE", valp);
	return(E_SYNTAX);
      }
      entry.td_tunnel_type = i;
      if (debug)
	printf("<D> parse_addmod: tutype = %s (%u)\n", tun_type[i], i);
      break;

    case KW_SRVLOC:			/* servers' location */
      for (i = 0; i < sizeof(server_loc)/sizeof(char *); i++)
	if (strncasecmp(valp, server_loc[i], vallen) == 0)
	  break;
      if (i == sizeof(server_loc)/sizeof(char *)) {
	if (!quiet)
	  fprintf(stderr, inv_val, "AUTYPE", valp);
	return(E_SYNTAX);
      }
      entry.td_server_loc = i;
      if (debug)
	printf("<D> parse_addmod: srvloc = %s (%u)\n", server_loc[i], i);
      break;

    case KW_PASSWD:
      if (strlen(valp) > TMS_PASSWD_LEN) {
	fprintf(stderr, "PASSWD too long (16-character maximum)\n");
	return(E_SYNTAX);
      }
      strncpy(entry.td_passwd, valp, TMS_PASSWD_LEN);
      if (debug)
	printf("<D> parse_addmod: passwd = \"%.16s\"\n", valp);
      break;

    default:				/* this really should NEVER happen */
      if (!quiet)
	fprintf(stderr, "INTERNAL PROGRAMMING ERROR - parse_addmod() %08x\n",
		kw_table[i].kw_value);
      return(E_GENERAL);
    } /*switch*/
  } /*while*/

  /*
   * make sure any required parameters have been specified
   */
  if (adding) {
    if ((kwmask & add_req) != add_req) {
      if (!quiet)
	fprintf(stderr, "Required parameter(s) missing\n");
      return(E_SYNTAX);
    }
    if (!(kwmask & KW_TUTYPE))
      entry.td_tunnel_type = TG_TUTYPE_DVS;
    if (!(kwmask & KW_SRVLOC))
      if (entry.td_auth_proto == TG_AUTHP_ACP)
	entry.td_server_loc = TG_SRVLOC_LOCAL;
      else
	entry.td_server_loc = TG_SRVLOC_REMOTE;
    if (kwmask & KW_HWTYPE) {
      if (!(kwmask & (KW_HWADDR | KW_HWALEN))) {
	if (!quiet)
	  fprintf(stderr, "HWADDR or HWALEN are required with HWTYPE\n");
	return(E_SYNTAX);
      }
    }
    if (kwmask & (KW_TATYPE | KW_TAMODE | KW_TAKEY)) {
      if ((kwmask & (KW_TATYPE | KW_TAMODE | KW_TAKEY)) !=
	  (KW_TATYPE | KW_TAMODE | KW_TAKEY)) {
	if (!quiet)
	  fprintf(stderr, "TATYPE, TAMODE and TAKEY are mutually required\n");
	return(E_SYNTAX);
      }
    }
    if (kwmask & (KW_ACCTP | KW_SACCT)) {
      if (!(kwmask & KW_PACCT)) {
	if (!quiet)
	  fprintf(stderr, "PACCT required for ACCTP and SACCT\n");
	return(E_SYNTAX);
      }
    }
  }

  /*
   * make sure any dependent parameters have been specified
   */
  if ((entry.td_pauth_addr.s_addr == 0L) &&
      ((entry.td_auth_proto != 0) || (entry.td_pauth_addr.s_addr))) {
    if (!quiet)
      fprintf(stderr, "PAUTH required for AUTHP and SAUTH\n");
    return(E_SYNTAX);
  }
  if ((entry.td_pacct_addr.s_addr == 0L) &&
      ((entry.td_acct_proto != 0) || (entry.td_pacct_addr.s_addr))) {
    if (!quiet)
      fprintf(stderr, "PACCT required for ACCTP and SACCT\n");
    return(E_SYNTAX);
  }
  if ((entry.td_paddr_addr.s_addr == 0L) &&
      ((entry.td_addr_proto != 0) || (entry.td_paddr_addr.s_addr))) {
    if (!quiet)
      fprintf(stderr, "PADDR required for ADDRP and SADDR\n");
    return(E_SYNTAX);
  }
  if (kwmask & (KW_HWADDR | KW_HWALEN)) {
    if (entry.td_hw_addr_len == 0)
      for (i = 0; i < TMS_HWADDR_LEN; i++)
	if (entry.td_hw_addr[i] != 0) {
	  if (!quiet)
	    fprintf(stderr, "HWADDR is non-zero and HWALEN is zero\n");
	  return(E_SYNTAX);
	}
  }

  return(E_SUCCESS);
}


/*
 * convert an ASCII character into a hex nibble
 */
static char
ctoh(asc)
  char asc;
{
  if ((asc >= '0') && (asc <= '9'))
    return(asc - '0');
  if ((asc >= 'A') && (asc <= 'F'))
    return(asc - 'A' + 10);
  if ((asc >= 'a') && (asc <= 'f'))
    return(asc - 'a' + 10);

  if (!quiet)
    fprintf(stderr, "ERROR - '%c' is not a hex digit\n", asc);
  return(0);
}

/************************************************************
 *
 * Name:
 *	parse_keyword
 *
 * Description:
 *	This function takes a keyword=value pair and returns
 *	pointers to the keyword and value.
 *
 * Inputs:
 *	argcp - pointer to standard argc
 *	argvp - pointer to standard argv
 *	kbuffp - pointer to keyword pointer
 *	vbuffp - pointer to value pointer
 *
 * Outputs:
 *	E_SUCCESS
 *	E_SYNTAX
 *
 * Notes:
 *	The values of argc and argv in the calling function
 *	are updated to point past the keyword=value pair.
 *
 *	The '=' in the argv buffer is replaced with a '\0'.
 *
 ************************************************************/

static int
parse_keyword(argcp, argvp, kbuffp, vbuffp)
  int  *argcp;
  char ***argvp;
  char **kbuffp;
  char **vbuffp;
{
  *kbuffp = **argvp;			/* set the keyword pointer */
  *vbuffp = strchr(*kbuffp, '=');	/* find the delimiter */
  if ((*vbuffp == NULL) || (*vbuffp == *kbuffp) || (*(*vbuffp+1) == '\0')) {
    if (!quiet)
      fprintf(stderr, "Invalid keyword=value pair \"%s\"\n", *kbuffp);
    return(E_SYNTAX);
  }

  **vbuffp = '\0';			/* change the '=' to a NULL */
  (*vbuffp)++;				/* point to the start of the value */
  (*argcp)--;				/* update caller's argc */
  (*argvp)++;				/* update caller's argv */
  return(E_SUCCESS);
}

#endif /* USE_NDBM */
