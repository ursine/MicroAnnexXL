/*
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 * 	Annex Network Administrator program "main" function
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 *****************************************************************************
 */


/*
 *	Include Files
 */
#include "../inc/config.h"
#include "../inc/vers.h"

#include <ctype.h>
#include <sys/types.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/uio.h>
#else 
#include <winsock.h>
#endif 

#include <setjmp.h>
#include <stdio.h>
#include <signal.h>

/* Tell include file to declare globals */
#define IN_MAIN		1
#include "../inc/na/na.h"
#include "../inc/erpc/netadmp.h"

/*
 *	External Definitions
 */

extern char *cmd_spellings[];
extern int (*cmd_actions[])();

/*
 *	Forward Routine Declarations
 */

int debug = 0;
int init_tables();

#ifdef _WIN32
void interrupt(int);
#else
void interrupt();
#endif

void cmd_sub();
int prompt();
int match();
int lex();
void devttyecho();		/* turn echo on */

/*
 *	Defines and Macros
 */

#define STDIN 0
#define ROOT 0

/*****************************************************************************
 *
 * NAME:  IsPrivileged
 *
 *
 *
 * DESCRIPTION:	Check if user is privileged.
 *
 *
 *
 * ARGUMENTS:  None
 *
 *
 *
 * RETURN VALUE: TRUE for privileged user. Otherwise FALSE.
 *
 *
 *
 * SIDE EFFECTS: 
 *
 *	None
 *
 * EXCEPTIONS:
 *
 *	None
 *
 * ASSUMPTIONS:
 *
 *	None
 */
int IsPrivileged()
{
#ifdef _WIN32
	/* Server tools will not use this security */
	/* All users will be allowed to run na */
	return(TRUE);
#else /* _WIN32 */
	return (getuid() == ROOT || geteuid() == ROOT);
#endif /* _WIN32 */
}


void show_usage()
{
	fprintf(stderr,
		"usage: na [-v] [-d<UDP-port>] [-D[<debug-level>]]\n");
	exit(1);
}

int
main(argc, argv)
int argc;
char *argv[];
{

	struct servent *Pserv;
	int port = -1, i;
#ifdef _WIN32
	/* set the screen buffer size to 80 column, 132 row */
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coordSize={80, 256};
	BOOL b = SetConsoleScreenBufferSize(hStdOut, coordSize);
#endif /* _WIN32 */

#ifdef CHANGE_DIR
/*
 * Note that we cannot use chroot here because of a bug in
 * gethostbyname -- it uses /etc/hosts and it gets lost if a new
 * root directory is set.
 */
	if (chdir(CHANGE_DIR) != 0) {
		perror("Cannot change to main directory");
		exit(2);
		}
#endif

	debug = 0;
	status = 0;

	/* process arguments */
	while (argc-- > 1) {
	    if (**++argv == '-') {
		switch ((*argv)[1]) {
		case 'd':
			if (isdigit((*argv)[2])) {
				(*argv)+=2;
			} else {
				argv++;
				argc--;
				if (*argv == NULL || !isdigit(**argv)) {
					fprintf(stderr,
						"na: port number required!\n");
					show_usage();
				}
			}
	    	        port = atoi(*argv);
	                break;
	    
		case 'D':
			if (isdigit((*argv)[2]))
				debug = (*argv)[2] - '0';
			else
				debug = 1;
			fprintf(stderr, "na: debug level %d\n", debug);
			break;

		case 'v':
			printf("na host tool version %s, released %s\n",
			       VERSION,RELDATE);
			exit(0);
			break;
		default:
			show_usage();
	        }	/* switch ((*argv)[1]) */
	    } else
		show_usage();
	}	/* while (argc) */


	/* Print banner. */
	printf("%s network administrator %s %s\n", Box, VERSION, RELDATE);

	/* decide what port number to use */

#ifdef _WIN32
	/* In Windows you start up the Socket Subsystem */
	    {
      WSADATA WSAData;

      if ((WSAStartup(MAKEWORD(1,1), &WSAData)) != 0) {
         fprintf(stderr,"WSAStartup Failed: %d\n", GetLastError());
         }
      
   }
#endif
	if (port != -1)
		erpc_port = htons((u_short)port);
	else {
		Pserv = getservbyname("erpc", "udp");
		if (Pserv == 0) {
			if (debug)
				fprintf(stderr, "na: udp/erpc: unknown service, Using 121.\n");
			erpc_port = htons(121);;
			}
		else
			erpc_port = Pserv->s_port;
	}
	if (debug)
		fprintf(stderr, "port=%d; using udp port %d\n",
			port, (int)ntohs(erpc_port));

	/* Set up to get input from pre-opened standard input. */
	cmd_file = stdin;

	/* Determine whether input is coming from a script file. */
	script_input = !isatty(STDIN);

	/* Determine whether user is super. */
	is_super = IsPrivileged();

	/* Assign the initial default port set. */

	Pdef_port_set = (PORT_SET *)malloc(sizeof(PORT_SET));
	Pdef_port_tail = Pdef_port_set;
	Pdef_port_set->next = NULL;
	Pdef_port_set->ports.pg_bits = PG_ALL;
	for (i=1;i<=ALL_PORTS;i++)
#ifdef DEFAULT_ALL_SET
	    SETPORTBIT(Pdef_port_set->ports.serial_ports,i);
#else
	    CLRPORTBIT(Pdef_port_set->ports.serial_ports,i);
#endif
	Pdef_port_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_port_set->name[0] = '\0';

	/* Assign the initial default port set. */

	Pdef_printer_set = (PRINTER_SET *)malloc(sizeof(PRINTER_SET));
	Pdef_printer_tail = Pdef_printer_set;
	Pdef_printer_set->next = NULL;
	Pdef_printer_set->printers.pg_bits = PG_ALL;
	for (i=1;i<=ALL_PRINTERS;i++)
#ifdef DEFAULT_ALL_SET
	    SETPRINTERBIT(Pdef_printer_set->printers.ports,i);
#else
	    CLRPRINTERBIT(Pdef_printer_set->printers.ports,i);
#endif
	Pdef_printer_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_printer_set->name[0] = '\0';

	/* Assign the initial default interface set. */

	Pdef_interface_set = (INTERFACE_SET *)malloc(sizeof(INTERFACE_SET));
	Pdef_interface_tail = Pdef_interface_set;
	Pdef_interface_set->next = NULL;
	Pdef_interface_set->interfaces.pg_bits = PG_ALL;
	for (i=1;i<=ALL_INTERFACES;i++)
#ifdef DEFAULT_ALL_SET
	    SETINTERFACEBIT(Pdef_interface_set->interfaces.interface_ports,i);
#else
	    CLRINTERFACEBIT(Pdef_interface_set->interfaces.interface_ports,i);
#endif
	Pdef_interface_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_interface_set->name[0] = '\0';

	/* Assign the initial default T1 set. */
	Pdef_t1_set = (T1_SET *)malloc(sizeof(T1_SET));
	Pdef_t1_tail = Pdef_t1_set;
	Pdef_t1_set->next = NULL;
	Pdef_t1_set->t1s.reset_type = 3; /***************/
	for (i=1;i<=ALL_T1S;i++)
	    CLRPORTBIT(Pdef_t1_set->t1s.engines,i);
	for (i=1;i<=ALL_DS0S;i++)
	    CLRPORTBIT(Pdef_t1_set->ds0s.ds0s,i);
	SETPORTBIT(Pdef_t1_set->t1s.engines,1);  /* Allow 1 engine for now! */ 
	Pdef_t1_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_t1_set->name[0] = '\0';

	/* Assign the initial default PRI set. */
	Pdef_pri_set = (PRI_SET *)malloc(sizeof(PRI_SET));
	Pdef_pri_tail = Pdef_pri_set;
	Pdef_pri_set->next = NULL;
	bzero(Pdef_pri_set->pris.modules,sizeof(Pdef_pri_set->pris.modules));
	bzero(Pdef_pri_set->bs.bs,sizeof(Pdef_pri_set->bs.bs));
	SETPORTBIT(Pdef_pri_set->pris.modules,1);
	SETPORTBIT(Pdef_pri_set->pris.modules,2);
	Pdef_pri_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_pri_set->name[0] = '\0';

	/* Assign the initial default internal modem set. */
	Pdef_intmod_set = (INTMOD_SET *)malloc(sizeof(INTMOD_SET));
	Pdef_intmod_tail = Pdef_intmod_set;
	Pdef_intmod_set->next = NULL;
	Pdef_intmod_set->intmods.reset_type = RESET_INTMODEM_HARD;
	for (i=1;i<=ALL_INTMODS;i++)
	    CLRPORTBIT(Pdef_intmod_set->intmods.intmods,i);
	Pdef_intmod_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_intmod_set->name[0] = '\0';

	/* Assign the initial default trunk set. */

	Pdef_trunk_set = (TRUNK_SET *)malloc(sizeof(TRUNK_SET));
	Pdef_trunk_tail = Pdef_trunk_set;
	Pdef_trunk_set->next = NULL;
	Pdef_trunk_set->trunks.pg_bits = PG_ALL;
	Pdef_trunk_set->trunks.serial_trunks = 0L;
	Pdef_trunk_set->annex_id.addr.sin_addr.s_addr = 0;
	Pdef_trunk_set->name[0] = '\0';

	/* Initialize table from help dictionary, check indices */

	(void) init_tables();

	/* Set up a signal handler to catch control-c's and go back
	   to the main command prompt. */

	(void)signal(SIGINT, interrupt);

	initialize_pager();

	/* Get and execute commands. */

	cmd_sub();
	exit(status);

#ifdef _WIN32
	return 0;
#endif
}	/* main() */
	   


void cmd_sub()

{
	int cmd_number;

	done = FALSE;	/* set to TRUE in quit_cmd() */

	while(!done)
	{

	    /* Come back here for another command prompt after an error. */
	    if (setjmp(cmd_env))
		printf("\n");

	    (void)setjmp(prompt_env);

	    close_pager();
	    prompt("command", NULLSP, FALSE);

	    /* If end of a script read by a read command, quit. */
	    if (eos)
		return;

	    /* Execute the specified command. */
	    cmd_number = match(symbol, cmd_spellings, "command");
	    (*cmd_actions[cmd_number])();

	    /* Warn human about any extraneous arguments. */
	    while (!eos)
		{
			printf("extra symbol '%s' ignored\n", symbol);
			(void)lex();
		}
	}

}	/* cmd_sub() */



void interrupt(arg)
int arg;
{
#ifndef _WIN32
#ifdef SYS_V
	signal(SIGINT, interrupt);
#endif
	devttyecho();
	stop_pager();
	longjmp(cmd_env, TRUE);
#endif
}	/* interrupt() */
