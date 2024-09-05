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
 * 	%$(Description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 *****************************************************************************
 */


/*
 *	Include Files
 */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <fcntl.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <strings.h>
#else
#endif /* _WIN32 */

#include <setjmp.h>
#include <stdio.h>
#include "../netadm/netadm_err.h"
#include "../inc/erpc/netadmp.h"
#include "../inc/na/interface.h"
#include "../inc/na/na.h"

#define CMD_H_PARAMS_ONLY
#include "../inc/na/cmd.h"

/*
 *	External Definitions
 */

extern UINT32		 masks[];	    /* initialized in parse.c */
extern char		*reset_params[];
extern char		*annex_params[];
extern char		*port_params[];
extern char		*interface_params[];
extern char		*t1_all_params[];
extern char		*wan_all_params[];
extern char		*modem_params[];
extern char		*printer_params[];
extern char *reset_modem_params[];
extern parameter_table	annexp_table[];
extern parameter_table	portp_table[];
extern parameter_table	syncp_table[];
extern parameter_table	interfacep_table[];
extern parameter_table	t1p_table[];
extern parameter_table	prip_table[];
extern parameter_table	modemp_table[];
extern parameter_table	printp_table[];
extern int		debug;

#ifndef _WIN32
extern char *inet_ntoa();
#endif
extern char *getlogin();
extern void decode();
extern int  get_internal_vers();

/*
 *	Defines and Macros
 */

#define OWNER_RW  0600
#define MAX_RETRIES 10

/*
 *	Structure Definitions
 */


/*
 *	Forward Routine Definitions
 */

#ifdef NA
void punt();
#endif

char *split_string();
int boot();
void netadm_error();
void broadcast_sub();
int broadcast();
void do_copy_port();
void do_copy_print();
void copy_printer();
int	Anyp_support();
int get_ln_param();
int set_ln_param();
void do_copy_interface();
void copy_interface();
int get_if_param();
int set_if_param();
void do_copy_port();
void copy_port();
void copy_annex();
int get_dla_param();
int set_dla_param();
void cmd_sub();
void reset_printer_sub();
void reset_sub();
void reset_interface_sub();
void write_annex_script();
void write_printer_script();
int lex();
int match();
int reset_annex();
int reset_all();
int reset_line();
void write_port_script();
void write_interface_script();
void do_copy_t1port();
void copy_t1();
int get_t1_param();
int set_t1_param();
int reset_t1();
void reset_intmod_sub();
void write_t1_script();
void reset_t1_sub();
int reset_intmod();
void do_copy_modem(),do_copy_pri(),do_copy_modemport(),copy_modem();
void do_copy_priport(),copy_pri(),do_reset_pri(),reset_pri_sub();
void write_modem_script(),get_if_name(),write_pri_script();
void free_modem_set(),free_pri_set();
void dor_list();

/*
 *	Global Data Declarations
 */


/*
 *	Static Declarations
 */

char	defalt[] = {0, 0, 0, 0};

static	unsigned char	disable_groups[LAT_GROUP_SZ + 1] = {
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0x00 };

static  u_char dorset[(ALL_DORS + (NBBY - 1)) /NBBY];

int
is_in_list(str,listp)
char *str,**listp;
{
  int idx;

  for (idx = 1; *listp != (char *)0; listp++, idx++)
    if (strcmp(str,*listp) == 0)
      return idx;
  return 0;
}

/*
 *****************************************************************************
 *
 * Function Name:
 *	do_boot()
 *
 * Functional Description:
 *	Attempt to boot all the annexez in the Annex list.  Annexes with
 *      Annexes are dropped from the list if the uses any options other
 *      then a file name or dump.
 *
 * Parameters:
 * 	switches - commands switches used.
 *      filename - image name to be booted.
 *      warning  - warning message.
 * 	Pannex_list - list of annexes to be booted.
 * 	boot_time - time offset in seconds to boot.
 *
 *****************************************************************************
 */


void do_boot(filename, Pannex_list, boot_time, switches, warning)

	short int  switches;
	char       filename[],
		   warning[];
	ANNEX_LIST *Pannex_list;
	time_t	   boot_time;

{
	int 
		boot_count = 0,
		maj_vers,
		hw,
	    	error_code;
	char 
		*username,
	         hostname[HOSTNAME_LENGTH+1];

	if ((username = getlogin()) == NULL)
		username = "unknown";
	(void)gethostname(hostname,HOSTNAME_LENGTH);
	hostname[HOSTNAME_LENGTH] = '\0';
	
	while (Pannex_list) {
	    get_internal_vers(Pannex_list->annex_id.sw_id, &maj_vers,&hw,
			     &Pannex_list->annex_id.flag, FALSE);	

	    if (maj_vers < VERS_5 && 
	        ((switches & SWDELAY) || (switches & SWDIAG) ||
		 (switches & SWFLASH) || (switches & SWABORT) ||
		 (warning[0] != '\0'))) {

	        printf("Shutdown not supported by pre-5.0 software\n");
		printf("Dropping %s from the list of %s\n",
				Pannex_list->name, BOXES);
	    } else {
		if ((switches & SWFLASH)
			 && (Pannex_list->annex_id.self_boot == 0)) {
		    printf("%s does not have self booting capability\n",
				     Pannex_list->name);
		    printf("Dropping %s from the list of %s\n",
				Pannex_list->name, BOXES);
		} else {

		    printf("%s %s %s\n",
			   switches&SWABORT ? "aborting boot" :
			   switches&SWDELAY ? "delay booting" : "booting", 
			       BOX, Pannex_list->name);

		    error_code = boot(&Pannex_list->annex_id.addr,
			filename, warning, switches, boot_time, username,
			hostname, (switches & SWDUMP), (maj_vers >= VERS_5));

	    	    if (error_code != NAE_SUCC)
		        netadm_error(error_code);

	    	    boot_count++;
		}
	    }
	    Pannex_list = Pannex_list->next;
	}
	if (!(switches & SWABORT) && (boot_count) && !(switches & SWDELAY)) {
		printf("The %s %s performing self-diagnostics, and will not respond\n",
	 	boot_count > 1 ? BOXES : BOX,
	 	boot_count > 1 ? "are" : "is");
		printf("to administration operations for a short period.\n");
	}
}	/* do_boot() */


void do_broadcast(Pport_set, Ptext)

	PORT_SET       *Pport_set;
	char	       *Ptext;

{
	ANNEX_LIST *Ptemp_annex_list;

	/* Send the message to each port in the given port set. */

	while (Pport_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */
	    if (Pport_set->annex_id.addr.sin_addr.s_addr)
		broadcast_sub(&Pport_set->annex_id, Pport_set->name,
		 &Pport_set->ports, Ptext);
	    else
		if (Pdef_annex_list)
		    for (Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		     Ptemp_annex_list = Ptemp_annex_list->next)
			broadcast_sub(&Ptemp_annex_list->annex_id,
			 Ptemp_annex_list->name, &Pport_set->ports, Ptext);
		else
		    punt(NO_BOXES, (char *)NULL);

	    Pport_set = Pport_set->next;
	    }

}	/* do_broadcast() */



void broadcast_sub(Pannex_id, name, Pports, Ptext)

	ANNEX_ID	   *Pannex_id;
	char                name[];
	PORT_GROUP	   *Pports;
	char               *Ptext;

{
	int                error_code,
			   loop, loop_limit;

	/* Send the message to each port whose bit is set in the port mask. */
	if(Pports->pg_bits && (PG_ALL|PG_SERIAL))
	    loop_limit = (int)Pannex_id->port_count;
        else 
	    loop_limit = ALL_PORTS;

	for (loop = 1; loop <= loop_limit; loop++)
	    if (PORTBITSET(Pports->serial_ports,loop))
	    {
		if (loop > (int)Pannex_id->port_count)
		{
		printf("\n%s %s does not have a port %d\n",
		       BOX, name, loop);
		    continue;
		}

	        if ((error_code = broadcast(&Pannex_id->addr, 
			(u_short)SERIAL_DEV, (u_short)loop,Ptext)) != NAE_SUCC)
		    if (error_code == NAE_PROC)
			{
			printf("%s '%s' does not support broadcast\n",
			 BOX, name);
			return;
			}
		    else
		        netadm_error(error_code);
	    }

	if (Pports->pg_bits & (PG_VIRTUAL | PG_ALL))
	    {
	     if ((Pannex_id->version < VERS_4) && (Pannex_id->hw_id != X25))
		{
		if (Pports->pg_bits & PG_VIRTUAL)
		    printf("%s '%s' does not support virtual ports\n",
			   BOX, name);
		return;
		}

	    if ((error_code = broadcast(&Pannex_id->addr, 
		    (u_short)PSEUDO_DEV, (u_short)0, Ptext)) != NAE_SUCC)
		if (error_code == NAE_PROC)
		    {
		    printf("%s '%s' does not support broadcast\n",
		     BOX, name);
		    return;
		    }
		else
		    netadm_error(error_code);
	    }

}	/* broadcast_sub() */



void do_copy(source_port_number, Psource_annex_id, Pport_set)

	unsigned short     source_port_number;
	ANNEX_ID	   *Psource_annex_id;
	PORT_SET           *Pport_set;

{
	ANNEX_LIST      *Ptemp_annex_list;


	/* Copy the parameters to each port in the port set. */


	while (Pport_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */

	    if (Pport_set->annex_id.addr.sin_addr.s_addr)

		    do_copy_port(Psource_annex_id, source_port_number,
			         &Pport_set->annex_id, 
				 Pport_set->ports.serial_ports,
		 	         Pport_set->name);

	    else if (Pdef_annex_list)

		for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		    Ptemp_annex_list = Ptemp_annex_list->next)

		    do_copy_port(Psource_annex_id, source_port_number,
			         &Ptemp_annex_list->annex_id,
				 Pport_set->ports.serial_ports,
				 Ptemp_annex_list->name);
	    else
		punt(NO_BOXES, (char *)NULL);

	    Pport_set = Pport_set->next;
	    }

}	/* do_copy() */

void
do_copy_modem(source_modem_number, Psource_annex_id, Pmodem_set)
	unsigned short     source_modem_number;
	ANNEX_ID	   *Psource_annex_id;
	MODEM_SET          *Pmodem_set;
{
	ANNEX_LIST      *Ptemp_annex_list;


	/* Copy the parameters to each modem port in the modem port set. */


	while (Pmodem_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */

	    if (Pmodem_set->annex_id.addr.sin_addr.s_addr)

		    do_copy_modemport(Psource_annex_id, source_modem_number,
			         &Pmodem_set->annex_id, 
				 Pmodem_set->modems.modems,
		 	         Pmodem_set->name);

	    else if (Pdef_annex_list)

		for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		    Ptemp_annex_list = Ptemp_annex_list->next)

		    do_copy_modemport(Psource_annex_id, source_modem_number,
			         &Ptemp_annex_list->annex_id,
				 Pmodem_set->modems.modems,
				 Ptemp_annex_list->name);
	    else
		punt(NO_BOXES, (char *)NULL);

	    Pmodem_set = Pmodem_set->next;
	    }

}	/* do_copy_modem() */

void do_copy_t1(source_t1_number, Psource_annex_id, Pt1_set)

	unsigned short     source_t1_number;
	ANNEX_ID	   *Psource_annex_id;
	T1_SET             *Pt1_set;

{
	ANNEX_LIST      *Ptemp_annex_list;


	/* Copy the parameters to each t1 engine in the t1 set. */


	while (Pt1_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */

	    if (Pt1_set->annex_id.addr.sin_addr.s_addr)

		    do_copy_t1port(Psource_annex_id, source_t1_number,
			         &Pt1_set->annex_id, 
				 Pt1_set->t1s.engines,
		 	         Pt1_set->name);

	    else if (Pdef_annex_list)

		for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		    Ptemp_annex_list = Ptemp_annex_list->next)

		    do_copy_t1port(Psource_annex_id, source_t1_number,
			         &Ptemp_annex_list->annex_id,
				 Pt1_set->t1s.engines,
				 Ptemp_annex_list->name);
	    else
		punt(NO_BOXES, (char *)NULL);

	    Pt1_set = Pt1_set->next;
	    }

}	/* do_copy_t1() */

void
do_copy_pri(source_pri_number, Psource_annex_id, Ppri_set)

	unsigned short     source_pri_number;
	ANNEX_ID	   *Psource_annex_id;
	PRI_SET             *Ppri_set;

{
	ANNEX_LIST      *Ptemp_annex_list;


	/* Copy the parameters to each WAN module in the PRI set. */


	while (Ppri_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */

	    if (Ppri_set->annex_id.addr.sin_addr.s_addr)

		    do_copy_priport(Psource_annex_id, source_pri_number,
			         &Ppri_set->annex_id, 
				 Ppri_set->pris.modules,
		 	         Ppri_set->name);

	    else if (Pdef_annex_list)

		for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		    Ptemp_annex_list = Ptemp_annex_list->next)

		    do_copy_priport(Psource_annex_id, source_pri_number,
			         &Ptemp_annex_list->annex_id,
				 Ppri_set->pris.modules,
				 Ptemp_annex_list->name);
	    else
		punt(NO_BOXES, (char *)NULL);

	    Ppri_set = Ppri_set->next;
	    }

}	/* do_copy_pri() */

void printer_copy(source_printer_number, Psource_annex_id, Pprinter_set)

	unsigned short     source_printer_number;
	ANNEX_ID	   *Psource_annex_id;
	PRINTER_SET        *Pprinter_set;

{
	ANNEX_LIST      *Ptemp_annex_list;


	/* Copy the parameters to each printer in the printer set. */


	while (Pprinter_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */

	    if (Pprinter_set->annex_id.addr.sin_addr.s_addr)

		    do_copy_print(Psource_annex_id, source_printer_number,
			         &Pprinter_set->annex_id, 
				 Pprinter_set->printers.ports,
		 	         Pprinter_set->name);

	    else if (Pdef_annex_list)

		for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		    Ptemp_annex_list = Ptemp_annex_list->next)

		    do_copy_print(Psource_annex_id, source_printer_number,
			         &Ptemp_annex_list->annex_id,
				 Pprinter_set->printers.ports,
				 Ptemp_annex_list->name);
	    else
		punt(NO_BOXES, (char *)NULL);

	    Pprinter_set = Pprinter_set->next;
	    }

}	/* printer_copy() */



void do_copy_print(Pannex_from, printer, Pannex_to, printer_mask, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		printer;
ANNEX_ID	  	*Pannex_to;
unsigned char		*printer_mask;
char			name[];
{
    int	loop;

    /* Copy parameters to each printer whose bit is set in the printer mask. */

    if (printer > (u_short)Pannex_from->printer_count)
	printf("\nsource %s does not have a printer %d\n", BOX, printer);
    else 
	for (loop = 1; loop <= ALL_PRINTERS; loop++)
	    if (PRINTERBITSET(printer_mask,loop))
	    {
		if (loop > (int)Pannex_to->printer_count)
		{
		    continue;
		}
		printf(
		"\tcopying eeprom serial printer parameters to %s %s printer %d\n",
		BOX, name, loop);

		copy_printer(Pannex_from, printer, Pannex_to, (u_short)loop, name);
	    }

}	/* do_copy_print() */


void copy_printer(Pannex_from, printer_from, Pannex_to, printer_to, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		printer_from;
ANNEX_ID	  	*Pannex_to;
unsigned short		printer_to;
char			name[];
{
	int		parm;
	u_short cat,id,type;

	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAXVALUE+2];
		};
	struct	p_param	*pp_param;
	char	*mem_pool;
	int	n_param = 0;

	/* allocate memory to read the port parameters in */
	for(parm = 0; Cp_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy printer: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read printer parameters */
	for(parm = 0; Cp_index(parm) != -1; parm++)
	    {
	    if(!Anyp_support(Pannex_from,parm,printp_table))
		continue;  /* skip parms not support on source annex */
	    cat = (u_short)Cp_category(parm);
	    id = (u_short)Cp_catid(parm);

	    if (cat == LP_CAT) {

		type = (u_short)Cp_type(parm);

		if(get_ln_param(&Pannex_from->addr, (u_short)P_PRINT_DEV, 
			(u_short)printer_from, cat, id,type,pp_param[parm].buf))
		    {
		    printf("\tusing default for %s\n", printer_params[parm]);
		    (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
		    }
		pp_param[parm].cat = cat;
		pp_param[parm].id = id;
		pp_param[parm].type = type;
		}
	    }   /* for(parm ... */
	    pp_param[parm].cat = (u_short)-1;

	/* write printer parameters */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	    {
		if ((cat = pp_param[parm].cat) == 0)
			continue;
		id = pp_param[parm].id;
		type = pp_param[parm].type;

		if(Anyp_support(Pannex_to,parm,printp_table))
		    {
		    if(set_ln_param(&Pannex_to->addr, (u_short)P_PRINT_DEV,
			(u_short)printer_to, cat, id, type, pp_param[parm].buf))

			    printf("\tcould not set %s\n", printer_params[parm]);
		    }
		else
		    printf("\t%s  does not support %s\n",name,
						printer_params[parm]);
	    }   /* for(parm ... */

	/* return memory */
	free(mem_pool);

}	/* copy_printer() */



void interface_copy(source_interface_number, Psource_annex_id, Pinterface_set)

	unsigned short     source_interface_number;
	ANNEX_ID	   *Psource_annex_id;
	INTERFACE_SET      *Pinterface_set;

{
	ANNEX_LIST      *Ptemp_annex_list;


	/* Copy the parameters to each interface in the interface set. */


	while (Pinterface_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */

	    if (Pinterface_set->annex_id.addr.sin_addr.s_addr)

		    do_copy_interface(Psource_annex_id, source_interface_number,
			         &Pinterface_set->annex_id, 
				 Pinterface_set->interfaces.interface_ports,
		 	         Pinterface_set->name);

	    else if (Pdef_annex_list)

		for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		    Ptemp_annex_list = Ptemp_annex_list->next)

		    do_copy_interface(Psource_annex_id, source_interface_number,
			         &Ptemp_annex_list->annex_id,
				 Pinterface_set->interfaces.interface_ports,
				 Ptemp_annex_list->name);
	    else
		punt(NO_BOXES, (char *)NULL);

	    Pinterface_set = Pinterface_set->next;
	    }

}	/* interface_copy() */



void do_copy_interface(Pannex_from, Interface, Pannex_to, interface_mask, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		Interface;
ANNEX_ID	  	*Pannex_to;
unsigned char		*interface_mask;
char			name[];
{
 	int		loop, asy_end, syn_end;


    /* en0 plus asy */
    	asy_end = (int)Pannex_to->port_count + 1;
	syn_end = ALL_PORTS + (int)Pannex_to->sync_count + 1;

    /*
     * Copy parameters to each interface whose bit is set in the
     * interface mask.
     */

	for (loop = 1; loop <= ALL_INTERFACES; loop++)
	  if ((loop <= asy_end) || ((loop > ALL_PORTS) && (loop <= syn_end))) {
	    if (INTERFACEBITSET(interface_mask,loop))
	    {
		/* convert the interface logical index into human-eye form */
		if (loop == M_ETHERNET)
			printf("\tcopying eeprom interface parameters to %s %s interface en%d:\n", BOX, name, loop-M_ETHERNET);

		else 
		if( loop <= ALL_PORTS )
		        printf("\tcopying eeprom interface parameters to %s %s interface asy%d:\n", BOX, name, loop-M_ETHERNET);

		else
			printf("\tcopying eeprom Interface parameters to %s %s Interface syn%d:\n", BOX, name, loop-M_ETHERNET-ALL_PORTS);
		copy_interface(Pannex_from, Interface, Pannex_to, (u_short)loop, name);
	    }
	}
}	/* do_copy_interface() */


void copy_interface(Pannex_from, interface_from, Pannex_to, interface_to, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		interface_from;
ANNEX_ID	  	*Pannex_to;
unsigned short		interface_to;
char			name[];
{
	int		parm;
	u_short cat,id,type;

	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAXVALUE+2];
		};
	struct	p_param	*pp_param;
	char 	*mem_pool;
	int	n_param = 0;

	/* allocate memory to read the interface parameters in */
	for(parm = 0; Ip_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy interface: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read interface parameters */
	for(parm = 0; Ip_index(parm) != -1; parm++)
	    {
	    if(!Anyp_support(Pannex_from,parm,interfacep_table))
		continue;  /* skip parms not support on source annex */
	    cat = (u_short)Ip_category(parm);
	    id = (u_short)Ip_catid(parm);

	    if (cat == IF_CAT) {

		type = (u_short)Ip_type(parm);

		if(get_if_param(&Pannex_from->addr, (u_short)INTERFACE_DEV, 
			(u_short)interface_from, cat, id,type,pp_param[parm].buf))
		    {
		    printf("\tusing default for %s\n", interface_params[parm]);
		    (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
		    }
		pp_param[parm].cat = cat;
		pp_param[parm].id = id;
		pp_param[parm].type = type;
		}
	    }   /* for(parm ... */
	    pp_param[parm].cat = (u_short)-1;

	/* write interface parameters */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	    {
		if ((cat = pp_param[parm].cat) == 0)
			continue;
		id = pp_param[parm].id;
		type = pp_param[parm].type;

		if(Anyp_support(Pannex_to,parm,interfacep_table))
		    {
		    if(set_if_param(&Pannex_to->addr, (u_short)INTERFACE_DEV,
			(u_short)interface_to, cat, id, type, pp_param[parm].buf))

			    printf("\tcould not set %s\n", interface_params[parm]);
		    }
		else
		    printf("\t%s  does not support %s\n",name,
						interface_params[parm]);
	    }   /* for(parm ... */

	/* return memory */
	free(mem_pool);

}	/* copy_interface() */



void do_copy_port(Pannex_from, port, Pannex_to, port_mask, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		port;
ANNEX_ID	  	*Pannex_to;
unsigned char		*port_mask;
char			name[];
{
    int	loop;

    /* Copy parameters to each port whose bit is set in the port mask. */

    if (port > (u_short)Pannex_from->port_count)
	printf("\nsource %s does not have a port %d\n", BOX, port);
    else 
	for (loop = 1; loop <= ALL_PORTS; loop++)
	    if (PORTBITSET(port_mask,loop))
	    {
		if (loop > (int)Pannex_to->port_count)
		{
		    printf("\n%s %s does not have a port %d\n",
			       BOX, name, loop);
		    continue;
		}
		printf(
		"\tcopying eeprom serial port parameters to %s %s port %d\n",
		BOX, name, loop);

		copy_port(Pannex_from, port, Pannex_to, (u_short)loop, name);
	    }

}	/* do_copy_port() */



void copy_port(Pannex_from, port_from, Pannex_to, port_to, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		port_from;
ANNEX_ID	  	*Pannex_to;
unsigned short		port_to;
char			name[];
{
	int		parm;
	int		error;
	u_short cat,id,type;

	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAXVALUE+2];
		};
	struct	p_param	*pp_param;
	char	*mem_pool;
	int	n_param = 0;

	/* allocate memory to read the port parameters in */
	for(parm = 0; Sp_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read in port parameters */
	for(parm = 0; Sp_index(parm) != -1; parm++)
	    {
	    if(!(Anyp_support(Pannex_from,parm,portp_table)))
		continue;  /* skip parms not supported on source annex */

	    cat = (u_short)Sp_category(parm);
	    id = (u_short)Sp_catid(parm);

	    if ((id == DEV2_PORT_PASSWD && cat == DEV2_CAT) ||
	     (id == PPP_PWORDRMT && cat == SLIP_CAT))
		continue;  			/* skip password */

	    if(cat == DEV_CAT ||
	       cat == EDIT_CAT ||
	       cat == INTF_CAT ||
               cat == DEV2_CAT  ||
	       cat == SLIP_CAT)

		{
		type = (u_short)Sp_type(parm);
#ifdef NA
                if (cat == DEV_CAT && id == DEV_ATTN) {
                    if ((Pannex_from->version < VERS_6_2)
			               || (Pannex_from->hw_id < ANX3)){
                        type = CARDINAL_P;
                    }
                }
		if (cat == DEV_CAT && id == DEV_BANNER) {
		    if((Pannex_from->version < VERS_14_0)) {
			type = BOOLEAN_P;
		    }
		}
#endif

		error = get_ln_param(&Pannex_from->addr, (u_short)SERIAL_DEV, 
			(u_short)port_from, cat, id, type, pp_param[parm].buf);

		/* If we are talking with an annex that uses 16 character username */
		/* fields, then we want to get the username as a 16 character string */
		if (error && ((id == DEV_NAME) || (id == PPP_UNAMERMT))) {
		    if (id == DEV_NAME)
			id = DEV_NAME_OLD;
		    else
			id = PPP_UNAMERMT_OLD;
		    type = STRING_P;
		    error = get_ln_param(&Pannex_from->addr, (u_short)SERIAL_DEV, 
			(u_short)port_from, cat, id, type, pp_param[parm].buf);
		}
 
		if (error)
		    {
		    printf("\tusing default for %s\n", port_params[parm]);
		    (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
		    }

		pp_param[parm].cat = cat;
		pp_param[parm].id = id;
		pp_param[parm].type = type;
		}
	    }
	    pp_param[parm].cat = (u_short)-1; /* end of table mark */

	/* write port parameters */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	    {
		if ((cat = pp_param[parm].cat) == 0)
			continue;
		id = pp_param[parm].id;
		type = pp_param[parm].type;

		if(Anyp_support(Pannex_to,parm,portp_table))
		    {
	            if ( (id == LAT_AUTHORIZED_GROUPS) && (cat == DEV_CAT)) {

		      /* disable all group codes first, then copy them in */
	              if (set_ln_param(&Pannex_to->addr, (u_short)SERIAL_DEV,
			        (u_short)port_to,cat,id,type,
				(char *)disable_groups)) {
	 	          printf("\tcould not set param %s\n",
			        port_params[parm]);
			  continue;
		      }

		      /* now enable according to src annex */
		      pp_param[parm].buf[LAT_GROUP_SZ] = 1;
	            }
		    if(set_ln_param(&Pannex_to->addr, (u_short)SERIAL_DEV,
			(u_short)port_to, cat, id, type, pp_param[parm].buf))

			    printf("\tcould not set %s\n", port_params[parm]);
		    }
		else
		    printf("\t%s does not support %s\n",name,
						port_params[parm]);
	    }   /* for(parm ... */

	/* return memory */
	free(mem_pool);

}	/* copy_port() */

void
do_copy_modemport(Pannex_from, modem, Pannex_to, modem_mask, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		modem;
ANNEX_ID	  	*Pannex_to;
unsigned char		*modem_mask;
char			name[];
{
    int	loop;

    /* Copy parameters to each modem port whose bit is set in the modem port mask. */

    if (modem > (u_short)Pannex_from->port_count)
	printf("\nsource %s does not have a modem %d\n", BOX, modem);
    else 
	for (loop = 1; loop <= ALL_MODEMS; loop++)
	    if (PORTBITSET(modem_mask,loop))
	    {
		if (loop > (int)Pannex_to->port_count)
		{
		    printf("\n%s %s does not have a modem %d\n",
			       BOX, name, loop);
		    continue;
		}
		printf(
		"\tcopying eeprom modem parameters to %s %s port %d\n",
		BOX, name, loop);

		copy_modem(Pannex_from, modem, Pannex_to, (u_short)loop, name);
	    }

}	/* do_copy_modemport() */


void
copy_modem(Pannex_from, modem_from, Pannex_to, modem_to, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		modem_from;
ANNEX_ID	  	*Pannex_to;
unsigned short		modem_to;
char			name[];
{
	int		parm;
	u_short cat,id,type;

	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAXVALUE+2];
		};
	struct	p_param	*pp_param;
	char	*mem_pool;
	int	i, n_param = 0;

	/* allocate memory to read the modem parameters in */
	for(parm = 0; Modemp_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read in port parameters */
	for(parm = 0; Modemp_index(parm) != -1; parm++)
	    {
	    if(!(Anyp_support(Pannex_from,parm,modemp_table)/* && 
	         Sp_support_check(Pannex_from,parm)*/))
		continue;  /* skip parms not supported on source annex */

	    cat = (u_short)Modemp_category(parm);
	    id = (u_short)Modemp_catid(parm);

	    if(cat == MODEM_CAT)

		{
		type = (u_short)Modemp_type(parm);

		if(get_modem_param(&Pannex_from->addr, (u_short)MODEM_DEV, 
			(u_short)modem_from, cat, id, type, pp_param[parm].buf))
		    {
		    printf("\tusing default for %s\n", modem_params[parm]);
		    (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
		    }

		pp_param[parm].cat = cat;
		pp_param[parm].id = id;
		pp_param[parm].type = type;
		}
	    }
	    pp_param[parm].cat = (u_short)-1; /* end of table mark */

	/* write modem port parameters */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	    {
		id = pp_param[parm].id;
		type = pp_param[parm].type;

	        if ( id == 0 ){ /* Should not allow this parameter to be copied */
		    continue;  		
	        }

		if(Anyp_support(Pannex_to,parm,modemp_table) /*&&
		   Modemp_support_check(Pannex_to,parm)*/)
		    {
		    if(set_modem_param(&Pannex_to->addr, (u_short)MODEM_DEV,
			(u_short)modem_to, cat, id, type, pp_param[parm].buf))
			   {
			    printf("\tcould not set %s\n", modem_params[parm]);
			   }
		    }
		else
		    {
		    printf("\t%s does not support %s\n",name,
						modem_params[parm]);
		    }
	    }   /* for(parm ... */

	/* return memory */
	free(mem_pool);

}	/* copy_modem() */


void do_copy_t1port(Pannex_from, engine_no, Pannex_to, t1_mask, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		engine_no;
ANNEX_ID	  	*Pannex_to;
unsigned char		*t1_mask;
char			name[];
{
    int	loop;

    /* Copy parameters to each t1 engine whose bit is set in the t1 mask. */

    if (engine_no > (u_short)Pannex_from->t1_count)
	printf("\nsource %s does not have a T1 engine %d\n", BOX, engine_no);
    else 
	for (loop = 1; loop <= ALL_T1S; loop++)
	    if (PORTBITSET(t1_mask,loop))
	    {
		if (loop > (int)Pannex_to->t1_count)
		{
		    printf("\n%s %s does not have a T1 engine %d\n",
			       BOX, name, loop);
		    continue;
		}
		printf(
		"\tcopying eeprom T1 parameters to %s %s engine %d\n",
		BOX, name, loop);

		copy_t1(Pannex_from, engine_no, Pannex_to, (u_short)loop, 
			name);
	    }

}	/* do_copy_t1port() */



void copy_t1(Pannex_from, t1_from, Pannex_to, t1_to, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		t1_from;
ANNEX_ID	  	*Pannex_to;
unsigned short		t1_to;
char			name[];
{
	int		parm;
	u_short cat,id,type;

	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAXVALUE+2];
		};
	struct	p_param	*pp_param;
	char	*mem_pool;
	int	n_param = 0;

	/* allocate memory to read the T1 parameters in */
	for(parm = 0; T1p_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read in port parameters */
	for(parm = 0; T1p_index(parm) != -1; parm++)
	    {
	    if(!(Anyp_support(Pannex_from,parm,t1p_table)/* && 
	         Sp_support_check(Pannex_from,parm)*/))
		continue;  /* skip parms not supported on source annex */

	    cat = (u_short)T1p_category(parm);
	    id = (u_short)T1p_catid(parm);

	    if(cat == T1_CAT)

		{
		type = (u_short)T1p_type(parm);

		if(get_t1_param(&Pannex_from->addr, (u_short)T1_DEV, 
			(u_short)t1_from, cat, id, type, pp_param[parm].buf))
		    {
		    printf("\tusing default for %s\n", t1_all_params[parm]);
		    (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
		    }

		pp_param[parm].cat = cat;
		pp_param[parm].id = id;
		pp_param[parm].type = type;
		}
	    }
	    pp_param[parm].cat = (u_short)-1; /* end of table mark */

	/* write t1 parameters */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	    {
		id = pp_param[parm].id;
		type = pp_param[parm].type;

	        if ( id == 0 ){ /* Should not allow this parameter to be copied */
		    continue;  		
	        }

		if(Anyp_support(Pannex_to,parm,t1p_table))
		    {
		    if(set_t1_param(&Pannex_to->addr, (u_short)T1_DEV,
			(u_short)t1_to, cat, id, type, pp_param[parm].buf))
			   {
			    printf("\tcould not set %s\n", t1_all_params[parm]);
			   }
		    }
		else
		    {
		    printf("\t%s does not support %s\n",name,
						t1_all_params[parm]);
		    }
	    }   /* for(parm ... */

	/* return memory */
	free(mem_pool);

}	/* copy_t1() */

void
do_copy_priport(Pannex_from, module_no, Pannex_to, pri_mask, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		module_no;
ANNEX_ID	  	*Pannex_to;
unsigned char		*pri_mask;
char			name[];
{
    int	loop;

/* Copy parameters to each WAN module whose bit is set in the PRI mask. */

    if (module_no > (u_short)Pannex_from->pri_count)
	printf("\nsource %s does not have a WAN module %d\n", BOX, module_no);
    else 
	for (loop = 1; loop <= ALL_PRIS; loop++)
	    if (PORTBITSET(pri_mask,loop))
	    {
		if (loop > (int)Pannex_to->pri_count)
		{
		    printf("\n%s %s does not have a WAN module %d\n",
			       BOX, name, loop);
		    continue;
		}
		printf(
		"\tcopying eeprom PRI parameters to %s %s module %d\n",
		BOX, name, loop);

		copy_pri(Pannex_from, module_no, Pannex_to, (u_short)loop, 
			name);
	    }

}	/* do_copy_priport() */


void
copy_pri(Pannex_from, pri_from, Pannex_to, pri_to, name)

ANNEX_ID	  	*Pannex_from;
unsigned short		pri_from;
ANNEX_ID	  	*Pannex_to;
unsigned short		pri_to;
char			name[];
{
	int		parm;
	u_short cat,id,type;

	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAXVALUE+2];
		};
	struct	p_param	*pp_param;
	char	*mem_pool;
	int	i, n_param = 0;

	/* allocate memory to read the PRI parameters in */
	for(parm = 0; Prip_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read in port parameters */
	for(parm = 0; Prip_index(parm) != -1; parm++)
	    {
	    if(!(Anyp_support(Pannex_from,parm,prip_table)/* && 
	         Sp_support_check(Pannex_from,parm)*/))
		continue;  /* skip parms not supported on source annex */

	    cat = (u_short)Prip_category(parm);
	    id = (u_short)Prip_catid(parm);

	    if(cat == WAN_CAT)

		{
		type = (u_short)Prip_type(parm);

		if(get_pri_param(&Pannex_from->addr, (u_short)PRI_DEV, 
			(u_short)pri_from, cat, id, type, pp_param[parm].buf))
		    {
		    printf("\tusing default for %s\n", wan_all_params[parm]);
		    (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
		    }

		pp_param[parm].cat = cat;
		pp_param[parm].id = id;
		pp_param[parm].type = type;
		}
	    }
	    pp_param[parm].cat = (u_short)-1; /* end of table mark */

	/* write PRI parameters */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	    {
		id = pp_param[parm].id;
		type = pp_param[parm].type;

	        if ( id == 0 ){ /* Should not allow this parameter to be copied */
		    continue;  		
	        }

		if(Anyp_support(Pannex_to,parm,prip_table))
		    {
		    if(set_pri_param(&Pannex_to->addr, (u_short)PRI_DEV,
			(u_short)pri_to, cat, id, type, pp_param[parm].buf))
			   {
			    printf("\tcould not set %s\n", wan_all_params[parm]);
			   }
		    }
		else
		    {
		    printf("\t%s does not support %s\n",name,
						wan_all_params[parm]);
		    }
	    }   /* for(parm ... */

	/* return memory */
	free(mem_pool);

}	/* copy_pri() */


void do_copy_annex(Pannex_id, Pannex_list)

ANNEX_ID 		*Pannex_id;
ANNEX_LIST		*Pannex_list;

{
	while(Pannex_list)
	   {
	     printf("\tcopying eeprom annex parameters to %s %s\n",
	    	    BOX, Pannex_list->name);
	     copy_annex(Pannex_id, &Pannex_list->annex_id, Pannex_list->name);
	     Pannex_list = Pannex_list->next;
	   }

} /* do_copy_annex */


void copy_annex(Pannex_from, Pannex_to, name)

ANNEX_ID	  	*Pannex_from;
ANNEX_ID	  	*Pannex_to;
char			name[];
{
	int		parm;

	u_short cat,id,type;
	struct	p_param	{
		u_short	cat;
		u_short	id;
		u_short	type;
		char	buf[MAX_STRING_128 + 4];
		};
	struct	p_param	*pp_param;
	char	*mem_pool;
	int	n_param = 0;

	/* allocate memory to read the port parameters in */
	for(parm = 0; Ap_index(parm) != -1; parm++) n_param++;
	mem_pool = (char *) malloc((n_param + 1) * sizeof(struct p_param));
	if (!mem_pool) {
		printf("\tcopy annex: could not allocate memory.\n");
		return;
		}
	bzero(mem_pool, (n_param + 1) * sizeof(struct p_param));
	pp_param = (struct p_param *)mem_pool;

	/* read in annex parameters */
	for (parm = 1; Ap_index(parm) != -1; parm++)	/* Skip zero (INET) */
	{

	  /* do not copy password, acp_key, option_key or lat_key */
	  if ( (Ap_category(parm) != DFE_CAT ||
	        (Ap_catid(parm) != DFE_PASSWORD &&
	         Ap_catid(parm) != DFE_ACP_KEY &&
	         Ap_catid(parm) != DFE_OPTION_KEY &&
		 Ap_catid(parm) != LAT_KEY_VALUE)) &&
		 (Ap_category(parm) == DLA_CAT || Ap_category(parm) == DFE_CAT
		        || Ap_category(parm) == ARAP_CAT
			|| Ap_category(parm) == RIP_CAT
			|| Ap_category(parm) == LAT_CAT) &&
		 Anyp_support(Pannex_from,parm,annexp_table))
	    {

	    if(get_dla_param(&Pannex_from->addr, (u_short)Ap_category(parm),
		    (u_short)Ap_catid(parm), (u_short)Ap_type(parm),
			 pp_param[parm].buf))
	      {
	      printf("\tusing default for %s\n", annex_params[parm]);
	      (void)strncpy(pp_param[parm].buf, defalt, sizeof defalt);
	      }

	     pp_param[parm].cat = Ap_category(parm);
	     pp_param[parm].id = Ap_catid(parm);
	     pp_param[parm].type = Ap_type(parm);
	    }
	}
	pp_param[parm].cat = (u_short)-1; /* end of table mark */

	/* write annex parameters out */
	for(parm = 0; pp_param[parm].cat != (u_short)-1; parm++)
	{
	    if ((cat = pp_param[parm].cat) == 0)
		continue;
	    id = pp_param[parm].id;
	    type = pp_param[parm].type;

	    if(Anyp_support(Pannex_to,parm,annexp_table))
	      {
	      if ((type == STRING_P_128)
	     		 && (Pannex_to->hw_id != ANX3)
			 && (Pannex_to->hw_id != ANX_MICRO))
		  {
		  /* use type STRING_P when writing to old annexes */
	          if(set_dla_param(&Pannex_to->addr, (u_short)cat,
                    (u_short)id, (u_short)STRING_P, pp_param[parm].buf))
	 	  printf("\tcould not set param %s\n", annex_params[parm]);
		  }
	       else
		  {
	          if ( ((id == LAT_GROUP_CODE) ||
			(id == LAT_VCLI_GROUPS)) &&
	     			 (cat == LAT_CAT)) {

		      /* disable all group codes first, then copy them in */
	              if (set_dla_param(&Pannex_to->addr,
		                (u_short)cat,
			        (u_short)id,(u_short)type,
				(char *)disable_groups)) {
	 	          printf("\tcould not set param %s\n",
			        annex_params[parm]);
			  continue;
		      }

		      /* now enable according to src annex */
		      pp_param[parm].buf[LAT_GROUP_SZ] = 1;
	          }
	          if(set_dla_param(&Pannex_to->addr, (u_short)cat,
                    (u_short)id, (u_short)type, pp_param[parm].buf))
	 	  printf("\tcould not set param %s\n", annex_params[parm]);
		  }
	      }
	    else
	      printf("%s does not support parameter: %s\n\n",name,
			    annex_params[parm]);

	}
	/* return memory */
	free(mem_pool);

}	/* copy_annex() */


void do_read(filename)

	char filename[];

{
	FILE *save_cmd_file;
	int   save_script_input;

	save_cmd_file = cmd_file;
	save_script_input = script_input;

	if ((cmd_file = fopen(filename, "r")) == NULL)
	    {
	    cmd_file = save_cmd_file;
	    punt("couldn't open ", filename);
	    }

	script_input = TRUE;

	cmd_sub();
	fclose(cmd_file);
	script_input = save_script_input;
	cmd_file = save_cmd_file;

}	/* do_read() */



void do_reset_printer(Pprinter_set)

	PRINTER_SET *Pprinter_set;

{
	ANNEX_LIST *Ptemp_annex_list;

	/* Reset each printer in the printer set. */

	while (Pprinter_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */
	    if (Pprinter_set->annex_id.addr.sin_addr.s_addr)
		reset_printer_sub(&Pprinter_set->annex_id, Pprinter_set->name,
		 &Pprinter_set->printers);
	    else
		if (Pdef_annex_list)
		    for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		     Ptemp_annex_list = Ptemp_annex_list->next)
			reset_printer_sub(&Ptemp_annex_list->annex_id,
			 Ptemp_annex_list->name, &Pprinter_set->printers);
		else
		    punt(NO_BOXES, (char *)NULL);

	    Pprinter_set = Pprinter_set->next;
	    }

}	/* do_reset_printer() */


void do_reset_port(Pport_set)

	PORT_SET *Pport_set;

{
	ANNEX_LIST *Ptemp_annex_list;

	/* Reset each port in the port set. */

	while (Pport_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */
	    if (Pport_set->annex_id.addr.sin_addr.s_addr)
		reset_sub(&Pport_set->annex_id, Pport_set->name,
		 &Pport_set->ports);
	    else
		if (Pdef_annex_list)
		    for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		     Ptemp_annex_list = Ptemp_annex_list->next)
			reset_sub(&Ptemp_annex_list->annex_id,
			 Ptemp_annex_list->name, &Pport_set->ports);
		else
		    punt(NO_BOXES, (char *)NULL);

	    Pport_set = Pport_set->next;
	    }

}	/* do_reset_port() */



void do_reset_interface(Pinterface_set)

	INTERFACE_SET *Pinterface_set;

{
	ANNEX_LIST *Ptemp_annex_list;

	/* Reset each interface in the interface set. */

	while (Pinterface_set)
	    {
	    /* If an annex id was specified, use it; otherwise, use the
	       default annex list. */
	    if (Pinterface_set->annex_id.addr.sin_addr.s_addr)
		reset_interface_sub(&Pinterface_set->annex_id, Pinterface_set->name, &Pinterface_set->interfaces);
	    else
		if (Pdef_annex_list)
		    for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
		     Ptemp_annex_list = Ptemp_annex_list->next)
			reset_interface_sub(&Ptemp_annex_list->annex_id,
			 Ptemp_annex_list->name, &Pinterface_set->interfaces);
		else
		    punt(NO_BOXES, (char *)NULL);

	    Pinterface_set = Pinterface_set->next;
	    }

}	/* do_reset_interface() */


void do_reset_t1(Pt1_set)
     T1_SET *Pt1_set;
{
  ANNEX_LIST *Ptemp_annex_list;


  t1_reset_decode( Pspec_t1_set );

  /* Reset each T1 in the T1 set. */
  
  while (Pt1_set) {

    /* If an annex id was specified, use it; otherwise, use the
       default annex list. */

    if (Pt1_set->annex_id.addr.sin_addr.s_addr) {
      reset_t1_sub(&Pt1_set->annex_id, Pt1_set->name, &Pt1_set->t1s);
    } else {
      if (Pdef_annex_list) {
        for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
            Ptemp_annex_list = Ptemp_annex_list->next) {
          reset_t1_sub(&Ptemp_annex_list->annex_id,
                       Ptemp_annex_list->name, &Pt1_set->t1s);
        }
      } else {
        punt(NO_BOXES, (char *)NULL);
      }
    }    
    Pt1_set = Pt1_set->next;
  }
} /* do_reset_t1() */

void
do_reset_pri(Ppri_set)
     PRI_SET *Ppri_set;
{
  ANNEX_LIST *Ptemp_annex_list;


  pri_reset_decode( Pspec_pri_set );

  /* Reset each PRI module in the PRI set. */
  
  while (Ppri_set) {

    /* If an annex id was specified, use it; otherwise, use the
       default annex list. */

    if (Ppri_set->annex_id.addr.sin_addr.s_addr) {
      reset_pri_sub(&Ppri_set->annex_id, Ppri_set->name, &Ppri_set->pris);
    } else {
      if (Pdef_annex_list) {
        for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
            Ptemp_annex_list = Ptemp_annex_list->next) {
          reset_pri_sub(&Ptemp_annex_list->annex_id,
                       Ptemp_annex_list->name, &Ppri_set->pris);
        }
      } else {
        punt(NO_BOXES, (char *)NULL);
      }
    }    
    Ppri_set = Ppri_set->next;
  }
} /* do_reset_pri() */

void do_reset_intmod(Pintmod_set)
     INTMOD_SET *Pintmod_set;
{
  ANNEX_LIST *Ptemp_annex_list;
  int reset_type;
  INTMOD_SET *Pset;

  if (!eos) {
    reset_type = is_in_list(symbol,reset_modem_params);
    if (reset_type == 0)
      punt("invalid int_modem reset type: ",symbol);
    (void)lex();
  } else
    reset_type = RESET_INTMODEM_HARD;

  for (Pset = Pintmod_set; Pset != NULL; Pset = Pset->next)
    Pset->intmods.reset_type = reset_type;

  /* Reset each internal modem in the internal modem set. */

  while (Pintmod_set) {

    /* If an annex id was specified, use it; otherwise, use the
       default annex list. */

    if (Pintmod_set->annex_id.addr.sin_addr.s_addr) {
      reset_intmod_sub(&Pintmod_set->annex_id, Pintmod_set->name, 
                       &Pintmod_set->intmods);
    } else {
      if (Pdef_annex_list) {
        for(Ptemp_annex_list = Pdef_annex_list; Ptemp_annex_list;
            Ptemp_annex_list = Ptemp_annex_list->next) {
          reset_intmod_sub(&Ptemp_annex_list->annex_id,
                           Ptemp_annex_list->name, &Pintmod_set->intmods);
        }
      } else {
        punt(NO_BOXES, (char *)NULL);
      }
    }
    Pintmod_set = Pintmod_set->next;
  }
} /* do_reset_intmod() */



void do_reset_box(Pannex_list)
ANNEX_LIST *Pannex_list;
{
    int	param;
    ANNEX_LIST *Ptemp_annex_list;
    u_short range_included;

	/* if no parameters, assume all subsystems reset */

    if (eos) {
	(void)strcpy(command_line, "all");
	Psymbol = command_line;
	eos = FALSE;
	(void)lex();
    }

	/* for each keyword in the reset annex list, for each annex */

    while (!eos) {
	param = match(symbol, reset_params, "reset parameter");
	(void)lex();
	Ptemp_annex_list = Pannex_list;

	/* Clear the dialout route bitmap. */
	bzero(dorset, ((ALL_DORS + (NBBY - 1)) /NBBY));

	switch (param)
	{
	case RESET_ANNEX_DIALOUT_TAB:
	  /* Need to check for a optional numeric range here. */
	  dor_list(dorset, &range_included);
	  break;

	default:
	  break;
	}

	for (;Ptemp_annex_list;Ptemp_annex_list=Ptemp_annex_list->next){
	    switch (param) {
	    case RESET_ANNEX_NAMESERVER:
		if (Ptemp_annex_list->annex_id.version < VERS_5) {
		    printf(
		"%s %s does not support resetting name servers\n",
			BOX, Ptemp_annex_list->name);
		    continue;
		}
		break;
	    case RESET_ANNEX_MACRO:
		if (Ptemp_annex_list->annex_id.version < VERS_5) {
		    printf("%s %s does not support macros\n",
			BOX, Ptemp_annex_list->name);
		    continue;
		}
		break;
	    case RESET_ANNEX_LAT:
		if (!Ptemp_annex_list->annex_id.lat) {
		    printf("%s %s does not support lat\n",
			BOX, Ptemp_annex_list->name);
		    continue;
		}
		break;
	    case RESET_ANNEX_MOTD:
		if (Ptemp_annex_list->annex_id.hw_id == ANX_MICRO_ELS) {
		    printf("%s %s does not support motd\n",
			BOX, Ptemp_annex_list->name);
		    continue;
		}
		break;
	    case RESET_ANNEX_SESSION:
		if (Ptemp_annex_list->annex_id.hw_id != ANX_PRIMATE) {
		  printf("%s %s does not support session blocks\n",
			 BOX, Ptemp_annex_list->name);
		  continue;
		}
		break;
	    }
	    printf("resetting %s on %s %s\n",reset_params[param],
		BOX, Ptemp_annex_list->name);
	    reset_annex(&Ptemp_annex_list->annex_id.addr,
		(u_short)param, (u_short)range_included, (u_char *)&dorset[0]);
	}
    }
}	/* do_reset_box() */



void reset_sub(Pannex_id, name, Pports)

	ANNEX_ID	   *Pannex_id;
	char               name[];
	PORT_GROUP	   *Pports;

{
	int error_code,
	    loop;

	/* If all ports are to be reset, call reset_all().  Otherwise,
	   call reset() for each port whose bit is set in the port mask. */
	if (Pports->pg_bits & (PG_ALL | PG_SERIAL))
	    {
	    printf("resetting all serial ports of %s %s\n", BOX, name);
	    if ((error_code = reset_all(&Pannex_id->addr)) != NAE_SUCC)
	        netadm_error(error_code);
	    }
	else
	    for (loop = 1; loop <= ALL_PORTS; loop++)
		if (PORTBITSET(Pports->serial_ports,loop))
		    {
			if (loop > (int)Pannex_id->port_count)
			{
			printf("\n%s %s does not have a port %d\n",
				       BOX, name, loop);
			    continue;
			}

	            printf("resetting serial port %d of %s %s\n",
		     loop, BOX, name);
		    if ((error_code = reset_line(&Pannex_id->addr,
			(u_short)SERIAL_DEV, (u_short)loop)) != NAE_SUCC)
	                netadm_error(error_code);
		    }

	/* Reset the virtual CLI ports if requested. */

	if (Pports->pg_bits & (PG_VIRTUAL | PG_ALL))
	    {
	     if ((Pannex_id->version < VERS_4) && (Pannex_id->hw_id != X25))
		{
		if (Pports->pg_bits & PG_VIRTUAL)
		    printf("%s '%s' does not support virtual ports\n",
			   BOX, name);
		return;
		}

	    printf("resetting virtual CLI ports of %s %s\n", BOX, name);
	    if ((error_code = reset_line(&Pannex_id->addr,
		 (u_short)PSEUDO_DEV, (u_short)0)) != NAE_SUCC)
	        netadm_error(error_code);
	    }

}	/* reset_sub() */



void reset_printer_sub(Pannex_id, name, Pprinters)

	ANNEX_ID	   *Pannex_id;
	char               name[];
	PRINTER_GROUP	   *Pprinters;

{
	int error_code,
	    loop;
	u_short number_reset = 0;

	for (loop = 1; loop <= ALL_PRINTERS; loop++) {
	    if (PRINTERBITSET(Pprinters->ports,loop)) {
		if (loop > (int)Pannex_id->printer_count) {
			    continue;
		}

	        printf("resetting printer %d of %s %s\n",
		     loop, BOX, name);
		number_reset++;
		if ((error_code = reset_line(&Pannex_id->addr,
			(u_short)P_PRINT_DEV, (u_short)loop)) != NAE_SUCC)
	                netadm_error(error_code);
	    }

	}
	if (number_reset == 0)
		printf("no printers were reset\n");

}	/* reset_printer_sub() */



void reset_interface_sub(Pannex_id, name, Pinterfaces)

	ANNEX_ID	   *Pannex_id;
	char               name[];
	INTERFACE_GROUP	   *Pinterfaces;

{
	int error_code,
	    if_num,
	    loop;
	u_short number_reset = 0;

	for (loop = 1; loop <= ALL_INTERFACES; loop++) {
	    if (INTERFACEBITSET(Pinterfaces->interface_ports,loop)) {

	    	if_num = loop;

		/*
		 * Not allow ethernet interface to reset for now
		 */
		if (if_num == M_ETHERNET) {
			printf("\n%s %s ethernet interface not allowed to be reset\n",
				       BOX, name);
			    continue;
		}

	    	/*
	     	 * Minus ethernet number.
	     	 */

	    	if_num = if_num - M_ETHERNET;


		if (if_num > (int)Pannex_id->port_count) {
			    continue;
		}

	        printf("resetting interface asy%d of %s %s\n",
		     if_num, BOX, name);
		/*
		 * Reseting the asy interface is identical to
		 * reset the serial port.
		 */
		number_reset++;
		if ((error_code = reset_line(&Pannex_id->addr,
			(u_short)SERIAL_DEV, (u_short)if_num)) != NAE_SUCC)
	                netadm_error(error_code);
	    }

	}
	if (number_reset == 0)
		printf("no interfaces were reset\n");

}	/* reset_interface_sub() */


void reset_t1_sub(Pannex_id, name, Pt1s)
     ANNEX_ID      *Pannex_id;
     char          name[];
     T1_GROUP      *Pt1s;
{
  int error_code, loop;
  u_short number_reset = 0;

  for (loop = 1; loop <= ALL_T1S; loop++) {
    if (PORTBITSET(Pt1s->engines,loop)) {
      
      printf("resetting t1 engine %d of %s %s\n",
             loop, BOX, name);
      number_reset++;
      if ((error_code = reset_t1(&Pannex_id->addr,
                       (u_short)loop, (u_short)Pt1s->reset_type)) != NAE_SUCC)
          netadm_error(error_code);
    }
  }
  if (number_reset == 0)
    printf("no t1 engines were reset\n");
  
} /* reset_t1_sub() */

void
reset_pri_sub(Pannex_id, name, Ppris)
     ANNEX_ID      *Pannex_id;
     char          name[];
     PRI_GROUP      *Ppris;
{
  int error_code, loop;
  u_short number_reset = 0;

  for (loop = 1; loop <= ALL_PRIS; loop++) {
    if (PORTBITSET(Ppris->modules,loop)) {
      
      printf("resetting WAN module %d on %s %s\n",
             loop, BOX, name);
      number_reset++;
      if ((error_code = reset_pri(&Pannex_id->addr,
                       (u_short)loop, (u_short)Ppris->reset_type)) != NAE_SUCC)
          netadm_error(error_code);
    }
  }
  if (number_reset == 0)
    printf("no WAN modules were reset\n");
  
} /* reset_pri_sub() */

void reset_intmod_sub(Pannex_id, name, Pintmods)
     ANNEX_ID      *Pannex_id;
     char          name[];
     INTMOD_GROUP  *Pintmods;
{
  int error_code, loop;
  u_short number_reset = 0;

  if (Pannex_id->port_count == 0 || Pannex_id->hw_id != ANX_PRIMATE) {
        printf("\n%s %s has no internal modems\n", BOX, name);
        return;
  }

  for (loop = 1; loop <= Pannex_id->port_count; loop++) {
    if (PORTBITSET(Pintmods->intmods,loop)) {
      
      printf("resetting internal modem %d of %s %s\n",
             loop, BOX, name);
      number_reset++;
      if ((error_code = reset_intmod(&Pannex_id->addr,
		     (u_short)Pintmods->reset_type, (u_short)loop)) != NAE_SUCC)
          netadm_error(error_code);
    }
  }
  if (number_reset == 0)
    printf("no internal modems were reset\n");
  
} /* reset_intmod_sub() */


void do_write(filename, Pannex_id, name)
char                *filename,
		    name[];
ANNEX_ID	   *Pannex_id;
{
    int		loop, asy_end, ispri;
    FILE        *fdesc;

#ifdef CHANGE_DIR
    if (index(filename,'/') || !strcmp(filename,".") || !strcmp(filename,".."))
	punt("illegal file name:  ",filename);
#endif
    /* Open the file. */

    if ((fdesc = fopen(filename, "w")) == NULL)
	punt("couldn't open ", filename);

    ispri = Pannex_id->hw_id == ANX_PRIMATE;

    /* Write an annex configuration file. */
    printf("\twriting...\n");

    /* Write the file. */
    fprintf(fdesc, "# %s %s\n", BOX, name);

    fprintf(fdesc, "\necho setting %s parameters\n", BOX);
    write_annex_script(fdesc, Pannex_id);

    for (loop = 1; loop <= Pannex_id->printer_count; loop++) {
	fprintf(fdesc,"\necho setting parameters for printer %d\n", loop);
	write_printer_script(fdesc, Pannex_id, loop);
    }

    if (ispri) {
      fprintf(fdesc, "\necho setting parameters for all ports\n");
      write_port_script(fdesc, Pannex_id, 1);
    } else
      for (loop = 1; loop <= Pannex_id->port_count; loop++) {
	fprintf(fdesc, "\necho setting parameters for async port %d\n", loop);
	write_port_script(fdesc, Pannex_id, loop);
      }

    for (loop = 1; loop <= Pannex_id->t1_count; loop++) {
      fprintf(fdesc, "\necho setting parameters for t1 engine %d\n", loop);
      write_t1_script(fdesc, Pannex_id, loop);
    }

    for (loop = 1; loop <= Pannex_id->pri_count; loop++) {
      fprintf(fdesc,"\necho setting parameters for WAN module %d\n",loop);
      write_pri_script(fdesc,Pannex_id,loop);
    }

    if (ispri) {
      for (loop = 1; loop <= Pannex_id->port_count; loop++) {
	fprintf(fdesc, "\necho setting parameters for modem %d\n", loop);
	write_modem_script(fdesc, Pannex_id, loop);
      }
      fprintf(fdesc,"\necho setting parameters for interface en0\n");
      write_interface_script(fdesc, Pannex_id, 1);
      fprintf(fdesc,"\necho setting parameters for interface port\n");
      write_interface_script(fdesc, Pannex_id, 2);
    } else {

/*
 * example for micro-annex M_SLUS = 16
 *		calling SETINTERFACEBIT(xxx, 1)  sets en0
 *		calling SETINTERFACEBIT(xxx, 2)  sets asy1
 *		calling SETINTERFACEBIT(xxx, 18) sets syn1
 */
      asy_end = (int)Pannex_id->port_count + 1;
      for (loop = 1; loop <= ALL_INTERFACES; loop++) {

	if (loop <= asy_end || loop > ALL_PORTS+1) {

	  if (loop == M_ETHERNET)
	    fprintf(fdesc,"\necho setting parameters for interface en%d\n",
		    loop-M_ETHERNET);
	  else if (loop <= (M_ETHERNET + ALL_PORTS))
	    fprintf(fdesc, "\necho setting parameters for interface asy%d\n",
		    loop-M_ETHERNET);
	  else
	    fprintf(fdesc, "\necho setting parameters for interface syn%d\n",
		    loop-M_ETHERNET-ALL_PORTS);

	  write_interface_script(fdesc, Pannex_id, loop);
	}
      }
    }

        if (chmod(filename, OWNER_RW))
           (void)unlink(filename);

	(void)fclose(fdesc);

}	/* do_write() */



void write_annex_script(file, Pannex_id)
FILE			*file;
ANNEX_ID	  	*Pannex_id;
{
    int		xx;
    static char	format[] = "%sset %s %s %s\n";
    long	align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	*internal = (char *)align_internal;
    char	external[LINE_LENGTH + 4];
    char	*start_delim;
    char   	*comment;
    
    for (xx = 1; Ap_index(xx) != -1; xx++) {	/* Skip zero (INET) */

	/*
	 * write out passwords and keys as comments:
	 *
	 * keys:
	 * option_key			DFE_CAT		DFE_OPTION_KEY
	 * lat_key			DFE_CAT		LAT_KEY_VALUE
	 *
	 * passwords:
	 * vcli_password		DFE_CAT		DFE_VCLI_PASSWD
	 * acp_key			DFE_CAT		DFE_ACP_KEY
	 * password			DFE_CAT		DFE_PASSWORD
	 * mop_password			DFE_CAT		DFE_MOP_PASSWD
	 * login_password		DFE_CAT		DFE_LOGIN_PASSWD
	 * rip_auth			RIP_CAT		RIP_RIP_AUTH
	 * ipx_dump_password		DLA_CAT		DLA_IPX_DMP_PASSWD
	 * radius_auth1_secret		DFE_CAT		DFE_RADIUS_SECRET
	 * radius_auth2_secret		DFE_CAT		DFE_RADIUS_AUTH2_SECRET
	 * radius_acct1_secret		DFE_CAT		DFE_RADIUS_ACCT1_SECRET
	 * radius_acct2_secret		DFE_CAT		DFE_RADIUS_ACCT2_SECRET
	 */
	comment = "";

	if (Ap_category(xx) == DFE_CAT) {
	    switch (Ap_catid(xx)) {
		case DFE_OPTION_KEY:
		case LAT_KEY_VALUE:
		case DFE_VCLI_PASSWD:
		case DFE_ACP_KEY:
		case DFE_PASSWORD:
		case DFE_MOP_PASSWD:
		case DFE_LOGIN_PASSWD:
		case DFE_RADIUS_SECRET:
		case DFE_RADIUS_AUTH2_SECRET:
		case DFE_RADIUS_ACCT1_SECRET:
		case DFE_RADIUS_ACCT2_SECRET:
		    comment = "# ";
		    break;
		default:
		    break;
	    }
	}
	else
	    if ((Ap_category(xx) == RIP_CAT && Ap_catid(xx) == RIP_RIP_AUTH) ||
		(Ap_category(xx) == DLA_CAT &&
		 Ap_catid(xx) == DLA_IPX_DMP_PASSWD))
		comment = "# ";

	if ((!Anyp_support(Pannex_id, xx,annexp_table)) || (Ap_category(xx) == VOID_CAT))
	    continue;

	if (!get_dla_param(&Pannex_id->addr, (u_short)Ap_category(xx),
			   (u_short)Ap_catid(xx), (u_short)Ap_type(xx),
			   internal)) {

	    decode(Ap_convert(xx), internal, external, Pannex_id);
	    if (Ap_convert(xx) == CNV_GROUP_CODE) {
		if (strcmp(external, NONE_STR) != 0) {
		  if (strcmp(external,ALL_STR) != 0)
		    fprintf(file, format, comment, BOX, annex_params[xx],
			    "all disable");
		  strcat(external, " enable");
		}
		else 
		    strcpy(external, "all disable");
	    }
	    if (start_delim = split_string(annex_params[xx],FALSE))
		fprintf(file, format, comment, BOX, start_delim, external);
	    else
		fprintf(file, format, comment, BOX, annex_params[xx],external);
	}
	else
	    printf("\tUnable to get %s parameter\n", annex_params[xx]);
    }
}	/* write_annex_script() */


void write_printer_script(file, Pannex_id, printer)
FILE			*file;
ANNEX_ID	  	*Pannex_id;
int			printer;
{
    int		xx;
    static char	format[] = "%sset printer=%d %s %s\n";
    long	align_internal[MAXVALUE/sizeof(long) + 1];
    char	*internal = (char *)align_internal;
    char	external[MAXVALUE];
    char	*start_delim;
    char   	*comment = "";
    
    for(xx = 0; Cp_index(xx) != -1; xx++) {
	
	if(Cp_category(xx) == LP_CAT && Anyp_support(Pannex_id,xx,printp_table)) {

	    if(!get_ln_param(&Pannex_id->addr, (u_short)P_PRINT_DEV,
			     (u_short)printer, (u_short)LP_CAT,
			     (u_short)Cp_catid(xx),
			     (u_short)Cp_type(xx), internal)) {
		decode(Cp_convert(xx), internal, external, Pannex_id);
		if (start_delim = split_string(printer_params[xx],FALSE))
		    fprintf(file, format, comment, printer, start_delim, 
			    external);
		else
		    fprintf(file, format, comment, printer, printer_params[xx],
			    external);
	    }
	    else
		printf("\tUnable to get %s parameter\n", printer_params[xx]);
	}
    }
}	/* write_printer_script() */


void write_port_script(file, Pannex_id, port)
FILE			*file;
ANNEX_ID	  	*Pannex_id;
int			port;
{
    int 	retries = 0;
    int		xx;
    int		x;
    static char	format[] = "%sset port=%d";
    static char priformat[] = "%sset port";
    static char format2[] = " %s %s\n";
    long	align_internal[MAXVALUE/sizeof(long) + 1];
    char	*internal = (char *)align_internal;
    char	external[MAXVALUE];
    short	id, category, convert, type;
    char	latter = FALSE;
    char	*start_delim;
    char	*comment;
    int		ispri;
    int		error;

    ispri = Pannex_id->hw_id == ANX_PRIMATE;
    xx = 0;
    while(Sp_index(xx) != -1) {

	comment = "";
	category = Sp_category(xx);
	id = Sp_catid(xx);

	/*
	 * write out passwords as comments:
	 *
	 * passwords:
	 * port_password		DEV2_CAT	DEV2_PORT_PASSWD
	 * ppp_password_remote		NET_CAT		PPP_PWORDRMT
	 */
	if ((category == DEV2_CAT && id == DEV2_PORT_PASSWD) ||
	    (category == NET_CAT && id == PPP_PWORDRMT))
	    comment = "# ";

	if ((!Anyp_support(Pannex_id, xx,portp_table)) || (category == VOID_CAT)) {
	    xx++;	/* Skip this param */
	    continue;
	}

	type = (u_short)Sp_type(xx);
	convert = (u_short) Sp_convert(xx);
	if (category == DEV_CAT && id == DEV_ATTN) {
	    if((Pannex_id->version < VERS_6_2) || (Pannex_id->hw_id < ANX3)) {
		convert = CNV_PRINT;
		type = CARDINAL_P;
		latter = TRUE;
	    }
	}
	if (category == DEV_CAT && id == DEV_BANNER) {
	    if((Pannex_id->version < VERS_14_0)) {
		convert = CNV_DFT_Y;
		type = BOOLEAN_P;
	    }
	}
	error = get_ln_param(&Pannex_id->addr, (u_short)SERIAL_DEV, (u_short)port,
			category, id, (u_short)type, internal);

	/* If we are talking with an annex that uses 16 character username */
	/* fields, then we want to get the username as a 16 character string */
	if (error && ((id == DEV_NAME) || (id == PPP_UNAMERMT))) {
	    if (id == DEV_NAME)
		id = DEV_NAME_OLD;
	    else
		id = PPP_UNAMERMT_OLD;
	    convert = CNV_STRING;
	    type = STRING_P;
	    error = get_ln_param(&Pannex_id->addr, (u_short)SERIAL_DEV, (u_short)port,
			category, id, (u_short)type, internal);
	}

	if ((error == NAE_TIME) && (retries++ < MAX_RETRIES)) {
		if(debug) {
			fprintf(stderr, "\tport %d:\n", port);
			fprintf(stderr, 
				"Timeout accessing parameter %s, retrying.\n",
				port_params[xx]);
		}
		continue;
	} else if(!error)
		retries = 0;
 
	if (error) {
	    printf("\tport %d:\n", port);
	    printf("\tUnable to get %s parameter, error %d\n", 
			port_params[xx], error);
	    netadm_error("na", error);
	}
	else {
	    decode(convert, internal, external, Pannex_id);
	    if (ispri)
	      fprintf(file,priformat,comment);
	    else
	      fprintf(file,format,comment,port);
	    if (convert == CNV_GROUP_CODE) {
		if (strcmp(external, NONE_STR) != 0) {
		  if (strcmp(external,ALL_STR) != 0)
		    fprintf(file, format2, port_params[xx], "all disable");
		  strcat(external, " enable");
		} else 
		    strcpy(external, "all disable");
	    }
	    if ((start_delim = split_string(port_params[xx], latter))!= NULL)
		fprintf(file, format2, start_delim, external);
	    else
		fprintf(file,format2, port_params[xx], external);
	}

	/* Increment to next param.
	 * We do this here so that we can restart on the same
	 * param if necessary.
	 */
	xx++;
    }
}	/* write_port_script() */

void
write_modem_script(file, Pannex_id, modem)
FILE			*file;
ANNEX_ID	  	*Pannex_id;
int			modem;
{
    int		xx;
    static	char	format[] = "set modem=%d %s %s\n";
    long		align_internal[MAXVALUE/sizeof(long) + 1];
    char		*internal = (char *)align_internal;
    char		external[MAXVALUE];
    u_short id,category,convert,type;
    char		latter = FALSE;
    char *start_delim;

    for(xx = 0; Modemp_index(xx) != -1; xx++) {
	category = Modemp_category(xx);
	id = Modemp_catid(xx);
	
	if (Anyp_support(Pannex_id,xx,modemp_table)) {
		type = (u_short)Modemp_type(xx);
		convert = (u_short) Modemp_convert(xx);
		if (get_modem_param(&Pannex_id->addr, (u_short)MODEM_DEV, 
				    (u_short)modem, category,
				id, (u_short)type, internal))
			printf("\tUnable to get modem %d %s parameter\n",
			       modem,modem_params[xx]);
		else
		    {
			decode(convert,internal,external,Pannex_id);
			if (start_delim=split_string(modem_params[xx],latter))
			    fprintf(file, format, modem, start_delim,
				    external);
			else
			    fprintf(file, format, modem, modem_params[xx],
				    external);
		    }
	    }
    }
    
}	/* write_modem_script() */

void
get_if_name(ifname,interface_idx,ispri)
char *ifname;
int interface_idx,ispri;
{
  if (ispri)
    strcpy(ifname,interface_idx == 1 ? "en0" : "port");
  else if (interface_idx == M_ETHERNET)
    sprintf(ifname,"en%d",interface_idx-M_ETHERNET);
  else if (interface_idx <= M_ETHERNET + ALL_PORTS)
    sprintf(ifname,"asy%d",interface_idx-M_ETHERNET);
  else
    sprintf(ifname,"syn%d",interface_idx-M_ETHERNET-ALL_PORTS);
}

void write_interface_script(file, Pannex_id, Interface)
FILE			*file;
ANNEX_ID	  	*Pannex_id;
int			Interface;
{
    int		xx;
    char	ifname[32];
    long	align_internal[MAXVALUE/sizeof(long) + 1];
    char	*internal = (char *)align_internal;
    char	external[MAXVALUE];
    char	*start_delim;
    char	*comment = "";
    int		ispri;
    
    ispri = Pannex_id->hw_id == ANX_PRIMATE;
    for(xx = 0; Ip_index(xx) != -1; xx++) {
	
	if(Ip_category(xx) == IF_CAT && Anyp_support(Pannex_id,xx,interfacep_table)) {

	    if(!get_if_param(&Pannex_id->addr, (u_short)INTERFACE_DEV,
			     (u_short)Interface, (u_short)IF_CAT,
			     (u_short)Ip_catid(xx), (u_short)Ip_type(xx),
			     internal)) {
	        decode(Ip_convert(xx), internal, external, Pannex_id);
		get_if_name(ifname,Interface,ispri);
		
		start_delim = split_string(interface_params[xx],FALSE);
		if (start_delim == NULL)
		  start_delim = interface_params[xx];

		fprintf(file,"%sset interface=%s %s %s\n",comment,ifname,
			start_delim, external);
	    } else
	      printf("\tUnable to get interface %s parameter\n",
		     interface_params[xx]);
	}
    }
}	/* write_interface_script() */

void write_t1_script(file, Pannex_id, engine)

FILE			*file;
ANNEX_ID	  	*Pannex_id;
int			engine;
{
    int		xx,                      /* T1 PARAMETER COUNTER */ 
                chan;                    /* REF: NEW external CONSTRUCTION */
    static	char	format[ 40 ];
    long	align_internal[MAXVALUE/sizeof(long) + 1];
    char       *internal = (char *)align_internal;
    char        external[ MAXVALUE ],
                tbuf[ 3 ];
    u_short     id,
                category,
                convert,
                type;
    char	latter = FALSE;
    char       *start_delim;
    char       *comment = "";

    /* FOR EACH T1 PARAMETER */
    for(xx = 0; T1p_index(xx) != -1; xx++) 
    {
	category = T1p_category(xx);
	id = T1p_catid(xx);
	
	if( Anyp_support( Pannex_id, xx, t1p_table ) )
	{
	    type = (u_short)T1p_type(xx);
	    convert = (u_short) T1p_convert(xx);

	    /* USE RPC TO OBTAIN T1 PARAMETER, (RETURNED IN internal) */
	    if( get_t1_param( &Pannex_id->addr, 
			      (u_short)T1_DEV, 
			      (u_short)engine, 
			      category,
			      id, 
			      (u_short)type, 
			      internal) )
	    {
	        printf("\tt1 engine %d:\n", engine);
		printf( "\tUnable to get %s parameter\n", 
			t1_all_params[xx]);
	    }
	    else
	    {
	        /* DISTINGUISH PARAMETERS THAT HANDLE PER DS0 SETTINGS */
	        switch( xx )
		{
		    case T1_DS0_MAP:
		    case T1_DS0_SIGPROTO:
		    case T1_DS0_RING:
			{
			char *ext_ptr = external;
			char *ds0_ptr, *ds0arg_ptr;

		        /* ADJUST FILE OUTPUT FORMAT FOR DS0 SYNTAX */
			strcpy( format, "%sset t1=%d %s %s %s\n" );

		        for( chan = 0; chan < ALL_DS0S; chan++ )
		            {  
 			    /* ds0 CHANNELS ARE STORED IN 1-BASED ARRAY */
			    /* SO MAKE ADJUSTMENTS BEFORE PASSING TO decode() */
			    tbuf[ 0 ] = ( chan + 1 );
			    tbuf[ 1 ] = internal[ 2*chan ];
			    tbuf[ 2 ] = internal[ 2*chan + 1 ];
			  
			    /* EXT. REPRESENTATION OF DATA RETURNED IN */
			    /* 'external' ARG  */
			    decode( convert, 
				    tbuf, 
				    external, 
				    Pannex_id );

			    /* CONVERT... */
			    /* external = "<param> ds0=xx <arg_1> <arg_2>" */
			    /* TO... */
			    /* external = "ds0=xx <param> <arg_1> <arg_2>" */
			    /* delete CR at the end */
			    external[ strlen( external ) - 1 ] =
					external[ strlen( external ) ];

			    /* delete leading spaces */
			    while(*ext_ptr == ' ')
				ext_ptr++;

			    /* get ds0 number */
			    ds0_ptr = ext_ptr;
			    ds0arg_ptr = index(ext_ptr, ' ');
			    if(ds0arg_ptr) {
				/* get rest of args */
				*ds0arg_ptr++ = 0;
				if( !(start_delim =
				      split_string(t1_all_params[xx], latter)) )
					{
					start_delim = t1_all_params[ xx ];
					}
				fprintf( file, format, 
					comment, 
					engine, 
					ds0_ptr, 
					start_delim, 
					ds0arg_ptr );
				}
			    }
			}
			break;
			    
			
		    default:
		        /* ADJUST FILE OUTPUT FORMAT */
		        strcpy( format, "%sset t1=%d %s %s\n" );

		        /* EXT. REPRESENTATION OF DATA RETURNED IN */
		        /* 'external' ARG  */
		        decode( convert, internal, external, Pannex_id );

			if( !(start_delim = 
			      split_string( t1_all_params[xx], latter )) )
			{
			    start_delim = t1_all_params[ xx ];
			}

			/* WRITE TO THE SCRIPT FILE */
			fprintf( file, format, 
				 comment, 
				 engine, 
				 start_delim, 
				 external);
			break;

		}
	    }
	}
    }    
}	/* write_t1_script() */

void
write_pri_script(file, Pannex_id, module)
FILE			*file;
ANNEX_ID	  	*Pannex_id;
int			module;
{
    int		xx,                      /* PRI PARAMETER COUNTER */ 
                chan,                    /* REF: NEW external CONSTRUCTION */
                offset,                  /* REF: NEW external CONSTRUCTION */
                error;
    static	char	format[ 40 ];
    long	align_internal[MAXVALUE/sizeof(long) + 1];
    char       *internal = (char *)align_internal;
    char        external[ MAXVALUE ];
    long	tbuf[ 2 ];
    u_short     id,
                category,
                convert,
                type;
    char	latter = FALSE;
    char       *start_delim;
    char       *comment = "";
    char        newExternal[ MAXVALUE ], /* NEW external CONSTRUCTION */
               *pExtRemain;              /* REF: NEW external CONSTRUCTION */
    int		retv;
    int	        b_chans;
   

    /* FOR EACH PRI PARAMETER */
    for(xx = 0; Prip_index(xx) != -1; xx++) 
    {
	category = Prip_category(xx);
	id = Prip_catid(xx);
	
	if( Anyp_support( Pannex_id, xx, prip_table ) )
	{
	    type = (u_short)Prip_type(xx);
	    convert = (u_short)Prip_convert(xx);

	    /* USE RPC TO OBTAIN PRI PARAMETER, (RETURNED IN internal) */
	    retv = get_pri_param(&Pannex_id->addr, 
				 (u_short)PRI_DEV,
				 (u_short)module,
				 category,
				 id,
				 (u_short)type, 
				 internal);
	    if (retv != 0) {
	        printf("\tWAN module %d:\n",module);
		printf( "\tUnable to get %s parameter\n", 
			wan_all_params[xx]);
	    } else {
	        /* DISTINGUISH PARAMETERS THAT HANDLE PER B-CHANNEL SETTINGS */
	        switch (id) {
		case WAN_IPX_NODE:
		  retv = 6;
		  break;
		case WAN_SIGPROTO:
		  retv = 2;
		  break;
		case WAN_RINGBACK:
		  retv = 1;
		  break;
		case WAN_REMOTE_ADDRESS:
		case WAN_IPX_NETWORK:
	          retv = 4;
		  break;
		default:
		  break;
		}

	        switch (id) {
		case WAN_IPX_NODE:
		case WAN_SIGPROTO:
		case WAN_RINGBACK:
		case WAN_REMOTE_ADDRESS:
		case WAN_IPX_NETWORK:
		  {
		    /* ADJUST FILE OUTPUT FORMAT FOR B-CHANNEL SYNTAX */
		    strcpy( format, "%sset pri=%d b=%d %s %s\n" );
		    b_chans = Pannex_id->b_count[module];
		    for ( chan = 0; chan < b_chans; chan++ ) {  
		      bcopy(internal+retv*chan,(char *)tbuf,retv);

		      decode(convert, (char *)tbuf, external, Pannex_id);

		      start_delim = split_string(wan_all_params[xx],
						 0);
		      if (start_delim == NULL)
			start_delim = wan_all_params[ xx ];
		      fprintf(file, format, comment, module,
			      chan+1, start_delim, external);
		    }
		  }
		  break;
			    
			
		default:
		        /* ADJUST FILE OUTPUT FORMAT */
		        strcpy( format, "%sset pri=%d %s %s\n" );

		        /* EXT. REPRESENTATION OF DATA RETURNED IN */
		        /* 'external' ARG  */
		        decode( convert, internal, external, Pannex_id );

			if( !(start_delim = 
			      split_string( wan_all_params[xx], latter )) )
			{
			    start_delim = wan_all_params[ xx ];
			}

			/* WRITE TO THE SCRIPT FILE */
			fprintf( file, format, 
				 comment, 
				 module, 
				 start_delim, 
				 external);
			break;

		}
	    }
	}
    }    
}	/* write_pri_script() */

void free_port_set(PPport_set)

	PORT_SET **PPport_set;

{
	PORT_SET *Ptemp_port_set;

	while (*PPport_set)
	    {
	    Ptemp_port_set = *PPport_set;
	    *PPport_set = (*PPport_set)->next;
	    free((char *)Ptemp_port_set);
	    }

}	/* free_port_set() */

void
free_modem_set(PPmodem_set)

	MODEM_SET **PPmodem_set;

{
	MODEM_SET *Ptemp_modem_set;

	while (*PPmodem_set)
	    {
	    Ptemp_modem_set = *PPmodem_set;
	    *PPmodem_set = (*PPmodem_set)->next;
	    free((char *)Ptemp_modem_set);
	    }

}	/* free_modem_set() */


void free_printer_set(PPprinter_set)

	PRINTER_SET **PPprinter_set;

{
	PRINTER_SET *Ptemp_printer_set;

	while (*PPprinter_set)
	    {
	    Ptemp_printer_set = *PPprinter_set;
	    *PPprinter_set = (*PPprinter_set)->next;
	    free((char *)Ptemp_printer_set);
	    }

}	/* free_printer_set() */

void free_t1_set(PPt1_set)
     T1_SET **PPt1_set;
{
  T1_SET *Ptemp_t1_set;

  while (*PPt1_set) {
    Ptemp_t1_set = *PPt1_set;
    *PPt1_set = (*PPt1_set)->next;
    free((char *)Ptemp_t1_set);
  }
} /* free_t1_set() */

void
free_pri_set(PPpri_set)
     PRI_SET **PPpri_set;
{
  PRI_SET *Ptemp_pri_set;

  while (*PPpri_set) {
    Ptemp_pri_set = *PPpri_set;
    *PPpri_set = (*PPpri_set)->next;
    free((char *)Ptemp_pri_set);
  }
} /* free_pri_set() */

void free_intmod_set(PPintmod_set)
     INTMOD_SET **PPintmod_set;
{
  INTMOD_SET *Ptemp_intmod_set;

  while (*PPintmod_set) {
    Ptemp_intmod_set = *PPintmod_set;
    *PPintmod_set = (*PPintmod_set)->next;
    free((char *)Ptemp_intmod_set);
  }
} /* free_intmod_set() */


void free_interface_set(PPinterface_set)

	INTERFACE_SET **PPinterface_set;

{
	INTERFACE_SET *Ptemp_interface_set;

	while (*PPinterface_set)
	    {
	    Ptemp_interface_set = *PPinterface_set;
	    *PPinterface_set = (*PPinterface_set)->next;
	    free((char *)Ptemp_interface_set);
	    }

}	/* free_interface_set() */


void free_annex_list(PPannex_list)

	ANNEX_LIST **PPannex_list;

{
	ANNEX_LIST *Ptemp_annex_list;

	while (*PPannex_list)
	    {
	    Ptemp_annex_list = *PPannex_list;
	    *PPannex_list = (*PPannex_list)->next;
	    free((char *)Ptemp_annex_list);
	    }

}	/* free_annex_list() */

char *
split_string(string, latter)
char	*string;
int	latter;
{
    static char split_token[80];
    char *delim;
    int offs;

    /*
     * Split the annex_params with commas.
     */
    delim = (char *)index(string,',');
    if (delim == NULL)
	return NULL;
    while (latter > 0 && delim != NULL) {
	string = delim + 1;
	delim = (char *)index(string, ',');
	latter--;
    }
    if (latter > 0)
	return NULL;
    if (delim == NULL)
	strcpy(split_token,string);
    else {
	offs = delim - string;
	strncpy(split_token,string,offs);
	split_token[offs] = '\0';
    }
    return split_token;
}
