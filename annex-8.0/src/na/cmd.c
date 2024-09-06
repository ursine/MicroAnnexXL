/*
 *****************************************************************************
 *
 *        Copyright 1989,1990, Xylogics, Inc.  ALL RIGHTS RESERVED.
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

#include <sys/types.h>
#include <setjmp.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <strings.h>
#endif 

#include <stdio.h>
#include "../inc/na/na.h"
#include "../inc/erpc/netadmp.h"
#include "../inc/na/cmd.h"
#include "../inc/na/help.h"

extern char *split_string();	/* in do.c */

static char t1_inval_sym=0,pri_inval_sym=0;

extern char *reset_modem_params[];

#ifdef NA
void punt();
#endif

int lex();
void prompt();
void free_annex_list();
void annex_list();
void boot_sub();
int lex_switch();
time_t delay_time();
void lex_string();
void warning_message();
void do_boot();
void free_port_set();
void port_set();
void message();
void do_broadcast();
int match();
int	annex_name();
void single_printer();
void single_port();
void single_interface();
void free_printer_set();
void free_interface_set();
void do_copy_annex();
void do_copy();
void interface_set();
void interface_copy();
void printer_set();
void printer_copy();
void skip_white_space();
void set_global_password();
void do_read();
void do_reset_box();
void do_reset_printer();
void do_reset_interface();
void do_reset_port();
int	annex_pair_list();
int	port_pair_list();
int	interface_pair_list();
int	printer_pair_list();
void annex_show_list();
void port_show_list();
void interface_show_list();
void printer_show_list();
void do_write();
int adm_set_cmd();
void single_t1();
void free_t1_set();
void t1_set();
void do_copy_t1();
void free_intmod_set();
void intmod_set();
void do_reset_t1();
void do_reset_intmod();
int t1_pair_list();
void t1_show_list();
int adm_modem_cmd();
int adm_wan_cmd();


int adm_box_cmd()
{
	/* Assign the default annex list. */

	ANNEX_LIST *Ptemp_annex_list = NULL,
	           *Ptemp_annex_tail = NULL;

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default %s list", BOX, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp annex list in case you came back here after
	   punting. */
	free_annex_list(&Ptemp_annex_list);

	/* Let a temp point at the annex list in case the human makes a
	   mistake, so that the old default will still be there after
	   punting. */
	annex_list(&Ptemp_annex_list, &Ptemp_annex_tail);

	/* No human mistakes, so move the temp annex list to the default
	   annex list.  Free the default first in case it had been
	   previously entered. */
	free_annex_list(&Pdef_annex_list);
	Pdef_annex_list = Ptemp_annex_list;
	Pdef_annex_tail = Ptemp_annex_tail;

	return 0;
}	/* adm_box_cmd() */

void MustBeSuperuser()
{
	if (!is_super)
#ifdef _WIN32
	    punt("must be administrator", (char *)NULL);
#else
	    punt("must be superuser", (char *)NULL);
#endif
}

int adm_boot_cmd()
{
	MustBeSuperuser();

	/* FALSE argument to boot_sub() means no dump. */
	boot_sub(FALSE);

	return 0;
}	/* adm_boot_cmd() */



/*
 *****************************************************************************
 *
 * Function Name:
 *	boot_sub
 *
 * Functional Description:
 * Used to implement both the boot and dumpboot coommands.
 * If no arguments were supplied, set prompt_mode so that they
 * will be prompted for. The syntax for the boot and dumpboot
 * command is :
 * [dump]boot [-a][-h][-d][-q] <time> <annex_list> <filename> <warning>
 *
 *  where -a will abort any boots
 *        -h will cause a halt or reset diag
 *        -d will force an upline dump
 *        -q will make the dumps quiet, send no warnings
 *
 * Parameters:
 *	dump true if we are called from dumpboot.
 *
 * Return Value:
 *       none
 *
 * Exceptions:
 *	Switches must be used to modify the command they are not prompted
 *      for during prompt mode.
 *
 *****************************************************************************
 */

void boot_sub(dump)
int	dump;

{
    char 	filename[FILENAME_LENGTH + 1], 
		warning[WARNING_LENGTH + 1];
    short int 	switch_mode = LEX_OK, 
		switches = 0;
    time_t	boot_time = 0;


    if(dump)
	switches|=SWDUMP;

    prompt_mode = lex(); 

    if ((prompt_mode == LEX_OK) && (inswitch = *symbol == '-')) {
	while ((switch_mode = lex_switch()) == LEX_OK) {

	    switch (*symbol) {

		case 'a' : switches |= SWABORT; break;

		case 'd' : switches |= SWDUMP; break;

		case 'h' : switches |= SWDIAG; break;

		case 'q' : switches |= SWQUIET; break;

		case 'l' : switches |= SWFLASH; break;

		default : punt("unknown switch",(char *)NULL);
	    }
	}
	/* 
	 * legal switch combos are: 
	 * -a alone or -d or -h
	 * any combo of 2 or more of -l, -d, and/or -h
	 * -q or -t can modify -d,-h,or standalone
         * -a and -d (dumpboot -a)
	 */
	if (((switches & SWABORT) && (switches != SWABORT && 
              switches != (SWDUMP|SWABORT))) || 
	    ((switches & SWDUMP) && (switches & SWDIAG)) ||
	    ((switches & SWDUMP) && (switches & SWFLASH)) ||
	    ((switches & SWFLASH) && (switches & SWDIAG))) 
	    punt("bad switch combinations",(char *)NULL);

        if (!(switches & SWABORT)) {
	    (void) lex();
        }
    }

    /*
     * If scripted input an no more arg data... punt.
     */
    prompt_mode = (prompt_mode == LEX_EOS) || (switch_mode == LEX_EOS);
    if ((prompt_mode && script_input))
	punt("missing arguments", (char *)NULL);

    /*
     * Get time.
     */
    if (!(switches & SWABORT)) {
	if (prompt_mode && !script_input) {
	    (void)setjmp(prompt_env);
	    prompt("\ttime (return for `now')",NULLSP, TRUE);
	}
	if(symbol_length > 0) {
	    boot_time = delay_time(FALSE);	
	    if (boot_time == BADTIME)
		punt("bad time format", (char *)NULL);
	    if (boot_time > 0)
		switches |= SWDELAY;
	}
    }

    /*
     * Get annex list.
     */
    if (!prompt_mode)
	prompt_mode = lex();

    if (prompt_mode && !script_input) {
	/* ask for the annex list */
	(void)setjmp(prompt_env);
	prompt("\t%s list (return for default)", BOX, TRUE);
    }

    free_annex_list(&Pspec_annex_list);
    if (eos) {
	if (!Pdef_annex_list)
	    punt(NO_BOXES, (char *)NULL);
    }
    else {
	annex_list(&Pspec_annex_list,&Pspec_annex_tail);
	/*
	 * lex got called in the bowels of annex_list here.
	 * so do the following hack.
	 */
	prompt_mode = eos;
    }

    /*
     * Get file name.
     */
    if (!(switches & SWABORT)) {
	filename[0] = '\0';
	if (prompt_mode && !script_input) {
	    (void)setjmp(prompt_env); 
	    prompt("\tfilename (return for default)", NULLSP, TRUE);
	}
	lex_string();

	if (symbol_length > FILENAME_LENGTH)
	    punt(LONG_FILENAME, (char *)NULL);
	if (symbol_length > 0)
	    (void)strcpy(filename, symbol);
	symbol_length = 0;   /* used this symbol for filename */
    }

    /*
     * prompt for warning message maxlength = 250.
     */
    if (!(switches & SWQUIET)){
	if (!prompt_mode && !(switches & SWABORT))
	    prompt_mode = lex();
	if (prompt_mode && !script_input) {
	    (void)setjmp(prompt_env); 
	    if (switches & SWABORT)
		prompt("\tabort message (return for none)", NULLSP, TRUE);
	    else
		prompt("\twarning (return for none)", NULLSP, TRUE);
	}
	if (eos)
	    warning[0] = '\0';
	else
	    warning_message(warning);
    }
    else
	warning[0] = '\0';

    (void) lex();

    /*
     *  Turn off prompt_mode so that subsequent errors will be punted
     *  back to the command prompt. 
     */
    prompt_mode = FALSE;

    /* 
     *  If an annex list was specified, boot those annexes; otherwise,
     *  boot the annexes in the default annex list. 
     */

    if (Pspec_annex_list)
	do_boot(filename,Pspec_annex_list,boot_time,switches,warning);
    else
	if (Pdef_annex_list)
	    do_boot(filename,Pdef_annex_list,boot_time,switches,warning);
	else
	    punt(NO_BOXES, (char *)NULL);

}	/* boot_sub() */



int adm_broadcast_cmd()

{
	struct
	    {
	    unsigned short length;
	    char           string[ADM_MAX_BCAST_MSG + 2];
	    }              courier_text;

	MustBeSuperuser();

	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);

	    if (Pspec_port_set == Pdef_port_set) {
		Pspec_port_set = NULL;
		Pspec_port_tail = NULL;
	    } else {
	        free_port_set(&Pspec_port_set);
	    }

	    prompt("\tenter port_set (hit return for default)", NULLSP, TRUE);

	    if (eos)
	        {
	        (void)lex();
	        if (!Pdef_port_set)
	            punt("default ports have not been specified",
	             (char *)NULL);
	        }
	    else
	        port_set(&Pspec_port_set, &Pspec_port_tail, VIRTUAL_OK);

	    (void)setjmp(prompt_env);

	    prompt("\tenter message", NULLSP, FALSE);
	    }
	else
	    {
	    if (Pspec_port_set == Pdef_port_set) {
		Pspec_port_set = NULL;
		Pspec_port_tail = NULL;
	    } else {
	        free_port_set(&Pspec_port_set);
	    }

	    if (symbol_length == 1 && symbol[0] == '=')
	        {
	        (void)lex();

	        if (eos)
	            punt("missing port identifier", (char *)NULL);
	        else
	            port_set(&Pspec_port_set, &Pspec_port_tail, VIRTUAL_OK);
	        }

	    if (eos)
	        punt("missing message", (char *)NULL);
	    }

	/* Parse the message.  Put it into a courier-style string with
	   a length word so that do_broadcast() doesn't have to copy it
	   into one later. */

	message(courier_text.string);

	courier_text.length = strlen(courier_text.string);

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Perform the broadcast. */

	if (Pspec_port_set)
	    do_broadcast(Pspec_port_set, (char *)&courier_text);
	else
	    if (Pdef_port_set)
	        do_broadcast(Pdef_port_set, (char *)&courier_text);
	    else
	        punt("default ports have not been specified", (char *)NULL);

	return 0;
}	/* adm_broadcast_cmd() */



int adm_comment_cmd()

{
	/* Ignore the rest of the line. */

	eos = TRUE;

	return 0;
}	/* adm_comment_cmd() */



int adm_copy_cmd()

{

	ANNEX_ID	   source_annex_id;
	unsigned short     source_port_number;
	unsigned short     source_printer_number;
	unsigned short     source_interface_number;
	unsigned short     source_t1_number;
	unsigned short     source_pri_number;
	unsigned short     source_modem_number;

	int category;

	MustBeSuperuser();

	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);

	    prompt("\tenter \"%s\", \"port\", \"printer\", \"interface\"",
                   BOX, FALSE);
	    category = match(symbol, param_classes, "copy argument");

	    (void)setjmp(prompt_env);

	    switch (category)
		{
		case BOX_CLASS:
	            prompt("\tenter source %s", BOX, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
			annex_name(&source_annex_id, (char *)NULL, 0);
		    break;

		case PRINTER_CLASS:
	            prompt("\tenter source printer", NULLSP, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_printer(&source_printer_number,&source_annex_id);
		    break;

		case PORT_CLASS:
	            prompt("\tenter source port", NULLSP, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_port(&source_port_number, &source_annex_id);
		    break;

		case INTERFACE_CLASS:
	            prompt("\tenter source interface", NULLSP, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_interface(&source_interface_number, &source_annex_id);
		    break;

		case T1_CLASS:
	            prompt("\tenter source t1 engine", NULLSP, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_t1(&source_t1_number, &source_annex_id);
		    break;

		  case PRI_CLASS:
	            prompt("\tenter source PRI line", NULLSP, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_pri(&source_pri_number, &source_annex_id);

		    break;

		  case MODEM_CLASS:
	            prompt("\tenter source modem number", NULLSP, FALSE);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_modem(&source_modem_number, &source_annex_id);
		    break;

		} /* end switch */

	    (void)setjmp(prompt_env);

	    /* case off the next appropriate prompt */
	    switch (category)
	       {
		case BOX_CLASS:
		    free_annex_list(&Pspec_annex_list);
		    prompt("\tenter destination %s (hit return for default)", 
			   BOX, TRUE);
		    break;

		case PRINTER_CLASS:
	            if (Pspec_printer_set == Pdef_printer_set) {
		        Pspec_printer_set = NULL;
		        Pspec_printer_tail = NULL;
	            } else {
	                free_printer_set(&Pspec_printer_set);
	            }
		    prompt("\tenter destination printer_set (hit return for default)", NULLSP, TRUE);
		    break;

		case PORT_CLASS:
	            if (Pspec_port_set == Pdef_port_set) {
		        Pspec_port_set = NULL;
		        Pspec_port_tail = NULL;
	            } else {
	                free_port_set(&Pspec_port_set);
	            }
		    prompt("\tenter destination port_set (hit return for default)", NULLSP, TRUE);
		    break;

		case INTERFACE_CLASS:
	            if (Pspec_interface_set == Pdef_interface_set) {
		        Pspec_interface_set = NULL;
		        Pspec_interface_tail = NULL;
	            } else {
	                free_interface_set(&Pspec_interface_set);
	            }
		    prompt("\tenter destination interface_set (hit return for default)", NULLSP, TRUE);
		    break;

		case T1_CLASS:
	            if (Pspec_t1_set == Pdef_t1_set) {
		        Pspec_t1_set = NULL;
		        Pspec_t1_tail = NULL;
	            } else {
	                free_t1_set(&Pspec_t1_set);
	            }
		    prompt("\tenter destination t1 set (hit return for default)", NULLSP, TRUE);
		    break;

		case PRI_CLASS:
	            if (Pspec_pri_set == Pdef_pri_set) {
		        Pspec_pri_set = NULL;
		        Pspec_pri_tail = NULL;
	            } else {
	                free_pri_set(&Pspec_pri_set);
	            }
		    prompt("\tenter destination PRI set (hit return for default)", NULLSP, TRUE);
		    break;
		case MODEM_CLASS:
	            if (Pspec_modem_set == Pdef_modem_set) {
		        Pspec_modem_set = NULL;
		        Pspec_modem_tail = NULL;
	            } else {
	                free_modem_set(&Pspec_modem_set);
	            }
		    prompt("\tenter destination modem set (hit return for default)", NULLSP, TRUE);
		    break;

	       }

	    }
	else  
	    { 

	    /* Parse source args off command line, no prompting here */

	    category = match(symbol, param_classes, "copy argument");
	    (void)lex();

	    switch (category)
	        {
		case BOX_CLASS:
	            free_annex_list(&Pspec_annex_list);

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
			annex_name(&source_annex_id, (char *)NULL, 0);

	            break;

		case PRINTER_CLASS:
	            if (Pspec_printer_set == Pdef_printer_set) {
		        Pspec_printer_set = NULL;
		        Pspec_printer_tail = NULL;
	            } else {
	                free_printer_set(&Pspec_printer_set);
	            }

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_printer(&source_printer_number,&source_annex_id);

	            break;

		case PORT_CLASS:
	            if (Pspec_port_set == Pdef_port_set) {
		        Pspec_port_set = NULL;
		        Pspec_port_tail = NULL;
	            } else {
	                free_port_set(&Pspec_port_set);
	            }

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_port(&source_port_number, &source_annex_id);

	            break;

		case INTERFACE_CLASS:
	            if (Pspec_interface_set == Pdef_interface_set) {
		        Pspec_interface_set = NULL;
		        Pspec_interface_tail = NULL;
	            } else {
	                free_interface_set(&Pspec_interface_set);
	            }

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_interface(&source_interface_number, &source_annex_id);

	            break;

		case T1_CLASS:
	            if (Pspec_t1_set == Pdef_t1_set) {
		        Pspec_t1_set = NULL;
		        Pspec_t1_tail = NULL;
	            } else {
	                free_t1_set(&Pspec_t1_set);
	            }

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_t1(&source_t1_number, &source_annex_id);

	            break;

		case PRI_CLASS:
	            if (Pspec_pri_set == Pdef_pri_set) {
		        Pspec_pri_set = NULL;
		        Pspec_pri_tail = NULL;
	            } else {
	                free_pri_set(&Pspec_pri_set);
	            }

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_pri(&source_pri_number, &source_annex_id);

	            break;

		  case MODEM_CLASS:
	            if (Pspec_modem_set == Pdef_modem_set) {
		        Pspec_modem_set = NULL;
		        Pspec_modem_tail = NULL;
	            } else {
	                free_modem_set(&Pspec_modem_set);
	            }

		    if (eos)
		        punt(NO_BOXES, (char *)NULL);
		    else
	       		single_t1(&source_modem_number, &source_annex_id);

	            break;

		}	/* switch (category) */

	        if (eos)
	            punt("missing destination list", (char *)NULL);
	    }

	/*
	 * Turn off prompt_mode so that subsequent errors will be punted
	 * back to the command prompt. 
	 */
	prompt_mode = FALSE;

	/* Parse the destination list and perform the copy operations. */

	switch (category)
	    {
	    case BOX_CLASS:
		/* Get the destination annex list */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_annex_list)
			punt(NO_BOXES, (char *)NULL);
		    }
	        else
		    annex_list(&Pspec_annex_list, &Pspec_annex_tail);

		/* Do the annex parameter copy */
	        if (Pspec_annex_list)
	            do_copy_annex(&source_annex_id, Pspec_annex_list);
	        else
	            if (Pdef_annex_list)
		        do_copy_annex(&source_annex_id, Pdef_annex_list);

	        break;

	    case PORT_CLASS:
		/* Parse off the destination ports to be copied to */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_port_set)
			punt("default ports have not been specified",
			 (char *)NULL);
		    }
	        else
		    port_set(&Pspec_port_set, &Pspec_port_tail, VIRTUAL_NOT_OK);

		/* Do the copy now */
	        if (Pspec_port_set)
	            do_copy(source_port_number, &source_annex_id, 
			    Pspec_port_set);
	        else
	            if (Pdef_port_set)
		        do_copy(source_port_number, &source_annex_id,
		         Pdef_port_set);
	        break;

	    case INTERFACE_CLASS:
		/* Parse off the destination interfaces to be copied to */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_interface_set)
			punt("default interfaces have not been specified",
			 (char *)NULL);
		    }
	        else
		    interface_set(&Pspec_interface_set, &Pspec_interface_tail,  VIRTUAL_NOT_OK);

		/* Do the copy now */
	        if (Pspec_interface_set)
	            interface_copy(source_interface_number, &source_annex_id, 
			    Pspec_interface_set);
	        else
	            if (Pdef_interface_set)
		       interface_copy(source_interface_number, &source_annex_id,
		         Pdef_interface_set);
	        break;

	    case PRINTER_CLASS:
		/* Parse off the destination printers to be copied to */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_printer_set)
			punt("default printers have not been specified",
			 (char *)NULL);
		    }
	        else
		    printer_set(&Pspec_printer_set, &Pspec_printer_tail);

		/* Do the copy now */
	        if (Pspec_printer_set)
	            printer_copy(source_printer_number, &source_annex_id, 
			    Pspec_printer_set);
	        else
	            if (Pdef_printer_set)
		        printer_copy(source_printer_number, &source_annex_id,
		         Pdef_printer_set);
	        break;

	    case T1_CLASS:
		/* Parse off the destination t1 engine to be copied to */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_t1_set)
			punt("default t1 engine has not been specified",
			 (char *)NULL);
		    }
	        else
		    t1_set(&Pspec_t1_set, &Pspec_t1_tail );

		/* Do the copy now */
	        if (Pspec_t1_set)
	            do_copy_t1(source_t1_number, &source_annex_id, 
			    Pspec_t1_set);
	        else
	            if (Pdef_t1_set)
		        do_copy_t1(source_t1_number, &source_annex_id,
		         Pdef_t1_set);
	        break;

	    case PRI_CLASS:
		/* Parse off the destination WAN module to be copied to */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_pri_set)
			punt("default WAN module has not been specified",
			 (char *)NULL);
		    }
	        else
		    pri_set(&Pspec_pri_set, &Pspec_pri_tail );

		/* Do the copy now */
	        if (Pspec_pri_set)
	            do_copy_pri(source_pri_number, &source_annex_id, 
			    Pspec_pri_set);
	        else
	            if (Pdef_pri_set)
		        do_copy_pri(source_pri_number, &source_annex_id,
		         Pdef_pri_set);
	        break;

	    case MODEM_CLASS:
		/* Parse off the destination modem number to be copied to */
	        if (eos)
		    {
		    (void)lex();
		    if (!Pdef_modem_set)
			punt("default modem set has not been specified",
			 (char *)NULL);
		    }
	        else
		    modem_set(&Pspec_modem_set, &Pspec_modem_tail );

		/* Do the copy now */
	        if (Pspec_modem_set)
	            do_copy_modem(source_modem_number, &source_annex_id, 
			    Pspec_modem_set);
	        else
	            if (Pdef_modem_set)
		        do_copy_modem(source_modem_number, &source_annex_id,
		         Pdef_modem_set);
	        break;

	    }


	return 0;
}	/* adm_copy_cmd() */

int adm_dumpboot_cmd()

{
	MustBeSuperuser();

	/* TRUE argument to boot_sub() means dump is requested. */

	boot_sub(TRUE);

	return 0;
}	/* adm_dumpboot_cmd() */



int adm_echo_cmd()

{
	/* Echo the rest of the line to standard output. */

	skip_white_space();

	printf("%s\n", Psymbol);

	eos = TRUE;

	return 0;
}	/* adm_echo_cmd() */

int
do_sub_help_match(str,symlen)
char *str;
int symlen;
{
	char *cp;
	int idx = 1;

	while (cp = split_string(str,idx)) {
		if (strncmp(symbol,cp,symlen) == 0)
			return 1;
		idx++;
	}
	return 0;
}

int adm_help_cmd()

{
	int help_nr,usage;
	int symlen;
	int found = 0;

	(void)lex();

	open_pager();
	if (eos)
	{
	    printf("\ncommands are:\n");
	    for (help_nr = 0; cmd_string[help_nr]; help_nr++)
	        printf("\t%s\n", cmd_string[help_nr]);
	}
	else
	{
	    while(!eos)
	    {
		symlen = strlen(symbol);
		for (help_nr = 0; D_key(help_nr) != NULL; help_nr++) {
		    usage = D_usage(help_nr);
		    if (usage < 0)
			usage = -usage-1;

		    /* ignore obsolete port parameters */
		    if ((usage == PORT_PARAM || usage == PORT_CATEGORY) &&
			Sp_category(D_index(help_nr)) == VOID_CAT)
			continue;

		    /* ignore obsolete annex parameters */
		    if ((usage == BOX_PARAM || usage == BOX_CATEGORY) &&
			Ap_category(D_index(help_nr)) == VOID_CAT)
			continue;

		    if ((symlen == 1 && symbol[0] == '*') ||
		        strncmp(symbol,D_key(help_nr),symlen) == 0 ||
			do_sub_help_match(D_key(help_nr),symlen)) {
			found++;
			printf("\n\t%s (%s):\n", D_key(help_nr),
			    usage_table[usage]);
			printf("\t%s\n", D_text(help_nr));
		    }
		}
		if (found == 0)
		    printf("\n\tNo help found for \"%s\"\n",
			symbol);
		(void)lex();
	    }
	}
	printf("\n");
	close_pager();
	return 0;
}	/* adm_help_cmd() */


int adm_password_cmd()
{
	char	*pass;
	char	nullstring = 0;

	(void)lex();

	if (eos)			/* prompt if no argument */
	{
	    if (script_input)
		pass = &nullstring;
	    else
		pass = get_password((struct in_addr *)0);
	}

	else				/* otherwise get it */
	{
	    (void)lex();
	    pass = symbol;		/* from command line */
	}

	set_global_password(pass);

	return 0;
}	/* adm_password_cmd() */


int adm_port_cmd()

{
	PORT_SET *Ptemp_port_set = NULL,
	         *Ptemp_port_tail = NULL;

	/* Assign the default port set. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default port set", NULLSP, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp port set in case you came back here after punting. */
	free_port_set(&Ptemp_port_set);

	/* Let a temp point at the port set in case the human makes a mistake,
	   so that the old default will still be there after punting. */
	port_set(&Ptemp_port_set, &Ptemp_port_tail, VIRTUAL_NOT_OK);

	/* No human mistakes, so move the temp port set to the default
	   port set.  Free the default first in case it had been previously
	   entered. */
	free_port_set(&Pdef_port_set);
	Pdef_port_set = Ptemp_port_set;
	Pdef_port_tail = Ptemp_port_tail;

	return 0;
}	/* adm_port_cmd() */

int
adm_modem_cmd()
{
	MODEM_SET *Ptemp_modem_set = NULL,
	         *Ptemp_modem_tail = NULL;

	/* Assign the default modem set. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default modem set", NULLSP, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp modem set in case you came back here after punting. */
	free_modem_set(&Ptemp_modem_set);

	/* Let a temp point at the modem set in case the human makes a mistake,
	   so that the old default will still be there after punting. */
	modem_set(&Ptemp_modem_set, &Ptemp_modem_tail);

	/* No human mistakes, so move the temp modem set to the default
	   modem set.  Free the default first in case it had been previously
	   entered. */
	free_modem_set(&Pdef_modem_set);
	Pdef_modem_set = Ptemp_modem_set;
	Pdef_modem_tail = Ptemp_modem_tail;
	return 0;

}	/* adm_modem_cmd() */

int
adm_wan_cmd()
{
	PRI_SET *Ptemp_pri_set = NULL,
	         *Ptemp_pri_tail = NULL;

	/* Assign the default pri set. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default wan set", NULLSP, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp pri set in case you came back here after punting. */
	free_pri_set(&Ptemp_pri_set);

	/* Let a temp point at the pri set in case the human makes a mistake,
	   so that the old default will still be there after punting. */
	pri_set(&Ptemp_pri_set, &Ptemp_pri_tail);

	/* No human mistakes, so move the temp pri set to the default
	   pri set.  Free the default first in case it had been previously
	   entered. */
	free_pri_set(&Pdef_pri_set);
	Pdef_pri_set = Ptemp_pri_set;
	Pdef_pri_tail = Ptemp_pri_tail;
	return 0;

}	/* adm_wan_cmd() */


int adm_interface_cmd()

{
	INTERFACE_SET *Ptemp_interface_set = NULL,
	         *Ptemp_interface_tail = NULL;

	/* Assign the default interface set. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default interface set", NULLSP, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp interface set */
	free_interface_set(&Ptemp_interface_set);

	/* Let a temp point at the interface set in case he makes a mistake,
	   so that the old default will still be there after punting. */
	/* Free the temp interface set */
	interface_set(&Ptemp_interface_set, &Ptemp_interface_tail);

	/* No human mistakes, so move the temp interface set to the default
	   interface set.  Free the default first in case it had been previously
	   entered. */
	free_interface_set(&Pdef_interface_set);
	Pdef_interface_set = Ptemp_interface_set;
	Pdef_interface_tail = Ptemp_interface_tail;

	return 0;
}	/* adm_interface_cmd() */

#ifdef not_used
int adm_t1_cmd()
{
	T1_SET *Ptemp_t1_set = NULL,
	       *Ptemp_t1_tail = NULL;

	/* Assign the default t1 set. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default t1 set", NULLSP, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp t1 set */
	free_t1_set(&Ptemp_t1_set);

	/* Let a temp point at the t1 set in case he makes a mistake,
	   so that the old default will still be there after punting. */
	/* Free the temp t1 set */
	t1_set(&Ptemp_t1_set, &Ptemp_t1_tail);

	/* No human mistakes, so move the temp t1 set to the default
	   t1 set.  Free the default first in case it had been previously
	   entered. */
	free_t1_set(&Pdef_t1_set);
	Pdef_t1_set = Ptemp_t1_set;
	Pdef_t1_tail = Ptemp_t1_tail;

	return 0;
}	/* adm_t1_cmd() */
#endif

int adm_quit_cmd()

{

	/* Terminate the main loop (in main.c). */

	done = TRUE;
	eos = TRUE;

	return 0;
}	/* adm_quit_cmd() */



int adm_read_cmd()

{
	char filename[FILENAME_LENGTH + 1];

	MustBeSuperuser();

	if (Pdef_annex_list == NULL)
	    punt(NO_BOXES, (char *)NULL);


	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tfilename", NULLSP, FALSE);
	    lex_string();
	    if (symbol_length > FILENAME_LENGTH)
		punt(LONG_FILENAME, (char *)NULL);
	    (void)strcpy(filename, symbol);
	    (void)lex();
	    }
	else
	    {
	    lex_string();
	    if (symbol_length > FILENAME_LENGTH)
		punt(LONG_FILENAME, (char *)NULL);
	    (void)strcpy(filename, symbol);
	    (void)lex();
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Perform the read operation. */

	do_read(filename);

	return 0;
}	/* adm_read_cmd() */


/* ====================================== */
/* Will not support trunk reset just yet! */
/* ====================================== */

int adm_reset_cmd()

{
	int reset_box = FALSE;
	int reset_printer = FALSE;
	int reset_interface = FALSE;
	int reset_t1 = FALSE;
	int reset_intmod = FALSE;
	int reset_pri = FALSE;
	unsigned short length;

	MustBeSuperuser();

	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter \"%s\", printer or port set (return resets default ports)",
		   BOX, TRUE);

	    /*
	     * Some broken machines (NCR) implement string macros in assembly
	     * and don't allow nested assembler macro calls (gak!)
	     */
	    length = strlen(symbol);
	    if(!eos && !strncmp(symbol, BOX, length))
		{
		reset_box = TRUE;
		free_annex_list(&Pspec_annex_list);
	        (void)setjmp(prompt_env);
	        prompt("\tenter %s list (hit return for default)",
		       BOX, TRUE);

		if (eos)
		    {
		    (void)lex();
		    if (!Pdef_annex_list)
			punt(NO_BOXES, (char *)NULL);
		    }
		else
		    annex_list(&Pspec_annex_list, &Pspec_annex_tail);

	        prompt("\tenter reset subsystem list (hit return for all)",
	    		NULLSP, TRUE);
		}
	    else if(length > 3 && !strncmp(symbol, PRINTER, length))
		{
		(void)lex();
		reset_printer = TRUE;
	        if (Pspec_printer_set == Pdef_printer_set) {
		    Pspec_printer_set = NULL;
		    Pspec_printer_tail = NULL;
	        } else {
	            free_printer_set(&Pspec_printer_set);
	        }
		if (eos)
		    {
	            prompt("\tenter printer set (return resets default printer set)", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_printer_set)
			    punt("default printers have not been specified",
			             (char *)NULL);
			Pspec_printer_set = Pdef_printer_set;
			}
		    else
		        printer_set(&Pspec_printer_set,&Pspec_printer_tail);
		    }
		else
		    {
		    printer_set(&Pspec_printer_set, &Pspec_printer_tail);
		    }
		}
	    else if(!strncmp(symbol, INTERFACES, length))
		{
		int need_set = 0;
		reset_interface = TRUE;
		(void)lex();
		if (*symbol == '=') {
		    need_set = 1;
		    (void)lex();
		}
	        if (Pspec_interface_set == Pdef_interface_set) {
		    Pspec_interface_set = NULL;
		    Pspec_interface_tail = NULL;
	        } else {
	            free_interface_set(&Pspec_interface_set);
	        }
		if (eos)
		    {
		    if (need_set)
                        punt("missing interface identifier", (char *)NULL);

	            prompt("\tenter interface set (return resets default interface set)", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_interface_set)
			    punt("default interfaces have not been specified",
			             (char *)NULL);
			Pspec_interface_set = Pdef_interface_set;
			}
		    else
		        interface_set(&Pspec_interface_set,&Pspec_interface_tail);
		    }
		else
		    {
		    interface_set(&Pspec_interface_set, &Pspec_interface_tail);
		    }
		}
	    else if (!strncmp(symbol, PRI, length) ||
		     !strncmp(symbol, OLDPRI, length))
		{
		(void)lex();
		reset_pri = TRUE;
	        if (Pspec_pri_set == Pdef_pri_set) {
		    Pspec_pri_set = NULL;
		    Pspec_pri_tail = NULL;
	        } 
		else {
	            free_pri_set(&Pspec_pri_set);
	        }

		if (eos)
		    {
	            prompt("\tenter WAN module list", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_pri_set)
			    punt("default WAN module list has not been specified",
			             (char *)NULL);
			Pspec_pri_set = Pdef_pri_set;
			}
		    else
		      pri_set(&Pspec_pri_set,&Pspec_pri_tail);
		    }
		else
		{
		  pri_set(&Pspec_pri_set, &Pspec_pri_tail);
		}
	    } else if(!strncmp(symbol, T1, length))
		{
		(void)lex();
		reset_t1 = TRUE;
	        if (Pspec_t1_set == Pdef_t1_set) {
		    Pspec_t1_set = NULL;
		    Pspec_t1_tail = NULL;
	        } 
		else {
	            free_t1_set(&Pspec_t1_set);
	        }

		if (eos)
		    {
	            prompt("\tenter T1 engine list and reset type", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_t1_set)
			    punt("default T1 engine list has not been specified",
			             (char *)NULL);
			Pspec_t1_set = Pdef_t1_set;
			}
		    else
		        t1_set(&Pspec_t1_set,&Pspec_t1_tail);
		    }
		else
		{
		    t1_set(&Pspec_t1_set, &Pspec_t1_tail);
		}
	    }
	    else if ((length >= 4 && !strncmp(symbol, INT_MODEM, length)) ||
		     !strncmp(symbol,MODEM,length)) {
		(void)lex();
		reset_intmod = TRUE;
	        if (Pspec_intmod_set == Pdef_intmod_set) {
		    Pspec_intmod_set = NULL;
		    Pspec_intmod_tail = NULL;
	        } else {
	            free_intmod_set(&Pspec_intmod_set);
	        }
		if (eos ||
		    is_in_list(symbol,reset_modem_params))
		    {
		      char savesym[LINE_LENGTH+1];
		      int saveeos = eos;
		      strcpy(savesym,symbol);
	            prompt("\tenter internal modem set (return resets default internal modem set)", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_intmod_set)
			    punt("default internal modem set has not been specified",
			             (char *)NULL);
			Pspec_intmod_set = Pdef_intmod_set;
			}
		    else
		        intmod_set(&Pspec_intmod_set,&Pspec_intmod_tail);
		      strcpy(symbol,savesym);
		      eos = saveeos;
		    }
		else
		    {
		    intmod_set(&Pspec_intmod_set, &Pspec_intmod_tail);
		    }
		}
	    else
		{

	        if (Pspec_port_set == Pdef_port_set) {
		    Pspec_port_set = NULL;
		    Pspec_port_tail = NULL;
	        } else {
	            free_port_set(&Pspec_port_set);
	        }
		if (eos)
		  {
		    (void)lex();
		    if (!Pdef_port_set)
			punt("default ports have not been specified",
			     (char *)NULL);
		    else
			Pspec_port_set = Pdef_port_set;
		    }
		else
		    {
		    port_set(&Pspec_port_set, &Pspec_port_tail, VIRTUAL_OK);
		    }
		}
	    }
	else
	    {
	    /*
	     * Some broken machines (NCR) implement string macros in assembly
	     * and don't allow nested assembler macro calls (gak!)
	     */
	    length = strlen(symbol);
	    if(!strncmp(symbol, BOX, length))
	        {
		reset_box = TRUE;

	        (void)lex();

		free_annex_list(&Pspec_annex_list);

	        if (symbol_length == 1 && symbol[0] == '=')
		    {
		    (void)lex();

		    if (eos)
			punt(NO_BOX, (char *)NULL);
		    else
			annex_list(&Pspec_annex_list, &Pspec_annex_tail);
		    }
		}
	    else if(length > 3 && !strncmp(symbol, PRINTER, length))
		{
		reset_printer = TRUE;
		(void)lex();
	        if (Pspec_printer_set == Pdef_printer_set) {
		    Pspec_printer_set = NULL;
		    Pspec_printer_tail = NULL;
	        } else {
	            free_printer_set(&Pspec_printer_set);
	        }

		if (eos)
		    {
	            prompt("\tenter printer set (return resets default printer set)", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_printer_set)
			        punt("default printers have not been specified",
			             (char *)NULL);
			Pspec_printer_set = Pdef_printer_set;
			}
		    else
		        printer_set(&Pspec_printer_set,&Pspec_printer_tail);
		    }
		else
		    printer_set(&Pspec_printer_set, &Pspec_printer_tail);
		}
	    else if(!strncmp(symbol, INTERFACES, length))
		{
		reset_interface = TRUE;
		(void)lex();
	        if (Pspec_interface_set == Pdef_interface_set) {
		    Pspec_interface_set = NULL;
		    Pspec_interface_tail = NULL;
	        } else {
	            free_interface_set(&Pspec_interface_set);
	        }

		if (eos)
		    {
	            prompt("\tenter interface set (return resets default interface set)", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_interface_set)
			        punt("default interfaces have not been specified", (char *)NULL);
			Pspec_interface_set = Pdef_interface_set;
			}
		    else
		        interface_set(&Pspec_interface_set,&Pspec_interface_tail);
		    }
		else
		    interface_set(&Pspec_interface_set, &Pspec_interface_tail);
		}
	    else if (!strncmp(symbol, PRI, length) ||
		     !strncmp(symbol, OLDPRI, length))
		{
		(void)lex();
		reset_pri = TRUE;
	        if (Pspec_pri_set == Pdef_pri_set) {
		    Pspec_pri_set = NULL;
		    Pspec_pri_tail = NULL;
	        } else {
	            free_pri_set(&Pspec_pri_set);
	        }
		if (eos)
		{
	            prompt("\tenter WAN module list", (char *) 0, TRUE);

		    if (eos)
		    {
		        if (!Pdef_pri_set)
			    punt("default WAN module list has not been specified",
			             (char *)NULL);
			Pspec_pri_set = Pdef_pri_set;
		    }
		    else
		    {
		        pri_set(&Pspec_pri_set,&Pspec_pri_tail);
		    }
		  } else {
		        pri_set(&Pspec_pri_set,&Pspec_pri_tail);
		  }
		} else if(!strncmp(symbol, T1, length)) {
		(void)lex();
		reset_t1 = TRUE;
	        if (Pspec_t1_set == Pdef_t1_set) {
		    Pspec_t1_set = NULL;
		    Pspec_t1_tail = NULL;
	        } else {
	            free_t1_set(&Pspec_t1_set);
	        }
		if (eos)
		{
	            prompt("\tenter T1 engine list and reset type", (char *) 0, TRUE);

		    if (eos)
		    {
		        if (!Pdef_t1_set)
			    punt("default T1 engine list and reset type has not been specified",
			             (char *)NULL);
			Pspec_t1_set = Pdef_t1_set;
		    }
		    else
		    {
		        t1_set(&Pspec_t1_set,&Pspec_t1_tail);
		    }
		}
		else
		    {
		    t1_set(&Pspec_t1_set, &Pspec_t1_tail);
		    }
		}
	    else if(!strncmp(symbol, INT_MODEM, length))
		{
		(void)lex();
		reset_intmod = TRUE;
	        if (Pspec_intmod_set == Pdef_intmod_set) {
		    Pspec_intmod_set = NULL;
		    Pspec_intmod_tail = NULL;
	        } else {
	            free_intmod_set(&Pspec_intmod_set);
	        }
		if (eos ||
		    is_in_list(symbol,reset_modem_params))
		    {
		      char savesym[LINE_LENGTH+1];
		      int saveeos = eos;
		      strcpy(savesym,symbol);
	            prompt("\tenter internal modem set (return resets default internal modem set)", (char *) 0, TRUE);
		    if (eos)
			{
		        if (!Pdef_intmod_set)
			    punt("default internal modem set has not been specified",
			             (char *)NULL);
			Pspec_intmod_set = Pdef_intmod_set;
			}
		    else
		        intmod_set(&Pspec_intmod_set,&Pspec_intmod_tail);
		      strcpy(symbol,savesym);
		      eos = saveeos;
		    }
		else
		    {
		    intmod_set(&Pspec_intmod_set, &Pspec_intmod_tail);
		    }
		}
	    else
		{
		int need_set = 0;
		if(((strncmp(symbol, PORT, length)) == 0) ||
		   ((strncmp(symbol, ASYNCHRONOUS, length)) == 0)) {
		    (void)lex();
		    if (*symbol == '=') {
			need_set = 1;
			(void)lex();
		    }
		}

	        if (Pspec_port_set == Pdef_port_set) {
		    Pspec_port_set = NULL;
		    Pspec_port_tail = NULL;
	        } else {
	            free_port_set(&Pspec_port_set);
	        }

		if (eos)
		    {
		    if (need_set)
			punt("missing port identifier", (char *)NULL);

		    prompt("\tenter port set (return resets default port set)", (char *) 0, TRUE);
		    if (eos)
			{
			if (!Pdef_port_set)
			    punt("default ports have not been specified", (char *)NULL);
			Pspec_port_set = Pdef_port_set;
		    }
		else
		    port_set(&Pspec_port_set, &Pspec_port_tail, VIRTUAL_OK);
		}
		else
		    port_set(&Pspec_port_set, &Pspec_port_tail, VIRTUAL_OK);
	    }

	}
	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Perform one of the requested reset functions - box or port list */

	if(reset_box)

	        if (Pspec_annex_list)
	            do_reset_box(Pspec_annex_list);
	        else
		{
	            if (Pdef_annex_list)
	                do_reset_box(Pdef_annex_list);
	            else
			punt(NO_BOXES, (char *)NULL);
		}

	else if(reset_printer)

	        if (Pspec_printer_set)
	            do_reset_printer(Pspec_printer_set);
	        else
		{
	            if (Pdef_port_set)
	                do_reset_printer(Pdef_printer_set);
	            else
	                punt("default printer ports have not been specified",
			 (char *)NULL);
		}

	else if(reset_interface)

	        if (Pspec_interface_set)
	            do_reset_interface(Pspec_interface_set);
	        else
		{
	            if (Pdef_interface_set)
	                do_reset_interface(Pdef_interface_set);
	            else
	                punt("default interfaces have not been specified",
			 (char *)NULL);
		}
	else if (reset_pri)

	        if (Pspec_pri_set)
		{
	            do_reset_pri( Pspec_pri_set );
		}
	        else
		{
	            if (Pdef_pri_set)
	                do_reset_pri(Pdef_pri_set);
	            else
	                punt("default WAN reset has not been specified",
			 (char *)NULL);
		}
	else if(reset_t1)

	        if (Pspec_t1_set)
		{
	            do_reset_t1( Pspec_t1_set );
		}
	        else
		{
	            if (Pdef_t1_set)
	                do_reset_t1(Pdef_t1_set);
	            else
	                punt("default t1 reset has not been specified",
			 (char *)NULL);
		}
	else if(reset_intmod)

	        if (Pspec_intmod_set)
	            do_reset_intmod(Pspec_intmod_set);
	        else
		{
	            if (Pdef_intmod_set)
	                do_reset_intmod(Pdef_intmod_set);
	            else
	                punt("default internal modems have not been specified",
			 (char *)NULL);
		}

	else
	        if (Pspec_port_set)
	            do_reset_port(Pspec_port_set);
	        else
		{
	            if (Pdef_port_set)
	                do_reset_port(Pdef_port_set);
	            else
	                punt("default ports have not been specified",
			 (char *)NULL);
		  }

	return 0;
}	/* adm_reset_cmd() */

int
adm_set_cmd()
{
	int	category;
	char	*msg,*msgf,*msg2;
	int	error = 0;

	MustBeSuperuser();

	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);

	    prompt("\tenter \"%s\", \"port\", \"interface\", \"printer\", or \"t1\"", 
                   BOX, FALSE);

	    category = match(symbol, param_classes, "set argument");

	    (void)setjmp(prompt_env);

	    switch (category)
		{
		case BOX_CLASS:
		    free_annex_list(&Pspec_annex_list);
	            prompt("\tenter %s list (hit return for default)",
			   BOX, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_annex_list)
			    punt(NO_BOXES, (char *)NULL);
			}
		    else
		        annex_list(&Pspec_annex_list, &Pspec_annex_tail);
		    break;

		case PRINTER_CLASS:
	            if (Pspec_printer_set == Pdef_printer_set) {
		        Pspec_printer_set = NULL;
		        Pspec_printer_tail = NULL;
	            } else {
	                free_printer_set(&Pspec_printer_set);
	            }
	            prompt("\tenter printer_set (hit return for default)",
			   NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_printer_set)
			    punt("default printers have not been specified",
			     (char *)NULL);
			}
		    else
		        printer_set(&Pspec_printer_set, &Pspec_printer_tail);
		    break;

		case PORT_CLASS:
	            if (Pspec_port_set == Pdef_port_set) {
		        Pspec_port_set = NULL;
		        Pspec_port_tail = NULL;
	            } else {
	                free_port_set(&Pspec_port_set);
	            }
	            prompt("\tenter port_set (hit return for default)",
			   NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_port_set)
			    punt("default ports have not been specified",
			     (char *)NULL);

			}
		    else
		        port_set(&Pspec_port_set, &Pspec_port_tail,
  			         VIRTUAL_NOT_OK);
		    break;

		case INTERFACE_CLASS:
	            if (Pspec_interface_set == Pdef_interface_set) {
		        Pspec_interface_set = NULL;
		        Pspec_interface_tail = NULL;
	            } else {
	                free_interface_set(&Pspec_interface_set);
	            }
	            prompt("\tenter interface_set (hit return for default)",
			   NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_interface_set)
			    punt("default interfaces have not been specified",
			     (char *)NULL);
			}
		    else
		        interface_set(&Pspec_interface_set, &Pspec_interface_tail);
		    break;

		case T1_CLASS:
	            if (Pspec_t1_set == Pdef_t1_set) {
		        Pspec_t1_set = NULL;
		        Pspec_t1_tail = NULL;
	            } else {
	                free_t1_set(&Pspec_t1_set);
	            }
	            prompt("\tenter t1 set (hit return for default)",
			   NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_t1_set)
			    punt("default t1 engine has not been specified",
			     (char *)NULL);
			}
		    else
		        t1_set(&Pspec_t1_set, &Pspec_t1_tail);
		    break;

		case PRI_CLASS:
	            if (Pspec_pri_set == Pdef_pri_set) {
		        Pspec_pri_set = NULL;
		        Pspec_pri_tail = NULL;
	            } else {
	                free_pri_set(&Pspec_pri_set);
	            }
	            prompt("\tenter WAN module set (hit return for default)",
			   NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_pri_set)
			    punt("default WAN module set has not been specified",
			     (char *)NULL);
			}
		    else
		        pri_set(&Pspec_pri_set, &Pspec_pri_tail);
		    break;

		case MODEM_CLASS:
	            if (Pspec_modem_set == Pdef_modem_set) {
		        Pspec_modem_set = NULL;
		        Pspec_modem_tail = NULL;
	            } else {
	                free_modem_set(&Pspec_modem_set);
	            }
	            prompt("\tenter modem set (hit return for default)",
			   NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_modem_set)
			    punt("default modem set has not been specified",
			     (char *)NULL);
			}
		    else
		        modem_set(&Pspec_modem_set, &Pspec_modem_tail);
		    break;

		}

	    (void)setjmp(prompt_env);

	    prompt("\tenter parameter list", NULLSP, FALSE);
	    }
	else
	    {
	    category = match(symbol, param_classes, "set argument");

	    (void)lex();

	    switch (category)
	        {
		case BOX_CLASS:
	            free_annex_list(&Pspec_annex_list);

	            if (symbol_length == 1 && symbol[0] == '=')
		        {
		        (void)lex();

			if (eos)
			    punt(NO_BOX, (char *)NULL);
			else
			    annex_list(&Pspec_annex_list, &Pspec_annex_tail);
			}

	            break;

		case PRINTER_CLASS:
	            if (Pspec_printer_set == Pdef_printer_set) {
		        Pspec_printer_set = NULL;
		        Pspec_printer_tail = NULL;
	            } else {
	                free_printer_set(&Pspec_printer_set);
	            }

	            if (symbol_length == 1 && symbol[0] == '=')
		        {
		        (void)lex();

			if (eos)
			    punt("missing printer identifier", (char *)NULL);
			else
			    printer_set(&Pspec_printer_set,&Pspec_printer_tail);
			}
	            break;

		case PORT_CLASS:
	            if (Pspec_port_set == Pdef_port_set) {
		        Pspec_port_set = NULL;
		        Pspec_port_tail = NULL;
	            } else {
	                free_port_set(&Pspec_port_set);
	            }

	            if (symbol_length == 1 && symbol[0] == '=')
		        {
		        (void)lex();

			if (eos)
			    punt("missing port identifier", (char *)NULL);
			else
			    port_set(&Pspec_port_set, &Pspec_port_tail,
	                     VIRTUAL_NOT_OK);
			}
	            break;

		case INTERFACE_CLASS:
	            if (Pspec_interface_set == Pdef_interface_set) {
		        Pspec_interface_set = NULL;
		        Pspec_interface_tail = NULL;
	            } else {
	                free_interface_set(&Pspec_interface_set);
	            }

	            if (symbol_length == 1 && symbol[0] == '=')
		        {
		        (void)lex();

			if (eos)
			    punt("missing interface identifier", (char *)NULL);
			else
			    interface_set(&Pspec_interface_set, &Pspec_interface_tail);
			}
	            break;

		case T1_CLASS:
	            if (Pspec_t1_set == Pdef_t1_set) {
		        Pspec_t1_set = NULL;
		        Pspec_t1_tail = NULL;
	            } else {
	                free_t1_set(&Pspec_t1_set);
	            }

	            if (symbol_length == 1 && symbol[0] == '=')
		    {
		        /* GET T1 ENGINE IDENTIFIER */
		        (void)lex();

			/* HANDLE IDENTIFIER ARGUMENT */
			if (eos)
			    punt("missing t1 identifier", (char *)NULL);
			else
			{
			    /* FOR NOW, DEFAULT TO HANDLE ONLY ONE T1 */
			    /* ENGINE... THAT BEING T1 ENGINE NUMBER 1*/
			    if( symbol_length == 1 && symbol[0] != '1' )
			      punt( "invalid t1 engine number" );

			    /* GET NEXT ARGUMENT */
			    (void)lex();			    
			    t1_set(&Pspec_t1_set, &Pspec_t1_tail);
			}
		    }
	            break;

		case PRI_CLASS:
	            if (Pspec_pri_set == Pdef_pri_set) {
		        Pspec_pri_set = NULL;
		        Pspec_pri_tail = NULL;
	            } else {
	                free_pri_set(&Pspec_pri_set);
	            }

	            if (symbol_length == 1 && symbol[0] == '=')
		    {
		        /* GET WAN modULE IDENTIFIER */
		        (void)lex();

			/* HANDLE IDENTIFIER ARGUMENT */
			if (eos)
			    punt("missing WAN identifier", (char *)NULL);
			else
			    pri_set(&Pspec_pri_set, &Pspec_pri_tail);
		    }
	            break;

		case MODEM_CLASS:
	            if (Pspec_modem_set == Pdef_modem_set) {
		        Pspec_modem_set = NULL;
		        Pspec_modem_tail = NULL;
	            } else {
	                free_modem_set(&Pspec_modem_set);
	            }

	            if (symbol_length == 1 && symbol[0] == '=')
		        {
		        (void)lex();

			if (eos)
			    punt("missing modem identifier", (char *)NULL);
			else
			    modem_set(&Pspec_modem_set, &Pspec_modem_tail,
	                     VIRTUAL_NOT_OK);
			}
	            break;

		}	/*switch (category) */

	        if (eos)
	            punt("missing parameter list", (char *)NULL);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Parse the parameter list and perform the set operations. */

	switch (category)
	    {
	    case BOX_CLASS:
	        if (Pspec_annex_list)
	            error = annex_pair_list(Pspec_annex_list);
	        else if (Pdef_annex_list)
	            error = annex_pair_list(Pdef_annex_list);
	        else
	            punt(NO_BOXES, (char *)NULL);

		if (!script_input && !error) {
		    printf(changes_will);
		    msgf = next_boot;
		    msg2 = cr_reset_all;
		    switch(Pset_list->param_num) {
		    case BOX_PASSWORD:
			msgf = imm_local;
			msg = annex_reset_secureserver;
			msg2 = or_reset_all;
			break;

		    case ALLOW_SNMP_SETS:	
		    case VCLI_PASSWORD:
		    case VCLI_SEC_ENA:
			printf(immediately);
			msgf = NULL;
			break;

		    case ACP_KEY:
			printf(or_passwd_cmd);
			msg2 = or_reset_all;
		    case NET_TURNAROUND:
		    case PREF_SECURE_1:
		    case PREF_SECURE_2:
		    case SECURSERVER_BCAST:
		    case ENABLE_SECURITY:
			msg = annex_reset_secureserver;
			break;

		    case NRWHOD:
		    case NMIN_UNIQUE:
		    case HTABLE_SZ:
		    case PRIMARY_NS:
		    case PRIMARY_NS_ADDR:
		    case SECONDARY_NS:
		    case SECONDARY_NS_ADDR:
		    case NAMESERVER_BCAST: 
			msg = annex_reset_nameserver;
			break;

		    case MOTD:
			msg = annex_reset_motd;
			break;

		    case HOST_NAME:
		    case HOST_NUMBER:
		    case SERVICE_LIMIT:
		    case KA_TIMER:
		    case CIRCUIT_TIMER:
		    case RETRANS_LIMIT:
		    case GROUP_CODE:
		    case QUEUE_MAX:
		    case VCLI_GROUPS:
			msg = annex_reset_lat;
			break;

		    default:
			msg = NULL;
			break;
		    }
		    if (msgf == NULL)
			break;
		    printf(msgf,BOX);
		    if (msg != NULL) {
			printf(msg,BOX);
			printf(msg2,BOX);
		    } else
			printf(annex_msg,BOX);
		}
	        break;

	    case PORT_CLASS:
	        if (Pspec_port_set)
	            error = port_pair_list(Pspec_port_set);
	        else if (Pdef_port_set)
	            error = port_pair_list(Pdef_port_set);
	        else
	            punt(NO_BOXES, (char *)NULL);

	        if (!script_input && !error) {
		    printf(changes_will);
		    printf(next_boot,BOX);
		    printf(port_msg);
		}
	        break;

	    case INTERFACE_CLASS:
	        if (Pspec_interface_set)
		    error = interface_pair_list(Pspec_interface_set);
	        else if (Pdef_interface_set)
		    error = interface_pair_list(Pdef_interface_set);
		else
		    punt(NO_BOXES, (char *)NULL);

	        if (!script_input && !error) {
		    printf(changes_will);
		    printf(next_boot,BOX);
		    printf(interface_msg);
		}
	        break;

	    case PRINTER_CLASS:
	        if (Pspec_printer_set)
	            error = printer_pair_list(Pspec_printer_set);
	        else if (Pdef_printer_set)
	            error = printer_pair_list(Pdef_printer_set);
	        else
	            punt(NO_BOXES, (char *)NULL);

	        if (!script_input && !error) {
		    printf(changes_will);
		    printf(next_boot,BOX);
		    printf(printer_msg);
		}
	        break;

	    case T1_CLASS:
	        if (Pspec_t1_set)
	            error = t1_pair_list(Pspec_t1_set);
	        else if (Pdef_t1_set)
	            error = t1_pair_list(Pdef_t1_set);
	        else
	            punt(NO_BOXES, (char *)NULL);

	        if (!script_input && !error) {
		    printf(changes_will);
		    printf(next_boot,BOX);
		    printf(printer_msg);
		}
	        break;

	    case PRI_CLASS:
	        if (Pspec_pri_set)
	            error = pri_pair_list(Pspec_pri_set);
	        else if (Pdef_pri_set)
	            error = pri_pair_list(Pdef_pri_set);
	        else
	            punt(NO_BOXES, (char *)NULL);

	        if (!script_input && !error) {
		    printf(changes_will);
		    printf(next_boot,BOX);
		    printf(pri_msg);
		}
	        break;

	    case MODEM_CLASS:
	        if (Pspec_modem_set)
	            error = modem_pair_list(Pspec_modem_set);
	        else if (Pdef_modem_set)
	            error = modem_pair_list(Pdef_modem_set);
	        else
	            punt(NO_BOXES, (char *)NULL);

	        if (!script_input && !error) {
		    printf(changes_will);
		    printf(next_boot,BOX);
		    printf(modem_msg);
		}
	        break;
	    }

	return error;  
}	/* adm_set_cmd() */



int adm_show_cmd()

{
	int category;

	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);

	    prompt("\tenter \"%s\", \"port\", \"interface\",\"printer\", or \"t1\"", 
                   BOX, FALSE);

	    category = match(symbol, param_classes, "show argument");

	    (void)setjmp(prompt_env);

	    switch (category)
		{
		case BOX_CLASS:
		    free_annex_list(&Pspec_annex_list);
	            prompt("\tenter %s list (hit return for default)",
		           BOX, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_annex_list)
			    punt(NO_BOXES, (char *)NULL);
			}
		    else
		        annex_list(&Pspec_annex_list, &Pspec_annex_tail);
		    break;

		case PRINTER_CLASS:
	            if (Pspec_printer_set == Pdef_printer_set) {
		        Pspec_printer_set = NULL;
		        Pspec_printer_tail = NULL;
	            } else {
	                free_printer_set(&Pspec_printer_set);
	            }
	            prompt("\tenter printer_set (hit return for default)",
		           NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_printer_set)
			    punt("default printers have not been specified",
			     (char *)NULL);
			}
		    else
		        printer_set(&Pspec_printer_set, &Pspec_printer_tail, 
	  			 VIRTUAL_NOT_OK);
	            break;

		case PORT_CLASS:
	            if (Pspec_port_set == Pdef_port_set) {
		        Pspec_port_set = NULL;
		        Pspec_port_tail = NULL;
	            } else {
	                free_port_set(&Pspec_port_set);
	            }
	            prompt("\tenter port_set (hit return for default)",
		           NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_port_set)
			    punt("default ports have not been specified",
			     (char *)NULL);
			}
		    else
		        port_set(&Pspec_port_set, &Pspec_port_tail, 
	  			 VIRTUAL_NOT_OK);
	            break;

		case INTERFACE_CLASS:
	            if (Pspec_interface_set == Pdef_interface_set) {
		        Pspec_interface_set = NULL;
		        Pspec_interface_tail = NULL;
	            } else {
	                free_interface_set(&Pspec_interface_set);
	            }
	            prompt("\tenter interface_set (hit return for default)",
		           NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_interface_set)
			    punt("default interfaces have not been specified",
			     (char *)NULL);
			}
		    else
		        interface_set(&Pspec_interface_set, &Pspec_interface_tail, 
	  			 VIRTUAL_NOT_OK);
	            break;

		case T1_CLASS:
	            if (Pspec_t1_set == Pdef_t1_set) {
		        Pspec_t1_set = NULL;
		        Pspec_t1_tail = NULL;
	            } else {
	                free_t1_set(&Pspec_t1_set);
	            }
	            prompt("\tenter t1 set (hit return for default)",
		           NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_t1_set)
			    punt("default t1 engine has not been specified",
			     (char *)NULL);
			}
		    else
		        t1_set(&Pspec_t1_set, &Pspec_t1_tail, 
	  			 VIRTUAL_NOT_OK);
	            break;

		case PRI_CLASS:
	            if (Pspec_pri_set == Pdef_pri_set) {
		        Pspec_pri_set = NULL;
		        Pspec_pri_tail = NULL;
	            } else {
	                free_pri_set(&Pspec_pri_set);
	            }
	            prompt("\tenter PRI set (hit return for default)",
		           NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_pri_set)
			    punt("default WAN module has not been specified",
			     (char *)NULL);
			}
		    else
		        pri_set(&Pspec_pri_set, &Pspec_pri_tail, 
	  			 VIRTUAL_NOT_OK);
	            break;

		case MODEM_CLASS:
	            if (Pspec_modem_set == Pdef_modem_set) {
		        Pspec_modem_set = NULL;
		        Pspec_modem_tail = NULL;
	            } else {
	                free_modem_set(&Pspec_modem_set);
	            }
	            prompt("\tenter modem set (hit return for default)",
		           NULLSP, TRUE);
		    if (eos)
			{
			(void)lex();
			if (!Pdef_modem_set)
			    punt("default modem set has not been specified",
			     (char *)NULL);
			}
		    else
		        modem_set(&Pspec_modem_set, &Pspec_modem_tail, 
	  			 VIRTUAL_NOT_OK);
	            break;

		}

	    (void)setjmp(prompt_env);

	    prompt("\tenter parameter list (hit return for all)",
	    	   NULLSP, TRUE);

	    if (eos)
		{
		(void)strcpy(command_line, "all");
		Psymbol = command_line;
		eos = FALSE;
		(void)lex();
		}

	    }
	else
	    {
	    category = match(symbol, param_classes, "show argument");

	    (void)lex();

		switch (category)
		    {
		    case BOX_CLASS:
			free_annex_list(&Pspec_annex_list);

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
				punt(NO_BOX, (char *)NULL);
			    else
			        annex_list(&Pspec_annex_list,
				 &Pspec_annex_tail);
			    }

			break;

		    case PRINTER_CLASS:
	                if (Pspec_printer_set == Pdef_printer_set) {
		            Pspec_printer_set = NULL;
		            Pspec_printer_tail = NULL;
	                } else {
	                    free_printer_set(&Pspec_printer_set);
	                }

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
			        punt("missing printer identifier", (char *)NULL);
			    else
			        printer_set(&Pspec_printer_set,&Pspec_printer_tail);
			    }
	                break;

		    case PORT_CLASS:
	                if (Pspec_port_set == Pdef_port_set) {
		            Pspec_port_set = NULL;
		            Pspec_port_tail = NULL;
	                } else {
	                    free_port_set(&Pspec_port_set);
	                }

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
			        punt("missing port identifier", (char *)NULL);
			    else
			        port_set(&Pspec_port_set, &Pspec_port_tail,
				 VIRTUAL_NOT_OK);
			    }
	                 break;

		    case INTERFACE_CLASS:
	                if (Pspec_interface_set == Pdef_interface_set) {
		            Pspec_interface_set = NULL;
		            Pspec_interface_tail = NULL;
	                } else {
	                    free_interface_set(&Pspec_interface_set);
	                }

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
			        punt("missing interface identifier", (char *)NULL);
			    else
			        interface_set(&Pspec_interface_set, &Pspec_interface_tail,
				 VIRTUAL_NOT_OK);
			    }
	                 break;

		    case T1_CLASS:
	                if (Pspec_t1_set == Pdef_t1_set) {
		            Pspec_t1_set = NULL;
		            Pspec_t1_tail = NULL;
	                } else {
	                    free_t1_set(&Pspec_t1_set);
	                }

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
			        punt("missing t1 identifier", (char *)NULL);
			    else
			        t1_set(&Pspec_t1_set, &Pspec_t1_tail,
				 VIRTUAL_NOT_OK);
			    }
	                 break;

		    case PRI_CLASS:
	                if (Pspec_pri_set == Pdef_pri_set) {
		            Pspec_pri_set = NULL;
		            Pspec_pri_tail = NULL;
	                } else {
	                    free_pri_set(&Pspec_pri_set);
	                }

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
			        punt("missing WAN identifier", (char *)NULL);
			    else
			        pri_set(&Pspec_pri_set, &Pspec_pri_tail,
				 VIRTUAL_NOT_OK);
			    }
	                 break;

		    case MODEM_CLASS:
	                if (Pspec_modem_set == Pdef_modem_set) {
		            Pspec_modem_set = NULL;
		            Pspec_modem_tail = NULL;
	                } else {
	                    free_modem_set(&Pspec_modem_set);
	                }

	                if (symbol_length == 1 && symbol[0] == '=')
		            {
		            (void)lex();

			    if (eos)
			        punt("missing modem identifier", (char *)NULL);
			    else
			        modem_set(&Pspec_modem_set, &Pspec_modem_tail,
				 VIRTUAL_NOT_OK);
			    }
	                 break;
		    }
		}

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Parse the parameter list and perform the show operations. */

	open_pager();

	switch (category)
	    {
	    case BOX_CLASS:
	        if (Pspec_annex_list)
	            annex_show_list(Pspec_annex_list);
	        else
		    if (Pdef_annex_list)
			annex_show_list(Pdef_annex_list);
		    else
			punt(NO_BOXES, (char *)NULL);
	        break;

	    case PORT_CLASS:
	        if (Pspec_port_set)
	            port_show_list(Pspec_port_set);
	        else
	            if (Pdef_port_set)
	                port_show_list(Pdef_port_set);
	            else
	                punt("default ports have not been specified",
			 (char *)NULL);
	        break;

	    case INTERFACE_CLASS:
	        if (Pspec_interface_set)
	            interface_show_list(Pspec_interface_set);
	        else
	            if (Pdef_interface_set)
	                interface_show_list(Pdef_interface_set);
	            else
	                punt("default interfaces have not been specified",
			 (char *)NULL);
	        break;

	    case PRINTER_CLASS:
	        if (Pspec_printer_set)
	            printer_show_list(Pspec_printer_set);
	        else
	            if (Pdef_printer_set)
	                printer_show_list(Pdef_printer_set);
	            else
	                punt("default printers have not been specified",
			 (char *)NULL);
	        break;

	    case T1_CLASS:
	        if (Pspec_t1_set)
	            t1_show_list(Pspec_t1_set);
	        else
	            if (Pdef_t1_set)
	                t1_show_list(Pdef_t1_set);
	            else
	                punt("default t1 engine has not been specified",
			 (char *)NULL);
	        break;

	    case PRI_CLASS:
	        if (Pspec_pri_set)
	            pri_show_list(Pspec_pri_set);
	        else
	            if (Pdef_pri_set)
	                pri_show_list(Pdef_pri_set);
	            else
	                punt("default WAN module has not been specified",
			 (char *)NULL);
	        break;

	    case MODEM_CLASS:
	        if (Pspec_modem_set)
	            modem_show_list(Pspec_modem_set);
	        else
	            if (Pdef_modem_set)
	                modem_show_list(Pdef_modem_set);
	            else
	                punt("default modem set has not been specified",
			 (char *)NULL);
	        break;
	    }
	close_pager();

	return 0;
}	/* adm_show_cmd() */



int adm_write_cmd()

{
	ANNEX_ID	   annex_id;
	char               name[FILENAME_LENGTH + 2],
			   filename[FILENAME_LENGTH + 2];
	MustBeSuperuser();

	/* Process the arguments. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\t%s identifier", BOX, FALSE);
	    (void)annex_name(&annex_id, name, 0);

	    (void)setjmp(prompt_env);
	    prompt("\tfilename", NULLSP, FALSE);
	    lex_string();
	    if (symbol_length > FILENAME_LENGTH)
		punt(LONG_FILENAME, (char *)NULL);
	    (void)strcpy(filename, symbol);
	    (void)lex();
	    }
	else
	    {
	    (void)annex_name(&annex_id, name, 0);

	    if (eos)
		punt("missing filename", (char *)NULL);
	    else
		{
		lex_string();
	        if (symbol_length > FILENAME_LENGTH)
		    punt(LONG_FILENAME, (char *)NULL);
	        (void)strcpy(filename, symbol);
		(void)lex();
		}
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Perform the write operation. */

	do_write(filename, &annex_id, name);

	return 0;
}	/* adm_write_cmd() */

int adm_printer_cmd()

{
	PRINTER_SET *Ptemp_printer_set = NULL,
	         *Ptemp_printer_tail = NULL;

	/* Assign the default printer set. */

	/* If no arguments were supplied, set prompt_mode so that they
	   will be prompted for. */
	prompt_mode = (lex() == LEX_EOS);

	if (prompt_mode)
	    {
	    if (script_input)
		punt("missing arguments", (char *)NULL);

	    (void)setjmp(prompt_env);
	    prompt("\tenter default printer set", NULLSP, FALSE);
	    }

	/* Turn off prompt_mode so that subsequent errors will be punted
	   back to the command prompt. */
	prompt_mode = FALSE;

	/* Free the temp printer set in case you came back here after punting.*/
	free_printer_set(&Ptemp_printer_set);

	/*Let a temp point at the printer set in case the human makes a mistake,
	   so that the old default will still be there after punting. */
	printer_set(&Ptemp_printer_set, &Ptemp_printer_tail);

	/* No human mistakes, so move the temp printer set to the default
	   printer set.  Free the default first in case it had been previously
	   entered. */
	free_printer_set(&Pdef_printer_set);
	Pdef_printer_set = Ptemp_printer_set;
	Pdef_printer_tail = Ptemp_printer_tail;

	return 0;
}	/* adm_printer_cmd() */

#if 0
int alternate_table[16];
int alternate_count = 0;
#endif

void init_tables()
{
	int seq,indx,usage;

/*  go through help table  */
	for (seq = 0; D_key(seq) != NULL; seq++) {
	    indx = D_index(seq);
	    usage = D_usage(seq);
#if 0
	    if (usage < 0) {
		alternate_table[alternate_count++] = seq;
		continue;
	    }
#else
	    if (usage < 0)
		continue;
#endif
	    switch (usage) {
	    case A_COMMAND:
		if (indx < NCOMMANDS) {
		    cmd_spellings[indx] = D_key(seq);
		    continue;
		}
		break;

	    case PARAM_CLASS:
		if(indx < NCLASSES) {
		    param_classes[indx] = D_key(seq);
		    continue;
		}
		break;

	    case BOX_PARAM:
	    case BOX_CATEGORY:
		if (indx < NBOXP) {
		    annex_params[indx] = D_key(seq);
		    continue;
		}
		break;

	    case PORT_PARAM:
	    case PORT_CATEGORY:
		if (indx < NPORTP) {
		    port_params[indx] = D_key(seq);
		    continue;
		}
		break;

	    case PRINTER_PARAM:
		if (indx < NPRINTP) {
		    printer_params[indx] = D_key(seq);
		    continue;
		}
		break;

	    case INTERFACE_PARAM:
		if (indx < NINTERFACEP) {
		    interface_params[indx] = D_key(seq);
		    continue;
		}
		break;

	    case T1_PARAM:
	    case T1_DS0_PARAM:
		if (indx < NT1P) {
		    t1_all_params[indx] = D_key(seq);
		    t1_ds0_params[indx] = 
			(usage == T1_DS0_PARAM) ? D_key(seq) : &t1_inval_sym;
		    continue;
		}
		break;
	    case WAN_PARAM:
	    case WAN_CHAN_PARAM:
		if (indx < NWANP) {
		    wan_all_params[indx] = D_key(seq);
		    wan_chan_params[indx] = ((usage == WAN_CHAN_PARAM) ?
					  D_key(seq) : &pri_inval_sym);
		    continue;
		}
		break;
	    case MODEM_PARAM:
		if (indx < NMODEMP) {
		    modem_params[indx] = D_key(seq);
		    continue;
		}
		break;

	    case HELP_ENTRY:
		continue;

	    default:
		printf("Help entry %s invalid usage:  %d\n",
		    D_key(seq),usage);
		continue;
	    }
	    printf("Help entry %s (%s) invalid value: %d\n",
		D_key(seq), usage_table[usage], indx);
	}
	cmd_spellings[NCOMMANDS] = (char *)NULL;
	param_classes[NCLASSES]  = (char *)NULL;
	annex_params[NBOXP]      = (char *)NULL;
	port_params[NPORTP]      = (char *)NULL;
	printer_params[NPRINTP]  = (char *)NULL;
	interface_params[NINTERFACEP]  = (char *)NULL;
	t1_all_params[NT1P]       = (char *)NULL;
	t1_ds0_params[NT1P]       = (char *)NULL;
	wan_all_params[NWANP]       = (char *)NULL;
	wan_chan_params[NWANP]       = (char *)NULL;
	modem_params[NMODEMP]       = (char *)NULL;

	symbol_length = 0;

}	/* init_tables() */
