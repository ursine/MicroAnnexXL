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

#include <sys/types.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <strings.h>
#endif 

#include <setjmp.h>
#include <stdio.h>
#include <errno.h>
#include "../inc/na/na.h"
#include "../netadm/netadm_err.h"

/*
 *	External Definitions
 */
extern int errno;
extern int debug;

/*
 *	Defines and Macros
 */


/*
 *	Structure Definitions
 */


/*
 *	Forward Routine Definitions
 */
#ifdef NA
void punt();
#endif

int lex();
void skip_white_space();
int match();


/*
 *	Global Data Declarations
 */


/*
 *	Static Declarations
 */
static char *netadm_errs[] = {
	"no errors",				/* NAE_SUCC */
	"unsupported address family",		/* NAE_ADDR */
	"erpc timeout",				/* NAE_TIME */
#if TLI
	"tli error",				/* NAE_SOCK init_socket.c */
#else
	"socket error",				/* NAE_SOCK */
#endif
	"read_memory count too large",		/* NAE_CNT */
	"read_memory response too short",	/* NAE_SRES */
	"incorrect parameter type",		/* NAE_TYPE */
	"unsupported response type",		/* NAE_RTYP */
	"invalid courier response",		/* NAE_CTYP */
	"erpc reject; details unknown",		/* NAE_REJ */
	"erpc reject; invalid program number",	/* NAE_PROG */
	"erpc reject; invalid version number",	/* NAE_VER */
	"erpc reject; invalid procedure number",/* NAE_PROC */
	"erpc reject; invalid argument",	/* NAE_ARG */
	"erpc reject; wrong password",		/* NAE_SREJECT */
	"erpc reject; must use SRPC protocol",	/* NAE_SESSION */
	"erpc message abort; details unknown",	/* NAE_ABT */
	"erpc abort; invalid parameter type",	/* NAE_PTYP */
	"erpc abort; invalid parameter count",	/* NAE_PCNT */
	"erpc abort; invalid parameter value",	/* NAE_PVAL */
	"erpc abort; eeprom write error",	/* NAE_E2WR */
	"erpc abort; too many sessions",	/* NAE_RSRC */
	"srpc error; session aborted for unknown reasons", /* NAE_SABORT */
	"does not support program",		/* NAE_NOANXSUP */
	"srpc abort; bad device requested",	/* NAE_BADDEV */
	"srpc abort; internal error",		/* NAE_INTERNAL */
	"erpc abort; can't boot-load a self-boot box" /*NAE_BADBOOT */
};



void prompt(string, arg, empty_ok)

	char string[];
	char *arg;
	int  empty_ok;

{
	int	cmd_cnt,
		read_cnt;
	char	*cmd_p;

	/* Print the prompt string and wait for a response.  If empty_ok
	   is FALSE, repeat until the response is non-empty. */

	do
	    {
	    if (!script_input)
		{
		if (arg == NULLSP)
		    printf("%s: ", string);
		else
		    {
		    printf(string, arg);
		    printf(": ");
		    }
		}

	    cmd_p = command_line;
	    cmd_cnt = sizeof(command_line);
	    while(1)
		{
		if (!fgets(cmd_p, cmd_cnt, cmd_file))
		    {
		    if(ferror(cmd_file) && (errno == EINTR))
			continue;
		    if (!script_input)
			exit(0);
		    else
			{
			eos = TRUE;
			return;
			}
		    }
		read_cnt = strlen(cmd_p);
		cmd_cnt -= read_cnt;
		cmd_p += read_cnt;
	        if(cmd_p == command_line || *(cmd_p - 2) != '\\')
			break;

		*(--cmd_p - 1) = '\n'; /* remove backslash if before newline */
		}
	    Psymbol = command_line;
	    eos = FALSE;
	    } while(lex() == LEX_EOS && !empty_ok);

}	/* prompt() */



int lex()

{
	/* Take the next symbol from the command line. */

	if (eos)
	    return LEX_EOS;

	symbol_length = 0;

	/* Skip white space. */

	skip_white_space();

	if (!*Psymbol)
	    {
	    eos = TRUE;
	    return LEX_EOS;
	    };

	/* Copy the symbol into "symbol"; advance Psymbol; count the symbol's
	   length. */

	if (*Psymbol == '"')
	    {
            int in_escape = 0;
	    Psymbol++;
	    while (*Psymbol)
		if (in_escape) {
		    symbol[symbol_length++] = *Psymbol++;
		    in_escape = 0;
		} else if (*Psymbol == '\\') {
		    symbol[symbol_length++] = *Psymbol++;
		    in_escape = 1;
		} else if (*Psymbol == '"') 
		    break;
                else
		    symbol[symbol_length++] = *Psymbol++;
	    if (*Psymbol)
	        Psymbol++;
	    else
		punt("missing closing delimiter", (char *)NULL);
	    }
	else
	    if (*Psymbol && index(PUNCTUATION, *Psymbol))
	        symbol[symbol_length++] = *Psymbol++;
	    else
	        while (*Psymbol && !index(SEPARATORS, *Psymbol))
	            symbol[symbol_length++] = *Psymbol++;

	symbol[symbol_length] = '\0';

	return LEX_OK;

}	/* lex() */

/*
 *	returns the next switch charaxter in the input or LEX_EOSW
 *	if none are left.  A switch is "-abcd" or -a -b -cd.  The
 *	next switch is returned in symbol.  The inswitch flag tells
 *	if we are in a group of switch chars or we are looking for
 *	a new one.
*/

int lex_switch()

{
	int looking = TRUE;

	/* Take the next symbol from the command line. */

	if (eos)
	    return (LEX_EOS);

	symbol_length = 0;
	while(looking)
	    if (!inswitch){
	        skip_white_space();

       	        if (*Psymbol == '-'){
		    inswitch = TRUE;
	    	    Psymbol++;
		    symbol[symbol_length++] = *Psymbol++;
		    looking = FALSE;
	        }
		else {
		    if(*Psymbol == '\0')
			return (LEX_EOS);
		    break;
		}
	    }
	    else
	       if(*Psymbol && !index(SEPARATORS, *Psymbol)){
	           symbol[symbol_length++] = *Psymbol++;
		   looking = FALSE;
	       }
	       else 
		   inswitch = FALSE;

	symbol[symbol_length] = '\0';

	return (looking ? LEX_EOSW : LEX_OK);

}	/* lex_switch() */

match_flag(string, falseval, trueval, message, defalt)

char	*string,		/* string to be looked up */
	*falseval,		/* string representing bit not set */
	*trueval,		/* string representing bit is set */
	*message;		/* error message to use if no match */

int	defalt;		/* value to return if string is "default" */
{
	int	value;		/* final return value */
	char	*table[4];	/* table */

	/* create table for match() to use */

	table[0] = falseval;
	table[1] = trueval;
	table[2] = "default";
	table[3] = (char *)NULL;

	value = match(string, table, message);

	/* if we matched "default", return the given default value */

	if(value == 2)
	  value = defalt;

	return value;
}


match(string, table, error_string)

	char *string,
	     *table[],
	     *error_string;

{
	unsigned int string_length;
	int  loop,
	     match_count = 0,
	     match_index;
	char error_msg[80];
	char test_delim[80];
	char *start, *delim;
	char alias = FALSE;

	/* Match the string to a spelling in the given lex table.  If a match
	   is found, return its index; if not, punt. */

	string_length = strlen(string);

	for (loop = 0; table[loop]; loop++) {
	    strcpy(test_delim, table[loop]);
	    start = test_delim;
	    alias = FALSE;
	    while (delim = (char *)index(start, ',')) {
		*delim = '\0';
		if (strncasecmp(string, start, string_length) == 0) {
		    match_index = loop;
		    if (string_length == strlen(start)) {
			match_count = 1;
			goto found_exact;
		    }
		    if (!alias)
		      match_count++;
		    alias = TRUE;
		}
		*delim++ = ',';
		start = delim;
	    }
	    if (strncasecmp(string, start, string_length) == 0) {
		match_index = loop;
		if (string_length == strlen(start)) {
		    match_count = 1;
		    goto found_exact;
		}
		if (!alias)
		  match_count++;
	    }
	}

found_exact:
	if (match_count == 0)
	    {
	    if (error_string == NULL)
		return -1;
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, error_string);
	    (void)strcat(error_msg, ": ");
	    (void)strcat(error_msg, string);

	    punt("invalid ", error_msg);
	    }
	else if (match_count > 1)
	    punt("non-unique symbol: ", string);

	return match_index;

}	/* match() */



in_table(table)

	char *table[];

{
	int loop;

	/* Match the current symbol to a spelling in the given lex table.
	   If a match is found, return TRUE; if not, return FALSE. */

	for (loop = 0; table[loop]; loop++)
	    if (strncasecmp(symbol, table[loop], symbol_length) == 0)
	        return TRUE;

	return FALSE;

}	/* in_table() */



void punt(string1, string2)

	char *string1,
	     *string2;

{

	/* This status will be returned by main(). */
	status = 1;

	/* Print the error text, then long-jump back to the last prompt. */

	if (string1)
	    printf("\t%s", string1);

	if (string2)
	    printf("%s", string2);

	if (prompt_mode)
	    {
	    if (string1 || string2);
	    printf("\n");

	    longjmp(prompt_env, 1);
	    }
	else
	    longjmp(cmd_env, 1);

}	/* punt */



void skip_white_space()

{
	/* Advance the command-line pointer to the next non-white character. */

	while (*Psymbol && index(WHITE_SPACE, *Psymbol))
	    Psymbol++;

}	/* skip_white_space() */

static void
print_netadm_error(ename,error)
char *ename;
int error;
{
	printf("%s:  %s\n",ename,
		(error >= 0 && error <
		 sizeof(netadm_errs)/sizeof(netadm_errs[0])) ?
			netadm_errs[error] :
			"internal error; unsupported error code"
		);
}

void
netadm_error(error)
int error;
{
	print_netadm_error("Netadm error",error);
	punt((char *)0,(char *)0);
}

void
token_error(error)
int error;
{
	if (error == NAE_TIME)
		printf("%s:  Not responding\n",symbol);
	else
		print_netadm_error(symbol,error);
}

#ifdef _WIN32
/*
** get login user name.
**
** return user name if success, otherwise return NULL
*/
char *getlogin()
{
	char *uname = (char *)malloc(256);
	DWORD len;

    if (GetUserName(uname,&len))
     	 return(uname);
    else
   	{
      	if(debug)
      		fprintf(stderr,"GetUserName Failed: %d\n", GetLastError());
		return((char *)0);
    }

}
#endif
