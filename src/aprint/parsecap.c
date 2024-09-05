/*
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale is strictly prohibited.
 *
 * Module Description:
 *
 * routines to parse /etc/printcap
 *
 * Original Author: Jack Oneil		Created on: June 3, 1986
 *
 * Module Reviewers: harris oneil lint
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/./aprint/RCS/parsecap.c,v 2.5 1994/09/23 11:51:47 carlson Exp $
 *
 * This file created by RCS from:
 *
 * $Source: /annex/common/src/./aprint/RCS/parsecap.c,v $
 *
 * Revision History:
 *
 * $Log: parsecap.c,v $
 * Revision 2.5  1994/09/23  11:51:47  carlson
 * SPR 3556 -- more picky compiler complaints.
 *
 * Revision 2.4  1989/04/05  12:08:15  loverso
 * Changed copyright notice
 *
 * Revision 2.3  88/05/24  18:19:17  parker
 * Changes for new install-annex script
 * 
 * Revision 2.2  87/09/23  22:15:47  loverso
 * changes to have formfeed string passed back via printcap_lookup()
 * rather than handled as a external global variable.
 * 
 * Revision 2.1  87/08/15  00:12:46  loverso
 * much fixed up version of the parsing routines, for 2.1 aprint
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *****************************************************************************
 */

#define RCSDATE $Date: 1994/09/23 11:51:47 $
#define RCSREV	$Revision: 2.5 $
#define RCSID   "$Header: /annex/common/src/./aprint/RCS/parsecap.c,v 2.5 1994/09/23 11:51:47 carlson Exp $"
#ifndef lint
static char rcsid[] = RCSID;
#endif


/*
 *	Include Files
 */
#include "../inc/config.h"

#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "aprint.h"

/*
 *	External Definitions
 */

extern int errno;
extern void fatal();

/*
 *	Forward Data Definitions
 */

char *copyto();

/*
 *	Global Data Declarations
 */

FILE *printcap;					/* printcap file, when open */
char p[BUFSIZ];					/* printcap buffer */
int px;							/* count into p[] */

/*
 * function: determine if printer specified exists in /etc/printcap
 *   if it exists, lookup "ra" and "al" capabilities which define
 *   the Annex network address and Annex port number (line) respectively
 *   (Must have "ra" capability to be an Annex printer, "al" if on serial line).
 *   Also, if you find an "ff" entry, return that, too.
 *
 * exit:
 *   *a_name contains a pointer to the string with the hostname of the Annex
 *   *a_line contains a the annex port #, 0 for parallel, 1-X for serial line
 *   *ff contains a pointer to the formfeed string
 */
void
printcap_lookup(p_name, a_name, a_line, ff)
char *p_name;
char **a_name;
int *a_line;
char **ff;
{
    errno = 0;
    printcap = fopen (PRINTCAP, "r");
    if (printcap == NULL)
    	fatal(PRINTCAP,CNULL);

	/*
	 * load in printcap entry for this printer, if it exists
	 */
    find_printer (p_name);
    parse_pname (p_name);

	/*
	 * gleam the info we want
	 */
    px = find_string (":ra=", &p[0]);
    if (px == 0)
		fatal(CNULL,"%s is not an Annex printer", p_name);
	*a_name = copyto(":",&p[px+4]);			/* 4 = offset for :ra= param */

    px = find_string (":al#", &p[0]);
    if (px != 0)
		*a_line = atoi(&p[px+4]);			/* 4 = offset for :al# param */

    px = find_string (":ff=", &p[0]);
    if (px != 0)
		*ff = copyto(":",&p[px+4]);			/* 4 = offset for :ff# param */

	(void) fclose(printcap);
}

/*
 * function: locate printer name in /etc/printcap
 *   bomb out if it cannot be found
 *
 * entry:  
 *   printcap is a FILE token for /etc/printcap
 * exit: 
 *   printer has been located and printcap is at 1st char after name
 */
find_printer (p_name)
char *p_name;
{
    int state = 1, match = 0;
    char chr;

#ifdef DEBUG
	fprintf(stderr,"looking for printer <%s>\n", p_name);
#define STATE(state) fprintf(stderr,"\n%s: ",state?"PARSING PRINTER NAME":"LOOKING FOR LINE WITH PRINTER NAME")
	STATE(state);
#endif
    while (match == 0) {
		chr = get_char(p_name);
#ifdef DEBUG
		fputc(chr,stderr);
#endif
		switch (state) {
			case 0:  /* looking for line with printer names */
 	    		if (chr == '\n' && isalnum(chr=get_char(p_name))) {
		    		px = 0;
		    		p[px++] = chr;
				    state = 1;
#ifdef DEBUG
					STATE(state);
#endif
				}
	    		break;

			case 1:  /* parsing printer name */
	    		if (chr != '|'  &&  chr != ':' && chr != '\n')
					p[px++] = chr;
	    		else {
					p[px] = 0;
					px = 0;
#ifdef DEBUG
					fprintf(stderr,"\nCHECKING <%s>\n",p);
#endif
					if (strcmp (&p[0], p_name) == 0)
		    			match = 1;
					else if (chr == ':') {
		    			state = 0;
#ifdef DEBUG
						STATE(state);
#endif
					}
	    		}
				break;
		}
    }
}

/*
 * parse_pname: parse printer entry into a null terminated string
 *    for further processing - enter with file pointer just past
 *    the printer name (or a synonym for the printer name)
 */
parse_pname (p_name)
char *p_name;
{
    int continuation = 0;
	char chr;

#ifdef DEBUG
	fprintf(stderr,"parsing printer <%s> - skipping: ", p_name);
#endif
    while ((chr=get_char(p_name)) != '\n')
#ifdef DEBUG
		fputc(chr, stderr);
#endif
		;
#ifdef DEBUG
	fprintf(stderr,"\nparsing: ");
#endif
    px = 0;
    for (;;) {
		chr = get_char (p_name);
#ifdef DEBUG
		fputc(chr, stderr);
#endif
		if (chr == '\n' && continuation == 0) {
			p[px++] = ':';			/* make sure last entry ":" terminated */
			p[px] = 0;
			break;
	    }
		if (isspace(chr))
	    	continue;
		if (chr == '\\') {
			continuation = 1;
	    	continue;
		}
		continuation = 0;
		p[px++] = chr;
    }
#ifdef DEBUG
	fprintf(stderr,"\nPARSED\n");
#endif
}

/*
 * function: read char from /etc/printcap and return value, 
 *   print unknown printer if we hit end of file here
 */
get_char (p_name)
char *p_name;
{
	char c;

    c = getc(printcap);
    if (feof(printcap) != 0)
		fatal(CNULL,"unknown printer %s", p_name);
    return (c);
}

/*
 * find_string: search for sub-string within a string
 *              The empty string will always be found
 */

find_string (sub_string, string)
char *sub_string, *string;
{
    int sbx = 0, stx = 0, matching = 1, m_start = 0;

    while (string[stx] != 0) {
		if (sub_string[sbx] == 0)
	    	break;
		if (matching == 1) {
	    	if (sub_string[sbx] == string[stx]) {
				sbx++;
				stx++;
	    	} else {
				matching = 0;
				sbx = 0;
				stx = ++m_start;
	    	}
		} else {
	    	if (sub_string[sbx] == string[stx]) {
				sbx++;
				m_start = stx++;
				matching = 1;
	    	} else
				stx++;
		}
    }
	/*
	 *	check if we got partial match of start of sub_string at end of string
	 */
	if (sub_string[sbx] != 0)
		matching = 0;

#ifdef DEBUG
	fprintf(stderr,"%s string %s at loc %d in %s\n",matching==1 ? "found": "didn't find",sub_string,m_start,string);
#endif
    return (matching == 1)? m_start : 0;
}

/*
 * copyto: copy from input string upto a NUL or character from a list
 *         of seperators, copying into malloc'd space
 */

char *
copyto(sep, from)
char *sep, *from;
{
	char *malloc(), *end = from, *new;

#ifdef DEBUG
	fprintf(stderr,"copyto(\"%s\",\"%s\")\n", sep, from);
#endif
	while (*end && index(sep, *end)==NULL)
		end++;

#ifdef DEBUG
	fprintf(stderr,"got %d bytes\n", end-from);
#endif
	
	if ((new = malloc((unsigned) (end-from) + 1)) == NULL)
		fatal("malloc",CNULL);

	*(new + (end-from)) = '\0';		/* just to be sure */

	return ((char *)strncpy(new, from, end-from));
}
