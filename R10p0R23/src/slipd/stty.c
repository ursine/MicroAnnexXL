/*****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *
 *	TTY Setup for Xenix UDP SL/IP Daemon
 *
 * Original Author:  Paul Mattes		Created on: 01/04/88
 *
 * Revision Control Information:
 *
 * $Header: /annex/common/src/slipd/RCS/stty.c,v 1.5 1993/03/17 18:39:15 carlson Rel $
 *
 * This file created by RCS from:
 * $Source: /annex/common/src/slipd/RCS/stty.c,v $
 *
 * Revision History:
 *
 * $Log: stty.c,v $
 * Revision 1.5  1993/03/17  18:39:15  carlson
 * Making it worse -- sprintf shouldn't be declared for AIX.
 *
 * Revision 1.4  89/04/05  13:57:55  loverso
 * Changed copyright notice
 * 
 * Revision 1.3  88/05/31  17:20:15  parker
 * fix build problems with XENIX/SLIP
 * 
 * Revision 1.2  88/05/24  18:45:55  parker
 * Changes for new install-annex script
 * 
 * Revision 1.1  88/04/15  12:13:18  mattes
 * Initial revision
 * 
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *****************************************************************************/

#define RCSDATE $Date: 1993/03/17 18:39:15 $
#define RCSREV	$Revision: 1.5 $
#define RCSID   "$Header: /annex/common/src/slipd/RCS/stty.c,v 1.5 1993/03/17 18:39:15 carlson Rel $"

#ifndef lint
static char rcsid[] = RCSID;
#endif

/*****************************************************************************
 *									     *
 * Include files							     *
 *									     *
 *****************************************************************************/

#include <sys/types.h>
#include "../inc/config.h"
#include <stdio.h>
#include <termio.h>


/*****************************************************************************
 *									     *
 * Local defines and macros						     *
 *									     *
 *****************************************************************************/

/*****************************************************************************
 *									     *
 * Structure and union definitions					     *
 *									     *
 *****************************************************************************/

struct kwtab {
    char *name;
    unsigned short value;
    };


/*****************************************************************************
 *									     *
 * External data							     *
 *									     *
 *****************************************************************************/

extern int debug;

#ifndef SYS_V
#ifndef AIX
char		*sprintf();
#endif
#endif

/*****************************************************************************
 *									     *
 * Global data								     *
 *									     *
 *****************************************************************************/

/*****************************************************************************
 *									     *
 * Static data								     *
 *									     *
 *****************************************************************************/

static struct kwtab baud_t[] = {
    { "50", B50 },
    { "75", B75 },
    { "110", B110 },
    { "134", B134 },
    { "150", B150 },
    { "200", B200 },
    { "300", B300 },
    { "600", B600 },
    { "1200", B1200 },
    { "1800", B1800 },
    { "2400", B2400 },
    { "4800", B4800 },
    { "9600", B9600 },
    { "exta", EXTA },
    { "extb", EXTB },
    { (char *)0, 0 }
    };

static struct kwtab stopb_t[] = {
    { "1", 0 },
    { "2", CSTOPB },
    { (char *)0, 0 }
    };

static struct kwtab parity_t[] = {
    { "none", 0 },
    { "odd", 1 },
    { "even", 2 },
    { (char *)0, 0 }
    };


/*****************************************************************************
 *									     *
 * Forward definitions							     *
 *									     *
 *****************************************************************************/

static int kw_search(table, keyword, result)
struct kwtab table[];
char *keyword;
unsigned short *result;
{
    int i;

    for(i = 0; table[i].name; ++i) {
	if(!strcmp(table[i].name, keyword)) {
	    *result = table[i].value;
	    return(1);
	    }
	}

    return(0);
    }

int sV_stty(ttyname, fd, kw, cnt, parmrk)
char *ttyname;
int fd;
char kw[][10];
int cnt;
int *parmrk;
{
    struct termio t;
    unsigned short c;
    int i;
    unsigned short baud = B9600, stopb = 0, parity = 0;
    char command[32];

    for(i = 0; i < cnt; ++i) {
	if(kw_search(baud_t, kw[i], &baud))
	    continue;
	else if(kw_search(stopb_t, kw[i], &stopb))
	    continue;
	else if(kw_search(parity_t, kw[i], &parity))
	    continue;
	else {
	    fprintf(stderr, "unknown terminal characteristic: %s\n", kw[i]);
	    exit(1);
	    }
	}

    *parmrk = parity ? 1 : 0;

    if(ioctl(fd, TCGETA, &t) == -1)
	return(-1);

    t.c_iflag = IGNBRK | (parity ? (PARMRK | INPCK) : 0);
    t.c_oflag = 0;
    c = t.c_cflag;

    c = (c & ~CBAUD) | baud;
    c = (c & ~CSIZE) | CS8;
    c = (c | stopb | CREAD | CLOCAL) & ~LOBLK;
    if(parity) {
	c |= PARENB;
	if(parity == 1)
	    c |= PARODD;
	else
	    c &= ~PARODD;
	}
    else
	c &= ~PARENB;

    t.c_cflag = c;
    t.c_lflag = 0;	/* raw mode */
    t.c_line = 0;	/* standard line discipline */

    for(i = 0; i < NCC; ++i)
	t.c_cc[i] = 0;
    t.c_cc[VEOF] = 1;	/* Require at least 1 character */
    t.c_cc[VEOL] = 30;	/* Wake up every 3 seconds regardless */

    if(ioctl(fd, TCSETA, &t) == -1)
	return(-1);

    if(debug) {
	fprintf(stderr, "\n");
	sprintf(command, "stty -a <%s", ttyname);
	system(command);
	}

    return(0);
    }
