/*
 *****************************************************************************
 *
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *     Routine to fill in for __ansi_fflush (needed for ACE/Server v2.0 & v2.1)
 *
 *
 * Original Author:    Created on: 
 *
 *****************************************************************************
*/

/* routine to fill in for __ansi_fflush */

#include <stdio.h>

__ansi_fflush(s)
FILE *s;
{
    return fflush(s);
}
