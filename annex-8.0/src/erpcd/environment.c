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
 * Revision Control Information:
 *
 * $Id: getacpuser.h,v 1.14 1994/09/14 16:53:25 reeve Exp $
 *
 * This file created by RCS from:
 * $Source: /annex/t1/src/erpcd/RCS/getacpuser.h,v $
 *
 * Revision History:
 *
 * $Log: getacpuser.h,v $
 *
 * This file is currently under revision by:
 *
 * $Locker:  $
 *
 *  DATE:	$Date: 1994/09/14 16:53:25 $
 *  REVISION:	$Revision: 1.14 $
 *
 ****************************************************************************
 */

#include "../inc/config.h"
#include <stdio.h>
#include <string.h>
#include "../inc/erpc/nerpcd.h"
#include "acp_policy.h"
#include "time_parser.h"
#include "acp_regime.h"
#include "acp_group.h"
#include "environment.h"

#define FIELD_SEPARATOR ';'
#define BITS_IN_MATCH     7

extern int debug;

/* Keyword structures */

/* Temporary buffer */
char tbuff[MAX_OPTION];


/******************************************************************************
 *
 * create_env
 *
 * This function is called to allocate memory for the environment structure 
 * and initialize the field to known values. This function calls calloc() to 
 * allocate memory for the environment and initialize the memory to zeros 
 * (default values for all elements). The received from calloc is returned.
 *
 * Arguments: None.
 * Return Value: 
 * Returns the address of the memory allocated for the environment. This may 
 * be NULL if the system is out of space.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *****************************************************************************/

struct environment_spec *create_env()
{
  return((struct environment_spec *)calloc(1,sizeof(struct environment_spec)));
}

/******************************************************************************
 *
 * release_env()
 * This function is called to release memory allocate for the environment. 
 * This function will release any memory associated with the group list 
 * and security regime.
 *
 * If there is a group list, then release_group_list() is called with the 
 * address of the group list. If there is a security regime, then 
 * release_security_regime() is called with the address of the security regime.
 * Finally, free() is called with the address of the environment.
 *
 * Arguments: 
 * struct environment_spec *env_p - Address of the environment specification.
 * Return Value: None.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *****************************************************************************/

void release_env(env_p)
struct environment_spec *env_p;
{
   if (env_p)
   {
      /* release the regime node. */
#ifndef _WIN32
      if (env_p->regime)
         release_security_regime(env_p->regime);
#endif

      /* release the group (link) list */
      if (env_p->group_list)
         release_group_list(&(env_p->group_list));

      /* free the allocated memory for env_p */
      free(env_p);
   }
   else
   {
     if (debug)
       fprintf(stderr,"release_env: Attempt to free NULL environment\n");
   }
}


/******************************************************************************
 *
 * best_env_match()
 *
 * This is a new function. The algorithm to determine the best match is 
 * encapsulated in this routine. The current algorithm used is longest
 * match. A new algorithm can be dropped in here and away we go.
 * 
 * Arguments:
 * struct environment_values *values1_p - Which is the best match.
 * struct environment_values *values2_p  
 * Return Value:
 * EQUAL_ENVS    - Both environment values matched the same fields.
 * ENV_1_BETTER  - Environment associated with weight1 is a longer match.
 * ENV_2_BETTER  - Environment associated with weight2 is a longer match.
 * Number of fields matched.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

#if 0   
int best_env_match(values1_p,values2_p)
struct environment_values *values1_p,*values2_p;
{
   int matches1,matches2;
   int i,m1bits = 0,m2bits = 0,retv;

   matches1 = values1_p->matches;
   matches2 = values2_p->matches;

   /* The one with the most bits wins */
   
   /* Count the bits in weights       */
   for(i = BITS_IN_MATCH; i--;)
   {
      if (matches1 & (1 << i))
         ++m1bits;

      if (matches2 & (1 << i))
         ++m2bits; 
   }

   if (m1bits == m2bits)
   {
      retv = EQUAL_ENVS; 
   }
   else if (m1bits > m2bits)
   {
      retv = ENV_1_BETTER; 
   }
   else 
   {
      retv = ENV_2_BETTER; 
   }

   return(retv);
}
#endif/*COMMENTING OUT THIS CODE,NOT USING THIS ROUTINE AT ALL. */
