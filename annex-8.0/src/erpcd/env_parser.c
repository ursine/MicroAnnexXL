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
 * Original Author: Chris Losso		Created on: 5/15/95
 *
 ****************************************************************************
 */

#include "../inc/config.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#ifdef _WIN32
#include "../inc/port/port.h"
#include "acp_policy.h"
#include "../inc/rom/syslog.h"
int syslog( int pri, const char *format, ...);
#else
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <syslog.h>
#endif

#include "acp_regime.h"
#include "../inc/erpc/nerpcd.h"
#include "time_parser.h"
#include "acp_group.h"
#include "environment.h"
#include "getacpuser.h"

/* #define DEBUG_ENVPARSE 1 */ 

#define MAX_PORT_REP MAX_PORTS
#define SP ' '
#define PROF_CRIT_DELIM ';'
#define RANGE_SYMBOL   '-'
#define PORT_DELIMITER ','
#define BITS_IN_BYTE  8
#define BITS_IN_INT  (sizeof(int) * BITS_IN_BYTE)

extern int debug;

int extract_annex_data();
int extract_endpoint_data();
int extract_group_data();
int extract_port_data();
int extract_port_type();
int extract_ports();
int extract_protocol_data();
int extract_regime_data();
int extract_time_data();
int extract_username_data();
int is_gropup_listed_wild_match();   /*new fxn for matching groups w/wildcard*/
int get_keyword_index();
void PrependDomainName();
int is_group_listed_wild_match();
int match_endpoint();
int extract_port_list();

#define MAX_ENV_KEYWORDS 8

/* Due to the design of the parser, all keywords must end with an
 * equal sign (ugh).
 */
#define ENV_FIELD_KW_ANNEX	"annex="
#define ENV_FIELD_KW_GROUP	"group="
#define ENV_FIELD_KW_PORTS	"ports="
#define ENV_FIELD_KW_PROTOCOL	"protocol="
#define ENV_FIELD_KW_REGIME	"regime="
#define ENV_FIELD_KW_TIME	"time="
#define ENV_FIELD_KW_USERNAME	"username="
#define ENV_FIELD_KW_ENDPOINT	"endpoint="

struct keywords_func environment_keywords[MAX_ENV_KEYWORDS] = {
   { ENV_FIELD_KW_ANNEX    , extract_annex_data    , 6 },
   { ENV_FIELD_KW_GROUP    , extract_group_data    , 6 },
   { ENV_FIELD_KW_PORTS    , extract_port_data     , 6 },
   { ENV_FIELD_KW_PROTOCOL , extract_protocol_data , 9 },
   { ENV_FIELD_KW_REGIME   , extract_regime_data   , 7 },
   { ENV_FIELD_KW_TIME     , extract_time_data     , 5 },
   { ENV_FIELD_KW_USERNAME , extract_username_data , 9 },
   { ENV_FIELD_KW_ENDPOINT , extract_endpoint_data , 9 },
};



#define FIELD_SEPARATOR ';'

/* All keyword values should be greater than 0 */
#define NO_MASK         0
#define PPP_PROTOCOL    SERVICE_PPP    /*from acp_policy.h. These values are*/
#define SLIP_PROTOCOL   SERVICE_SLIP   /*sent in the security authentication*/
#define RLOGIN_PROTOCOL SERVICE_RLOGIN /*requests to the routines such as   */
#define TELNET_PROTOCOL SERVICE_TELNET /*port_to_annex etc*/
#define CLI_PROTOCOL    SERVICE_CLI    /*first of 5 (see match_env_options()*/

#define MAX_PROTOCOLS 5

#define ENV_PROTO_KW_PPP	"ppp"
#define ENV_PROTO_KW_SLIP	"slip"
#define ENV_PROTO_KW_CLI	"cli"
#define ENV_PROTO_KW_RLOGIN	"rlogin"
#define ENV_PROTO_KW_TELNET	"telnet"

struct keyword_data protocol_keywords[MAX_PROTOCOLS] = {
{ ENV_PROTO_KW_PPP    , PPP_PROTOCOL    , 3},
{ ENV_PROTO_KW_SLIP   , SLIP_PROTOCOL   , 4},
{ ENV_PROTO_KW_CLI    , CLI_PROTOCOL    , 3},
{ ENV_PROTO_KW_RLOGIN , RLOGIN_PROTOCOL , 6},
{ ENV_PROTO_KW_TELNET , TELNET_PROTOCOL , 6}
};

#define MAX_REGIMES 8

#define ENV_REGIME_KW_ACP	"acp"
#define ENV_REGIME_KW_SAFEWORD	"safeword"
#define ENV_REGIME_KW_KERBEROS	"kerberos"
#define ENV_REGIME_KW_NATIVE	"native"
#define ENV_REGIME_KW_SECURID	"securid"
#define ENV_REGIME_KW_DENY	"deny"
#define ENV_REGIME_KW_NONE	"none"
#define ENV_REGIME_KW_RADIUS    "radius"

struct keyword_data security_keywords[MAX_REGIMES] = {
   {ENV_REGIME_KW_ACP      , ACP_MASK      , 3},
   {ENV_REGIME_KW_SAFEWORD , SAFEWORD_MASK , 6},
   {ENV_REGIME_KW_KERBEROS , KERBEROS_MASK , 8},
   {ENV_REGIME_KW_NATIVE   , NATIVE_MASK   , 6},
   {ENV_REGIME_KW_SECURID  , SECURID_MASK  , 7},
   {ENV_REGIME_KW_DENY     , DENY_MASK     , 4},
   {ENV_REGIME_KW_NONE     , NONE_MASK     , 4},
   {ENV_REGIME_KW_RADIUS   , RADIUS_MASK   , 6}
};

char ebuff[MAX_OPTION];
char sbuf[512];

static char *ptypenames[DEV_MAX] = {
"asy", "syn", "pts", "do", "en", "rcf", "ta", "ctl", "mp", "vpn", "gsy"
};

/* NOTE: All port numbers (n) below must be 0-based (not 1-based)!! */
#define SETPORT(n, pa) (((char *)pa)[n/BITS_IN_BYTE] |= 1<<(n%BITS_IN_BYTE))
#define ISSETPORT(n,pa) (((char *)pa)[n/BITS_IN_BYTE] & 1<<(n%BITS_IN_BYTE))



/*****************************************************************************
 *
 * NAME:  env_print_ports(env_string,values_p)
 * env_print_ports
 * Print a ports specification
 * IN  ports_p		ports array
 * Results: returns list of ports in ports bitmap
 * NOTE:  Results are written into a static buffer that is overwritten by
 * 	  each successive call.
 */
char *env_print_ports(ports_p,ptype)
char *ports_p;
int ptype;
{
	static char retbuf[512];	/* TODO: Size for this? */
	char cur_port[128];		/* Could be a range */
	char port_sep[2];
	int which_bit;
	int printed_one = 0;
	int lo_range = -1;		/* Not in a range yet */
	int hi_range;

	/* Clear out array */
	(void) strcpy(retbuf, ptypenames[ptype]);

	/* Copy port separator into string for convenience */
	(void) sprintf(port_sep, "%c", PORT_DELIMITER);

	/* Loop through all bits, printing entries as found */
	for (which_bit = 0; which_bit < MAX_PORT_REP; which_bit++) 
	  /* Check to see if the bit is set */
	  if (ISSETPORT(which_bit,ports_p)) {
	    /* Record as beginning of lo range if
	     * we are currently not in a range.
	     */
	    if(lo_range == -1)
	      lo_range = which_bit + 1;
	  } else if (lo_range != -1) {
	    /* Print any range saved up */
	    if(printed_one)
	      (void) strcat(retbuf, port_sep);
			
	    /* Calculate the port # - remember to
	     * subtract one, since we're actually at
	     * the first port beyond the range. 
	     */
	    hi_range = which_bit;
				
	    /* Now print the range itself */
	    if(hi_range == lo_range) {
	      /* Single port */
	      (void) sprintf(cur_port, "%d", 
			     lo_range);
	    } else if((hi_range - lo_range == 1)) {
	      /* Only two ports */
	      (void) sprintf(cur_port, "%d%c%d",
			     lo_range, PORT_DELIMITER,
			     hi_range);
	    } else {
	      /* Larger range */
	      (void) sprintf(cur_port, "%d%c%d",
			     lo_range, RANGE_SYMBOL,
			     hi_range);
	    }

	    /* Print it, and turn off the range 
	     * indicator.
	     */
	    (void) strcat(retbuf, cur_port);
	    lo_range = -1;

	    /* Say we did one */
	    printed_one = 1;
	  }

	/* Even though we're finished with the loop, we might have had
	 * a range that included the highest ports.  If so, print them
	 * now.
	 */

	if(lo_range != -1) {
		/* Print any range saved up */
		if(printed_one)
			(void) strcat(retbuf, port_sep);

		/* Calculate the port # - remember to
		 * subtract one, since we're actually at
		 * the first port beyond the range. 
		 */
		hi_range = which_bit;
				
		/* Now print the range itself */
		if(hi_range == lo_range) {
			/* Single port */
			(void) sprintf(cur_port, "%d", lo_range);
		} else if((hi_range - lo_range == 1)) {
			/* Only two ports */
			(void) sprintf(cur_port, "%d%c%d", lo_range, 
				PORT_DELIMITER, hi_range);
		} else {
			/* Larger range */
			(void) sprintf(cur_port, "%d%c%d", lo_range, 
				RANGE_SYMBOL, hi_range);
		}

		/* Print it, and turn off the range indicator. */
		(void) strcat(retbuf, cur_port);
		lo_range = -1;

		/* Say we did one */
		printed_one = 1;
	}

	if (!printed_one)
	  retbuf[0] = '\0';

	/* Return the buffer */
	return(retbuf);
} /* env_print_ports */

/******************************************************************************
 * env_print_protocols
 * Print a protocol specification
 * IN  protocol		protocol mask
 * Results: returns list of protocols in protocol bitmap
 * NOTE:  Results are written into a static buffer that is overwritten by
 * 	  each successive call.
 */
char *env_print_protocols(protocol)
int protocol;
{
	static char retbuf[128];	/* TODO: Size for this? */
	char port_sep[2];
	int which_proto;
	int printed_one = 0;

	/* Clear out array */
	(void) strcpy(retbuf, "");

	/* Put port separator in string for convenience */
	(void) sprintf(port_sep, "%c", PORT_DELIMITER);

	/* Loop through all bits, printing entries as found */
	for(which_proto = 0; which_proto < MAX_PROTOCOLS; which_proto++) 
		/* Check to see if the bit is set */
		if(protocol == protocol_keywords[which_proto].mask) {
			if(printed_one)
				(void) strcat(retbuf, port_sep);
		
			/* Add the protocol keyword */	
			(void) strcat(retbuf, 
				protocol_keywords[which_proto].keyword);

			/* Say we did one */
			printed_one = 1;
		}

	/* Return the buffer */
	return(retbuf);
} /* env_print_protocols */

/******************************************************************************
 * env_print_regimes
 * Print a regime specification
 * IN  regime		regime mask
 * Results: returns list of regimes in regime bitmap
 * NOTE:  Results are written into a static buffer that is overwritten by
 * 	  each successive call.
 */
char *env_print_regimes(regime)
int regime;
{
	static char retbuf[128];	/* TODO: Size for this? */
	char port_sep[2];
	int which_regime;
	int printed_one = 0;

	/* Clear out array */
	(void) strcpy(retbuf, "");

	/* Put port separator in string for convenience */
	(void) sprintf(port_sep, "%c", PORT_DELIMITER);

	/* Loop through all bits, printing entries as found */
	for(which_regime = 0; which_regime < MAX_PROTOCOLS; which_regime++) 
		/* Check to see if the bit is set */
		if(regime == security_keywords[which_regime].mask) {
			if(printed_one)
				(void) strcat(retbuf, port_sep);
		
			/* Add the protocol keyword */	
			(void) strcat(retbuf, 
				security_keywords[which_regime].keyword);

			/* Say we did one */
			printed_one = 1;
		}

	/* Return the buffer */
	return(retbuf);
} /* env_print_regimes */

/******************************************************************************
 * env_print_values
 * Print an environment specification string
 * IN  env_p		environment values specification
 * Results:  Returns environment specification string
 * NOTE:  Results are written into a static buffer that is overwritten by
 * 	  each successive call.
 */
char *env_print_values(env_p)
struct environment_values *env_p;
{
	static char retbuf[512];	/* TODO: Is there a max len? */
	int printed_one = 0;		/* Boolean: for semicolons */
	int did_ports_once,ptype;
	char field_sep[2];		/* Convenience */
	char quote_char[2];
	char *tmp_p;

	/* Clear out the buffer */
	(void) strcpy(retbuf, "");

	/* Put the field separator in a string, for convenience */
	(void) sprintf(field_sep, "%c", FIELD_SEPARATOR);
	(void) sprintf(quote_char, "\"");

	/* Print the username if it exists */
	if(strlen(env_p->username)) {
		/* Print the field name and the value.  Equal
		 * signs are embedded in the field names.  ugh.
		 */
		(void) strcat(retbuf, ENV_FIELD_KW_USERNAME);		
		(void) strcat(retbuf, env_p->username);
		printed_one = 1;	/* Printed an entry */
	}

	/* Print the groupname if it exists */
	if(strlen(env_p->groupname)) {
		/* If we've already printed an entry, add a field
		 * separator between the fields.
		 */
		if(printed_one)
			(void) strcat(retbuf, field_sep);
	
		/* Print the field name and the value.  Equal
		 * signs are embedded in the field names.  ugh.
		 */
		(void) strcat(retbuf, ENV_FIELD_KW_GROUP);		
		(void) strcat(retbuf, env_p->groupname);
		printed_one = 1;	/* Printed an entry */
	}

	/* Print the annex name if it exists */
	if(strlen(env_p->annex)) {
		/* If we've already printed an entry, add a field
		 * separator between the fields.
		 */
		if(printed_one)
			(void) strcat(retbuf, field_sep);
	
		/* Print the field name and the value.  Equal
		 * signs are embedded in the field names.  ugh.
		 */
		(void) strcat(retbuf, ENV_FIELD_KW_ANNEX);		
		(void) strcat(retbuf, env_p->annex);
		printed_one = 1;	/* Printed an entry */
	}

	/* Print the port information if it exists */
	did_ports_once = 0;
	for (ptype = 0; ptype < DEV_MAX; ptype++) {
	  tmp_p = env_print_ports(env_p->ports[ptype],ptype);

	  if (tmp_p[0] != '\0') {
		/* If we've already printed an entry, add a field
		 * separator between the fields.
		 */
		if(printed_one)
			(void) strcat(retbuf, field_sep);
		printed_one = 1;	/* Printed an entry */
		if (!did_ports_once) {
		  /* Print the field name and the value.  Equal
		   * signs are embedded in the field names.  ugh.
		   */
		  (void) strcat(retbuf, ENV_FIELD_KW_PORTS);		
		  did_ports_once = 1;
		}
		(void) strcat(retbuf, tmp_p);
	  }
	}

	/* Print the protocol information if it exists */
	tmp_p = env_print_protocols(env_p->protocol);

	if(strlen(tmp_p)) {
		/* If we've already printed an entry, add a field
		 * separator between the fields.
		 */
		if(printed_one)
			(void) strcat(retbuf, field_sep);
	
		/* Print the field name and the value.  Equal
		 * signs are embedded in the field names.  ugh.
		 */
		(void) strcat(retbuf, ENV_FIELD_KW_PROTOCOL);		
		(void) strcat(retbuf, tmp_p);
		printed_one = 1;	/* Printed an entry */
	}

	/* Print the regime information if it exists */
	tmp_p = env_print_regimes(env_p->regime);

	if(strlen(tmp_p)) {
		/* If we've already printed an entry, add a field
		 * separator between the fields.
		 */
		if(printed_one)
			(void) strcat(retbuf, field_sep);
	
		/* Print the field name and the value.  Equal
		 * signs are embedded in the field names.  ugh.
		 */
		(void) strcat(retbuf, ENV_FIELD_KW_REGIME);		
		(void) strcat(retbuf, tmp_p);
		printed_one = 1;	/* Printed an entry */
	}

	/* Print the time information if it exists */
	if(env_p->time_format) {
		tmp_p = time_print_range(&(env_p->start_time),
			&(env_p->end_time), env_p->time_format);

		if(strlen(tmp_p)) {
			/* If we've already printed an entry, add a field
			 * separator between the fields.
			 */
			if(printed_one)
				(void) strcat(retbuf, field_sep);
	
			/* Print the field name and the value.  Equal
			 * signs are embedded in the field names.  ugh.
			 */
			(void) strcat(retbuf, ENV_FIELD_KW_TIME);		
			(void) strcat(retbuf, quote_char);
			(void) strcat(retbuf, tmp_p);
			(void) strcat(retbuf, quote_char);
			printed_one = 1;	/* Printed an entry */
		}
	}

	/* Finally, return the result */
	return(retbuf);

} /* env_print_values */

/******************************************************************************
 *
 * DESCRIPTION: The function parses through the env_string looking for keywords
 *              and then depending on a match it proceeds to take action 
 *              according to the one described in the struct
 *              environment_keywords[] defined above as Global
 *            
 * ARGUMENTS:  env_string- pointer to the environment string 
 *             values_p - a pointer to the struct environment_values
 *
 * RETURN VALUE: 0 on failure and 
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: 
 *
 */
int env_keyword_routine(env_string,values_p)
char *env_string;
struct environment_values *values_p;
{
   char sbuf[256];
   int keyword_index = -1, num_of_keywords;
   int good_options = 0, option_return;

   num_of_keywords = sizeof(environment_keywords)/sizeof(struct keywords_func);

   while(*env_string != '\0'){
	if(debug > 4)
           fprintf(stderr, "env_string %s\n", env_string);
     keyword_index = get_keyword_index(&env_string, environment_keywords, num_of_keywords);
     if(keyword_index != -1){
       option_return = (*(environment_keywords[keyword_index].action))(&env_string, values_p);
	if(debug > 8)
           fprintf(stderr, "option_return %d\n", option_return);
       if (option_return)
         good_options |= option_return;
       else{
         sprintf(sbuf,"Duplicate keyword found: %s", environment_keywords[keyword_index].keyword);
#ifdef USE_SYSLOG
	 syslog(LOG_ERR, sbuf); 
#endif	 
		 return(-1);
       }
     }
     else{
       syslog(LOG_ERR, "Invalid keyword found: %s", env_string);
       return(-1);  /* bad keyword */
     }
   }
   return(good_options);
 }

/*****************************************************************************
 *
 * NAME: get_keyword_index(env_string, keywords, num_of_keywords)
 *
 * DESCRIPTION: The function searches the structure of keywords to find a 
 *              match.
 *            
 * ARGUMENTS:  env_string- a pointer to the environment string
 *             keywords - a pointer to a static struct of type keywords_func
 *             num_of_keywords - the number of keywords in the static struct.
 *
 * RETURN VALUE: -1 if no match else the index.
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: 
 *
 */
int
get_keyword_index(env_string, keywords, num_of_keywords)
char **env_string;
struct keywords_func *keywords;
int num_of_keywords;
{


       while(!isalpha(**env_string))
         ++(*env_string);
       return(match_keyword(env_string, keywords, num_of_keywords));

}

/******************************************************************************
 *
 * match_keyword()
 * This function attempts to match the current field in the environment
 * string with a environment keyword. If a match is found, then the
 * environment string pointer will be pointing to first character after
 * the keyword and the index of the keyword data extraction function is
 * returned. Otherwise the environment string pointer is not updated and a
 * value of zero is returned.
 *
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct keywords_func *keywords - the pointer to the static array struct of
 *                                  keywords
 * int num_of_keywords - the number of keywords present in the array.
 *
 * Return Value:
 * On success, the index of the environment keywords entry is returned.
 * Otherwise a value of -1 is returned.
 * Side Effects: On success, the address in string_p is updated to point
 *               to the first character after the keyword.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/
int
match_keyword(string_p, keywords, num_of_keywords)
char **string_p;
struct keywords_func *keywords;
int num_of_keywords;
{
   int i;

   for(i = 0; i < num_of_keywords; ++i)
   {
      if (!strncasecmp(*(string_p),
                       keywords[i].keyword,
                       keywords[i].len))
      {
        if(debug)
         fprintf(stderr, "keyword %s, length %d\n", keywords[i].keyword,keywords
[i].len);
         (*string_p) += keywords[i].len;
         return(i);
      }
   }

   return(-1);
}


/******************************************************************************
 *
 * get_keyword_mask()
 * This function runs through the list of keyword structures and compares 
 * the data_value to the value in the keyword entry. This is done until 
 * data_value is equal to the value in a keyword entry or number_of_keywords 
 * is exceeded. If data_value is equal to the value in a keyword entry, then 
 * TRUE is returned. If number_of_keywords is exceeded, then FALSE is returned.
 *
 * Arguments:
 * int data_value - Keyword value.
 * struct keyword_data *key_p - Array of keywords to be searched.
 * int number_of_keywords. - Number of elements in the array.
 * Return Value:
 * TRUE - Keyword data matches.
 * FALSE - Keyword data does not match.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

int get_keyword_mask(keyword,key_p,number_of_keywords)
char *keyword;
struct keyword_data *key_p;
int number_of_keywords;
{
   int i;

   for(i = 0; i < number_of_keywords; ++i)
   {
     if (!strcasecmp(keyword,key_p[i].keyword))
       {
        return(key_p[i].mask);
      }
   }

   return(NO_MASK);
}
/* State of retrieving and converting port data */
#define S0 0
#define S1 1
#define S2 2
#define S3 3
#define S4 4
#define S5 5
#define S6 6



/******************************************************************************
 *
 * extract_port_data()
 * 
 * This function extracts the ports from the environment string. Each port 
 * or range is parsed from the string and the string incremented to the next
 * field. The port number is converted to a bit representation. A port number 
 * has a single bit in the array that can be used to indicate the presence 
 * of the port (the bit is set to 1). The port field (in environment values) 
 * is an array of unsigned 32-bit integers. The number of elements in the 
 * array is set to a design constant MAX_PORTS (nominally set to 4). This will
 * allow up to 128 ports (0-127) to be represented. The word in port that 
 * is to be used is determined by dividing the port number by 32 (number of 
 * bits in the word). The bit that is to be set in that word is determined 
 * by port number modulo 32 and used to shift 1 the specified number of bits:
 * 
 * 	port[port number / 32] = 1 << (port number % 32)
 * 
 * If the port number is exceeds the maximum port number, then all words in 
 * port field are cleared and FALSE is returned. The process is repeated for
 *  each listed port. Once all ports have been process, then TRUE is returned.
 * 
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

#define SP ' '

#define ALL_PORTS (-1)
#define SPR_S0 0
#define SPR_S1 1
#define SPR_S2 2

void set_port_range(sp,ep,ports_array)
int sp,ep;
char *ports_array;
{
   if (sp > ep)
   {
      int tmp;

      tmp = sp;
      sp  = ep;
      ep  = tmp;
   }

   for(; sp <= ep; ++sp)
   {
      SETPORT(sp, ports_array);
   }   
}


void set_port(p,ports_array)
int p;
char *ports_array;
{
#ifdef DEBUG_ENVPARSE
   if (debug > 1)
     printf(
	"Set_port Index %x Mask %x\n", (p/BITS_IN_INT), (1<<(p%BITS_IN_INT)));
#endif

   SETPORT(p, ports_array);
}

int extract_port_type(p)
char *p;
{
    int ptype = DEV_SERIAL;
    for (; ptype < DEV_MAX; ptype++)
        if (strncmp(p,ptypenames[ptype],strlen(ptypenames[ptype]))==0)
	  break;

    return(ptype);
}

int extract_ports(string_p, port_p )
char **string_p;
char *port_p;
{
   int state = S0;
   int sp,ep,rv = TRUE, done = 0;
   char *p;
   char *digit = (char *)NULL;

   /*
    * This fxn. is passed a char string that can have ports
    * defined as comma separated individual ports or ranges:
    *
    * port-string     := <port><port-expr>
    * port-expr       := {} | ,[ <port-string> | <port-range> ]
    * port-range      := <port><port-range-expr>
    * port-range-expr := -<port-string>
    * port            := annex port#s 
    *
    * TODO: Rename states and re-write this parser according
    * to the grammar above. That way it'll readible and 
    * extensible.
    */

   p = *string_p;
   while (rv == TRUE && !done) {
#ifdef DEBUG_ENVPARSE
     if (debug > 2)
       printf("State %d String :%s:\n", state, p);
#endif
     
      switch(state) {
	 /* parse <port><port-expr> */
         case S0: /* look for first digit */
	    if (isdigit(*p)) {
               sp = ep = -1;
               digit = p;
	       state = S1;
	       p++;
	       break;
	    }
	    
	    /* if we have reached another keyword or end of string */
	    if (*p == '\0' || isalpha(*p)){
	      *string_p = p;
	      done = 1;
	    }
	    /* everything else is an error and is handled by caller */
	    else {
	      rv = FALSE;
	      done = 1;
	    }

         break;

	 /* parse <port-expr> */
         case S1:
            if (isdigit(*p)) {
               ;
            }
            else if (*p == RANGE_SYMBOL) {
                    *p = 0;

#ifdef DEBUG_ENVPARSE
		    if (debug > 2)
                       printf("Convert first port in range %s\n",digit);
#endif

                    sp = atoi(digit) - 1;
                    state = S3;
            }
            else if (*p == PORT_DELIMITER || *p == 0 ||(*p == PROF_CRIT_DELIM))
            {
                    if (*p != 0)
                    {
                       *p = 0;
                    }
                    else
                    {
                       --p;
                    }
                    state = S4;                    
	    } 
            else if (*p > SP) /* Must be the next field */
	    {
               *string_p = p;
               done = 1;
	    }
            ++p;
         break;

	    /* parse <port><port-range-expr> */
         case S3:
            if (isdigit(*p)) {
               digit = p;
               state = S5; 
            }
            else if (*p == 0) {
               *string_p = p;
               rv = FALSE;
            }
            ++p;
         break;
	
	    /* parse <port> */
         case S4: /* Single port */
#ifdef DEBUG_ENVPARSE
	    if (debug > 2)
               printf("Convert single port %s\n",digit);
#endif
            sp = atoi(digit) - 1;
            if (sp > (-1) && sp < MAX_PORT_REP) {
               set_port(sp,port_p);
	       rv = TRUE;
               state = S0;
	    }
            else {
              *string_p = p;
               rv = FALSE;
               done = 1;
            }
         break;

	    /* parse <port-range-expr> */
         case S5:
            if (isdigit(*p))
            {
               ;
            }
            else if (*p == PORT_DELIMITER || *p == 0 ||(*p == PROF_CRIT_DELIM))
            {
                    if (*p != 0)
                    {
                       *p = 0;
                    }
	            else
	            {
                       --p;
                    }
                    state = S6;                    
	             
	    } 
            else if (*p > SP) /* Must be the next field */
	    {
               *string_p = p;
               rv = FALSE;
	    }
            ++p;
         break;

         case S6: /* Range of ports */
#ifdef DEBUG_ENVPARSE
	    if (debug > 2)
               printf("Convert second port in range %s\n",digit);
#endif

            if (sp > (-1) && sp < MAX_PORT_REP) {
               ep = atoi(digit) - 1;
               if (ep > (-1) && ep < MAX_PORT_REP) {
                  set_port_range(sp,ep,port_p);
		  rv = 1;
                  state = S0;
	       }
               else {
                  *string_p = p;
                  rv = FALSE;
               }               
	    }
            else {
               *string_p = p;
               rv = FALSE;
            }
         break;

         default:
            puts("Failed to parse");
            rv = FALSE;
         break;
      }
   } 
return(rv);
}

int extract_port_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
  /*
   * If we already got a "ports" field, flag this as an error
   */
  if (values_p->port_is_set)
    return(FALSE);
  values_p->port_is_set = extract_port_list(string_p,values_p->ports);
  return values_p->port_is_set;
}

#define PORTTYPE        1
#define PORTSTRINGREST  2
#define DONE            3
#define ERROR_STATE     4

int extract_port_list(string_p,ports)
char **string_p;
char ports[DEV_MAX][MAX_PORTS/8];
{
   int state = PORTTYPE;
   int rv = TRUE, done = 0;
   char *p, buff[80];
   char *digit = (char *)NULL;
   int ptype = DEV_SERIAL;

   strncpy(buff, *string_p, 80);
   buff[79]='\0';
   p = *string_p;

#ifdef DEBUG_ENVPARSE
     if (debug > 2)
       printf("State %d String :%s:\n", state, p);
#endif

   /* 
    * ports           := <port-type>[ <sp_char> | <port-string> ]
    * port-string     := <port><port-expr>
    * port-expr       := {} | ,[ <port-string> | <port-range> ]
    * port-range      := <port><port-range-expr>
    * port-range-expr := -<port-string>
    * port            := annex port#s 
    * port-type       := "asy" | "syn" | "pts" | "do" | "en" | "rcf" | "ta" | "ctl" 
    * sp_char         := "*" | {}
    *
    * We start our parsing with the
    * port-type. If it's valid, we proceed to parse the special
    * characters or strings of port numbers. 
    * There are two special chars. that are allowed in the ports 
    * criteria: asterisk and space/nothing. They both mean the 
    * same thing. Example ports=pts; or ports=pts*;
    * port-string includes comma separated ports and
    * ranges (a-b) or just individual ports. For this 
    * extract_ports() is called.
    */

   while(!done) {
     switch(state) {
       
       /* parse <port-type> */
     case PORTTYPE:
		if (isdigit(*p))
			 ;
       else if (!isdigit(*p) && ((ptype = extract_port_type(p)) >= DEV_MAX)){
		*string_p = p;
		state = ERROR_STATE;
		break;
       }
	   else
		p += strlen(ptypenames[ptype]);
       state = PORTSTRINGREST;
       break;
       
       /* parse [ <sp_char> | <port-string> ] */
     case PORTSTRINGREST:
       if (isdigit(*p)){
	 state = extract_ports(&p, ports[ptype]);
	 if (state)
	   state = DONE;
	 else 
	   state = ERROR_STATE;
       }
       else if (*p == '\0' ||
		(*p == '*' && p[1] == FIELD_SEPARATOR) ||
		*p == FIELD_SEPARATOR) {
	   set_port_range(0,MAX_PORT_REP-1,ports[ptype]);
	   if (*p == '*')
	     p += 2;
	   else if (*p == FIELD_SEPARATOR)
	     p++;
	   state = DONE;
	 }
       else 
	 state = ERROR_STATE;

       *string_p = p;
       rv = state == DONE;
       break;

       /* error out */
     case ERROR_STATE:
       rv = FALSE;
       done = TRUE;
       break;
       
       /* end parsing */
     case DONE:
     default:
       done = TRUE;
       break;

     }
   }
     
   return(rv);
}


/******************************************************************************
 *
 * fill_field()
 *
 * This function copies contiguous all non-whitespace characters from src_p 
 * to tgt_p until one of the following conditions is met. The copying process 
 * will stop when:
 *        The terminator of src_p is encountered
 *        The length of the buffer in tgt_p is exceeded
 *        A whitespace or field delimiter character is encountered
 * Then the string in tgt_p is terminated.
 *
 * Arguments:
 * char **src_p - Address of a data in the source string.
 * char *tgt_p  - Address of the buffer that will receive the data in src_p.
 * int   n      - Size of buffer in tgt_p.
 * Return Value:
 * The number of bytes copied.
 * Side Effects: If the data On success, the address in option_string_p is 
 *               updated to point to the first character after the data.
 * Exceptions: None.
 * Assumptions: Assumes that src_p is a `C' string.
 *
 *****************************************************************************/



int fill_field(src_p,tgt_p,n)
char **src_p, *tgt_p;
int n;
{
   int i;
   char c;

   --n; /* Reserve one byte for the terminator */
   for(i = 0;(c = **src_p) && (i != n); ++i,++(*src_p))
   {
      if ((c <= SP) || (c == FIELD_SEPARATOR))
      {
         break;
      }
      else
      {
         *(tgt_p+i) = c;
      }
   }

   *(tgt_p+i) = 0;
   return(i);
}
/******************************************************************************
 *
 * Accessor for security keywords 
 *
 *****************************************************************************/

int get_protocol_mask(protocol)
char *protocol;
{
   return(get_keyword_mask(protocol,&protocol_keywords[0],MAX_PROTOCOLS));
}

/******************************************************************************
 *
 * Accessor for security keywords 
 *
 *****************************************************************************/

int get_regime_mask(regime)
char *regime;
{
   return(get_keyword_mask(regime,security_keywords,MAX_REGIMES));
}




/******************************************************************************
 *
 * extract_group_data()
 *
 * This function extracts the group name from the environment string This 
 * is accomplished by calling the function fill_field with string_p and 
 * the address of groupname (in environment_values). The function fill_field 
 * returns the number of bytes copied. If the number of bytes copied exceeds
 * zero, then string_p is incremented by this number and TRUE is returned. 
 * Otherwise, string_p is not incremented and FALSE is returned.
 * 
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/
int extract_group_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
     char *wildchar;
#ifdef DEBUG_ENVPARSE
    if (debug > 1)
	printf( "extract_group_data %s\n", *string_p);
#endif
 
   /*
    * If we already got a "group" field, flag this as an error
    */
   if (values_p->groupname[0] != '\0')
      return(FALSE);

   /*
    * If we already got a "group" field, flag this as an error
    */
   if (values_p->groupname[0] != '\0')
      return(FALSE);

    if (fill_field(string_p, values_p->groupname, LEN_USERNAME)) {
#ifdef DEBUG_ENVPARSE
	if (debug > 1)
	    printf( "extract_group_data suceeded\n");
#endif

 	wildchar = strchr(values_p->groupname, '*');
 	if (wildchar != NULL && wildchar[1] != '\0')
        {
		syslog(LOG_ERR, "Invalid group specification: %s", values_p->groupname);
 		return FALSE;
	}
#ifdef _WIN32
	 /* prepend default domain name if necessary */
	PrependDomainName(values_p->groupname);
#endif /*_WIN32*/
	    
	return(TRUE);
    }

#ifdef DEBUG_ENVPARSE
    if (debug > 1)
	printf( "extract_group_data failed\n");
#endif
    return(FALSE);
}

/******************************************************************************
 *
 * extract_annex_data()
 *
 * This function extracts the Annex address or name from the environment 
 * string. This function validates this string by testing for wildcards in 
 * a name or the presence of too many fields if this is an internet address. 
 * If the string passes validation, then it is copied to the environment 
 * values structure.
 *
 * This is accomplished by calling the function fill_field with string_p and 
 * the address of annex (in environment_values). The function fill_field 
 * returns the number of bytes copied. If the number of bytes copied exceeds 
 * zero, then string_p is incremented by this number and TRUE is returned. 
 * Otherwise, string_p is not incremented and FALSE is returned.
 *
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

#define INET_DELIMITER '.'
#define WILDCARD_CHAR  '*'
#define WILDCARD       "*"  /*for wildmatch for user&group M_ALI 11/18/95*/
#define MAX_INET_DELIMITER    3
#define MAX_DIGITS_INET 3

int extract_annex_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
   int i,
       annextype, /* Annex type 0 - Hostname  */
                      /* Annex type 1 - Inet addr */
                      /* Annex type 2 - Wildcard  */
       dotc = 0,
       dc = 0,
       rv = TRUE,
       wildcard_present = FALSE;
   char *t;
   char *annex_p;

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf("extract_annex_data %s\n",*string_p);
#endif
 
   /*
    * If we already got an "annex" field, flag this as an error
    */
   if (values_p->annex[0] != '\0')
      return(FALSE);

   /*
    * If we already got an "annex" field, flag this as an error
    */
   if (values_p->annex[0] != '\0')
      return(FALSE);

   if ((i = fill_field(string_p,(t = ebuff), LEN_USERNAME)))
   {
      annex_p = values_p->annex;
      if (isdigit(*t))
         annextype = 1;
      else if (*t == WILDCARD_CHAR)
         annextype = 2;
      else 
	 annextype = 0;

#ifdef DEBUG_ENVPARSE
      if (debug > 1)
         printf("extract_annex_data annex type %d\n",annextype);
#endif
      /* There can only be a wildcard for an entire name 
	 host portion of the inet addr */
      switch(annextype)
      {
         case 0:
	    for(;i-- && rv == TRUE;)
	    {
               if (*t == WILDCARD_CHAR)
                  rv = FALSE;
               *annex_p++ = *t++;  
            }
	 break;

         case 1:
            for(;i-- && rv == TRUE;)
	    {
               if (*t == INET_DELIMITER)
	       {
		  /* Process the next field in address and reset digit count */
		  dc = 0;
		  ++dotc;
	       }
	       else if (dotc < MAX_INET_DELIMITER) /* Process first three fields */
	       {
		  if (dc <= MAX_DIGITS_INET && (isdigit(*t) || (*t=='*' && dc==0)))
		     ++dc;
		  else
		     rv = FALSE;
	       }
	       else /* Process the host field */
	       {
		  if (dotc == MAX_INET_DELIMITER && dc <= MAX_DIGITS_INET)
		  {
		     if (isdigit(*t) && wildcard_present == FALSE)
		        ++dc;
                     else if (*t == WILDCARD_CHAR && dc == 0)
			wildcard_present = TRUE;
		     else
                        rv = FALSE;
		  }
		  else
		     rv = FALSE;
	       }
               *annex_p++ = *t++;  
            }
	 break;

         case 2:
            if (i == 1) /* This can be the ONLY character in the string */
            {
	       *annex_p     = *t;
	       *(annex_p+1) =  0;
	    }
	 break;

         default:
	 break;
      }
      if(rv == FALSE)
      {
		syslog(LOG_ERR, "Invalid annex specification: %s", ebuff);
	  }
   }

   if (rv == FALSE)
   {
      /* Clear it out when it is FALSE */
      values_p->annex[0] = 0;
   }

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
     printf("extract_annex_data annex retrieved %s\n",values_p->annex);
#endif

   return(rv);
}





/******************************************************************************
 *
 * extract_protocol_data()
 *
 * This function extracts the protocol data from the environment string 
 * and advances the pointer to the next field. The protocol data is compared 
 * to the keywords in the protocol_keywords array. If a match is found, then 
 * the protocol value from that entry of the array is copied to the protocol 
 * field in environment values and TRUE is returned. Otherwise, the protocol 
 * field is set to zero and FALSE is returned.
 *
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

int extract_protocol_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
   int protocol_mask;

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf("In extract_protocol_data: %s\n",*string_p);
#endif
 
   /*
    * If we already got a "protocol" field, flag this as an error
    */
   if (values_p->protocol != NO_MASK)
      return(FALSE);

   /*
    * If we already got a "protocol" field, flag this as an error
    */
   if (values_p->protocol != NO_MASK)
      return(FALSE);

   if (fill_field(string_p, ebuff, MAX_OPTION)) {
      protocol_mask = get_protocol_mask(ebuff);
      if (protocol_mask) {
         values_p->protocol = protocol_mask;
#ifdef DEBUG_ENVPARSE
	 if (debug > 1)
            printf("extract_protocol_data: Mask %d\n",protocol_mask);
#endif
         return(TRUE);
      }
      else
      {
		syslog(LOG_ERR, "Invalid protocol specification: %s", ebuff);
	  }
   }

#ifdef DEBUG_ENVPARSE
   if (debug)
      printf("Out extract_protocol_data: extract failed\n");
#endif
   return(FALSE);

}


/******************************************************************************
 *
 * extract_regime_data()
 * This function extracts the regime data from the environment string. This 
 * is regime data is compared to the keywords in the security_keywords array. 
 * If a match is found, then the regime value from that entry of the array 
 * is copied to the regime field in environment values and TRUE is returned.
 *  Otherwise, the regime field is set to zero and FALSE is returned.
 *
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in option_string_p is updated 
 *               to point to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/
int extract_regime_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
   int regime_mask;

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf("extract_regime_data: %s\n",*string_p);
#endif
 
   /*
    * If we already got a "regime" field, flag this as an error
    */
   if (values_p->regime != NO_REGIME_MASK)
      return(FALSE);

   /*
    * If we already got a "regime" field, flag this as an error
    */
   if (values_p->regime != NO_REGIME_MASK)
      return(FALSE);

   if (fill_field(string_p, ebuff, MAX_OPTION)) {
      regime_mask = get_regime_mask(ebuff);

#ifdef _WIN32
		syslog(LOG_ERR, "Security regime ignored");
		return FALSE;
#endif

      if (regime_mask) {
         values_p->regime = regime_mask;

#ifdef DEBUG_ENVPARSE
	 if (debug > 1)
            printf("extract_regime_data: regime %d\n",regime_mask);
#endif

         return(TRUE);
      }
#ifdef USE_SYSLOG
		syslog(LOG_ERR, "Invalid security regime specification: %s", ebuff);
#endif
   }

#ifdef DEBUG_ENVPARSE
   if (debug)
      printf("extract_regime_data: No regime found\n");
#endif

   return(FALSE);

}


/******************************************************************************
 *
 * extract_time_data()
 * This function is new to the ERPCD. It is a port of the time parsing 
 * software (dos_dis_ent) that was developed for dialout slip (9.3) and 
 * lives in the Annex (oper/dfe/dfe_dialout). It is being modified to use 
 * the environment_values structure instead of the dos_disabled structure 
 * and return TRUE or FALSE.
 ** char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Arguments:

 * Return Value:
 * TRUE - Parse of the time string was successful.
 * FALSE - Parse of the time string failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

#define TIME_DELIMITER '\"'
#define FIELD_SEPARATOR ';'

int extract_time_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
   int time_type = 0;
   char *time, buff[80];
   int i, time_str_length;

#ifdef DEBUG_ENVPARSE
   if (debug > 1) {
      printf("In extract_time_data\n");
      printf( "string_p: %s\n", *string_p);
   }
#endif
 
   /*
    * If we already got a "time" field, flag this as an error
    */
   if (values_p->time_format)
      return(FALSE);

   /*
    * If we already got a "time" field, flag this as an error
    */
   if (values_p->time_format)
      return(FALSE);

   strncpy(buff, *string_p, 80);
   if (**string_p == TIME_DELIMITER) {
      time = ++(*string_p);
      time_str_length = strlen(time);
      for (i=0; **string_p != TIME_DELIMITER && i < time_str_length; ++(*string_p), i++) 
         if (**string_p == 0 || i==time_str_length) {
			syslog(LOG_ERR, "Invalid time specification: %s", buff);
            return(FALSE);
	}		
      **string_p = 0;

#ifdef DEBUG_ENVPARSE
      if (debug > 2)
         printf("TIME %s\n",time);
#endif

      for (++(*string_p); ;++(*string_p)) {
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
            printf("STR %s\n",*string_p);
#endif

         if (**string_p == FIELD_SEPARATOR || **string_p == 0)
            break;
      }

      /* Instead, assigning the value to values_p->time_format*/
      /*;this field is not in the spec but it is used else    */
      /* in the code , so I'll use it and update the spec.    */
      /* M_ALI 9/8/95                                         */

#if 0
      time_type = get_time_entry(&values_p->start_time,
                                 &values_p->end_time,
                                 time);
#endif /* 0 */

      values_p->time_format = get_time_entry(&values_p->start_time,
					     &values_p->end_time,
					     time);
   }
#ifdef DEBUG_ENVPARSE
   if (debug > 2)
      printf("Time type %d\n",time_type);
#endif

      
      
      /* values_p->time_format INDICATES IF TIME IS PARSED */
      /*  CORRECTLY. M_ALI 9/11/95                         */

   if (values_p->time_format)
      return(TRUE);

#ifdef USE_SYSLOG
   syslog(LOG_ERR, "Invalid time specification: %s", buff);
#endif
   return(FALSE);
}


/******************************************************************************
 *
 * extract_username_data()
 *
 * This function extracts the Annex address or name from the environment 
 * string. This is accomplished by calling the function fill_field with 
 * string_p and the address of username (in environment_values). The function 
 * fill_field returns the number of bytes copied. If the number of bytes 
 * copied exceeds zero, then string_p is incremented by this number and TRUE 
 * is returned. Otherwise, string_p is not incremented and FALSE is returned.
 *
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

int extract_username_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf("extract_username_data %s\n",*string_p);
#endif

   /*
    * If we already got a "username" field, flag this as an error
    */
   if (values_p->username[0] != '\0')
      return(FALSE);

   /*
    * If we already got a "username" field, flag this as an error
    */
   if (values_p->username[0] != '\0')
      return(FALSE);

   if (fill_field(string_p, values_p->username, MAX_OPTION)) {
#ifdef DEBUG_ENVPARSE
     if (debug > 1)
	printf( "extract_username_data suceeded\n");
#endif

#ifdef _WIN32
	 /* prepend default domain name if necessary */
	PrependDomainName(values_p->username);
#endif /*_WIN32*/
	    
      return(TRUE);
   }

#ifdef DEBUG_ENVPARSE
   if (debug)
      printf("extract_username_data failed.\n");
#endif
   return(FALSE);
}
/******************************************************************************
 *
 * match_env_options()
 *
 * This function is new. This function controls the matching process for 
 * testing the environment with the values parsed from a environment string. 
 * For each field the appropriate evaluation routine will be called to 
 * compare the values. If even one entry fails to match then the FALSE
 * is returned otherwise a TRUE is returned meaning that all the entries
 * in the env_string matched the user.  The functions to be used for matching
 * are:
 * 
 *                         username - strcasecmp()
 *                         groupname - strcasecmp()
 *                         annex - wild_match() (from acp_policy).
 *                         protocol - match_keyword_data()
 *                         regime - match_keyword_data()
 *                         time - match_time()
 *                         endpoint - match_endpoint()
 * 
 * Arguments:
 * struct environment_spec *env_p - Pointer to the environment being tested.
 * struct environment_values *values_p - Pointer to values parsed from the 
 *                                       environment string.
 * Return Value:
 * Number of fields matched.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/


/* Defines to indicate which field were matched.  This value is passed to    */
/* the routine best_env_match() to determine which env values to use for     */
/* the control                                                               */

int
match_env_options(env_p, values_p)
    struct environment_spec *env_p;
    struct environment_values *values_p;
{
    int  matches = NO_MATCHES;
    char *temp;

#define MATCH_USERNAME    0x0001
#define MATCH_GROUPNAME   0x0002
#define MATCH_ANNEX       0x0004
#define MATCH_PROTOCOL    0x0008
#define MATCH_REGIME      0x0010
#define MATCH_PORT        0x0020
#define MATCH_TIME        0x0040
#define MATCH_ENDPOINT    0x0080
#define BITS_IN_MATCH     8

#ifdef DEBUG_ENVPARSE
    if (debug > 1)
	printf( "In match_env_options\n");
#endif
/*CHANGE### This is to make sure that calls from get_user_profile_by_env*/
/*with empty structs do not crash the program M_ALI 10_6_95 */

#ifdef _WIN32
	 /* prepend default domain name if necessary */
	PrependDomainName(env_p->username);
	_strlwr(env_p->username);
	_strlwr(values_p->username);
	_strlwr(values_p->groupname);
#endif /*_WIN32*/

    if (values_p == NULL) {
#ifdef DEBUG_ENVPARSE
	if (debug > 1)
	    printf( "match_env_options: value_p == NULL\n");
#endif
	return(FALSE);
    }

   /* If username exists in values_p struct */
   /* then check if it matches. If it does  */
   /* not match then futile to proceed.     */
   /* M_ALI 8/25/95                         */

   /* Adding code for wild_match for usern- */
   /* ame. M_ALI 11/18/95                   */
   
     if (isalnum(values_p->username[0]) ||
		 (strncmp(values_p->username, WILDCARD, strlen(WILDCARD)) == 0)) {
#ifdef DEBUG_ENVPARSE
	if (debug > 1)
	    printf("check 1, username exists\n");
#endif

	if (strstr(values_p->username, WILDCARD)) {
	    temp = strtok(values_p->username, WILDCARD);

	    if (temp) { 
		/* if (!strncasecmp(env_p->username, temp, strlen(temp))) */
		/* changing to ... M_ALI 11/29/95 */
		if (strncmp(env_p->username, temp, strlen(temp)) == 0) {
		    matches |= MATCH_USERNAME;
#ifdef DEBUG_ENVPARSE
		    if (debug > 2)
				printf("match_env_options: Matched username\n");
#endif
		}
		else {
#ifdef DEBUG_ENVPARSE
		    if (debug > 2)
			printf("match_env_options: username \"%s\" != \"%s\"\n",
			       env_p->username, temp);
#endif
		    return(FALSE);
		}
	    }
	    else {
		matches |= MATCH_USERNAME;
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: Matched username\n");
#endif
	    }
	}
	else {
	    /* if (!strcasecmp(env_p->username,values_p->username)) */
	    /* changing to ... M_ALI 11/29/95 */
		if (strcmp(env_p->username, values_p->username) == 0) {
			matches |= MATCH_USERNAME;
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: Matched username\n");
#endif
	    }  
	    else {
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: username \"%s\" != \"%s\"\n",
			   env_p->username, values_p->username);
#endif
		return(FALSE);
	    }
	}
    }/*username ends here*/

     
    /* If groupname exists in values_p struct*/
    /* then check if it matches. If it does  */
    /* not match then futile to proceed.     */
    /* M_ALI 8/25/95                         */	

    /* if (isalnum(values_p->groupname[0])||(!(strncasecmp(\
       values_p->groupname,WILDCARD,strlen(WILDCARD))))) M_ALI 11/29/95 */
   
    if (isalnum(values_p->groupname[0]) ||
	(strncmp(values_p->groupname, WILDCARD, strlen(WILDCARD)) == 0)) {
	if (strstr(values_p->groupname, WILDCARD)) {
	    if (is_group_listed_wild_match(env_p->group_list,
					   values_p->groupname)) {
		matches |= MATCH_GROUPNAME;
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: Matched group\n");
#endif
	    }
	    else {
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: not1 group \"%s\" and \"%s\"\n",
			   env_p->group_list, values_p->groupname);
#endif
		return(FALSE);
	    }
	}
	else {
#ifdef DEBUG_ENVPARSE
	    if (debug > 2)
		printf("check 2, groupname exists\n");
#endif
	    if (is_group_listed(env_p->group_list, values_p->groupname)) {
	        matches |= MATCH_GROUPNAME;
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: Matched group\n");
#endif
	    }
	    else {
#ifdef DEBUG_ENVPARSE
		if (debug > 2)
		    printf("match_env_options: not2 group \"%s\" and \"%s\"\n",
			   env_p->group_list, values_p->groupname);
#endif
		return(FALSE);
	    }
	}
    }

    /* If annex  exists in values_p struct   */
    /* then check if it matches. If it does  */
    /* not match then futile to proceed.     */
    /* M_ALI 8/25/95                         */

    if (isalnum(values_p->annex[0])) {
	if (wild_match(values_p->annex, env_p->annex)) {
	    matches |= MATCH_ANNEX;
#ifdef DEBUG_ENVPARSE
	    if (debug > 2)
		printf("match_env_options: Matched annex \"%s\"\n",
		       values_p->annex);
#endif
	}
	else {
#ifdef DEBUG_ENVPARSE
	    if (debug > 2) {
		unsigned char *ap = (unsigned char *)(&env_p->annex);
		printf("match_env_options: annex \"%u.%u.%u.%u\" != \"%s\"\n",
		       *ap, *(ap+1), *(ap+2), *(ap+3), values_p->annex);
	    }
#endif
	    return(FALSE);
	}
    }/*annex ends here */


     /* If protocol exists in values_p struct */
     /* then check if it matches. If it does  */
     /* not match then futile to proceed.     */
     /* M_ALI 8/25/95                         */
     
     /* Adding code for Cli which encompasses */
     /* rlogin and telnet. M_ALI 1/2/96       */

     if (values_p->protocol) {
#ifdef DEBUG_ENVPARSE
       if (debug > 2) {
         printf("check 3, protocol exists\n");
         printf("values_p->protocol=%d, env_p->protocol=%d\n",
		values_p->protocol, env_p->protocol);
       }
#endif

       if ((env_p->protocol == values_p->protocol) ||
	   ((values_p->protocol == CLI_PROTOCOL) &&
	    ((env_p->protocol == SERVICE_RLOGIN) ||
	     (env_p->protocol == SERVICE_TELNET) ||
	     (env_p->protocol == SERVICE_CLI_HOOK)))) {
	   matches |= MATCH_PROTOCOL;
#ifdef DEBUG_ENVPARSE
	   if (debug > 2)
	     printf("match_env_options: Matched protocol\n");
#endif
       }
       else {
#ifdef DEBUG_ENVPARSE
	   if (debug > 2)
	     printf("match_env_options: Not matched protocol\n");
#endif
	   return (FALSE);
       }
     }/*protocol ends here*/

#ifdef DEBUG_ENVPARSE
  if (debug > 1)
     printf("match_env_options: Before regimes\n");
#endif
     
     /* If regimes  exists in values_p struct */
     /* then check if it matches. If it does  */
     /* not match then futile to proceed.     */
     /* Adding values_p->regime to make       */
     /* things even. M_ALI 8/25/95            */
 	
    if (values_p->regime) {
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	    printf("check 4, regime exists\n");
#endif
      if ((env_p->regime) &&
	  (env_p->regime->regime_mask == values_p->regime)) {
	     matches |= MATCH_REGIME;
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	     printf("match_env_options: Matched regimes\n");
#endif
	}
	else {
#ifdef DEBUG_ENVPARSE
	    if (debug > 2)
		printf("match_env_options: env_p->regime->regime_mask value doesn't exist, yet\n");
#endif
	    return(FALSE);
	}
    }/*regimes ends here */
	
    /* If ports    exists in values_p struct */
    /* then check if it matches. If it does  */
    /* not match then futile to proceed.     */
    /* M_ALI 8/25/95                         */

    if (values_p->port_is_set) {
	if (ISSETPORT((env_p->port - 1),values_p->ports[env_p->ptype])) {
	    matches |= MATCH_PORT;
#ifdef DEBUG_ENVPARSE
	    if (debug > 2) {
	       printf("match_env_options: Matched annex port\n");
	       printf("match_env_options: env_p->port=%d, env_p->ptype=%d\n",
		      env_p->port, env_p->ptype);
	    }
#endif
	}
	else {
#ifdef DEBUG_ENVPARSE
	    if (debug > 2)
		printf("match_env_options: Matched annex port\n");
#endif
	    return (FALSE);
	}
    }/*ports ends here */


    /* If tmfields exists in values_p struct */
    /* then check if it matches. If it does  */
    /* not match then futile to proceed.     */
    /* M_ALI 8/25/95                         */

    if (values_p->time_format) {
#ifdef DEBUG_ENVPARSE
      if (debug > 2)
	printf("check 5, timeexists\n");
#endif
      if (match_time(&env_p->time, &values_p->start_time,
		     &values_p->end_time, values_p->time_format)) {
	matches |= MATCH_TIME;
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	  printf("match_env_options: Matched time\n");
#endif
      } 
      else {
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	  printf("match_env_options: Not matched annex port\n");
#endif
	return(FALSE);
      }
    }/* tm ends here */

    /* If endpoint exists in values_p struct */
    /* then check if it matches. If it does  */
    /* not match then futile to proceed.     */

    if (values_p->endpoint.valid > 0) {
#ifdef DEBUG_ENVPARSE
      if (debug > 2)
	printf("check 6, endpoint\n");
#endif
      if (match_endpoint(&env_p->endpoint, &values_p->endpoint)) {
	matches |= MATCH_ENDPOINT;
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	  printf(stderr,"match_env_options: Matched endpoint\n");
#endif
      } 
      else {
#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	  printf(stderr,"match_env_options: Not matched endpoint\n");
#endif
	return(FALSE);
      }
    }/* endpoint ends here */

     /* returning TRUE. matches could be zero */
     /* which means that the env. string is   */
     /* blank M_ALI 8/25/95.                  */	 
     /* Blocking out this code, won't need    */
     /* "matches" field of the struct anymore */
     /* M_ALI 9/8/95                          */

#if 0
     if(matches == NO_MATCHES)
         values_p->matches = MATCH_USERNAME | MATCH_GROUPNAME | MATCH_ANNEX | 
	                     MATCH_PROTOCOL | MATCH_REGIME | MATCH_PORT | 
                             MATCH_TIME ;    
     else 
         values_p->matches = matches;
#endif /* 0 */

#ifdef DEBUG_ENVPARSE
    if (debug > 2)
      printf("match_env_options: leaving with %d matches\n", matches);
#endif

     return(TRUE);   
}


/************************************************************************
 *
 * FUNCTION:
 *   dos_convert_time - This routine will convert a 5-tuple
 *   (month, day, hour, min, sec) into an integer.
 *
 * DESCRIPTION:
 *   see above
 *
 * INPUT:
 *   Month, day, hour, minutes, seconds.
 *
 * RETURNS:
 *   The second corrosponding to the 5-tuple.
 *
 */

int dos_convert_time(m,d,h,mi,s)
int m,d,h,mi,s;
{
return ((m * 60 * 60 * 24 * 31) +
        (d * 60 * 60 * 24) +
        (h * 60 * 60) +
        (mi * 60) + s);
}


/******************************************************************************
 *
 * match_time()
 * This is a utility routine. This function compares the TM structure 
 * containing the time stamp for this ACP session the start and end times 
 * from environment values. The comparison of the time field will be performed
 * according to the DOS_DIS_TYPE returned. This is a port of the function
 * dos_check_disabled() in oper/dfe/dfe_dialout.c
 * 
 * Arguments:
 * struct tm *tmc - Time of request.
 * struct tm *tm1, *tm2 - Time range during which access is 
 *                                     allowed.
 * int time_format;
 * Return Value:
 * TRUE - Time is within the specified range.
 * FALSE - Time is not within the specified range.
 * Side Effects: None.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/

int match_time(tmc,tm1,tm2,time_format)
struct tm *tmc, *tm1, *tm2;
int time_format;
{
	int inside = 0;		/* True if inside the range, false otherwise */
	int t1, t2, tc;

#ifdef DEBUG_ENVPARSE
	if (debug > 2)
	    printf( "time format = %d\n", time_format);
#endif

	switch(time_format) {

	    /*
	     * This disabled period is of the 'weekday' type.
	     * See if the current weekday is out of its range.
	     */

	    case TIME_TYPE1:
	    case TIME_TYPE2:
	    case TIME_TYPE3:

		/* Find out if we're inside the range.  In the normal
		 * case, the first weekday is less than the second, so
		 * we merely need to check to see if we're between the two.
 		 *
		 * If they are reversed (as in Sat-Tues), tm1->tm_wday
		 * will be greater than tm2->tm_wday, and the range will
		 * be everything except the numbers between these two.  
		 * We need to test for "<" as opposed to "<=" because the
		 * "range" should still be inclusive (i.e., Sat and Tues
		 * would be inside the range) since we're ultimately going
		 * to invert the result.
		 */
		if(tm1->tm_wday <= tm2->tm_wday)
	                inside = ((tm1->tm_wday <= tmc->tm_wday) &&
                                  (tmc->tm_wday <= tm2->tm_wday));
		else
			inside = !((tm2->tm_wday < tmc->tm_wday) &&
				   (tmc->tm_wday < tm1->tm_wday));

#ifdef DEBUG_ENVPARSE
		if (debug > 2) {
		    printf( "tm1->tm_wday=%d, tm2->tm_wday=%d, tmc->tm_wday=%d\n",
			    tm1->tm_wday, tm2->tm_wday, tmc->tm_wday);
		    printf("inside=%d\n", inside);
		}
#endif

                if (!inside)
                   return(FALSE);

		break;
	}

	switch(time_format) {

	    case TIME_TYPE1:

			return (TRUE);

	    case TIME_TYPE2:

                /*
                 * This is disabled period of the type:
                 * "10:00 - 4:00 Mon - Thurs"
                 */
		t1 = dos_convert_time(0,0, tm1->tm_hour, tm1->tm_min, 59);
		t2 = dos_convert_time(0,0, tm2->tm_hour, tm2->tm_min, 59);
		tc = dos_convert_time(0,0, tmc->tm_hour, tmc->tm_min, 59);
		break;


	    case TIME_TYPE3:

                /*
                 * This is disabled period of the type:
                 * "10:00 Mon - 4:00 Thurs"
                 */
		if (tmc->tm_wday == tm1->tm_wday && tmc->tm_wday == tm2->tm_wday){
			t1 = dos_convert_time(0,0, tm1->tm_hour, tm1->tm_min, 59
);
t2 = dos_convert_time(0,0, tm2->tm_hour, tm2->tm_min, 59
);
		}
		else if (tmc->tm_wday == tm1->tm_wday) {
                	t1 = dos_convert_time(0,0, tm1->tm_hour, tm1->tm_min, 59);
                	t2 = dos_convert_time(0,0, 23, 59, 59);
		}
		else if (tmc->tm_wday == tm2->tm_wday) {
                	t1 = dos_convert_time(0,0, 0, 0, 0);
                	t2 = dos_convert_time(0,0, tm2->tm_hour, tm2->tm_min, 59);
		}
		else {
			return (TRUE);
		}

                tc = dos_convert_time(0,0, tmc->tm_hour, tmc->tm_min, 59);
		break;


	    case TIME_TYPE4:

                /*
                 * This is disabled period of the type:
                 * "10:00 Nov 30 - 16:30 April 3"
                 */
		t1 = dos_convert_time(tm1->tm_mon, tm1->tm_mday,
			              tm1->tm_hour, tm1->tm_min, 59);
		t2 = dos_convert_time(tm2->tm_mon, tm2->tm_mday,
			              tm2->tm_hour, tm2->tm_min, 59);
		tc = dos_convert_time(tmc->tm_mon, tmc->tm_mday,
			              tmc->tm_hour, tmc->tm_min, tmc->tm_sec);
		break;

	    default:
		return(FALSE);	/* Keeps compiler happy */


	}	/* switch */

	/* We need to be sure that we still fall in the specified range
	 * even if the order of the entries is reversed, as in the
	 * Sat-Tue case above.
	 */
	if(t1 <= t2)
		inside = ((t1 <= tc) && (tc <= t2));
	else
		inside = !((t2 < tc) && (tc < t1));

#ifdef DEBUG_ENVPARSE
	if (debug > 2) {
	    printf( "time1: %d/%d  %d:%d\n", tm1->tm_mon+1, 
		   tm1->tm_mday, tm1->tm_hour, tm1->tm_min);
	    printf( "time2: %d/%d  %d:%d\n", tm2->tm_mon+1, 
		    tm2->tm_mday, tm2->tm_hour, tm2->tm_min);
	    printf("inside = %d\n", inside);
	}
#endif

	if (inside)
		return (TRUE);

  return (FALSE);
}

/******************************************************************************
 *
 * match_endpoint()
 * This is a utility routine designed to match an Endpoint Discriminator.
 * 
 * Arguments:
 * EndpDesc *input_endpoint - pointer to endpoint discriminator to match
 * EndpDesc *user_endpoint - pointer to user environment endpoint discriminator
 *
 * Return Value:
 * TRUE - Ennpoint matches
 * FALSE - Endpoint doesn't match
 *
 * Side Effects: None.
 *
 * Exceptions: None.
 *
 * Assumptions: None.
 *
 *****************************************************************************/

int match_endpoint (input_endpoint, user_endpoint)
EndpDesc *input_endpoint;
EndpDesc *user_endpoint;
{
    if ((input_endpoint != NULL) && (input_endpoint->valid > 0) &&
        (user_endpoint !=NULL)) {
	if ((input_endpoint->length == user_endpoint->length) &&
	    (input_endpoint->class == user_endpoint->class) &&
            (memcmp(input_endpoint->address, user_endpoint->address,
                user_endpoint->length) == 0))
    	    return(TRUE);
    }

    return(FALSE);
}


/******************************************************************************
*
* is_group_listed
*
* This is function searches the group list for the specified group. If a 
* match is found, then a TRUE is returned. Otherwise, FALSE is returned.
*
* Arguments:
* struct group_entry *group_list;
* char *group;
* Return Value: 
* TRUE  - The group is in the group list.
* FALSE -The group is not in the group list.
* Side Effects: None.
* Exceptions: None.
* Assumptions: None.
******************************************************************************/
int is_group_listed(list,group)
struct group_entry *list;
char *group;
{
   int found = FALSE;

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf( "is_group_listed: Looking for %s\n", group);
#endif

   while (found == FALSE && list) {
#ifdef DEBUG_ENVPARSE
      if (debug > 2)
	 printf( "is_group_listed: Group %s\n", list->groupname); 
#endif

      /* if (!strcasecmp(list->groupname,group)) changing to ... */
      /* M_ALI 11/29/95 */
      if (!strcmp(list->groupname,group)) {
#ifdef DEBUG_ENVPARSE
	 if (debug > 1)
	    printf( "is_group_listed: Found %s\n", list->groupname); 
#endif

         found = TRUE;
      }
      else {
	    list = list->next;
      }
   }

   return(found);
}

/******************************************************************************
*
* is_group_listed_wild_match
*
* This is function searches the group list for a wild_match. If a 
* match is found, then a TRUE is returned. Otherwise, FALSE is returned.
* M_ALI 11/18/95
*
* Arguments:
* struct group_entry *group_list;
* char *group;
* Return Value: 
* TRUE  - The group is in the group list.
* FALSE -The group is not in the group list.
* Side Effects: None.
* Exceptions: None.
* Assumptions: None.
******************************************************************************/
int is_group_listed_wild_match(list, group)
struct group_entry *list;
char *group;
{
   int found = FALSE;
   char *temp;
   int len;

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf( "is_group_listed_wild_match: Looking for %s\n", group);
#endif

   if (!(temp = strtok(group, WILDCARD)))
      return(TRUE);
   else {
      len = strlen(temp);
      while (found == FALSE && list) {
#ifdef DEBUG_ENVPARSE
	 if (debug > 2)
	    printf( "is_group_listed_wild_match: Group %s\n",
		    list->groupname);
#endif

	 if (!strncasecmp(list->groupname,temp, len)) {
#ifdef DEBUG_ENVPARSE
	    if (debug > 1)
	       printf( "is_group_listed: Found %s\n",
		       list->groupname);
#endif

	    found = TRUE;
	 }
	 else {
	    list = list->next;
	 }
      }
   }

   return(found);
}


inet_match(Host_string,internet,mask)
char Host_string[];
UINT32	 internet;
UINT32	 mask;
{
  UINT32 address;
  UINT32 masked_addr;
  struct in_addr *Inet;
  struct hostent *Host;

	internet |= mask;
/* see if passed Host_string is a name or in dot notation */
	if (isdigit(Host_string[0]))
	   {

	   /* dot notation, convert to 32 bit address */
	   address = inet_addr(Host_string);    
           if(address != (UINT32)-1)
		{
		masked_addr = mask | address;
		return(masked_addr == internet);
		}
	   }
	
	   /* it's a name, get the address */
	
	    Host = gethostbyname(Host_string);
	    if(!Host)
		masked_addr = mask;
	    else
	        {
#ifdef h_addr
		char **ap = (char **)Host->h_addr_list;
	        while ((Inet = (struct in_addr *) *ap++) != NULL) {
		  masked_addr = Inet->s_addr | mask;
	          if (masked_addr == internet)
		     return(TRUE);
		  }
		return(FALSE);
#else /* old style */
		Inet = (struct in_addr *)Host->h_addr;
		masked_addr = Inet->s_addr | mask;
#endif
	        }

	return(masked_addr == internet);
}


/*
 *	wild_match()	- does host identified by string match internet?
 *
 *	Wildcards, names, or Internet addresses in dot notation are allowed.
 *	A wildcard may be a * in any position of an Internet address.  It
 *	is usually used to specify every host on a network (net.*) or every
 *	host on all networks (*).  For example:
 *
 *	*		matches any host
 *	60.*		matches any host on network 60, equivalent to 60.*.*.*
 *	131.1.*		matches any host on net 131.1, equivalent to 131.1.*.*
 *	195.5.35.*	matches any host on network 195.5.35
 *	66.*.1.*	matches 66.0.1.1, 66.1.1.0, 66.2.1.25, etc.
 */

wild_match(token, internet)

char		*token;				/* hostname or dot notation */
UINT32		internet;			/* inet addr, internal fmt */
{
	UINT32		maskwild;		/* mask derived from token */
	unsigned char	*pmask = (unsigned char *)&maskwild;
	int		mx, tx;			/* index into mask, token */

	/*
	 *  If not a digit or '*' in the first position, assume hostname
	 *  Return match based on hostname translation matching internet
	 */

	if(token[0] != '*' && !isdigit(token[0]))
		return inet_match(token,internet,0);
	/*
	 *  Otherwise, we must create a possible wildcard mask (don't care)
	 *  and replace any *'s in the token with ASCII 0's.
	 */

	for(tx = mx = 0 ;; tx++)			/* breaks on EOS */
	{
		if(token[tx] == '.' || token[tx] == 0)	/* dot or null? */
		{
			if(token[tx - 1] == '*')	/* wildcard part? */
			{
				token[tx - 1] = '0';	/* change * to 0 */
				pmask[mx] = 0xff;
			}
			else
				pmask[mx] = 0;		/* else normal part */

			if(token[tx] == 0)		/* end of string? */
				break;			/* end loop */
			else
				mx++;			/* else bump */
		}
	}

	/*
	 *  Now we adjust for incomplete (not four part) addresses
	 *  Take character at current index, and propagate it
	 */

	while(mx < 3)		/* while index (# of dots) is not at end */
	{
		pmask[mx + 1] = pmask[mx];	/* next byte equals current */
		mx++;				/* avoid confusion */
	}
	
	/*
	 *  Translate token to internet address, mask and match w/internet
	 */
	return inet_match(token,internet,maskwild);
}


/******************************************************************************
 *
 * extract_endpoint_data()
 *
 * This function extracts the endpoint discriminator from the environment 
 * string. The syntax of this field is as followd:
 *
 *    mp_endpoint_option:mp_endpoint_value
 *
 * where mp_endpoint_option is an integer between 0 and 5 (inclusive) which
 * describes the syntax of the mp_endpoint_value.  The meaning of the values
 * is
 *            0 - NULL Class (empty) (can be '0', '0:', or '0:0')
 *            1 - Locally Assigned Address (up to 40 ascii characters, interpreted
 *                as hex digits)
 *            2 - IP address
 *            3 - MAC address
 *            4 - PPP Magic-Number Block (up to 5 comma separated 4 byte numbers)
 *            5 - Public Switched Network Directory Number
 *
 * Arguments:
 * char **string_p - This is used as a pointer to the environment string.
 * struct environment_values *values_p - Pointer to environment values 
 *                                       structure to be updated with any 
 *                                       new environment values.
 * Return Value:
 * TRUE - The data extraction was successful.
 * FALSE - the data extraction failed.
 * Side Effects: On success, the address in string_p is updated to point 
 *               to the first character after the data.
 * Exceptions: None.
 * Assumptions: None.
 *
 *****************************************************************************/
#ifdef _WIN32
satoi(char c)
{
	int n;
	char tmpstr[2];

	switch(c)
	{
	case 'A':
	case 'a':
		n = 10;
		break;
	case 'B':
	case 'b':
		n = 11;
		break;
	case 'C':
	case 'c':
		n = 12;
		break;
	case 'D':
	case 'd':
		n = 13;
		break;
	case 'E':
	case 'e':
		n = 14;
		break;
	case 'F':
	case 'f':
		n = 15;
		break;
	default:
		tmpstr[0] = c;
		tmpstr[1] = '\0';
		n = atoi(tmpstr);
		break;
	}

	return n;
}

BYTE atoh(char *buf)
{
	BYTE b;
	b = satoi(buf[0]) * 16 + satoi(buf[1]); 
	return b;
}

struct ether_addr *ether_aton(tt)
char *tt;
{
	int i, j, k, len;
	char *pch = tt;
	char buf[2];
	struct ether_addr *p = (struct ether_addr *)malloc(sizeof(struct ether_addr));
	j = 0;
	k = 0;
	len = strlen(tt) + 1;
	for (i=0; len; i++)
	{
		if (tt[i] == ':' || tt[i] == 0)
		{
			if (j == 1)
			{
				buf[1] = buf[0];
				buf[0] = '0';
			}
			p->ether_addr_octet[k++] = atoh(buf);
			j = 0;
		}
		else if (j<2)
			buf[j++] = tt[i];
	}
	return p;
}
#endif

int extract_endpoint_data(string_p,values_p)
char **string_p;
struct environment_values *values_p;
{
#if __sgi || HP
/*
   Berkeley defines this in /usr/include/netinet/if_ether.h, but Silicon
   Graphics removed it from there, and their man page says to define it
   yourself.  Why?  Good question.
 */
struct ether_addr {
    u_char ether_addr_octet[6];
};
#endif
   char *tt, *p_disc, *p_string, *p_end, *p_temp, temp_string[80];
   u_short endp_option;
   struct ether_addr *ether_addr;
   UINT32 temp_long;
   int temp_int, length;

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf("extract_endpoint_data %s\n",*string_p);
#endif
 
   /*
    * If we already got a "endpoint" field, flag this as an error
    */
   if (values_p->endpoint.valid)
      return(FALSE);

   if (fill_field(string_p, ebuff, MAX_OPTION)) {
     tt = ebuff;

     if (!isdigit(*tt)) {
#ifdef DEBUG_ENVPARSE
        if (debug > 1)
           printf("extract_endpoint_data failed.\n");
#endif
        return(FALSE);
     }

     bzero (&values_p->endpoint, sizeof(EndpDesc));

     endp_option = *tt++ - '0';
     if (*tt++ != ':') {
#ifdef DEBUG_ENVPARSE
        if (debug > 1)
           printf("extract_endpoint_data failed.\n");
#endif
        return(FALSE);
     }

     switch (endp_option) {

	case 0:		/* NULL class */
	   if ((temp_int = atoi(tt)) != 0) {
#ifdef DEBUG_ENVPARSE
	      if (debug > 1)
	         printf("extract_endpoint_data failed.\n");
#endif
	      return(FALSE);
           }
	   values_p->endpoint.valid = 1;
	   break;

	case 1:		/* Locally assigned address */

	   /* Pad out address to fit into an even 4-byte increment */
	   temp_int = strlen(tt) % 8;
	   temp_int = (temp_int == 0) ? 0 : 8 - temp_int;
	   while (temp_int-- > 0)
		strcat(tt, "0");
	   bzero (temp_string, sizeof(temp_string));
	   values_p->endpoint.length = 0;
	   for (p_string = tt, p_disc = (char *)values_p->endpoint.address,
	     temp_int = 0;	/* number of characters processed */
	     temp_int < (int)strlen(tt) &&
	     values_p->endpoint.length < sizeof(values_p->endpoint.address);
	     values_p->endpoint.length += sizeof(UINT32),
	     p_disc += sizeof(UINT32), p_string += 8) {
		bcopy (p_string, temp_string, 8);
		temp_long = strtol (temp_string, &p_end, 16);

		/* If there was some non-hex character in string, error */
		if (p_end != &temp_string[8]) 
		    break;
		bcopy (&temp_long, p_disc, sizeof(UINT32));
		temp_int += 8;
	   }
	   /*
	    * If we've filled the amount of space allocated, and we're still not
	    * done processing the string, then this endpoint is too long; error
	    */
	   if ((values_p->endpoint.length == sizeof(values_p->endpoint.address)) &&
		(temp_int < (int)strlen(tt))) {
#ifdef DEBUG_ENVPARSE
	      if (debug > 1)
	         printf("extract_endpoint_data failed.\n");
#endif
	      return(FALSE);
           }
#ifdef DEBUG_ENVPARSE
           if (debug > 1) {
	     for (temp_int = 0; temp_int < values_p->endpoint.length; temp_int++)
		printf("0x%x ",(char *)values_p->endpoint.address[temp_int]);
	     printf("\n");
	   }
#endif
	   values_p->endpoint.valid = 1;
	   break;

	case 2:		/* IP Address */
	   temp_long = inet_addr(tt);
	   values_p->endpoint.class = endp_option;
	   bcopy (&temp_long, values_p->endpoint.address,sizeof(temp_long));
	   values_p->endpoint.length = sizeof(temp_long);
	   values_p->endpoint.valid = 1;
	   break;

	case 3:		/* MAC Address */
	   /*
	    * ether_aton() expects ':' between bytes, but we want to allow
	    * both ':' and '-', so we'll convert here to make ether_aton() happy
	    */
	   for (p_string = tt; *p_string != '\0'; p_string++)
		if (*p_string == '-')
		    *p_string = ':';

	   if ((ether_addr = (struct ether_addr *)ether_aton(tt)) == NULL) {
#ifdef DEBUG_ENVPARSE
	      if (debug > 1)
	         printf("extract_endpoint_data failed.\n");
#endif
	      return(FALSE);
           }

	   values_p->endpoint.class = endp_option;
	   bcopy (ether_addr, values_p->endpoint.address, sizeof(struct ether_addr));
	   values_p->endpoint.length = sizeof(struct ether_addr);
	   values_p->endpoint.valid = 1;
	   break;

	case 4:		/* PPP Magic number block */

		/*
		 * This is pretty messy code, hastily written that
		 * should at least be commented as to why it does some
		 * seemingly strange stuff
		 */
	   for (temp_int = 0, p_string = tt, 
	     p_disc = (char *)values_p->endpoint.address,
	     values_p->endpoint.length = 0;
	     temp_int <= 5;
	     temp_int++, p_disc += sizeof(UINT32)) {
		p_end = strchr (p_string, ',');
		if (p_end != NULL) {
		    length = p_end - p_string;
		} else {
		    length = strlen(p_string);
		}
		bcopy (p_string, temp_string, length);
		temp_string[length] = '\0';
		temp_long = strtol (temp_string, &p_temp, 0);
		if (p_temp != &temp_string[length]) {
		    p_string = p_temp;
		    break;
		}
		bcopy (&temp_long, p_disc, sizeof(UINT32));
		values_p->endpoint.length += sizeof(UINT32);
		if (p_end == NULL) {
		    p_string = p_end;
		    break;
		}
		p_string = p_end + 1;
	   }
	   if (p_string != NULL) {
#ifdef DEBUG_ENVPARSE
	      if (debug > 1)
	         printf("extract_endpoint_data failed.\n");
#endif
	      return(FALSE);
           }
#ifdef DEBUG_ENVPARSE
           if (debug > 1) {
	     for (temp_int = 0; temp_int < values_p->endpoint.length; temp_int++)
		printf("0x%x ",(char *)values_p->endpoint.address[temp_int]);
	     printf("\n");
	   }
#endif
	   values_p->endpoint.valid = 1;
	   break;

	case 5:		/* Public Switched Network Directory Number (E.164) */
	   values_p->endpoint.class = endp_option;
	   bcopy (tt, values_p->endpoint.address, strlen(tt));
	   values_p->endpoint.length = strlen(tt);
	   values_p->endpoint.valid = 1;
	   break;

	default:
#ifdef DEBUG_ENVPARSE
	   if (debug > 1)
	      printf("extract_endpoint_data failed.\n");
#endif
	   return(FALSE);
	   break;
     }

#ifdef DEBUG_ENVPARSE
     if (debug > 1)
	printf( "extract_endpoint_data suceeded\n");
#endif
      return(TRUE);
   }

#ifdef DEBUG_ENVPARSE
   if (debug > 1)
      printf("extract_endpoint_data failed.\n");
#endif
   return(FALSE);
}
