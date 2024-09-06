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
 * Module Function:
 *	Second part of conversion routines. It had to be split in 2 parts
 *	(conv1.c conv2.c) so it would compile on wonderful XENIX PC (ran
 *	 out of HEAP before).
 *
 * Original Author: D. Emond	Created on: 4/2/90 for R5.0.2
 *
 *****************************************************************************
 */

/*
 *****************************************************************************
 *                                                                           *
 *		     Include Files                                           *
 *                                                                           *
 *****************************************************************************
 */

#ifdef NA

/* This file must be first -- in the host NA only! */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/uio.h>
#include <syslog.h>
#else
#include "../inc/rom/syslog.h"
#endif 

#include <fcntl.h>
#include <setjmp.h>
#include <ctype.h>
#define CMD_H_PARAMS_ONLY
#include "../inc/na/cmd.h"
#else
#include "../inc/port/port.h"
#include "types.h"
#include "stdio.h"
#include "../netinet/in.h"
#include "netdb.h"
#include "strings.h"
#include "uio.h"
#include "setjmp.h"
#include "ctype.h"
#include "externs.h"
#include "../inc/rom/syslog.h"
#endif

#include "../inc/na/na.h"
#include "../inc/na/iftype.h"
#include "../inc/na/server.h"
#include "../inc/erpc/netadmp.h"
#include "../inc/na/na_selmods.h"

/*
 ***********************************************************************
 *                                                                     *
 *		     Defines and Macros                                *
 *                                                                     *
 ***********************************************************************
 */

#define lower_case(x) 	(isalpha(x) ? (islower(x) ? x : tolower(x)) : x)

#define xylo_min(a, b)	(((a) > (b)) ? (b) : (a))

#define CHUNK_SZ	5

#define NETID_MIN	0x0000
#define NETID_MAX	0xfffe
#define NODEID_MAX	0xfe

#ifndef M_PRIBS
#define M_PRIBS 32
#endif

/*
 *****************************************************************************
 *                                                                           *
 *		     Structure Definitions                                   *
 *                                                                           *
 *****************************************************************************
 */



/*
 *****************************************************************************
 *                                                                           *
 *		     External Data Declarations                              *
 *                                                                           *
 *****************************************************************************
 */

#ifndef _WIN32
extern UINT32 
	inet_addr();
extern char 
	*inet_ntoa();
#endif
extern int
	str_to_inet();

extern int errno;

#ifdef NA
extern void encode();
#else
extern int encode();
#endif
/*
 *****************************************************************************
 *                                                                           *
 *		     Global Data Declarations                                *
 *                                                                           *
 *****************************************************************************
 */



/*
 *****************************************************************************
 *                                                                           *
 *		     Static Declarations                                     *
 *                                                                           *
 *****************************************************************************
 */

static char hex_digits[] = /*NOSTR*/"0123456789abcdef";
static char oct_digits[] = /*NOSTR*/"01234567";

/* syslog_levels[], serv_options[], selectable_mods[] and ncp_options []
   need to be in alphabetical order because of parse_list() */
struct mask_options syslog_levels[] = { 
    { 1<< LOG_ALERT,     "alert" },
    { 0xff,              "all"},
    { 1<< LOG_CRIT,      "critical" },
    { 1<< LOG_DEBUG,     "debug" },
    { 0,                 "default"},
    { 1<< LOG_EMERG,     "emergency" },
    { 1<< LOG_ERR,       "error" },
    { 1<< LOG_INFO,      "info" },
    { 0,                 "none"},
    { 1<< LOG_NOTICE,    "notice" },
    { 1<< LOG_WARNING,   "warning" },
    { 0,                  (char *)0 }
    };

/* Must be in alphabetic order by text of option */
struct mask_options serv_options[] = {
    { SERVE_ALL,      "all"},
    { SERVE_CONFIG,   "config" },
    { SERVE_IMAGE,    "image" },
#ifndef MICRO_ELS
    { SERVE_MOTD,     "motd" },
#endif
    { 0,              "none"},
    { 0,               (char *)0 }
    };

struct mask_options selectable_mods[] = OPT_MASK_TABLE;

/* Must be in alphabetic order by text of option */
struct mask_options ncp_options[] = {
    { 0x01, /* NCP_ALL  */ "all" },
    { 0x04, /* NCP_ATCP */ "atcp"},
    { 0x20, /* NCP_CCP  */ "ccp" },
    { 0x02, /* NCP_IPCP */ "ipcp"},
    { 0x08, /* NCP_IPXCP*/ "ipxcp"},
    { 0x10, /* NCP_MP   */ "mp"  },
    { 0,                   (char *)0}
    };


#ifdef NA
static struct {
	int code;
	char	*hw_name;
	char 	*sw_name;
} products[] = {
	{ 0,  "Annex",       "" },	{ 11, "Annex",       "-MX" },
	{ 13, "Annex",       "-UX" },	{ 16, "Annex-II",    "-MX" },
	{ 17, "Annex-II",    "-UX" },	{ 32, "Annex-X.25",  ""  },
	{ 42, "Annex-3",     "-UX" },	{ 43, "Annex-3",     "-MX" },
	{ 46, "RA4000", "" },
	{ 52, "Micro-Annex", "-UX" },	{ 53, "Micro-Annex", "-MX" },
	{ 55, "Micro-Annex-ELS", "-UX" }, { 56, "RA2000", "" },
	{ 63, "Annex", "-RAC" },
	{ -1, NULL, NULL }
};

static char sw_id_buff[128];
#endif	/* NA */


/*
 *****************************************************************************
 *                                                                           *
 *		     Forward Routine Declarations                            *
 *                                                                           *
 *****************************************************************************
 */



UINT32 parse_sequence();
UINT32 parse_list();
#ifdef NA
int Sp_support_check();
int Ap_support_check();
void punt();
#endif
char	*lex_token();



int
print_to_c(string, Pcardinal)	/* printable string (representing a character)
				   to cardinal conversion */
	char    string[];
	unsigned short *Pcardinal;
{
	int len;

	len = strlen(string);
	if (len == 1) {
	    if (Pcardinal)
		*Pcardinal = (unsigned short)string[0];
	    }
	else if (len == 2 && string[0] == '^')
	    {
	    if (Pcardinal)
		if (string[1] == '@')
			*Pcardinal = 0;
		else if (string[1] == '?')
			*Pcardinal = 0177;
		else if (((string[1] > 040) && (string[1] < 077)) 
			|| (string[1] == 0134)  || (string[1] == '`') ||
			(string[1] == '|') || (string[1] == '~')) 
			punt("invalid character:", string);
		else	
			*Pcardinal = (unsigned short)string[1] & 037;
	    }
	else if (len <= 4 && string[0] == '0')
	    {
	    unsigned short value;
	    char *Pstring,
		 *Pdigit;

	    value = 0;

	    if (string[1] == 'x' || string[1] == 'X')
		{
		Pstring = &string[1];

		while (*++Pstring)
		    { 
		    Pdigit = (char *)index(hex_digits, lower_case(*Pstring));

		    if (Pdigit)
			value = value * 16 + (Pdigit - hex_digits);
		    else if (Pcardinal)
			punt("invalid hex number: ", string);
		    else
			return 1;
		    }
		}
	    else
	        {
		Pstring = &string[1];

		while (*Pstring)
		    { 
		    Pdigit = (char *)index(oct_digits, *Pstring++);
		    if (Pdigit)
			value = value * 8 + (Pdigit - oct_digits);
		    else if (Pcardinal)
			punt("invalid octal number: ", string);
		    else
			return 1;
		    }
		}

	    *Pcardinal = value;
	    }
        else if (Pcardinal)
	    punt("invalid character: ", string);
	else
	    return 1;

	return(0);
} /* print_to_c() */


void
c_to_print(cardinal, string) /* cardinal to printable character conversion */

	u_short cardinal;
	char    string[];

{
	if (cardinal == 0)
	    (void)strcpy(string, /*NOSTR*/"^@");
	else if (cardinal == 0177)
	    (void)strcpy(string, /*NOSTR*/"^?");
	else if (cardinal < ' ')
	    {
	    string[0] = '^';
	    string[1] = cardinal + 0x40;
	    string[2] = '\0';
	    }
	else
	    {
	    string[0] = (char)cardinal;
	    string[1] = '\0';
	    }

}	/* c_to_print */


	/*
	 *  string to inet addr conversion
	 */

#ifdef NA
str_to_inet(string, Ps_addr, zero_ok, oblivious)

	char          string[];
	UINT32        *Ps_addr;
	int           zero_ok,
		      oblivious;	/* oblivious to errors - dont punt */

{
	struct hostent *Phostent;

	/* If the string begins with a digit, assume a "dot notation" inet
	   address; otherwise, assume a /etc/hosts name. */

	if (isdigit(string[0]))
	{
	    *Ps_addr = inet_addr(string);
	    if (*Ps_addr == -1 && strcmp(string,/*NOSTR*/"255.255.255.255"))
	    {
		if(oblivious)
		    return -1;
		else
		    punt(BAD_BOX, string);
	    }

	    if (*Ps_addr == 0 && !zero_ok)
	    {
		if(oblivious)
		    return -1;
		else
		    punt(NONYMOUS_BOX, (char *)NULL);
	    }
	}
	else
	{
	    if (!(Phostent = gethostbyname(string)))
	    {
		if(oblivious)
		    return -1;
		else
		    punt(WHAT_BOX, string);
	    }
	    bcopy(Phostent->h_addr, (char *)Ps_addr, Phostent->h_length);
	}
	return (0);

}	/* str_to_inet() */
#endif


#ifdef NA
int
get_internal_vers(id, vers, hw, flag, ask)
UINT32 	id; 
UINT32  *vers, *hw, *flag;
int	ask;
{

/*printf("caling get_internval_vers\n"); */
	/* Pick off the version number */
	switch (id & 0x0000FFFF) {
        case 0x00000100:	/* VER. 1.0 */
		*vers = VERS_1;
		break;
        case 0x00000200:	/* VER. 2.0 */
	case 0x00000201:	/* VER. 2.1 */
		*vers = VERS_2;
		break;
	case 0x00000300:	/* VER. 3.0 */
		*vers = VERS_3;
		break;
	case 0x00000400:	/* VER. 4.0 */
		*vers = VERS_4;
		break;
	case 0x00000401:	/* VER. 4.1 */
		*vers = VERS_4_1;
		break;
	case 0x00000500:	/* VER. 5.0 */
		*vers = VERS_5;
		break;
	case 0x00000600:	/* VER. 6.0 */
		*vers = VERS_6;
		break;
	case 0x00000601:	/* VER. 6.1 */
		*vers = VERS_6_1;
		break;
	case 0x00000602:	/* VER. 6.2 */
		*vers = VERS_6_2;
		break;
	case 0x00000700:	/* VER. 7.0 */
		*vers = VERS_7;
		break;
	case 0x00000701:	/* VER. 7.1 */
		*vers = VERS_7_1;
		break;
	case 0x00000800:	/* VER. 8.0 */
		*vers = VERS_8;
		break;
	case 0x00000801:        /* VER. 8.1 */
		*vers = VERS_8_1;
		break;
	case 0x00000900:	/* VER. 9.0 */
        case 0x00000902:        /* VER. 9.2 */
		*vers = VERS_BIG_BIRD;
		break;
	case 0x00000901:	/* VER. 9.1 */
        case 0x00000903:        /* VER. 9.3 */
		*vers = VERS_POST_BB;
		break;
	case 0x00000a00:	/* Ver. 10.0 (?) */
	case 0x00000a01:	/* Ver. 10.1 (?) */
		*vers = VERS_DENALI; 
		break;
	case 0x00000b01:	/* Ver. 11.1 */
		*vers = VERS_MCK2;
		break;
	case 0x00000d00:	/* Ver. 13.0? */
		*vers = VERS_PRIMATE;
		break;
	case 0x00000b02:        /*Ver. 11.2? */ 
	case 0x00000d01:        /*Ver. 13.1? */
	case 0x00003800:	/*Ver. 56.0? */
		*vers = VERS_RUSHMORE;
		break;
	case 0x00000d02:	/* Ver. 13.2 */
	case 0x00003801:	/* Ver. 56.1 */
		*vers = VERS_WASHINGTON;
		break;
	case 0x00000d03:	/* Ver. 13.3 */
		*vers = VERS_WASH_2;
		break;
	case 0x00000e00:	/* Ver. 14.0 */
		*vers = VERS_14_0;
		break;
	case 0x00000e01:	/* Ver. 14.1 */
		*vers = VERS_14_1;
		break;
	case 0x00000e02:	/* Ver. 14.1 */
		*vers = VERS_14_2;
		break;
	default:
#define NEWEST_NAME	"14.2"
#define DEFAULT_VERS	VERS_14_2
#define DEFAULT_NAME	"14.2"
/* This define should be kept at the current version!  Don't forget to
   fix the prompt string below */

		if (ask == FALSE) {
		    *vers = DEFAULT_VERS;
		    break;
		}
		if (script_input) {
		    printf("Unknown software version, using default (%s)\n",
			   DEFAULT_NAME);
		    *vers = DEFAULT_VERS;
		}
		else {
#define REPLY_LENGTH 10
		    char	query_reply[REPLY_LENGTH];
		    char	*cmd_p = query_reply;
		    int		cmd_cnt = sizeof(query_reply);

		    fprintf(stdout, 
"Annex \"%s\" is running software which is newer than NA %s.\nSome parameters will not be accessible.\n\tDo you wish to continue as %s anyway? (y/n) [n]: ",
			    symbol,NEWEST_NAME,DEFAULT_NAME);
		    while (!fgets(cmd_p, cmd_cnt, stdin)) {
			if(ferror(cmd_file) && (errno == EINTR))
			    continue;
			return 1;
		    }
		    while (*cmd_p && index(WHITE_SPACE, *cmd_p))
			cmd_p++;

		    if (*cmd_p == 'y' || *cmd_p == 'Y') {
			*vers = DEFAULT_VERS;
			break;
		    }
		    else
			return 1;
		}
		break;
	}

	/* Pick off the product ID */
	switch ((id >> 16) & 0x0000FFFF) {
	case 11:			/* ANNEX-I MX */
		*flag |= ANX_RDRP;
	case 13:			/* ANNEX-I UX */
		*hw = ANX_I;
		break;

	case 16:			/* ANNEX-II MX */
		*flag |= ANX_RDRP;
	case 17:			/* ANNEX-II UX */
		*hw = ANX_II;
		break;

	case 32:			/* ANNEX-X25 */
		*hw = X25;
		break;

	case 43:			/* ANNEX-3 MX */
		*flag |= ANX_RDRP;
	case 42:			/* ANNEX-3 UX */
	case 46:			/* RA4000 */
		*hw = ANX3;
		break;

	case 53:			/* MICRO-ANNEX MX */
		*flag |= ANX_RDRP;
	case 52:			/* MICRO-ANNEX UX */
	case 56:			/* RA2000 */
		*hw = ANX_MICRO;
		break;

	case 55:			/* MICRO-ANNEX-ELS UX */
		*hw = ANX_MICRO_ELS;
		break;

	case 63:			/* RA6300, 5393 */
	case 64:			/* 5399, 8000 */
		*hw = ANX_PRIMATE;
		break;

	default:
		printf("Unknown hardware type, using default\n");
		*hw = ANX_I;
		break;
	}
   return 0;
}

#define PRODUCT 	1
#define MAJOR_REV	2
#define MINOR_REV	3

char *
display_sw_id(sw_id,hw_id)
	UINT32  sw_id, hw_id;
{
	union {
		UINT32	id_long;
		char	id_chars[4];
	} id_union;

	char *product_str = NULL, *sw_str = NULL;
	int i;

	if(!sw_id)
		return("Annex R1.0 - R2.0");

	id_union.id_long = htonl(sw_id);

	for (i = 0; product_str == NULL; i++)
	    if (products[i].code < 0) {
		product_str = /*NOSTR*/"??";
		sw_str = /*NOSTR*/"";
	    } else if (products[i].code ==
		(int)id_union.id_chars[PRODUCT]) {
		product_str = products[i].hw_name;
		sw_str = products[i].sw_name;
	    }

	sprintf(sw_id_buff, /*NOSTR*/"%s%s%s R%d.%d", product_str,
		hw_id == ANX_II_EIB ? /*NOSTR*/"e":/*NOSTR*/"",
		sw_str,
		id_union.id_chars[MAJOR_REV],
		id_union.id_chars[MINOR_REV]);

	return(sw_id_buff);
}
#endif	/* NA */

UINT32
parse_sequence(b, port_count)	/* returned in net order */
char *b;
INT32 port_count;
{
    int entered = 0;
    char chunk[CHUNK_SZ], *comma;
    union {
	UINT32 as_long;
	unsigned char seq[sizeof(UINT32)];
	} r;
    unsigned int i, slipper;
    int	length;

    for(i = 0; i < sizeof(r.seq); ++i)
	r.seq[i] = IFBYTE_NONE;

    if (strcmp(b, "default") == 0) {
      r.seq[0] = 0;
      return(r.as_long);
    }

    while(*b) {

	comma = (char *)index(b, ',');

	if(!comma) {			/* End of string */
	    (void)strncpy(chunk, b, CHUNK_SZ);
	    b += strlen(b);
	    }
	else {				/* Comma-delimited item */
	    (void)strncpy(chunk, /*NOSTR*/"", CHUNK_SZ);
	    (void)strncpy(chunk, b, xylo_min(CHUNK_SZ, comma - b));
	    b = comma + 1;
	    }

	if(chunk[CHUNK_SZ - 1]) {
	    chunk[CHUNK_SZ - 1] = '\0';
	    punt("interface name too long: ", chunk);
	    }

	if(entered == PDL_IS_SIZ)
	    punt("only 1-4 interfaces can be entered", (char *)0);

	/*
	 * Some broken machines (NCR) implement string macros in assembly and
	 * don't allow nested assembler macro calls (gak!)
	 */
	length = strlen(chunk);
	if(!strncmp(chunk, "net", length))
	    r.seq[entered++] = 0;

	else if(!strncmp(chunk, "sl", 2) && isdigit(chunk[2])) {
#if NSLIP == 0
	    punt("invalid interface name: ", chunk);
#else
	    slipper = atoi(&chunk[2]);
	    if(slipper < 2 || slipper > port_count)
		punt("invalid port number: ", chunk);
	    r.seq[entered++] = IFTYPE_SLIP | (slipper - 1);
#endif
	    }

	else if (!strncmp(chunk, "self", length)) {
	    r.seq[entered++] = IFTYPE_FLASH;
	    }

	else
	    punt("invalid interface name: ", chunk);

	} /* end of while(*b) loop */

    if(!entered)
	punt("invalid sequence", (char *)0);

    return(r.as_long);
}


void
decode_sequence(result, internal)
char *result;
UINT32 internal;	/* network order */
{
    unsigned char *u = (unsigned char *)&internal;
    int i, any = 0;
    unsigned char ifbyte;
    char *s;

    if(internal == 0L) {
	(void)strcpy(result, "net");
	return;
	}


    *result = '\0';

    for(i = 0; i < PDL_IS_SIZ; ++i) {

	ifbyte = *u++;

	if(ifbyte == IFBYTE_NONE)
	    continue;

	if(any++)
	    (void)strcat(result, /*NOSTR*/",");

	s = (char *)index(result, '\0');

	switch(ifbyte & IFTYPE_MASK) {
	case 0:
	    if(ifbyte & ~IFTYPE_MASK)
		sprintf(s, /*NOSTR*/"%s%d", "net",(ifbyte & ~IFTYPE_MASK) + 1);
	    else
		sprintf(s, "net");
	    break;
	case IFTYPE_SLIP:
	    sprintf(s, /*NOSTR*/"%s%d", "sl", (ifbyte & ~IFTYPE_MASK) + 1);
	    break;
	case IFTYPE_FLASH:
	    sprintf(s, "self");
	    break;
	default:
	    sprintf(s, /*NOSTR*/"??%d", (ifbyte & ~IFTYPE_MASK) + 1);
	    break;
	    }
	}

	if(!any)
	    (void)strcpy(result, "net");
}


UINT32
parse_list(b,table)	/* returned in host order */
char *b;
struct mask_options *table;
{
    char *comma, *bnext;
    int i, clen;
    UINT32 result;

    result = 0;

    while(*b) {

	comma = (char *)index(b, ',');

	if(!comma) {			/* End of string */
	    clen = strlen(b);
	    bnext = b + strlen(b);
	    }
	else {				/* Comma-delimited item */
	    clen = comma - b;
	    bnext = comma + 1;
	    }

	if(!clen) {
	  ++b;
	  continue;
	  }

	for (i = 0; table[i].name; ++i) 
	  if (!strncasecmp(b, table[i].name, clen)) {
	    if (table[i+1].name) {
	      if (!strncasecmp(b, table[i+1].name, clen)) {
		punt("non-unique symbol: ", b);
		break;
	      }
	      else {
		result |= table[i].mask;
		break;
	      }
	    }
	    else {
	      result |= table[i].mask;
	      break;
	    }
	  }

	if(!table[i].name) 
	  punt("invalid option: ", b);

	b = bnext;

	} /* end of while(*b) loop */

    return(result);
}


void
decode_mask(result, internal, table)
char *result;
UINT32 internal;	/* host order */
struct mask_options *table;
{
    UINT32 c = internal; /* (unsigned char)ntohs(internal); */
    int any = 0;
    int i;
    UINT32 ignorelist;

    (void)strcpy(result, /*NOSTR*/"");
    any = 0;
    /*
     * Ignore list is used to handle aliases; we want to display them
     * only once.  First alias found is the preferred name.
     */
    ignorelist = 0;
    for (i = 0; table[i].name; ++i)
	    /* If table[i].name is "all" or "default", keep looking. */
	    if ((c & table[i].mask) == table[i].mask &&
		!(table[i].mask & ignorelist) &&
	        strcmp(table[i].name, "default") != 0) {

		if(any)
		    (void)strcat(result, /*NOSTR*/",");
		any = 1;
		(void)strcat(result, table[i].name);
		ignorelist |= table[i].mask;
	    }
}


void
decode_anxsyslog_mask(result, internal)
char *result;
UINT32 internal;
{
  int i, any = 0;
  
  (void)strcpy(result, /*NOSTR*/"");
  for (i = 0; syslog_levels[i].name; ++i) 
    if ((syslog_levels[i].mask <= internal) && (syslog_levels[i].mask != 255) 
	&& (syslog_levels[i].mask != 0)) {
      if (any)
	(void) strcat(result, ",");
      any = 1;
      (void) strcat (result, syslog_levels[i].name);
    }
}




/*
 *****************************************************************************
 *
 * Function Name:	trans_prompt()
 *
 * Functional Description:
 *			Converts formatting codes into corresponding control
 *			characters
 *
 * Parameters:		p - prompt to be converted
 *			accept_ucode - TRUE(used by cli_prompt) or FALSE
 *			(used by radius prompt parameters). For cli_prompt %u 
 *			is a valid format code whereas for radius prompts %u is
 *			 not a valid format code 
 *
 * Return Value:	0 => success
 *			-1 => failure (invalid formatting code contained in 
 *				string). punt, incase of na does a longjmp to
 *				place for entering next command. But for admin,
 *				punt is a macro that returns -1
 *
 * Side Effects:	This function updates the prompt pointer p with the 
 *			converted characters
 *
 * Exceptions:
 *
 * Assumptions:
 *
 *****************************************************************************
 */
int trans_prompt(p, accept_ucode)
char *p;
int accept_ucode;
{
    char *src = p;
    char *dest = p;
#ifdef NA
    char *str = p;
#endif
    char fc;

    while(*src) {
	if(*src == '%') {			/* percent sign... */
    		fc = *(src + 1);
		switch (fc) {
       		case 'A':	
       		case 'C':	
       		case 'D':	
       		case 'I':	
       		case 'J':	
       		case 'L':	
       		case 'N':	
       		case 'P':	
        	case 'R':	
        	case 'S':	
        	case 'T':	
			*dest++ = fc - 'A' + 1;	/* uppercase control codes */
			++src;
			break;
        	case 'a':	
        	case 'c':	
        	case 'd':	
        	case 'i':	
        	case 'j':	
        	case 'l':	
        	case 'n':	
        	case 'p':	
        	case 'r':	
        	case 's':	
        	case 't':	
			*dest++ = fc - 'a' + 1;
			++src;
			break;
        	case 'U':	
        	case 'u':	
			if (accept_ucode == TRUE) {
				if (fc == 'U')
					*dest++ = fc - 'A' + 1;
				else
					*dest++ = fc - 'a' + 1;
				++src;
				break;
			} /* else for accept_ucode==FALSE used by radius_prompts
			     fall thru' */
        	case '%':	
			*dest++ = fc;
			++src;
			break;
		default:
			p[0] = '%'; p[1] = fc; p[2] = '\0';
			punt("invalid formatting code: ", str);
			break;
		}
	}
	else					/* literal */
	    *dest++ = *src;
	++src;
	}

    *dest = '\0';
    return 0;
}

#ifdef NA
int
Ap_support_check(id, param)
ANNEX_ID *id;
int param;
{
	return 1;
}
int
Anyp_support(id,param,table)
ANNEX_ID *id;
int param;
parameter_table *table;
{
  UINT32 mask_val = 0;
  UINT32 *mask_ptr;
  UINT32 mask_offset = 0;

  mask_ptr =  table[param].pt_version[(id)->hw_id];
  if (mask_ptr == 0)
     return(0);
  if ((id)->version <= VERS_POST_BB) {
	mask_val = *mask_ptr;
	return((id)->version & mask_val);
       }
  else {
        mask_offset = ((id)->version & 0x7fff) - 1;
        mask_val = *(mask_ptr + 1 + mask_offset/32);
	return( (1 << (mask_offset%32)) & mask_val );
        }
}
int Ip_support_check(id, param)
ANNEX_ID *id;
int param;
{
	return (1);
}

int Sp_support_check(id, param)
ANNEX_ID *id;
int param;
{
	if (id->flag & ANX_MICRO_V11 && 
		(param == CONTROL_LINE_USE || param == NEED_DSR))
	  return(0);
  	return(1); 
}
#endif 


/*
 * encode interface parameters rip_accept and rip_advertise
 */
int
encode_rip_routers (external, internal)

char *external;                 /*  external representation (for human) */
char *internal;                 /*  internal representation (for Annex) */
{
	INTERN	Internal;
	int 	i, indx, length,
		err = 0;
	char 	*ptr;
        u_short         exclude = 0,
			include = 0;
	char            address_list[MAX_RIP_INT_STRING+1];
        char            token[MAX_RIP_EXT_STRING+1];     /* max length of network routing list */

	/* initialize first */
	Cinternal = internal;
	i = 1;
	indx = 1;
	CS_length = 1;
	length = 1;
	ptr = external;
	if (strlen(ptr) > MAX_RIP_EXT_STRING) {
		/*invalid parameter value*/
		return(1);
	}
	ptr = lex_token(ptr, token, (char *) NULL);
	/* 
	 * The acceptable parameter values for
	 * set interface rip_accept/rip_advertise are:
	 * 1. none
	 * 2. all or default
	 * 3. include/exclude xx.xx.xx.xx,xx....
	 * where xx.xx.xx.xx,xx... up to eight IP address.
	 */

	/*
	 * Here is the encode mechanism:
	 * There are 33 bytes in EEPROM, the first byte indicates
	 * the parameter type and the rest of 32 bytes store 
	 * the list of IP address in long format (four-byte hex).
	 * The first byte is encoded as follow:
	 * 	0x00 -> all (this is default)
	 *	0x01 -> none
	 * 	other -> the length of total bytes including the
	 *	         first byte. For example, 
	 *		 5 -> one IP ( 1 + 4)
	 *		 9 -> two IPs (1 + 8) and so on. 
	 *      Also, the highest bit of the first byte masks
	 *      either include or exclude.
	 *      mask off -> include
	 *      mask on -> exclude
	 */
	while (TRUE) {
		if (strncmp(token, "include", strlen(token)) == 0) {
			include=1;
			if (!ptr || !*ptr) {
				/*invalid syntax*/
				return(-1);
			}
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue; 
		}
		if (strncmp(token, "exclude", strlen(token)) == 0) {
			exclude=1;
			if (!ptr || !*ptr) {
				/*invalid syntax*/
				return(-1);
			}
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue;
		}
		if (token[0] == ',') {
			if (!ptr || !*ptr) {
				/*invalid syntax*/
				return(-1);
			}
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue;
		}
		/*
		 * all -> length one byte and value is 0
		 */
		if ((strcmp(token, ALL_STR) == 0) ||
		    (strcmp(token, "default") == 0)) {
			length = 1;
			CS_length = 1;
			CS_string[0] = 0;
			break;
		} else if (strcmp(token, NONE_STR) == 0) {
			length = 1;
			CS_length = 1;
			CS_string[0] = 1;
			break;
		} else {
			if (!include && !exclude) 
				/*invalid syntax*/
				return(-1);
			/* 
			 * convert dot-decimal format into inet format
			 */
			err = str_to_inet(token, Linternal, TRUE, 1);
			if ( err )
				/*invalid parameter value */
				return(1);
			/* 
			 * stores as string byte 
			 */
			*(INT32 *)internal = *Linternal; 
			indx = indx + 4;
			if (length >= MAX_RIP_INT_STRING) {
				/*invalid parameter value */
				return(1);
			}
			for ( i = length; i < indx; i++)
				address_list[i] = *internal++;
			length = length + 4;
			if (!ptr || !*ptr)
				break;
			ptr++;
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue; 
		}
	}
	if ( include || exclude ) {
		CS_length = length;
		if ( exclude )
			address_list[0] = length | 0x80;
		else
			address_list[0] = length;
		ptr = address_list;
		bcopy(ptr, CS_string, length);
	}
	return (0);
}


/*
 * encode annex rip_routers parameter
 */
int
encode_box_rip_routers (external, internal)

char *external;                 /*  external representation (for human) */
char *internal;                 /*  internal representation (for Annex) */
{
	INTERN	Internal;
	int 	i, indx, length,
		err = 0;
	char 	*ptr;
        char            address_list[MAX_RIP_INT_STRING+1];
        char            token[MAX_RIP_EXT_STRING+1];     /* max length of network routing list */

	/* initialize first */
	Cinternal = internal;
	i = 1;
	indx = 1;
	CS_length = 1;
	length = 1;
	ptr = external;
	if (strlen(ptr) > MAX_RIP_EXT_STRING) {
		/*invalid parameter value */
		return(1);
	}
	ptr = lex_token(ptr, token, /*NOSTR*/",");
	/* 
	 * The acceptable parameter values for
	 * set annex rip_routers are:
	 * 1. all or default
	 * 2. xx.xx.xx.xx,xx....
	 * where xx.xx.xx.xx,xx... up to eight IP address.
	 * check CNV_RIP_ROUTERS for detail encode mechanism:
	 */

	while (TRUE) {
		/*
		 * all -> length one byte and value is 0
		 */
		if ((strcmp(token, ALL_STR) == 0) ||
		    (strcmp(token, "default") == 0)) {
			CS_string[0] = 0;
			break;
		} else if (token[0] == ',') {
			if (!ptr || !*ptr) {
				/*invalid syntax*/
				return(-1);
			}
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue;
		} else {
			/* 
			 * convert dot-decimal format into inet format
			 */
			err = str_to_inet(token, Linternal, TRUE, 1);
			if ( err )
				/*invalid parameter value */
				return(1);
			/* 
			 * stores as string byte 
			 */
			*(INT32 *)internal = *Linternal; 
			indx = indx + 4;
			if (length >= MAX_RIP_INT_STRING) {
				/*invalid parameter value */
				return(1);
			}
			for ( i = length; i < indx; i++)
				address_list[i] = *internal++;
			length = length + 4;
			if (!ptr || !*ptr)
				break;
			ptr++;
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue; 
		}
	}
	/*
	 * if not "all" string, must be IP address
	 */
	if ( length != 1) {
		CS_length = length;
		address_list[0] = length;
		ptr = address_list;
		bcopy(ptr, CS_string, length);
	}
	return (0);	

}	

/*
 * decode interface rip_accept and rip_advertise parameters
 */
int
decode_rip_routers(internal, external)

char *internal;			/*  internal representation (for Annex) */
char *external;			/*  external representation (for human) */
{
	char		*ptr;
	INTERN		Internal;	/*  union of pointers to types	*/
	int		length; 	/*  length of a string		*/
	char            address_list[MAX_RIP_EXT_STRING+1];

	Cinternal = internal;	/*  move to pointer to various types	*/
	
	length = CS_length;

	address_list[0] = '\0';
	ptr = CS_string;
		
	/*
	 * none -> the value of first byte is 1
	 */
	if (length == 1 && *ptr == 1) {
		strcpy(external, NONE_STR);
		return(0);
	}
	/*
	 * all -> default
	 */
	else if (length <= 1) {
		strcpy(external, ALL_STR);
		return(0);
	}
	else if ((*ptr & RIP_LEN_MASK) < 5 || 
			(*ptr & RIP_LEN_MASK) > MAX_RIP_INT_STRING ||
			(((*ptr &  RIP_LEN_MASK) - 1) % 4) != 0) {
		/*bad format of eeprom router address string*/
		strcpy(external, NONE_STR);
		return(-1);
	}
	/*
	 * contains include/exclude IP address. Decode the way
	 * as it encodes. See the comments on encode routine 
	 * for detail.
	 */
	else {
		(void)strcat(address_list, "include ");
		length = *ptr++;
		if (length & 0x80) {
			length = length & RIP_LEN_MASK;
			(void)strcpy(address_list, "exclude ");
		}
		length = length - 1;

		while (length > 0) {
			 bcopy(ptr, Linternal, sizeof(INT32));
#ifdef NA
			(void)strcpy(external, inet_ntoa(*Ninternal));
#else
			inet_ntoa(external, *Ninternal);
#endif
			(void)strcat(address_list, external);
			ptr = ptr + 4;
			length = length - 4;
			if (length > 0)
				(void)strcat(address_list, /*NOSTR*/",");
		}
		(void)strcpy(external, address_list);
	}
	return(0);
}

/*
 * decode annex rip_routers parameter
 */
int
decode_box_rip_routers(internal, external)

char *internal;			/*  internal representation (for Annex) */
char *external;			/*  external representation (for human) */
{
	char		*ptr;
	INTERN		Internal;	/*  union of pointers to types	*/
	int		length; 	/*  length of a string		*/
        char            address_list[MAX_RIP_EXT_STRING+1];

	Cinternal = internal;	/*  move to pointer to various types	*/

	length = CS_length;
	address_list[0] = '\0';
	ptr = CS_string;
	/*
	 * all -> default
	 */
	if (length <= 1) {
		strcpy(external, ALL_STR);
		return(0);
	}
	else if (*ptr < 5 || *ptr > MAX_RIP_INT_STRING ||
		    ((u_short) ((*ptr) - 1) % 4) != 0) {
		/*bad format of eeprom router address string*/
		strcpy(external, ALL_STR);
		return(-1);
	}
	/*
	 * contains IP address. Decode the way as it encodes.
	 * See the comments on encode routine for detail.
	 */
	else {
		length = *ptr++;
		length = length - 1;
		while (length > 0) {
			 bcopy(ptr, Linternal, sizeof(INT32));
#ifdef NA
			(void)strcpy(external, inet_ntoa(*Ninternal));
#else
			inet_ntoa(external, *Ninternal);
#endif
			(void)strcat(address_list, external);
			ptr = ptr + 4;
			length = length - 4;
			if (length > 0)
				(void)strcat(address_list, /*NOSTR*/",");
		}
		(void)strcpy(external, address_list);
	}
	return(0);
}

/*
 * encode node_id and at_nodeid appletalk parameters
 */
int
encode_nodeid (external, internal)

char *external;                 /*  external representation (for human) */
char *internal;                 /*  internal representation (for Annex) */
{
	INTERN		Internal;
	int 		indx, err;
	UINT32 	sum, factor;
	u_short		shift, node_value, net_value;
	u_char		num;
	char		c;
	char		*ptr2, *ptr;
	
	/* initialize first */
	Cinternal = internal;
	num = err = 0;

	/*
	 * Check net_value.node_value format first
	 * Format: xxxx.xx
         *     where xxxx -> range from 1 .. 0xfffe
	 *           xx   -> range from 0 .. 0xfe
	 *     xxxx and xx can be either hex or decimal format.
         */
	ptr2 = (char *)index(external,'.');
	if (ptr2 == (char *)NULL)
	    /* Incorrect format for this parameter */
	    return(-1);
        /* initialize */
        ptr = external;
	indx = 0;
	/*
	 * Hex or decimal ?
         */
	if (external[0] == '0' && external[1] == 'x') {
	    ptr = ptr + 2;
	    shift = 0x10;
	}
	else {
	    shift = 10;
        }
										  /* Look for period character and find the length of xxxx */
	for (; *ptr != '.'; ptr++)
	    indx++;
	if (indx > 5)
	    /* Incorrect format for this parameter */
	    return(-1);
	/*
	 * Convert xxxx into net_value
         */
        for (factor = 1, net_value = 0;
		   indx > 0;
		   indx--, factor *= shift) {
	    c = *--ptr;;
	    if (isxdigit(c)) {
	        if (isupper(c))
	      	    num = (u_char)c - (u_char)'A' + 10;
	        else if (islower(c))
		    num = (u_char)c - (u_char)'a' + 10;
		else if (isdigit(c))
		    num = (u_char)c - (u_char)'0';
		/*
		 * Don't accept non-digit chars if non-hex format
		 */
		if ((shift == 10) && (num > 9))
			return(-2);
	        net_value += factor * num;
	    }
	    else
	        /* Invalid character in this parameter */
		return(-2);
        }
						       
        /* Make sure range falls between 1 .. 0xfffe */
	if (net_value < NETID_MIN || net_value > NETID_MAX)
	    /* Invalid range in this parameter */
	    return(-3);
				     
	/* Look for node_value now */
	ptr2++;
	ptr = ptr2;
	indx = 0;
	if ( *ptr2 == '0' && *++ptr2 == 'x') {
	    ptr = ptr + 2;
	    shift = 0x10;
        }
        else  {
	    shift = 10;
        }
        for (; *ptr != '\0'; ptr++)
	    indx++;
	if (indx > 3)
	    /* Incorrect format for this parameter */
	    return(-1);
        /*
         * Convert xx into node_value
	 */
	for (factor = 1, node_value = 0; indx > 0;
		  indx--, factor *= shift) {
	    c = *--ptr;
	    if (isxdigit(c)) {
	        if (isupper(c))
		    num = (u_char)c - (u_char)'A' + 10;
		else if (islower(c))
		    num = (u_char)c - (u_char)'a' + 10;
	        else if (isdigit(c))
		    num = (u_char)c - (u_char)'0';
		/*
		 * Don't accept non-digit chars if non-hex format
		 */
		if ((shift == 10) && (num > 9))
			return(-2);
		node_value += factor * num;
	    }
	    else
		/* Invalid character in this parameter */
		return(-2);
	}

	/* Make sure range fall between 0 ..0xfd */
	if (node_value > NODEID_MAX)
	    /* Invalid range in this parameter */
	    return(-3);
				     
	/*
	 * Store net_value and node_value (both unsigned short) into
	 * 4 bytes (UINT32) in EEPROM now
	 */
        sum = (net_value << 16) | node_value;
        *Linternal = sum;
	return (0);
}

/*
 * encode AppleTalk default_zone_list parameters.
 * external is a string with quotes (") and backslashes (\) already escaped.
 * appletalk zone list can have embedded spaces so they can also be escaped.
 * this is a list of zones comma or space separated o comma and spaces need
 * to be escaped. 
 */
int
encode_def_zone_list (external, internal)

char *external;                 /*  external representation (for human) */
char *internal;                 /*  internal representation (for Annex) */
{
	INTERN		Internal;
	unsigned char	*ptr, *zone_len_ptr, *zone_ptr, c;
	int		length, i, zone_len, total_zones_length;
	int		in_escape = 0;
	
#define iszonechar(c) (((c >=0x20) && (c != 0x7f) && (c <= 0xd8))?1:0)

	/* initialize first */
	Cinternal = internal;
	ptr = (unsigned char *)external;
	length = strlen(external);
        zone_len_ptr = (unsigned char *)CS_string;
	zone_ptr = zone_len_ptr +1; 
        zone_len = 0;
        total_zones_length = 1; /* count first length byte */
	
	/* 
         * scan each input byte and check for:
	 * 1. is it a valid zone character?
	 * 2. if prior byte was an escape "\" then keep this one and exit
         *    escaping state
         * 3. if its an escape "\" then enter ecape state and test next byte.
	 * 4. Is it a zone separator " " or "," or tab then write the len, setup
	 *    the next zone and set the current len to 0.  If len is already
	 *    0 then we are in the case of duplicate separators or trailling
	 *    separators like "blue    red,,,green".  Just strip the extras.
	 * 5. just data move and count it.
         * 6. make sure we don't exceed the max zone len 32 or the max zone 
	 *    list len of 100 including length bytes.
         */
	for (i=0; i < length; i++) {
          c = *ptr++;
	  if (in_escape) {
	    in_escape = 0;
            if (iszonechar(c)) {
              *zone_ptr++ = c;
	      zone_len++;
            } else
	      return (-2);
          } else if ( c == '\\' ) {
	    in_escape = 1;
            continue;
          } else if ( c == ' ' || c == ',' || c == '\t') {
            if (zone_len == 0)
              continue;
	    *zone_len_ptr = zone_len;
            zone_len_ptr = zone_ptr++;
            zone_len = 0;
          } else {
	    if (iszonechar(c)) {
	       zone_len++;
	       *zone_ptr++ = c;
	    } else
	       return (-2);
          }
          if ( zone_len > 32 )
            return (-3);
          total_zones_length++;
          if (total_zones_length > 100)
	    return (-1);
	}
        *zone_len_ptr = zone_len;
	CS_length = total_zones_length;
	return (0);
}

/*
 * encode AppleTalk zone parameter.
 * external is a string with quotes (") and backslashes (\) already escaped.
 * appletalk zones can have embedded spaces so they can also be escaped.
 */
int
encode_zone (external, internal)

char *external;                 /*  external representation (for human) */
char *internal;                 /*  internal representation (for Annex) */
{
	INTERN		Internal;
	unsigned char		*ptr, *zone_ptr, c;
	int		length, i, zone_len;
	int		in_escape = 0;
	
	/* initialize first */
	Cinternal = internal;
	ptr = (unsigned char *)external;
	length = strlen(external);
        zone_ptr = (unsigned char *)CS_string;
        zone_len = 0;
	
	/* 
         * scan each input byte and check for:
	 * 1. is it a valid zone character?
	 * 2. if prior byte was an escape "\" then keep this one and exit
         *    escaping state
         * 3. if its an escape "\" then enter ecape state and test next byte.
	 * 4. just data move and count it.
         * 5. make sure we don't exceed the max zone len 32 
         */
	for (i=0; i < length; i++) {
          c = *ptr++;
	  if ( !iszonechar(c) ) 
	    return (-2);
	  else if (in_escape) {
	    in_escape = 0;
            *zone_ptr++ = c;
	    zone_len++;
          } else if ( c == '\\' ) {
	    in_escape = 1;
            continue;
          } else {
	    zone_len++;
	    *zone_ptr++ = c;
          }
          if ( zone_len > 32 )
            return (-1);
	}
	CS_length = zone_len;
	return (0);
}

/*
 *****************************************************************************
 *
 * Function Name:	lex_token()
 *
 * Functional Description:	As the name implies, this function performs
 *				a type of lexical analysis.  It "peels"
 *				out the next parameter in the string, from,
 *				and copies it to an output field, to.
 *				Also, there is a string of "special"
 *				characters that may are used as delimiters
 *				in addition to the normal white space.
 *
 * Parameters:		from - that pointer to the pointer of the string;
 *			to   - pointer to buffer to copy next arg;
 *			special - string of chars that are delimiters, in
 *				conjunction to normal white space.
 *
 * Return Value:	pointer to next arguement in list
 *
 * Side Effects:	This function updates the from pointer to the next
 *			argument location.
 *
 * Exceptions:
 *
 * Assumptions:
 *
 *****************************************************************************
 */

char *
lex_token (from, to, special)
    char *from,		/* ptr to char ptr (string to parse) */
         *to,			/* dst of next arg */
         *special;		/* other delimeters */
{
	char *ptr = from;	/* ptr to string to parse */

	if (!ptr || !*ptr) {	/* if nothing to parse */
		*to = '\0';
		return(ptr);
	}

	for (; *ptr && isspace(*ptr); ptr++);	/* skip spaces */

	/* parse up to white space or special delimiter */
	while (*ptr && (isgraph(*ptr) || iscntrl(*ptr)) &&
		( !special || !index(special, *ptr))) {
	    *to++ = *ptr++;
	}
	*to = '\0';	/* null terminate parsed arg */

	for (; *ptr && isspace(*ptr); ptr++);	/* skip spaces */

	return(ptr);		/*    return ptr to the rest */
}

int
str_to_enet(string, addr)
char *string;
unsigned char *addr;
{
    int cnt = 0;
    unsigned int val = 0;

    for (cnt = 0; *string; string++) {
        if (isdigit(*string)) {
            val = (val << 4) + (*string - '0');
        } else if (isxdigit(*string)) {
            val = (val << 4) + (*string + 10 - (islower(*string) ? 'a' : 'A'));
        } else if ((*string == '-') || (*string == ' ')) {
            if (val > 255 || *(string + 1) == '\0') {
                return(-1);
            }
	    if(++cnt > 6)
		    return(-1);
            *addr++ = (unsigned char) val;
            val = 0;
        } else {
            return(-1);
        }
    }
    if (val > 255 || ++cnt != 6) {
        return(-1);
    }
    *addr++ = (unsigned char) val;
    return(0);
}

int
str_to_mop_passwd(string, addr)
char *string;
unsigned char *addr;
{
    int iid = 0;        /* input index */
    int oid = 0;        /* output index */
    int i;
    int sz;
    unsigned int val = 0;
    u_char *ptr;

    iid = strlen(string);
    if (iid > (MOP_PASSWD_SZ * 2))
        return(-1);
    oid = 0;

    bzero(addr, MOP_PASSWD_SZ);

    /* convert 16-hex ascii into 8 bin values - mop password */
    /* who can figure */

    /* convert from the string end, to string begin */
    /* the -1 in loop insures that we get all data */
    /* of strings that have an odd length */
    /* converted, reversed and stored into addr */

    for (iid -= 2, sz = 2; iid >= -1; iid -= 2) {
        if (iid < 0) {
            iid = 0;
            sz = 1;
        }
        val = 0;
        ptr = (u_char *)&string[iid];
        for (i = 0; i < sz; i++, ptr++) {
            if (isdigit(*ptr)) {
                val = (val << 4) + (*ptr - '0');
            } else if (isxdigit(*ptr)) {
                *ptr |= 0x20;   /* make lower case */
                val = (val << 4) + (*ptr + 10 - 'a');
            } else
                return(-1);
        }

        if (oid >= MOP_PASSWD_SZ)
            return(-1);
        addr[oid++] = (unsigned char) val;
    }
    return(0);
}

void
convert_bit_to_num(bitstring, pattern)
	char *bitstring;
	char *pattern;
{
	char	*ptr;
	int 	length,		/*  length of a string		*/
		byte, 
		lastone = MAX_BIT_STRING * NBBY, /* initially large */
		span = FALSE,
		bit;


	/* start from scratch */
	*pattern = '\0';
	ptr = bitstring;
	for (byte = 0; byte < MAX_BIT_STRING; byte++) {
	    for (bit = 0; bit < NBBY; bit++) {
		length = strlen(pattern);
		if (*ptr & 0x01) {
		    if ((lastone + 1) == (byte * NBBY) + bit) {
			span = TRUE;
		    } else {
			/*
			 * plus one from zero_base to one_base
			 */
		        sprintf(&pattern[length], /*NOSTR*/"%d,",
			        (byte * NBBY) + bit + 1);
		    }
		    lastone = (byte * NBBY) + bit;
		} else {
		    if (span) {
			length--;
			/*
			 * plus one from zero_base to one_base
			 */
		        sprintf(&pattern[length], /*NOSTR*/"-%d,",
				lastone + 1);
		    }
		    span = FALSE;
		}
		*ptr >>= 1;
	    }
	    ptr++;
	}
	if (span) {
	    length--;
	    sprintf(&pattern[length], /*NOSTR*/"-%d", lastone + 1);
	}
	length = strlen(pattern);
	if (length) {
	    if (pattern[length - 1] == ',') 
	        pattern[length - 1] = '\0';
	 }
}

/*
 * encode annex kerberos hosts and tags parameter
 */
int
encode_kerberos_list (external, internal)

char *external;                 /*  external representation (for human) */
char *internal;                 /*  internal representation (for Annex) */
{
	INTERN	Internal;
	int 	i, indx, length,
		err = 0;
	char 	*ptr;
        char            address_list[MAX_KERB_INT_STRING+1];
        char            token[MAX_KERB_EXT_STRING+1];     /* max length of kerberos list */

	/* initialize first */
	Cinternal = internal;
	i = 1;
	indx = 1;
	CS_length = 1;
	length = 1;
	ptr = external;
	if (strlen(ptr) > MAX_KERB_EXT_STRING) {
		/*invalid parameter value */
		return(1);
	}
	ptr = lex_token(ptr, token, /*NOSTR*/",");
	/* 
	 * The acceptable parameter values for
	 * set annex kerberos lists are:
	 * 1. default (Null list)
	 * 2. xx.xx.xx.xx,xx....
	 * where xx.xx.xx.xx,xx... up to four IP address.
	 */

	while (TRUE) {
		/*
		 * default -> length one byte and value is 0
		 */
		if ((strcmp(token, "default") == 0)) {
			CS_string[0] = 0;
			break;
		} else if (token[0] == ',') {
			if (!ptr || !*ptr) {
				/*invalid syntax*/
				return(-1);
			}
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue;
		} else {
			/* 
			 * convert dot-decimal format into inet format
			 */
			err = str_to_inet(token, Linternal, TRUE, 1);
			if ( err )
				/*invalid parameter value */
				return(1);
			/* 
			 * stores as string byte 
			 */
			*(INT32 *)internal = *Linternal; 
			indx = indx + 4;
			if (length >= MAX_KERB_INT_STRING) {
				/*invalid parameter value */
				return(1);
			}
			for ( i = length; i < indx; i++)
				address_list[i] = *internal++;
			length = length + 4;
			if (!ptr || !*ptr)
				break;
			ptr++;
			ptr = lex_token(ptr, token, /*NOSTR*/",");
			continue; 
		}
	}
	/*
	 * if not "default" string, must be IP address
	 */
	if ( length != 1) {
		CS_length = length;
		address_list[0] = length;
		ptr = address_list;
		bcopy(ptr, CS_string, length);
	}
	return (0);	

}	


/*
 * decode annex kerberos hosts and tags parameter
 */
int
decode_kerberos_list(internal, external)

char *internal;			/*  internal representation (for Annex) */
char *external;			/*  external representation (for human) */
{
	char		*ptr;
	INTERN		Internal;	/*  union of pointers to types	*/
	int		length; 	/*  length of a string		*/
        char            address_list[MAX_KERB_EXT_STRING+1];

	Cinternal = internal;	/*  move to pointer to various types	*/

	length = CS_length;
	address_list[0] = '\0';
	ptr = CS_string;
	/*
	 * default...no addresses in the list.
	 */
	if (length <= 1) {
		strcpy(external, "0.0.0.0");
		return(0);
	}
	else if (*ptr < 5 || *ptr > MAX_KERB_INT_STRING ||
		    ((u_short) ((*ptr) - 1) % 4) != 0) {
		/*bad format of eeprom kerberos address string*/
		strcpy(external, "0.0.0.0");
		return(-1);
	}
	/*
	 * contains IP address. Decode the way as it encodes.
	 * See the comments on encode routine for detail.
	 */
	else {
		length = *ptr++;
		length = length - 1;
		while (length > 0) {
			 bcopy(ptr, Linternal, sizeof(INT32));
#ifdef NA
			(void)strcpy(external, inet_ntoa(*Ninternal));
#else
			inet_ntoa(external, *Ninternal);
#endif
			(void)strcat(address_list, external);
			ptr = ptr + 4;
			length = length - 4;
			if (length > 0)
				(void)strcat(address_list, /*NOSTR*/",");
		}
		(void)strcpy(external, address_list);
	}
	return(0);
}

#if NT1_ENG > 0
/*
 *****************************************************************************
 *
 * Function Name:	t1ds0_encode()
 *
 * Functional Description:	This functions encodes the t1 parameter
 *				specified by the user. Some ds0 parameters
 *				take 2 arguments, others just 1.
 *
 * Parameters:
 *				p_t1ds0set - pointer to ds0 mask
 *				p_symbol - pointer to symbol
 *				p_annex - pointer to annex address
 *				catid - parameter's category id
 *				convid - parameter's conversion id
 *				parm - parameter id
 *				args - pointer to command args
 *				encode_buf- encore buffer where encoded
 *					parameter is returned.
 *
 * Return Value:		ESUCCESS if no errors.
 *				-1 if invalid.
 *
 * Exceptions:
 *
 * Assumptions:
 *
 *****************************************************************************
 */
int
t1ds0_encode(p_t1ds0set, p_symbol, p_annex, cat_id, conv_id, encode_buf, args)
char *p_t1ds0set;
char *p_symbol;
ANNEX_ID *p_annex;
short cat_id, conv_id;
char *encode_buf;
char *args;
{
    int        ds0_ch;	/* ds0 loop */
    char       *encode_ptr;
    int        ret_val = -1;
    char       two_args = FALSE;
    u_char     modem_number=0;

    encode_ptr = encode_buf;

    switch(cat_id) {
    case T1_MAP:
        /* set t1 ds0=<set> map may have 2 value fields.    */
	/* Pass the rest of argument to the encode routine. */
        bzero(encode_buf, 2*ALL_DS0S);
        for (ds0_ch = 1; ds0_ch<=ALL_DS0S; ds0_ch++, encode_ptr+=2)
            if(PORTBITSET(p_t1ds0set, ds0_ch))
                  {
                  /* format: map <map_value> [<modem_number>] */
#ifndef NA
	          ret_val =
#endif
			    encode(conv_id,args,encode_ptr, p_annex);
#ifndef NA
                  if(ret_val)
                      break;
#endif
                  if(encode_ptr[1] != 0) {
                      /* modem number was set */
                      two_args = TRUE;  /* 2 fields were consumed */
                      if(modem_number == 0)
                           modem_number = encode_ptr[1] + 1;
                      else if(modem_number <= ALL_DS0S)
                           encode_ptr[1] = modem_number++;
                      else {
                           ret_val = -1;
                           break;
                           }
                      }
                    }
	break;

    case T1_SIGPROTO:
        /* set t1 ds0=<set> sigproto has 2 value fields.    */
        /* Pass the rest of argument to the encode routine. */
        bzero(encode_ptr, 2*ALL_DS0S);
        for (ds0_ch = 1; ds0_ch<=ALL_DS0S; ds0_ch++, encode_ptr+=2)
	    {
            if(PORTBITSET(p_t1ds0set, ds0_ch))
                {
#ifndef NA
	        ret_val =
#endif
		    encode(conv_id,args,encode_ptr, p_annex);
#ifndef NA
                if(ret_val)
                    break;
#endif
                }
	    }
	break;

    case T1_RING:
	/* set t1 ds0=<set> ring has 1 value fields.        */
	/* Pass the rest of argument to the encode routine. */
        bzero(encode_ptr, ALL_DS0S);
        for (ds0_ch = 1; ds0_ch<=ALL_DS0S; ds0_ch++, encode_ptr++)
            if(PORTBITSET(p_t1ds0set, ds0_ch))
                {
#ifndef NA
	        ret_val =
#endif
	        	encode(conv_id, args, encode_ptr, p_annex);
#ifndef NA
                if(ret_val)
                    break;
#endif
                }
	break;
    default:
#ifndef NA
        ret_val =
#endif
		encode(conv_id, p_symbol, encode_buf, p_annex);
	break;
    }

    return(ret_val);
}
#endif /* NT1_ENG */

#if NPRI > 0
/*
 *****************************************************************************
 *
 * Function Name:	prib_encode()
 *
 * Functional Description:	This functions encodes the PRI parameter
 *				specified by the user.
 *
 * Parameters:
 *				p_pribset - pointer to channel mask
 *				p_symbol - pointer to symbol
 *				p_annex - pointer to annex address
 *				catid - parameter's category id
 *				convid - parameter's conversion id
 *				parm - parameter id
 *				args - pointer to command args
 *				encode_buf- encore buffer where encoded
 *					parameter is returned.
 *
 * Return Value:		ESUCCESS if no errors.
 *				-1 if invalid.
 *
 * Exceptions:
 *
 * Assumptions:
 *
 *****************************************************************************
 */

int
prib_encode(p_pribset,p_symbol,p_annex,cat_id,conv_id,encode_buf,args)
char *p_pribset;
char *p_symbol;
ANNEX_ID *p_annex;
short cat_id, conv_id;
char *encode_buf;
char *args;
{
    int        b_ch;	/* channel loop */
    char       *encode_ptr;
    int        ret_val = -1;
    u_long	temp_buf[3];

    encode_ptr = encode_buf;

    switch (cat_id) {
    case WAN_REMOTE_ADDRESS:
    case WAN_IPX_NETWORK:
      /* set pri b=<set> remote_address has 1 or 2 value fields.    */
      /* set pri b=<set> ipx_network has 1 or 2 value fields.    */
      /* Pass the rest of argument to the encode routine. */
      bzero(encode_ptr, 4*ALL_BS);
#ifndef NA
      ret_val =
#endif
	encode(conv_id,args,temp_buf,p_annex);
      
      for (b_ch = 1; b_ch <= M_PRIBS; b_ch++, encode_ptr += 4)
	if (PORTBITSET(p_pribset, b_ch)) {
	  *(u_long *)encode_ptr = temp_buf[0];
	  temp_buf[0] += temp_buf[1];
	}
      break;
    case WAN_IPX_NODE:
      /* set pri b=<set> ipx_node has 1 or 2 value fields.    */
      /* Pass the rest of argument to the encode routine. */
      bzero(encode_ptr, 6*ALL_BS);
#ifndef NA
	ret_val =
#endif
	  encode(conv_id,args,temp_buf,p_annex);
      for (b_ch = 1; b_ch <= M_PRIBS; b_ch++, encode_ptr += 6)
	if (PORTBITSET(p_pribset, b_ch)) {
	  int carry,sum,i;
	  u_char *bpt,*bpf;

	  bcopy((char *)temp_buf,encode_ptr,6);
	  carry = 0;
	  bpt = (u_char *)temp_buf + 5;
	  bpf = bpt+6;
	  for (i = 5; i >= 0; i--) {
	    sum = *bpt + *bpf + carry;
	    carry = sum > 255 ? 1 : 0;
	    *bpt = sum;
	    --bpt,--bpf;
	  }
	}
      break;
    case WAN_SIGPROTO:
        /* set wan ds0=<set> sigproto has 2 value fields.    */
        /* Pass the rest of argument to the encode routine. */
        bzero( encode_ptr, 2*ALL_BS );
        for( b_ch = 1; b_ch <= ALL_BS; b_ch++, encode_ptr+=2 )
	{
	    if( PORTBITSET( p_pribset, b_ch ) )
	    {
#ifndef NA
	        ret_val =
#endif
		    encode( conv_id, args, encode_ptr, p_annex );
#ifndef NA
                if(ret_val)
                    break;
#endif
	    }
	}
	break;

    case WAN_RINGBACK:
	/* set wan ds0=<set> ring has 1 value fields.        */
	/* Pass the rest of argument to the encode routine. */
        bzero( encode_ptr, ALL_BS );
        for( b_ch = 1; b_ch <= ALL_BS; b_ch++, encode_ptr++ )
            if( PORTBITSET( p_pribset, b_ch ) )
            {
#ifndef NA
	        ret_val =
#endif
		           encode(conv_id, args, encode_ptr, p_annex);
#ifndef NA
                if(ret_val)
                    break;
#endif
            }
	break;

    default:
#ifndef NA
        ret_val =
#endif
	  encode(conv_id, p_symbol, encode_buf, p_annex);
	break;
    }

    return(ret_val);
}
#endif /* NPRI */
