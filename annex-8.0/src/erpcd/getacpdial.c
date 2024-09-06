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
 *****************************************************************************
 */

/*
 *	Include Files
 */

#include "../inc/config.h"
#include "../inc/port/port.h"
#include <stdio.h>

#ifndef _WIN32
#include <pwd.h>
#include <strings.h>
#endif 

#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "acp_policy.h"
#include "ctype.h"
#include "getacpuser.h"

static char DIALUP[PATHSZ];
static FILE *duf = NULL;
static char line[BUFSIZ+1];
#ifdef _WIN32
static char domain_and_name[64];
#endif
extern int debug_dialup;


/* Routine Declarations */
static int test_port();
static int	get_ports();

UINT32 inet_address();

#ifdef _WIN32
/* in ntsupport.c */
extern char *PrependDomainNameAndFix(char *src, char *dest);
#endif

/*
 * setacpdialup
 *
 * This module will set up the global file descriptor for 
 * reading the dialup addresses file.
 *
 */
int
setacpdialup()
{
	int status;

	if ((status = pre_setacpdialup()) != ACPU_ESUCCESS) {
		duf = NULL;
		if (status == ACPU_ESKIP)
			return (0);
		else
			return (-1);
	}

	ACP_DIALUP(DIALUP);		/* build path to file */
	if( duf == NULL ) {
		duf = fopen( DIALUP, "r" );
		if (duf == NULL)
			return -1;
		}
	else
		rewind( duf );
	return 0;
}
/*
 * endacpdialup
 *
 * This module will close global file descriptor for 
 * reading the dialup addresses file.
 *
 */
endacpdialup()
{
	int status;

	if ((status = pre_endacpdialup()) != ACPU_ESKIP) {
		duf = NULL;
		return (0);
	}

	if( duf != NULL ){
		fclose( duf );
		duf = NULL;
	}
	return 0;
}

static char *
getblanksep(cpp)
char **cpp;
{
	char *cp1,*cp2;

	cp1 = *cpp;
	while (isspace(*cp1))
		cp1++;
	if (*cp1 == '\0')
		return NULL;
	cp2 = cp1;
	while (*cp2 != '\0')
		if (isspace(*cp2)) {
			*cp2++ = '\0';
			break;
			}
		else
			cp2++;
	*cpp = cp2;
	return cp1;
}

/*
 * test_port
 *
 * This module will take a string and a port
 * number and determine if that port has been 
 * given access somewhere in the string.
 *
 * Ex: test_port(&"5,6,10-12",11) = 1
 * and test_port(&"5,6,10-12",18) = 0
 *
 */

static int
test_port(l,port,port_type)
char **l;
int port, port_type;
{
	int test, p1, p2, retval = -1;

	do {
		test = get_ports(l, &p1, &p2, port_type);
		if (test < 0)
			return retval;
		retval = 0;
		if (debug_dialup) {
			printf("\nPorts extracted: %2d  %2d",p1,p2);
			fflush(stdout);
		}
		if (port >= p1 && port <= p2)
			return 1;
	} while (test == 0);

	return 0;
}

#define SCAN_WS		1
#define SCAN_COMMA	2
#define SCAN_DIGITS	4
#define SCAN_ALPHA  8

/*
 * scan
 *
 * This module will scan over certain 
 * specified characters in the string.
 *
 */
static int
scan(p,over)
char **p;
int over;
{
	char *t,chr;
	int code;

	t = *p;
	for (;;) {
		chr = *t;
		if (chr == ',')
			code = SCAN_COMMA;
		else if (isspace(chr))
			code = SCAN_WS;
		else if (isdigit(chr))
			code = SCAN_DIGITS;
		else if (isalpha(chr))
			code = SCAN_ALPHA;
		else
			code = 0;
		if ((code & over) == 0)
			break;
		t++;
		}
	*p = t;
	return code;
}

/*
 * get_ports
 *
 * This module will take the remainder of a line and
 * return the next range of ports.
 * Ex:
 *	Calling get_ports on "7,8,10-12" sets
 *	port1 = 7 and port2 = 7
 *      and
 *	Calling get_ports on "10-12" sets
 *	port1 = 10 and port2 = 12 
 *
 */
static int
get_ports(s, port1, port2, port_type)
char **s;
int *port1, *port2;
int port_type;
{
	char *p = *s;

	if (!(scan(&p,SCAN_WS|SCAN_COMMA) & SCAN_DIGITS)) {
	  if (port_type == PORT_SYNC) {
		/* Look for syn string */
		if (!strncmp(p,"syn",3)) {
		  scan(&p,SCAN_ALPHA);
		  if (!isdigit(*p)) 
			return -1;
		} else {
		  return -1;
		}
	  } else {
		return -1;
	  }
	}
	*port1 = atoi(p);
	scan(&p,SCAN_DIGITS);
	scan(&p,SCAN_WS);
	if (*p == '-') {
		p++;
		if (!(scan(&p,SCAN_WS) & SCAN_DIGITS)) {
		  if (port_type == PORT_SYNC) {
			/* Look for syn string */
			if (!strncmp(p,"syn",3)) {
			  scan(&p,SCAN_ALPHA);
			  if (!isdigit(*p)) 
				return -1;
			} else {
			  return -1;
			}
		  } else {
			return -1;
		  }
		}
		*port2 = atoi(p);
		if (*port2 < *port1)
			return -1;
		scan(&p,SCAN_DIGITS);
		*s = p;
		return 0;
	} else if (*p == ',' || *p == '@') {
		*port2 = *port1;
		*s = p;
		return (*p == '@') ? 1 : 0;
	}
	return -1;
}

/* int isipxaddr(u_char *p)
 *
 * lightning-fast check to see if address is in IPX format
 *
 * valid format is:
 *    1-8 hexadecimal chars plus ":" plus 1-12 hexadecimal chars
 *    leading zeroes are ignored for count of chars
 *
 * Example valid:
 *
 * 4:5   12345678:123456789ABC   000000000043:000000000000000000000000000000001
 *
 * Example not valid:
 *
 * 123456789:123456789ABC   my:host   37:   :55   0:0   132.245.33.8   89AB
 * 0x12345678:0x1234
 *
 * assumes p is non-NULL
 *
 * returns TRUE if valid, FALSE if not valid
 */
static int isipxaddr(p)
u_char *p;
{
	int len = 0;

	if (*p == '*') {
		p++;
		if (*p != ':')
			return(FALSE);
	}
	else {
		for (;;p++) {
			if (isxdigit(*p)) {
				if (*p != '0' || len)
					len++;
				if (len > 8)
					return(FALSE);
			}
			else if (*p == ':')
				break;
			else
				return(FALSE);
		}
		if (len == 0)
			return(FALSE);

	}

	p++;
	if (*p == '*') {
		p++;
		if (*p == '\0')
			return(TRUE);
		else
			return(FALSE);
	}
	
	for (len = 0; *p; p++) {
		if (isxdigit(*p)) {
			if (*p != '0' || len)
				len++;
			if (len > 12)
				return(FALSE);
		}
		else
			return(FALSE);
	}

	if (len == 0)
		return(FALSE);

	return(TRUE);
}

static int hexval(c)
int c;
{
	if (isdigit(c))
		return(c - '0');

	if (isupper(c))
		return(c - 'A' + 10);

	if (islower(c))
		return(c - 'a' + 10);

	return(0);
}
	
/* assumes netnum, p and *p are non-NULL.  also assumes already in correct
   format */
static u_long get_ipx_netnum(p)
u_char **p;
{
	u_char *q, *r, len;
	u_long factor, sum;

	sum = 0;
	
	q = (u_char*)strchr(*p, (int)':');
	if (q) {
		*q = '\0';
		q++;
	}

	/* note: since we assume proper format, wildcard "*" hexval will be 0,
	   so wildcard evaluates to 0, which is what we want */
	for (len = strlen(*p), factor = 1, r = *p + len - 1; len; 
		 len--, r--, factor *= 0x10)
		sum += factor * hexval(*r);

	*p = q;
	return(sum);
}

/* assumes nodenum is non-NULL and points to six valid bytes.  also assumes
   already in correct format */
static int get_ipx_nodenum(p, nodenum)
u_char *p;
u_char *nodenum;
{
	u_char len, *r;
	int i;

	for(i = 0; i < 6; i++)
		nodenum[i] = 0;

	if (p == NULL || *p == '\0')
		return(FALSE);

	/* note: since we assume proper format, wildcard "*" hexval will be 0,
	   so wildcard evaluates to 0, which is what we want */
	for (len = strlen(p), r = p + len -1, i = 11; len && i >= 0; 
		len--, r--, i--) {
		if (i % 2)
			nodenum[i / 2] += hexval(*r);
		else
			nodenum[i / 2] += 16 * hexval(*r);
	}

	return(TRUE);
}
	
/*
 * findacpdialup
 *
 * This module reads the acp_dialup file one line at a time
 * searching for a line that contains the arguments "user_key"
 * and "inet_key". Once the line is found it returns the
 * following four values:
 *
 *	uname
 *	inet address associated with that username
 *	local dialup address
 *	remote dialup address
 * 
 * If an error occured reading the file, or the end-of-file
 * was reached, than a (-1) is returned, and that routine,
 * dialup_address_validate(), will know to stop reading
 * lines from the file. When no errors occur, then a (1)
 * value is sent back.
 * 
 * Internet address and port number specification format:
 *
 *	[<port1>[-<port2>][,<port1>[-<port2>]]*@](annexname|*)
 *
 * Blanks may appear anywhere in this format for readability.
 *
 * Internet addresses of 0 are used as "wildcard" markers.
 */

int
findacpdialup(uname, inet, type, loc, rem, node, port, ptype, user_key, inet_key, dialup_flags)
char	 	**uname;
UINT32	*inet;
int type;
UINT32 *loc, *rem;
char *node;
int port,ptype;
char	*user_key;
UINT32	inet_key;
UINT32  *dialup_flags;
{
	int code;
	char *p, *p2, *p_dbg;
	int status;
#ifdef _WIN32
	char user_key_domain[64];
	char *ptr_user_key;
	char *ptr_user_name;
#endif

	if ((status = pre_findacpdialup(uname, inet, type, loc, rem, node, port,
			ptype, user_key, inet_key, dialup_flags)) != ACPU_ESUCCESS) {

		if (status == ACPU_ESKIP)
			return (1);
		else
			return (-1);
	}

	/*
	 * Go through dialup addresses file end get one line.
	 * Try to extract a username and two addresses.
	 */ 
	if (duf == NULL)
		return -1;

#ifdef _WIN32
	ptr_user_key = PrependDomainNameAndFix(user_key, user_key_domain);
#endif

	if (debug_dialup) {
#ifdef _WIN32
	  printf("findacpdialup: searching for <%s> at 0x%x type %s\n",
		 ptr_user_key, inet_key,((type == IPX_ADDRT)?"IPX":"IP") );
#else
	  printf("findacpdialup: searching for <%s> at 0x%x type %s\n",
		 user_key, inet_key,((type == IPX_ADDRT)?"IPX":"IP") );
#endif
	}
			
	*loc = *rem = 0;
	bzero(node, 6);

    for(;;)
	{
	p = fgets(line,BUFSIZ-1,duf);
	if (p == NULL)
		return -1;
	line[BUFSIZ-1] = '\0';
	if (debug_dialup)
		printf("read <%s>\n",line);
	/*
	 * Remove trailing comments, if any.
	 */
	for (;*p != '\0';p++)
		if (*p == '#') {
			*p = '\0';
			break;
			}

	/*
	 * Extract the username.
	 */
	p = line;
	p_dbg = p;
	if ((*uname = getblanksep(&p)) == NULL) {
		if (debug_dialup)
			printf("Can't get user name from line -- skipping.\n");
		continue;
		}
#ifdef _WIN32
	/* Adjust name to include domain */
	ptr_user_name = PrependDomainNameAndFix(*uname, domain_and_name);
	/* point returned name to fixed NT version */
	*uname = ptr_user_name;
	if(stricmp(ptr_user_name, ptr_user_key) != 0) {
#else
	if(strcmp(*uname, user_key) != 0) {
#endif
	  if (debug_dialup)
	    printf("user name does not match -- skipping.\n");
	  /* get next line */
	  continue;
	}

	/*
	 * Extract the port range, if any specified. 
	 */

	if ((code = test_port(&p,port,ptype)) == 0) {
		if (debug_dialup)
			printf("Port is not in range -- skipping.\n");
		continue;
		}

	/* Go to the '@' sign if we've seen a port range specifier */
	if (code > 0) {
		for (;*p != '@';p++)
			if (*p == '\0') {
				if (debug_dialup)
					printf("Ran into null looking for @\n");
				continue;
				}
		p++;
		}

	/*
	 * Extract the internet address associated with this user.  
	 */

	if ((p2 = getblanksep(&p)) == NULL) {
		if (debug_dialup)
			printf("Annex internet address is missing.\n");
		continue;
		}
	if (!strcmp(p2,"*"))
		*inet = 0;
	else if ((*inet = inet_address(p2)) == 0) {
		if (debug_dialup)
			printf("Annex internet address is invalid.\n");
		continue;
		}
	else if (*inet != inet_key) {
		if (debug_dialup)
			printf("Annex internet address mismatch.\n");
		continue;
		}

	/*
	 * Extract the remote dialup address. 
	 */

	if ((p2 = getblanksep(&p)) == NULL) {
		if (debug_dialup)
			printf("Remote internet address is missing.\n");
		continue;
		}

	/*
         * First we see whether DHCP should be used for this user.
	 * If not, look for ip-address.
	 */
	
	if(((strcasecmp("DHCP", p2)) == 0) && (type == IP_ADDRT)) {
	   *dialup_flags = REQ_GRANT_DHCP;
	   *loc = *rem = 0;
	   break;
	 }

	if (!strcmp(p2,"*")) {
		if (type != IP_ADDRT)
			continue;
	}
	else if (isipxaddr(p2)) {
		if (type != IPX_ADDRT)
			continue;
		if (debug_dialup)
		  printf("p2 %x\n", p2);
		*rem = get_ipx_netnum(&p2);
		if (debug_dialup)
		  printf("netnum %x, p2 %x, node string %s\n", *rem, p2, p2);
		get_ipx_nodenum(p2, node);
	}
	else if (type != IP_ADDRT)
		continue;
	else {
		if ((*rem = inet_address(p2)) == 0) {
			if (debug_dialup)
				printf("Remote internet address is invalid.\n");
			continue;
		}
	}

	/*
	 * Extract the local dialup address (optional for IP only).
	 */

	if (type == IP_ADDRT) {
		if ((p2 = getblanksep(&p)) != NULL) {
			if (strcmp(p2,"*") && ((*loc = inet_address(p2)) == 0)) {
					if (debug_dialup)
						printf("Local internet address is invalid.\n");
					continue;
				}
		}
	}

	/* Ignore any trailing junk for future expansion */

	break;
	}

    if (debug_dialup)
	printf("findacpdialup: good entry <%s>.\n",p_dbg);

    return (1);
}
