/*****************************************************************************
 *
 *        Copyright 1996 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module: radius_parser.c
 *
 * Author: Daniel Fox
 *
 * Module Description: This module contains the routines to build and parse
 *                     RADIUS packets
 *
 *                     RADIUS is a session, presentation and application
 *                     layer protocol built on UDP (although these functions
 *                     are not dependent upon the underlying transport layer)
 *
 *****************************************************************************
 */

/***************************************************************************
 *
 *    DESIGN DETAILS
 *    For building, these functions should be called in this order:
 *    radius_build_header();
 *    radius_add_attribute();
 *    radius_add_attribute();
 *    .
 *    .
 *    .
 *    radius_fix_length();
 *
 *    Call radius_crunch_password() to encrypt the user password
 *    
 *    For parsing, one function:
 *    radius_parse_server_response();
 *       which will build a list of attributes returned, as well as
 *       authenticate the packet
 *
 *    Call radius_uncrunch_password() to decrypt the user password
 *
 *    MODULE INITIALIZATION -
 *    None
 *       
 *    PERFORMANCE CRITICAL FACTORS - 
 *
 *      RESOURCE USAGE -
 *
 *    SIGNAL USAGE -
 *
 *      SPECIAL EXECUTION FLOW - 
 *
 *     SPECIAL ALGORITHMS - 
 *
 ***************************************************************************
 */

/* Include Files */

#include "../inc/config.h"

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <syslog.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "../inc/port/port.h"
#include "../libannex/srpc.h"
#include "radius.h"
#include "../inc/erpc/nerpcd.h"
#include "acp_policy.h"
#include "acp_regime.h"
#include "acp.h"

#ifdef _WIN32
extern void MDString(char *string, unsigned int len, unsigned char result[16]);
extern int outputstring(ACP *Acp, char *String);
extern void random_key(char *password);
#endif

extern int debug;

/* when adding to codetype, increase NCODETYPES in radius.h */
char *codetype[] = {
	"Access-Request",
	"Access-Accept",
	"Access-Reject",
	"Accounting-Request",
	"Accounting-Response",
	"\0",
	"\0",
	"\0",
	"\0",
	"\0",
	"Access-Challenge",
	"Status-Server",
	"Status-Client",
        "\0"
};	

static u_char valtype[] = {
    0,               /* 0 UNASSIGNED */
    PW_TYPE_STRING,  /* 1 User-Name */
    PW_TYPE_STRING,  /* 2 User-Password */
    PW_TYPE_STRING,  /* 3 CHAP-Password */
    PW_TYPE_IPADDR,  /* 4 NAS-IP-Address */
    PW_TYPE_INTEGER, /* 5 NAS-Port */
    PW_TYPE_INTEGER, /* 6 Service-Type */
    PW_TYPE_INTEGER, /* 7 Framed-Protocol */
    PW_TYPE_IPADDR,  /* 8 Framed-IP-Address */
    PW_TYPE_IPADDR,  /* 9 Framed-IP-Netmask */
    PW_TYPE_INTEGER, /* 10 Framed-Routing */
    PW_TYPE_STRING,  /* 11 Filter-Id */
    PW_TYPE_INTEGER, /* 12 Framed-MTU */
    PW_TYPE_INTEGER, /* 13 Framed-Compression */
    PW_TYPE_IPADDR,  /* 14 Login-IP-Host */
    PW_TYPE_INTEGER, /* 15 Login-Service */
    PW_TYPE_INTEGER, /* 16 Login-Port */
    0,               /* 17 UNASSIGNED */
    PW_TYPE_STRING,  /* 18 Reply-Message */
    PW_TYPE_STRING,  /* 19 Callback-Number */
    PW_TYPE_STRING,  /* 20 Callback-Id */
    0,               /* 21 UNASSIGNED */
    PW_TYPE_STRING,  /* 22 Framed-Route */
    PW_TYPE_IPADDR,  /* 23 Framed-IPX-Network */
    PW_TYPE_STRING,  /* 24 State */
    PW_TYPE_STRING,  /* 25 Class */
    PW_TYPE_STRING,  /* 26 Vendor-Specific */
    PW_TYPE_INTEGER, /* 27 Session-Timeout */
    PW_TYPE_INTEGER, /* 28 Idle-Timeout */
    PW_TYPE_INTEGER, /* 29 Termination-Action */
    PW_TYPE_STRING,  /* 30 Called-Station-Id */
    PW_TYPE_STRING,  /* 31 Calling-Station-Id */
    PW_TYPE_STRING,  /* 32 NAS-Identifier */
    PW_TYPE_STRING,  /* 33 Proxy-State */
    PW_TYPE_STRING,  /* 34 Login-LAT-Service */
    PW_TYPE_STRING,  /* 35 Login-LAT-Node */
    PW_TYPE_STRING,  /* 36 Login-LAT-Group */
    PW_TYPE_INTEGER, /* 37 Framed-Appletalk-Link */
    PW_TYPE_INTEGER, /* 38 Framed-Appletalk-Network */
    PW_TYPE_STRING,  /* 39 Framed-Appletalk-Zone */
    PW_TYPE_INTEGER, /* 40 Acct-Status-Type */
    PW_TYPE_INTEGER, /* 41 Acct-Delay-Time */
    PW_TYPE_INTEGER, /* 42 Acct-Input-Octets */
    PW_TYPE_INTEGER, /* 43 Acct-Output-Octets */
    PW_TYPE_STRING,  /* 44 Acct-Session-Id */
    PW_TYPE_INTEGER, /* 45 Acct-Authentic */
    PW_TYPE_INTEGER, /* 46 Acct-Session-Time */
    PW_TYPE_INTEGER, /* 47 Acct-Input-Packets */
    PW_TYPE_INTEGER, /* 48 Acct-Output-Packets */
    PW_TYPE_INTEGER, /* 49 Acct-Terminate-Cause */
    PW_TYPE_STRING,  /* 50 Acct-Multi-Session-Id */
    PW_TYPE_INTEGER, /* 51 Acct-Link-Count */
    0, 0, 0, 0, 0, 0, 0, 0, /* 52-59 UNASSIGNED */
    PW_TYPE_STRING,  /* 60 CHAP-Challenge */
    PW_TYPE_INTEGER, /* 61 NAS-Port-Type */
    PW_TYPE_INTEGER, /* 62 Port-Limit */
    PW_TYPE_STRING,  /* 63 Login-LAT-Port */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 64-79 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80-95 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 96-111 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 112-127 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 128-143 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 144-159 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 162-175 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 176-191 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 192-207 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 208-223 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 224-239 UNASSIGNED */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  /* 240-255 UNASSIGNED */
};

/* Annex to RADIUS port types */
static char xa2r_port_type[] =
{
    PW_PORT_ASYNC,	                /* 0  DEV_SERIAL */
    PW_PORT_ISDN_SYNC,	                /* 1  DEV_SYNC */
    PW_PORT_VIRTUAL,	            /* 2  DEV_VIRTUAL */
    PW_PORT_VIRTUAL,	            /* 3  DEV_DIALOUT */
    PW_PORT_VIRTUAL,                /* 4  DEV_ETHERNET */
    -1,            	                /* 5  DEV_RFC */
    PW_PORT_ISDN_V120,	            /* 6  DEV_V120 */
    -1,			                    /* 7  DEV_CONTROL */
    PW_PORT_VIRTUAL,			    /* 8  DEV_MP */
    PW_PORT_VIRTUAL,                /* 9  DEV_VPN */
    PW_PORT_SYNC                 /* 10 DEV_GENSYNC */
};

/* allow prototype checking, but only when requested */
#ifdef _
#undef _
#endif
#ifndef _
#if (__STDC__ && PROTOTYPES)
#define _(x)  x
#else
#define _(x)  ()
#endif /* STDC */
#endif /* _ */

int outputstring _((ACP*, char *output));

/*****************************************************************************
 *
 * NAME: radius_build_attribute
 *
 * DESCRIPTION: This formats a radius attribute into a buffer
 *
 * ARGUMENTS:
 *  u_char **bpp - INPUT pointer to address of buffer to put attribute in
 *                 OUTPUT pointer to place to put the next attribute
 *  struct radius_attribute *attribp - INPUT the attribute to build
 *
 * RETURN VALUE: none
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

void radius_build_attribute(bpp, attribp)
u_char **bpp; /* pointer to address to add attribute */
struct radius_attribute *attribp;
{
    u_char *bp;
    UINT32 intval;
    u_char alen = (u_char)(attribp->length + 2*sizeof(u_char));
    
    if (bpp == (u_char**)NULL || *bpp == (u_char*)NULL)
        return;

    bp = *bpp;
    *bp = (u_char)attribp->type;
    bp++;
    *bp = alen;
    bp++;

    switch(valtype[attribp->type]) {
    case PW_TYPE_INTEGER:
    case PW_TYPE_DATE:
        intval = htonl(attribp->lvalue);
        bcopy((char*)&intval, bp, attribp->length);
        break;

    case PW_TYPE_IPADDR:
        bcopy((char*)&attribp->lvalue, bp, attribp->length);
        break;

    case PW_TYPE_STRING:
    default:
        bcopy(attribp->strvalp, bp, attribp->length);
        break;
    }
    
    bp += attribp->length;
    *bpp = bp;
}

/*****************************************************************************
 *
 * NAME: radius_parse_attribute
 *
 * DESCRIPTION: This parses an attribute portion of a RADIUS packet
 *
 * ARGUMENTS:
 *  u_char **bpp - INPUT pointer to the attribute in the packet
 *                 OUTPUT pointer to the next attribute in the packet
 *  struct radius_attribute *attribp - OUTPUT the attribute parsed
 *
 * RETURN VALUE: none
 *
 * RESOURCE HANDLING: if the attribute is a string, allocates space for it.
 *                    free it with radius_destroy_attribute()
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

static void radius_parse_attribute(bpp, attribp)
u_char **bpp; /* pointer to address of attribute in data stream */
struct radius_attribute *attribp;
{
    u_char *bp = *bpp;

    attribp->type =(UINT32)*bp;
    bp++;
    attribp->length = ((UINT32)*bp) - 2;
    bp++;

    switch(valtype[attribp->type]) {
    case PW_TYPE_INTEGER:
    case PW_TYPE_DATE:
        if (attribp->length == sizeof(UINT32)) {
            bcopy(bp, (char*)&attribp->lvalue, attribp->length);
            attribp->lvalue = ntohl(attribp->lvalue);
        }
        break;

    case PW_TYPE_IPADDR:
        if (attribp->length == sizeof(UINT32)) {
            bcopy(bp, (char*)&attribp->lvalue, attribp->length);
        }
        break;

    case PW_TYPE_STRING:
    default:
	attribp->strvalp = (u_char*)calloc(1, attribp->length + 1);
        if (attribp->strvalp)
            bcopy(bp, attribp->strvalp, attribp->length);
	if(debug)
	   printf("radius_parser: %s\n", attribp->strvalp);
        break;
        
    }
    
    bp += attribp->length;
    *bpp = bp;
    
}

/*****************************************************************************
 *
 * NAME: radius_build_header
 *
 * DESCRIPTION: This formats a radius header into a buffer
 *
 * ARGUMENTS:
 *  u_char **bpp - INPUT pointer to buffer
 *                 OUTPUT pointer to attribute portion in buffer
 *  UINT32 code - INPUT The type of RADIUS packet (the code)
 *  UINT32 id - INPUT the identifier
 *  char *authenticator - INPUT 16-byte authenticator buffer
 *                        if NULL and Access-Request, generate random value
 *                        else if NULL, use all zeroes
 *                        else, use this value
 *
 * RETURN VALUE: the authenticator used or NULL if failure
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

u_char *radius_build_header(bpp, code, id, authenticator)
u_char **bpp;
UINT32 code;
UINT32 id;
u_char *authenticator; /* ignored for Access-Request */
{
    u_char *bp;
    u_short length = 0;
    u_char *ap;
    
    if (bpp == NULL || *bpp == NULL)
        return(NULL);

    /* code */
    bp = *bpp;
    *bp = (u_char)code;
    bp++;

    /* identifier, random for now */
    *bp = (u_char)id;
    bp++;

    /* length, 0 for now */
    length = htons(length);
    *bp = (*((u_char*)&length));
    bp++;
    *bp = (*((u_char*)&length + 1));
    bp++;

    /* authenticator */
    ap = bp;
    if (authenticator == NULL && code == PW_AUTHENTICATION_REQUEST) {
        random_key(bp);
    }
    else if (authenticator == NULL)
        bzero(bp, KEYSZ);
    else
        bcopy(authenticator, bp, KEYSZ);

    bp += KEYSZ;
    *bpp = bp;

    return(ap);
}

/*****************************************************************************
 *
 * NAME: radius_uncrunch_password
 *
 * DESCRIPTION: This decrypts a RADIUS user password
 *
 * ARGUMENTS:
 * u_char *password - OUTPUT 16-byte buffer to put decrypted password
 * u_char *authenticator - INPUT value of authenticator from packet
 * u_char *hidpwd - INPUT 16-byte value of hidden password
 * u_char *secret - INPUT 16-byte shared secret
 *
 * RETURN VALUE: none
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

void radius_uncrunch_password(password, authenticator, hidpwd, secret)
u_char *password;
u_char *authenticator;
u_char *hidpwd;
u_char *secret;
{
    KEY digest;
    u_char *mdstring;
    int i, slen;

    mdstring = (u_char*)malloc(KEYSZ + KEYSZ);
    if (mdstring == NULL)
        return;

    /* MD5(secret + authenticator) */
    for(slen=0; slen<KEYSZ && secret[slen] != '\0'; slen++);
    bcopy(secret, mdstring, slen);
    bcopy(authenticator, mdstring + slen, KEYSZ);
    MDString(mdstring, slen + KEYSZ, digest);

    /* newkey xor password */
    for (i = 0; i < KEYSZ; i++)
        password[i] = (digest[i] ^ hidpwd[i]);

    free(mdstring);
}

/*****************************************************************************
 *
 * NAME: radius_crunch_password
 *
 * DESCRIPTION: This encrypts a RADIUS user password
 *
 * ARGUMENTS:
 * u_char *newkey - OUTPUT 16-byte buffer to put encrypted password
 * u_char *authenticator - INPUT value of authenticator from packet
 * u_char *password - INPUT buffer of cleartext password
 * u_short pwdlen - INPUT length of cleartext password
 * u_char *secret - INPUT 16-byte shared secret
 *
 * RETURN VALUE: none
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

void radius_crunch_password(newkey, authenticator, password, pwdlen, secret)
u_char *newkey;
u_char *authenticator;
u_char *password;
UINT32 pwdlen;
u_char *secret;
{
    u_char *mdstring;
    int i, j, slen, blocks;

    mdstring = (u_char*)malloc(KEYSZ + KEYSZ);
    if (mdstring == NULL) {
        bzero(newkey, KEYSZ);
        return;
    }

    if (pwdlen == 0)
        blocks = 0;
    else
        blocks = ( (pwdlen-1) / KEYSZ) + 1;
    
    /* MD5(secret + authenticator) */
    for(slen=0; slen<KEYSZ && secret[slen] != '\0'; slen++);
    bcopy(secret, mdstring, slen);

    for(i=0; i < blocks; i++) {
        if (i == 0)
            bcopy(authenticator, mdstring + slen, KEYSZ);
        else
            bcopy(newkey + ((i-1)*KEYSZ), mdstring + slen, KEYSZ);
        MDString(mdstring, slen + KEYSZ, newkey + i*KEYSZ);

        for(j = i*KEYSZ; (j < (int)pwdlen) && (j < ((i+1)*KEYSZ)); j++)
            newkey[j] ^= password[j];

        for(; (j < ((i+1)*KEYSZ)); j++)
            newkey[j] ^= 0;
    }

    free(mdstring);
}

/*****************************************************************************
 *
 * NAME: radius_add_attribute
 *
 * DESCRIPTION: This adds a radius attribute to a packet
 *
 * ARGUMENTS:
 *  u_char **bpp - INPUT pointer to address of buffer to put attribute in
 *                 OUTPUT pointer to place to put the next attribute
 *  UINT32 type - INPUT attribute type
 *  UINT32 length - INPUT length of attribute (not including TL fields)
 *  u_char *strvalp - INPUT value of attribute if string
 *  UINT32 lvalue - INPUT value of attribute if not string
 *
 * RETURN VALUE: none
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

void radius_add_attribute(bpp, type, length, strvalp, lvalue)
u_char **bpp, *strvalp;
UINT32 type, length, lvalue;
{
    struct radius_attribute attrib;

    attrib.next = NULL;
    attrib.type = type;
    attrib.length = length;
    attrib.strvalp = strvalp;
    attrib.lvalue = lvalue;

    radius_build_attribute(bpp, &attrib);
}

/*****************************************************************************
 *
 * NAME: radius_fix_length
 *
 * DESCRIPTION: Post-processing function to set the length of the RADIUS
 *              packet
 *
 * ARGUMENTS:
 *  u_char *start - INPUT the start of the RADIUS packet
 *  u_char *end - OUTPUT pointer to space just after RADIUS packet
 *
 * RETURN VALUE: none
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

void radius_fix_length(start, end)
u_char *start, *end;
{
    u_short length = (u_short)(end - start);

    length = htons(length);
    bcopy((u_char*)&length, start + 2, 2);
}

/*****************************************************************************
 *
 * NAME: radius_convert_type
 *
 * DESCRIPTION: Converts an ACP port type to a RADIUS port type
 *
 * ARGUMENTS: int type - INPUT ACP port type
 *
 * RETURN VALUE: the RADIUS port type, -1 if no equivalent
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

int radius_convert_type(acptype)
int acptype;
{
    return ((int)xa2r_port_type[acptype]);
}

/*****************************************************************************
 *
 * NAME: radius_auth_server_packet
 *
 * DESCRIPTION: Authenticates an incoming RADIUS packet from a RADIUS server
 *
 * ARGUMENTS:
 *  u_char *datagram - INPUT RADIUS packet received
 *  int dlen - INPUT Length of RADIUS packet received(as reported in packet)
 *  u_char *reqauth - INPUT Authenticator from corresponding Access-Request
 *  struct in_addr remaddr - INPUT Internet address of RADIUS server
 *
 * RETURN VALUE: none
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

static int radius_auth_server_packet(datagram, dlen, reqauth, remaddr)
u_char *datagram;
int dlen;
u_char *reqauth;
struct in_addr remaddr;
{
    u_char *mdstring;
    KEY digest;
    int rv, slen;
    Radius_serverinfo *sinfo = NULL;

    sinfo = get_serverinfo(remaddr);
    if(!sinfo){
        if(debug > 4)
            printf("server info not found\n");
        return(FALSE);
    }

    mdstring = (u_char *)malloc(dlen + KEYSZ);
    if (mdstring == NULL)
        return(FALSE);

    bcopy(datagram, mdstring, dlen);
    bcopy(reqauth, mdstring + 4, KEYSZ);
    for(slen=0; slen<KEYSZ && sinfo->shared_secret[slen] != '\0'; slen++);
    bcopy(sinfo->shared_secret, mdstring + dlen, slen);

    MDString(mdstring, dlen + slen, digest);

    if (memcmp(digest, datagram + 4, KEYSZ) == 0)
        rv = TRUE;
    else
        rv = FALSE;

    free(mdstring);
    return(rv);
}

/*****************************************************************************
 *
 * NAME: radius_parse_server_response
 *
 * DESCRIPTION: Parses a server response
 *
 * ARGUMENTS:
 *  u_char *datagram - INPUT RADIUS packet received
 *  int dlen - INPUT Length of RADIUS packet received
 *  int identifier - INPUT Identifier from corresponding Access-Request
 *  u_char *reqauth - INPUT Authenticator from corresponding Access-Request
 *  struct in_addr remaddr - INPUT Internet address of RADIUS server
 *  struct radius_attribute **attriblistp - OUTPUT Pointer to attribbute list
 *
 * RETURN VALUE: Packet code type, 0 if not authenticated
 *
 * RESOURCE HANDLING: allocates memory for the attribute list
 *                    the attribute list can be freed with
 *                    radius_destroy_alist()
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */

int radius_parse_server_response(datagram, dlen, identifier, reqauth,
                                 remaddr)
u_char *datagram;
int dlen, identifier;
u_char *reqauth;
struct in_addr remaddr;
{
    int code, id;
    u_short len;
    u_char *bp = datagram;

    code = (int)*bp;
    bp++;

    /* discard any packet type not known */
    switch(code) {
    case PW_AUTHENTICATION_REQUEST:
    case PW_AUTHENTICATION_ACK:
    case PW_AUTHENTICATION_REJECT:
    case PW_ACCOUNTING_RESPONSE:
    case PW_ACCESS_CHALLENGE:
        break;

    default:
        return 0;
    }
    
    /* discard if id doesn't match */
    id = (int)*bp;
    bp++;

    if (identifier != id)
        return 0;

    bcopy(bp, (u_char *)&len, sizeof(u_short));
    len = ntohs(len);
    bp += sizeof(u_short);

    /* discard if bad length field */
    if (len < 20 || dlen < len)
        return 0;

    /* authenticate packet */
    if (!radius_auth_server_packet(datagram, len, reqauth, remaddr))
        return 0;

    return(code);
    
}

/*****************************************************************************
 *
 * NAME: radius_get_attribute
 *
 * DESCRIPTION: Retrieves the next attribute of a specific type from the
 *              RADIUS-formatted attribute portion
 *
 * ARGUMENTS:
 *  u_char **bufp - INPUT pointer to place in the buffer to begin search
 *                  OUTPUT pointer to next place in the buffer after attrib
 *                         or same as INPUT if not found
 *  int *buflen - INPUT pointer to length of block after bufp
 *                OUTPUT pointer to remaining length of block
 *                       or same as INPUT if not found
 *  struct radius_attribute *attrib - INPUT pointer to pre-allocated radius
 *                                          attribute to fill in
 *                                    OUTPUT pointer to filled-in attribute
 *
 * RETURN VALUE: TRUE attribute match retrieved
 *               FALSE no attribute match found
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

int radius_get_attribute(bufp, buflenp, attrib)
u_char **bufp;
u_short *buflenp;
    
struct radius_attribute *attrib;
{
    int len = *buflenp;
    u_char *buf = *bufp;

    while (len > 2) {
        if (*buf == (u_char)attrib->type) {
            radius_parse_attribute(&buf, attrib);
            *buflenp = (u_short)(len - attrib->length - 2);
            *bufp = attrib->next = buf;
            return(TRUE);
        }
        len -= *(buf + 1);
        buf += *(buf + 1);
    }
    
    return(FALSE);
}

/*****************************************************************************
 *
 * NAME: radius_get_secret
 *
 * DESCRIPTION: Retrieves the RADIUS secret for a server
 *
 * ARGUMENTS:
 *  UINT32 host - INPUT The RADIUS server internet address in network order
 *
 * RETURN VALUE: The 16-byte secret
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

u_char *radius_get_secret(host)
UINT32 host;
{
    KEYDATA *keydata;

    keydata = annex_key(host);
    return((u_char*)keydata->password);
}

/*****************************************************************************
 *
 * NAME: display_mem
 *
 * DESCRIPTION: Displays memory, used for de-bugging
 *
 * ARGUMENTS:
 *  char *buffer - buffer to display
 *  int buflen - length of buffer to display
 *
 * RETURN VALUE: none
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

void display_mem(buffer, buflen)
char *buffer;
int buflen;
{
        int i, rem;
        unsigned char *buf = (unsigned char *)buffer;
        char line[17];
 
        line[16] = 0;
        for (i=0; i < buflen; i++) {
            printf("%x%x ", buf[i] >> 4, buf[i] & 0x0f);
            line[i % 16] = (buf[i] >= 32 && buf[i] <= 127) ? buf[i] : '.';
            if (15 == (i % 16))
                printf("  %s\n", line);
        }
        rem = 16 - (i % 16);
        if (rem == 16)
            rem = 0;

        if (rem) {
            line[rem + 1] = '\0';
            for(i=0; i < rem; i++)
                printf("   ");
            printf(" %s\n", line);
        }

        printf("\n");
}       /* display */

/*****************************************************************************
 *
 * NAME: dump_attributes
 *
 * DESCRIPTION: Dumps RADIUS attributes to stdout
 *
 * ARGUMENTS:
 * u_char *packet - start of RADIUS packet
 *
 * RETURN VALUE: none
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

void dump_attributes(packet)
u_char *packet;
{
    struct radius_attribute attrib;
    u_char *bp = packet + AUTH_HDR_LEN;
    u_short blen;
    
    /* Note: this is not the most efficient way to do this.  The purpose is
       to test the radius_get_attribute() interface */

    bzero((u_char*)&attrib, sizeof(struct radius_attribute));
    bcopy(packet, (u_char*)&blen, 2);
    blen = ntohs(blen);
    
    for(attrib.type = 0; attrib.type < 256; attrib.type++) {
        if (radius_get_attribute(&bp, &blen, &attrib)) {
            printf("Attribute %d Length %d Value ", (int)attrib.type,
                   (int)attrib.length);
            switch(valtype[attrib.type]) {
            case PW_TYPE_INTEGER:
            case PW_TYPE_DATE:
                printf("%d\n", (int)ntohl(attrib.lvalue));
                break;
                
            case PW_TYPE_IPADDR:
            {
                
                u_char *ap = (u_char*)&attrib.lvalue;
                
                printf("%u.%u.%u.%u\n", ap[0], ap[1], ap[2], ap[3]);
                break;
            }
            
            case PW_TYPE_STRING:
            default:
                display_mem(attrib.strvalp, attrib.length);
                free(attrib.strvalp);
                attrib.strvalp=NULL;
                break;
                
            }
        }
    }
    
}

void radius_print_reply_message(acp)
	ACP *acp;
{
    u_char *bp = acp->auth.radius_packet + AUTH_HDR_LEN;
    u_short blen;
    struct radius_attribute attrib;
    char *display;

    bcopy(acp->auth.radius_packet + 2, (u_char*)&blen, 2);
    blen = ntohs(blen) - AUTH_HDR_LEN;
    
    bzero((u_char*)&attrib, sizeof(struct radius_attribute));
    attrib.type = PW_PORT_MESSAGE;
    
  	while(radius_get_attribute(&bp, &blen, &attrib)) {
        display = (char*)malloc(attrib.length + 2);
        bcopy(attrib.strvalp, display, attrib.length);
        display[attrib.length] = '\n';
        display[attrib.length+1] = '\0';
		outputstring(acp, display);
        free(attrib.strvalp);
	free(display);
        display=NULL;
	attrib.strvalp=NULL;
    }
}


