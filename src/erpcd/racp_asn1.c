/*****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description:: This library contains parsing and building functions
 *			for RACP ASN.1 PDU's.
 *
 * Detailed Design Specification:
 *
 *    MODULE INITIALIZATION -
 *   No initialization required
 *
 *      RESOURCE USAGE -
 *       Needs to allocate/free large buffers for parsing/building
 *
 * Original Author: %$(author)$%    Created on: %$(created-on)$%
 *
 *****************************************************************************
 */

/*
 *    INCLUDE FILES
 */

#ifdef ANNEX
#include "udas.h"

#include "types.h"
#include "externs.h"
#include "param.h"
#include "errno.h"
#include "socket.h"
#include "strings.h"
#include "malloc.h"
#include "syslog.h"
#include "../netinet/in.h"
#include "stdio.h"
#include "../courier/courier.h"
#include "../erpc/erpc.h"
#include "../erpc/erpc_annex.h"
#include "../srpc/srpc.h"
#include "erpc/nerpcd.h"
#include "../acp/acp_types.h"
#include "../acp/acp.h"
#include "erpc/acp_tms.h"
#include "asn1.h"

#else /* ANNEX */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/time.h>
#else
#include <process.h>
#include "../ntsrc/acplog/acplogmsg.h"
#endif
#include <signal.h>

#include "../libannex/api_if.h"
#include "../inc/erpc/netadmp.h"

#include "../inc/port/install_dir.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "acp_policy.h"
#include "../inc/erpc/acp_tms.h"
#include "tms.h"
#include "errno.h"
#include "../libannex/asn1.h"
#include "getacpuser.h"

#ifdef USE_SYSLOG
#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#endif /* _WIN32 */
#endif /* USE_SYSLOG */
#endif /* ANNEX */
extern int parse_domain();
/*
 *    CONSTANT AND MACRO DEFINES
 *    - Comment those that are external interfaces
 */
#ifndef MIN
#define MIN(a,b) ( (a<b) ? a : b )
#endif

/* #define DEBUG_TMS 1 */

#define MAXPDUHEAD 4

void shift_array();

/*
 *    STRUCTURE AND TYPEDEF DEFINITIONS
 *    - Comment those that are external interfaces
 */

/*
 *    GLOBAL DATA DECLARATIONS
 */

/*
 *    STATIC DATA DECLARATIONS
 */

/*
 *    Forward Function Definitions
 *     - Follow ANSI prototype format for ALL functions.
 */

/*****************************************************************************
 *
 * NAME: fix_length()
 *
 * DESCRIPTION: Fixes up the encoded length of an ASN.1 PDU segment
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to header of the PDU segment to be fixed
 * u_char *packet_end - INPUT pointer to the end of the PDU segment
 * u_char *out_reqid - INPUT pointer to the end of the PDU segment header
 * u_char type - INPUT the type of the PDU segment
 * int *datalength -  INPUT/OUTPUT pointer to valid size of packet_end
 *
 * RETURN VALUE: new end of PDU segment
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
static u_char *fix_length(data, packet_end, out_reqid, type, datalength)
u_char *data, *packet_end, *out_reqid, type;
int *datalength;
{
       /*
     * Because of the assumption above that header lengths 
     * would be encoded in one byte, things need to be fixed, 
     * now that the actual lengths are known.
     */

    int                out_length;
    int                header_shift;
    u_char             *out_data; 

    header_shift = 0;
    out_length = packet_end - out_reqid;
    if (out_length >= 0x80){
        header_shift++;
        if (out_length > 0xFF)
        header_shift++;
    }
    
    if  (header_shift){
        /*
         * Shift packet (from request id to end of packet) by the 
         * sum of the necessary shift counts.
         */
        shift_array(out_reqid, packet_end - out_reqid, 
                    header_shift);

        /* Now adjust pointers into the packet */
        
    }
        
    out_data = data;
    out_length = packet_end - out_reqid;
    out_data = asn_build_header(out_data, &out_length, type, out_length);
    
    *datalength -= header_shift;
    return(packet_end + header_shift);    
}


/*****************************************************************************
 *
 * NAME: build_net_addr()
 *
 * DESCRIPTION: Converts c struct NetAddr to the ASN.1 type NetAddr
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * NetAddr *in_coming - INPUT pointer to NetAddr data to convert to ASN.1
 *
 * RETURN VALUE: next free space after NetAddr data
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 * Assumes internet address in network order
 *
 */
static u_char *build_net_addr(data, datalength, in_coming)
u_char *data;
int *datalength;
NetAddr *in_coming;

{
    u_char *begin_header = ((void *)NULL);
    u_char *end_header = ((void *)NULL);
    u_char *bh, *eh;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif
    int inet;

    if (!data || !datalength || !in_coming)
        return(NULL);


    switch (in_coming->type) {
      case LAT_ADDRT:
        bh = data;
        if ((data = asn_build_header(data, datalength, NETADDR_LAT, 0))
            == NULL)
            return(NULL);
        eh = data;
        if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                     in_coming->n.lat_addr.service, 
                                     strlen(in_coming->n.lat_addr.service)))
            == NULL)
            return(NULL);
        if (in_coming->n.lat_addr.node != ((void *)NULL)) {
            begin_header = data;
            if ((data = asn_build_header(data, datalength, LATADDR_SERVICE,
                                         0)) == NULL)
                return(NULL);
            end_header = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                    in_coming->n.lat_addr.node, 
                                    strlen(in_coming->n.lat_addr.node)))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header, data, end_header,
                                   LATADDR_SERVICE, datalength)) == NULL)
                return(NULL);
        }
        if (in_coming->n.lat_addr.port != ((void *)NULL)) {
            begin_header = data;
            if ((data = asn_build_header(data, datalength, LATADDR_PORT, 0))
                == NULL)
                return(NULL);
            end_header = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         in_coming->n.lat_addr.port, 
                                         strlen(in_coming->n.lat_addr.port)))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header, data, end_header,
                                   LATADDR_PORT, datalength)) == NULL)
                return(NULL);
        }
        data = fix_length(bh, data, eh, NETADDR_LAT, datalength);
        break;
  
      case IP_ADDRT:
        inet = ntohl(in_coming->n.ip_addr.inet);
        bh = data;
        if ((data = asn_build_header(data, datalength, NETADDR_IP, 0))
            == NULL)
            return(NULL);
        eh = data;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER, &inet,
                                  intsize))    == NULL)
            return(NULL);
        if(in_coming->n.ip_addr.port) {
            begin_header = data;
            if ((data = asn_build_header(data, datalength, IPADDR_PORT, 0))
                == NULL)
                return(NULL);
            end_header = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                      &(in_coming->n.ip_addr.port), intsize))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header, data, end_header,
                                   IPADDR_PORT, datalength)) == NULL)
                return(NULL);
        }
        data = fix_length(bh, data, eh, NETADDR_IP, datalength);
        break;
  
      case IPX_ADDRT:
        if (!in_coming->n.ipx_addr.network && !in_coming->n.ipx_addr.node &&
            !in_coming->n.ipx_addr.socket)
            return(data);
        bh = data;
        if ((data = asn_build_header(data, datalength, NETADDR_IPX, 0))
            == NULL)
            return(NULL);
        eh = data;
        if(in_coming->n.ipx_addr.network) {
            begin_header = data;
            if ((data = asn_build_header(data, datalength, IPXADDR_NETNUM, 0))
                == NULL)
                return(NULL);
            end_header = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                      &(in_coming->n.ipx_addr.network),
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header, data, end_header,
                                   IPXADDR_NETNUM, datalength)) == NULL)
                return(NULL);
        }
        if(in_coming->n.ipx_addr.node != ((void *)NULL)) {
            begin_header = data;
            if ((data = asn_build_header(data, datalength, IPXADDR_NODE, 0))
                == NULL)
                return(NULL);
            end_header = data;
            if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                         in_coming->n.ipx_addr.node, 
                                         sizeof(in_coming->n.ipx_addr.node)))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header, data, end_header,
                                   IPXADDR_NODE, datalength)) == NULL)
                return(NULL);
        }
        if(in_coming->n.ipx_addr.socket) {
            begin_header = data;
            if ((data = asn_build_header(data, datalength, IPXADDR_SOCKET, 0))
                == NULL)
                return(NULL);
            end_header = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                      &(in_coming->n.ipx_addr.socket),
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header, data, end_header,
                                   IPXADDR_SOCKET, datalength)) == NULL)
                return(NULL);
        }                
        data = fix_length(bh, data, eh, NETADDR_IPX, datalength);
        break;
        
      default:
        break;
    }

    return(data);
}


/*****************************************************************************
 *
 * NAME: parse_net_addr()
 *
 * DESCRIPTION: Parses NetAddr segment of an RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * NetAddr *in_coming - OUTPUT parsed NetAddr
 *
 * RETURN VALUE: next free space after NetAddr data
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 * Assumes internet address in network order
 *
 */
static u_char *parse_net_addr(data, datalength, in_coming)
u_char *data;
int *datalength;
NetAddr *in_coming;
{
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif
    u_char choice;
    u_char type = 0;
    u_char *temp;
    u_char *start = data;
    int temp_len ;
    int netlength = *datalength;
    int strlength = 0;
    int socket = 0;

    if (data == NULL || datalength == NULL)
        return(NULL);

    if ((data = asn_parse_header(data, &netlength, &choice)) == NULL)
        return(NULL);
    
    if (in_coming == NULL)
        data += netlength;
    
    switch (choice) {

      case NETADDR_LAT:

        in_coming->type = LAT_ADDRT;
        strlength = netlength;
        if (asn_parse_header(data, &strlength, &type) == NULL)
            return(NULL); /*sniffing the length of the string object*/
        in_coming->n.lat_addr.service = (char *)malloc(strlength + 1);
        if ((data = asn_parse_string(data, &netlength, &type,
                                     in_coming->n.lat_addr.service,
                                     &strlength)) == NULL)
            return(NULL);
        in_coming->n.lat_addr.service[0] = '\0';

        while (data != NULL && netlength > 2) {
            temp = data; /*storing crucial info. in temp vars.*/
            temp_len = netlength;/*storing crucial info. in temp vars.*/
            if ((data = asn_parse_header(temp, &temp_len, &choice)) == NULL)
                return(NULL);
            netlength -= (int)(data - temp);
            switch (choice) {
              case LATADDR_NODE:
                strlength = netlength;
                if (asn_parse_header(data, &strlength, &type) == NULL)
                    return(NULL); /*sniffing the length of the string object*/
                in_coming->n.lat_addr.node = (char *)malloc(strlength + 1);
                if ((data = asn_parse_string(data, &netlength, &type,
                                             in_coming->n.lat_addr.node,
                                             &strlength)) == NULL)
                    return(NULL);
                in_coming->n.lat_addr.node[0] = '\0';
                break;
                          
              case LATADDR_PORT:
                strlength = netlength;
                if (asn_parse_header(data, &strlength ,&type) == NULL)
                    return(NULL); /*sniffing the length of the string object*/
                in_coming->n.lat_addr.port = (char *)malloc(strlength+1);
                if ((data = asn_parse_string(data, &netlength, &type,
                                             in_coming->n.lat_addr.port,
                                             &strlength)) == NULL)
                    return(NULL);
                in_coming->n.lat_addr.port[0] = '\0';
                 break;

              default:
                return (data);
                break;    /* all else failed& that segment of the*/
            }                   /* pdu is empty, return the address */  
        }          /*i.e. data rigth b4 the parse header call. this is*/
        /*header for some other segment and pointer should b*/
        break;         /*kept intact.*/
    
      case NETADDR_IP:
        in_coming->type = IP_ADDRT;
        if ((data = asn_parse_int(data, &netlength, &type,
                                  &in_coming->n.ip_addr.inet, intsize))
            == NULL)
            return(NULL);
        in_coming->n.ip_addr.inet = htonl(in_coming->n.ip_addr.inet);
        if (netlength > 2) {
            temp = data;
            temp_len = netlength;
            if ((data = asn_parse_header(temp, &temp_len, &choice)) == NULL)
                return(NULL);
            netlength -= (int)(data - temp);
            switch(choice){
              case IPADDR_PORT:
                if ((data = asn_parse_int(data, &netlength, &type,
                                          &in_coming->n.ip_addr.port, intsize))
                    == NULL)
                    return(NULL);
                break;
                
              default:
                break;
      
            }
        }
        
        break;

      case NETADDR_IPX:
        in_coming->type = IPX_ADDRT;
                    
        while (data != NULL && netlength > 2){
            temp = data; temp_len = netlength;
            if ((data = asn_parse_header(temp, &temp_len, &choice)) == NULL)
                return(NULL);
            netlength -= (int)(data - temp);
            switch (choice) {
              case IPXADDR_NETNUM:
                if ((data = asn_parse_int(data, &netlength, &type,
                                          &in_coming->n.ipx_addr.network,
                                          intsize)) == NULL)
                    return(NULL);
    
                break; /*is'nt infinite since this case is a SEQ-*/
              case IPXADDR_NODE:   /*UENCE.*/
                strlength = 6;
                if ((data = asn_parse_string(data, &netlength, &type,
                                             in_coming->n.ipx_addr.node,
                                             &strlength)) == NULL)
                    return(NULL);
                break;
              case IPXADDR_SOCKET:
                if ((data = asn_parse_int(data, &netlength, &type, &socket,
                                          intsize)) == NULL)
                    return(NULL);
                in_coming->n.ipx_addr.socket = (u_short)socket;
                break;
              default:
                return(data); 
                break;   
    
            }
        }
    
        break;
        
      default: 
        data += netlength;
        break;
    }

    *datalength -= (int)(data - start);
    return(data);
}


/*****************************************************************************
 *
 * NAME: build_at_profile()
 *
 * DESCRIPTION: Builds the appletalk profile segment of the RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * AT_PROFILE_RETURN *atp - INPUT the appletalk profile
 *
 * RETURN VALUE: next free space after atp data
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
u_char *build_at_profile(data, datalength, at_profile)
u_char *data;
int *datalength;
AT_PROFILE_RETURN *at_profile;
{
    u_char *begin_header1 = ((void *)NULL);
    u_char *begin_header2 = ((void *)NULL);
    u_char *end_header1 = ((void *)NULL);
    u_char *end_header2 = ((void *)NULL);

    int count_temp;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif
    u_char *temp = NULL;
        

    if ((data = asn_build_string(data, datalength, ASN_VIS_STR ,
                                 at_profile->passwd,
                                 strlen(at_profile->passwd))) == NULL)
        return(NULL);

    begin_header1 = data;
    if ((data = asn_build_header(data, datalength, (ASN_SET | ASN_CONSTRUCTOR),
                                 0)) == NULL)
        return(NULL);
    end_header1 = data;


    if (at_profile->connect_time) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ATP_CONTIME, 0))
            == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                  &(at_profile->connect_time), intsize))
            == NULL)
            return(NULL);
        if ((data = fix_length(begin_header2, data, end_header2, ATP_CONTIME,
                               datalength)) == NULL)
            return(NULL);
    }

    if (at_profile->zone_count > 0) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ATP_ZONES, 0)) == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                  &(at_profile->zone_count), intsize)) == NULL)
            return(NULL);
        if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                  &(at_profile->zones_len), intsize)) == NULL)
            return(NULL);
        /*****implicit sequence of visible strings*****/
        temp = at_profile->zones_list;
        count_temp = at_profile->zone_count;
        while(count_temp > 0) {
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         &temp[1], temp[0])) == NULL)
                return(NULL);
            temp+=temp[0]+1;
            count_temp--;
        }
        if ((data = fix_length(begin_header2, data, end_header2, ATP_ZONES,
                               datalength)) == NULL)
            return(NULL);
    }

    /**********building the nve segment of the pdu*********/
    if (at_profile->nve_count > 0) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ATP_NVE, 0)) == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_boolean(data, datalength, ASN_BOOLEAN,
                                      &(at_profile->nve_exclude))) == NULL)
            return(NULL);
        if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                  &(at_profile->nve_count), intsize)) == NULL)
            return(NULL);
    
        count_temp = at_profile->nve_count;
        temp = at_profile->nve;
        while (count_temp > 0) {
            /*nve_object*/
            if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                         &temp[1], temp[0])) == NULL)
                return(NULL);
            temp += temp[0]+1;
            /*nve_type*/
            if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                         &temp[1], temp[0])) == NULL)
                return(NULL);
            temp += temp[0]+1;
            /*nve_zone*/
            if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                         &temp[1], temp[0])) == NULL)
                return(NULL);
            temp += temp[0]+1;
            count_temp--;
        }
        if ((data = fix_length(begin_header2, data, end_header2, ATP_NVE,
                               datalength)) == NULL)
            return(NULL);
    }

    return(fix_length(begin_header1, data, end_header1,
                      (ASN_SET | ASN_CONSTRUCTOR), datalength));
}


/*****************************************************************************
 *
 * NAME: parse_at_profile()
 *
 * DESCRIPTION: Parses the appletalk profile segment of the RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * AT_PROFILE_RETURN *atp - OUTPUT the returned appletalk profile
 *
 * RETURN VALUE: next free space after atprofile data
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
static u_char *parse_at_profile(data, datalength, atp)
u_char *data;
int *datalength;
AT_PROFILE_RETURN *atp;
{

    u_char type =0;
    u_char command;
    u_char *temp;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif
    unsigned
    int length;
    int strlength;
    int i;
    int space;
    u_char *p;

    if (data == NULL || datalength == NULL || atp == NULL)
        return(NULL);

    bzero(atp, sizeof(AT_PROFILE_RETURN));

    strlength = ACP_MAXUSTRING;
    if ((data = asn_parse_string(data, datalength, &type, atp->passwd,
                                 &strlength)) == NULL)
        return(NULL);
    atp->passwd[strlength] = 0;

    if (*datalength >= 2) {
        length = *datalength;
        if ((temp = asn_parse_header(data, &length, &type)) == NULL)
            return(NULL);
        *datalength -= (int)(temp - data);
        data = temp;
    }
    
    while(data != NULL && *datalength > 2) {

        length = *datalength;
        if ((temp = asn_parse_header(data, &length, &command)) == NULL)
            return(NULL);
        *datalength -= (int)(temp - data);
        data = temp;
        if (*datalength == 0 && length == 0)
            break;
        if (*datalength <= 2 || length <= 2)
            return(NULL);
        
        switch (command) {
          case ATP_CONTIME:
            if ((data = asn_parse_int(data, datalength, &type,
                                      &atp->connect_time, intsize)) == NULL)
                return(NULL);
            break;
            
          case ATP_ZONES:
            if ((data = asn_parse_int(data, datalength, &type,
                                      &atp->zone_count, intsize)) == NULL)
                return(NULL);
            if ((data = asn_parse_int(data, datalength, &type, &atp->zones_len,
                                      intsize)) == NULL)
                return(NULL);
            if (atp->zone_count > 0) {
                p = atp->zones_list;

                for(i = atp->zone_count, space = ATZONELIST - 1;
                    i > 0 && space > 0; i--, space -= (strlength + 1)) {
                    strlength = space;

                    if ((data = asn_parse_string(data,datalength, &type,
                                                 p + 1, &strlength)) == NULL)
                        return(NULL);
                    *p = strlength;
                    p += (strlength + 1);
                }
                *p = '\0';
            }
            break;
            
          case ATP_NVE:
            if ((data = asn_parse_boolean(data, datalength, &type,
                                          &atp->nve_exclude, intsize)) == NULL)
                return(NULL);
            if ((data = asn_parse_int(data, datalength, &type,
                                      &atp->nve_count, intsize)) == NULL)
                return(NULL);
            if (atp->nve_count > 0) {
                p = atp->nve;

                for(i = atp->nve_count, space = ATFILTERLEN;
                    i > 0 && space > 0;    i--) {
                    int j;

                    for(j = 0; j < 3 && space > 0; j++) {
                        strlength = MIN(space, ACP_MAXSTRING);
                        if ((data = asn_parse_string(data,datalength, &type,
                                                     (p + 1), &strlength))
                            == NULL)
                            return(NULL);
                        *p = strlength;
                        p += (strlength + 1);
                        space -= (strlength + 1);
                    }
                }
                *p = '\0';

            }
            break;
        
            default:
              data += length;
              *datalength -= length;
            break;
        }
    
    }

    return(data);
}


/*****************************************************************************
 *
 * NAME: parse_string_list()
 *
 * DESCRIPTION: Parses a string list
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * int length - INPUT length of the string list
 * STR_LIST **strlist - OUTPUT address of string list created
 *
 * RETURN VALUE: next free space after string list data
 *
 * RESOURCE HANDLING: racp_create_strlist mallocs strlist
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
static u_char *parse_string_list(data, datalength, length, strlist)
u_char *data;
int *datalength, length;
STR_LIST **strlist;
{
    char *buffer;
    u_char *end = NULL;
    int size = MAXPDUSIZE;
    STR_LIST *laststr = NULL;
    STR_LIST *new = NULL;
    u_char type;
    int strlen;

    if ((buffer = (char*)malloc(size)) == NULL)
        return(NULL);

    if (data == NULL || datalength == NULL)
        goto psl_done;

    if (*datalength < length)
        goto psl_done;

    *datalength -= length;
    end = data + length;

    if (strlist == NULL)
        goto psl_done;

    while(data != NULL && length > 2) {

        strlen = size;
        if ((data = asn_parse_string(data, &length, &type, buffer, &strlen))
            == NULL)
            continue;

        new = racp_create_strlist(buffer, strlen);
        if (laststr != NULL)
            laststr->next = new;
        else
            *strlist = new;
        laststr = new;
    }

  psl_done:

    RACP_FREE(buffer, size);
    return(end);
}

/*****************************************************************************
 *
 * NAME: build_string_list()
 *
 * DESCRIPTION: Builds a string list
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to build into
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * STR_LIST *strlist - INPUT string list
 *
 * RETURN VALUE: next free space in pdu
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
static u_char *build_string_list(data, datalength, strlist)
u_char *data;
int *datalength;
STR_LIST *strlist;
{
    STR_LIST *next;

    for (next = strlist; data != NULL && next != NULL; next = next->next) {

        data = asn_build_string(data, datalength, ASN_VIS_STR, next->str,
                                next->strlen);
    }
    
    return(data);
}

/*****************************************************************************
 *
 * NAME: build_port_stats()
 *
 * DESCRIPTION: Builds the port stats RACP ASN.1 data type
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to build in
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * LOG_PORT_STATS *incoming_port_stats - INPUT the port statistics
 *
 * RETURN VALUE: next free space after port stats data
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
static u_char *build_port_stats(data, datalength, incoming_port_stats)
u_char *data;
int *datalength;
LOG_PORT_STATS *incoming_port_stats;
{
#if defined(ALPHA)
    int intsize = sizeof(unsigned int);
#else
    int intsize = sizeof(unsigned long);
#endif

    if (data == NULL || datalength == NULL || incoming_port_stats == NULL)
        return(NULL);

    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port_stats->bytes_rx),
                              intsize)) == NULL)
        return(NULL);
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port_stats->bytes_tx),
                              intsize)) == NULL)
        return(NULL);
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port_stats->pkts_rx),
                              intsize)) == NULL)
        return(NULL);
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port_stats->pkts_tx),
                              intsize)) == NULL)
        return(NULL);
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port_stats->elapsed_time),
                              intsize)) == NULL)
        return(NULL);
    
    return(data);
}


/*****************************************************************************
 *
 * NAME: parse_port_stats()
 *
 * DESCRIPTION: Parses the port stats segment of the RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * LOG_PORT_STATS *port_stats - OUTPUT the port statistics
 *
 * RETURN VALUE: next free space after port stats data
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
static u_char *parse_port_stats(data, datalength, port_Stats)
u_char *data;
int *datalength;
LOG_PORT_STATS *port_Stats;
{
    u_char type = 0;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if ((data = asn_parse_int(data, datalength, &type,
                              &(port_Stats->bytes_rx), intsize)) == NULL)
        return(NULL);
    if ((data = asn_parse_int(data, datalength, &type,
                              &(port_Stats->bytes_tx), intsize)) == NULL)
        return(NULL);
    if ((data = asn_parse_int(data, datalength, &type,
                              &(port_Stats->pkts_rx), intsize)) == NULL)
        return(NULL);
    if ((data = asn_parse_int(data, datalength, &type,
                              &(port_Stats->pkts_tx), intsize)) == NULL)
        return(NULL);
    /* Very ugly hack to support pre-14.0 Annexes. */
    if (*datalength <= 6)
      return data;
    return(asn_parse_int(data, datalength, &type,
			 &(port_Stats->elapsed_time), intsize));
}


/*****************************************************************************
 *
 * NAME: parse_port()
 *
 * DESCRIPTION: Parses the port segment of the RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * SECPORT *port_variable - OUTPUT the port
 *
 * RETURN VALUE: next free space after port data
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
static u_char *parse_port(data, datalength, port_variable)
u_char *data;
int *datalength;
SECPORT *port_variable;
{
    u_char type = 0;
    u_char *temp;
    int length = *datalength;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (data == NULL || datalength == NULL || port_variable == NULL)
        return(NULL);

    if ((temp = asn_parse_header(data, &length, &type)) == NULL)
        return(NULL);

    *datalength -= (int)(temp - data);
    /* sanity checks */
    if (*datalength < PORT_MIN || length < PORT_MIN)
        return(NULL);
    if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR))
        return(NULL);

    
    if ((data = asn_parse_int(temp, datalength, &type, &port_variable->type,
                              intsize)) == NULL)
        return(NULL);
    data = asn_parse_int(data, datalength, &type, &port_variable->unit,
                         intsize);
    return (data);
}


/*****************************************************************************
 *
 * NAME: build_port()
 *
 * DESCRIPTION: Builds the port segment of the RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to build in
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * SECPORT *incoming_port - OUTPUT the port
 *
 * RETURN VALUE: next free space after port data
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
static u_char *build_port(data, datalength, incoming_port)
u_char *data;
int *datalength;
SECPORT *incoming_port;
{
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif
    u_char *begin_header;
    u_char *end_header;

    begin_header = data;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);
    end_header = data;
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port->type), intsize)) == NULL)
        return(NULL);
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &(incoming_port->unit), intsize)) == NULL)
        return(NULL);

    return(fix_length(begin_header, data, end_header,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}

/*****************************************************************************
 *
 * NAME: build_mp_endpoint()
 *
 * DESCRIPTION: Converts c struct mp_end_disc to the ASN.1 type mp_end_disc
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * struct mp_end_disc *endpoint - INPUT pointer to mp_end_disc data to convert to ASN.1
 *
 * RETURN VALUE: next free space after mp_end_disc data
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
static u_char *build_mp_endpoint (data, datalength, endpoint)
u_char *data;
int *datalength;
EndpDesc *endpoint;

{
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (!data || !datalength || !endpoint)
        return(NULL);

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &endpoint->class, intsize))
	    == NULL)
	    return(NULL);
    if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                 endpoint->address, endpoint->length)) == NULL)
            return(NULL);

    return(data);
}

/*****************************************************************************
 *
 * NAME: parse_mp_endpoint()
 *
 * DESCRIPTION: Parses passed c struct mp_end_disc from the ASN.1 type mp_end_disc
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * EndpDesc *endpoint - OUTPUT pointer to EndpDesc data to from ASN.1 from
 *
 * RETURN VALUE: next free space after mp_end_disc data
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
static u_char *parse_mp_endpoint (data, datalength, endpoint)
u_char *data;
int *datalength;
EndpDesc *endpoint;

{
    u_char type = 0;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (!data || !datalength || !endpoint)
        return(NULL);

    if ((data = asn_parse_int(data, datalength, &type, &endpoint->class, intsize))
	    == NULL)
	    return(NULL);
    endpoint->length = sizeof(endpoint->address);
    if ((data = asn_parse_string(data, datalength, &type, endpoint->address,
                                 &endpoint->length)) == NULL)
            return(NULL);

    endpoint->valid = 1;

    return(data);
}


/*****************************************************************************
 *
 * NAME: racp_build_info_req()
 *
 * DESCRIPTION: Builds the information-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * u_long version -  INPUT racp version
 * long service_from - INPUT service user is coming from
 * long service_request - INPUT service user requests to use
 * SECPORT *port_from - INPUT port user is coming from
 * SECPORT *port_to - INPUT port user is going out on
 * IRQ_PROFILE *opt_info - Optional INPUT; fill in wanted fields
 *
 * RETURN VALUE: next free space after NetAddr data
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 * Assumes internet address in network order
 *
 */
u_char *racp_build_info_req(data, datalength, version, service_from,
                            service_request, port_from, port_to, opt_info)
u_char *data;
int *datalength;
u_long version;
long service_from;
long service_request;
SECPORT *port_from, *port_to;
IRQ_PROFILE *opt_info;
{

    u_char             *packet = data;
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);

    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
    u_char             *savepduhead, *inforeqhead, *inforeqbody;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (data == NULL || datalength == NULL)
      return(NULL);

    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);

    savepduhead = data;

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
                              intsize)) == NULL)
        return(NULL);

    inforeqhead = data;
    if ((data = asn_build_header(data, datalength, RACP_INFO_REQ, 0)) == NULL)
        return(NULL);
    inforeqbody = data;

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_from,
			      intsize)) == NULL)
        return(NULL);
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_request,
			      intsize)) == NULL)
        return(NULL);

    if ((data = build_port(data, datalength, port_from)) == NULL)
        return(NULL);

    if ((data = build_port(data, datalength, port_to)) == NULL)
        return(NULL);

/**** BUILDING THE (OPTIONAL) AUTH_RESP DATA SEGMENT OF THE PDU ****/
    if (opt_info != ((void *)NULL)) {
        begin_header1 = data;
        if ((data = asn_build_header(data, datalength,
                                     (ASN_CONSTRUCTOR | ASN_SET), 0)) == NULL)
            return(NULL);
        end_header1 = data;
        if (opt_info->user_name != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRQ_USERNAME, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         opt_info->user_name,
                                         strlen(opt_info->user_name)))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRQ_USERNAME, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->text != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRQ_TEXT, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->text,
                                         strlen(opt_info->text))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, IRQ_TEXT,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->code != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRQ_CODE, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER, opt_info->code,
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, IRQ_CODE,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->max_logon != ((void *)NULL)) {
          begin_header2 = data;
          if ((data = asn_build_header(data, datalength, IRQ_MAX_LOGON, 0))
              == NULL)
            return(NULL);
          end_header2 = data;
          if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                    opt_info->max_logon, intsize)) == NULL)
            return(NULL);
          if ((data = fix_length(begin_header2, data, end_header2,
                                 IRQ_MAX_LOGON, datalength)) == NULL)
            return(NULL);
        }

        if (opt_info->local_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRQ_LOCADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->local_Address))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRQ_LOCADDR, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->remote_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRQ_REMADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->remote_Address))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRQ_REMADDR, datalength)) == NULL)
                return(NULL);
        }

	if (opt_info->endpoint.valid != 0) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRQ_ENDPOINT, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_mp_endpoint(data, datalength, &opt_info->endpoint)) 
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, IRQ_ENDPOINT,
                                   datalength)) == NULL)
                return(NULL);
	}

        data = fix_length(begin_header1, data, end_header1,
                          (ASN_CONSTRUCTOR | ASN_SET), datalength);
    }
    if ((data = fix_length(inforeqhead, data, inforeqbody, RACP_INFO_REQ,
                           datalength)) == NULL)
        return(NULL);
    
    return(fix_length(packet, data, savepduhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}


/*****************************************************************************
 *
 * NAME: racp_parse_info_req()
 *
 * DESCRIPTION: Parses the information-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int datalength -  INPUT pointer to valid size of data
 * any of the following can be NULL, in which case no info is returned
 * int *servfromp - OUTPUT service user is coming from
 * int *servreqp - OUTPUT information service requested
 * SECPORT *port_from - OUTPUT port user is coming from
 * SECPORT *port_to - OUTPUT port user is going out on
 * IRQ_PROFILE *opt_info - OUTPUT optional information fields
 *
 * RETURN VALUE: next free space after PDU
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 * Assumes internet address in network order
 *
 */
u_char *racp_parse_info_req(data, datalength, servfromp, servreqp, port_from,
                            port_to, opt_info)
u_char *data;
int datalength, *servfromp, *servreqp;
SECPORT *port_from, *port_to;
IRQ_PROFILE *opt_info;
{

    u_char type =0;
    u_char command;
    u_char *temp;
    int strlength = ACP_MAXUSTRING;
    int length;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (data == NULL)
        return(NULL);
    
    if ((data = asn_parse_int(data, &datalength, &type, servfromp, intsize))
        == NULL)
        return(NULL);
    if ((data = asn_parse_int(data, &datalength, &type, servreqp, intsize))
        == NULL)
        return(NULL);
    if (port_from) {
        if ((data = parse_port(data, &datalength, port_from)) == NULL)
            return(NULL);
    }
    else {
        length = datalength;
        temp = asn_parse_header(data, &length, &type);
        datalength -= ((temp - data) + length);
        data = temp + length;
    }
            
    if (port_to) {
        if ((data = parse_port(data, &datalength, port_to)) == NULL)
            return(NULL);
    }
    else {
        length = datalength;
        temp = asn_parse_header(data, &length, &type);
        datalength -= ((temp - data) + length);
        data = temp + length;
    }
            
    if (datalength > 2) {

        length = datalength;
        if ((temp = asn_parse_header(data, &length, &type)) == NULL)
            return(NULL);
        datalength -= (int)(temp - data);
        data = temp;

    }
   
    while(data != NULL && datalength > 2) {

        length = datalength;
        if ((temp = asn_parse_header(data, &length, &command)) == NULL)
            return(NULL);

        datalength -= (int)(temp - data);
        data = temp;
      
       switch (command) {
         case IRQ_USERNAME:
              strlength = ACP_MAXUSTRING;
           if ((data = asn_parse_string(data, &datalength, &type, opt_info->user_name,
                                        &strlength)) == NULL)
               return(NULL);
           if (opt_info->user_name)
             opt_info->user_name[strlength] = 0;
           break;
        case IRQ_TEXT:
           if ((data = asn_parse_string(data, &datalength, &type, opt_info->text,
                                        &strlength)) == NULL)
               return(NULL);
           if (opt_info->text)
             opt_info->text[strlength] = 0;
           break;
        case IRQ_CODE:
           if ((data = asn_parse_int(data, &datalength, &type, opt_info->code, intsize))
               == NULL)
               return(NULL);
           break;
       case IRQ_LOCADDR:
           if (opt_info->local_Address != NULL) {
               if ((data = parse_net_addr(data, &datalength, opt_info->local_Address))
                   == NULL)
                   return(NULL);
           }
           else {
               data += length;
               datalength -= length;
           }
           break;
       case IRQ_REMADDR:
           if (opt_info->remote_Address != NULL) {
               if ((data = parse_net_addr(data, &datalength, opt_info->remote_Address))
                   == NULL)
                   return(NULL);
           }
           else {
               data += length;
               datalength -= length;
           }
           break;

        case IRQ_ENDPOINT:
           if ((data = parse_mp_endpoint(data, &datalength, &opt_info->endpoint))
                == NULL) {
                return(NULL);
	   }
           break;
           
         default:
           data += length;
           datalength -= length;
           break;
       }
    }

    return(data);
}


/*****************************************************************************
 *
 * NAME: racp_build_info_resp()
 *
 * DESCRIPTION: Builds the information-response RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * u_long version -  INPUT racp version
 * int grant - INPUT status of information grant
 * IRQ_PROFILE *opt_info - INPUT pointer to structure of optional information
 *
 * RETURN VALUE: next free space after PDU
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
u_char *racp_build_info_resp(data, datalength, version, grant, opt_info)

u_char *data;
int *datalength;
u_long version;
long grant;
IRQ_PROFILE *opt_info;
{
    u_char             *packet = data;
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);

    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
    u_char *savepduhead, *inforesphead, *inforespbody;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);

    savepduhead = data;

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
                              intsize)) == NULL)
        return(NULL);

    inforesphead = data;
    if ((data = asn_build_header(data, datalength, RACP_INFO_RESP, 0)) == NULL)
        return(NULL);
    inforespbody = data;


    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &grant,
			      intsize)) == NULL)
        return(NULL);

/**** BUILDING THE (OPTIONAL) INFO_RESP DATA SEGMENT OF THE PDU ****/
    if (opt_info != ((void *)NULL)) {
        begin_header1 = data;
        if ((data = asn_build_header(data, datalength,
                                     (ASN_CONSTRUCTOR | ASN_SET), 0)) == NULL)
            return(NULL);
        end_header1 = data;

        if (opt_info->at_profile != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_ATPROFILE, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_at_profile(data, datalength, opt_info->at_profile))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRS_ATPROFILE, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->text != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_TEXT, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->text,
                                         strlen(opt_info->text))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, IRS_TEXT,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->code != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_CODE, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER, opt_info->code,
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, IRS_CODE,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->max_logon != ((void *)NULL)) {
          begin_header2 = data;
          if ((data = asn_build_header(data, datalength, IRS_MAX_LOGON, 0))
              == NULL)
            return(NULL);
          end_header2 = data;
          if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                                    opt_info->max_logon, intsize)) == NULL)
            return(NULL);
          if ((data = fix_length(begin_header2, data, end_header2,
                                 IRS_MAX_LOGON, datalength)) == NULL)
            return(NULL);
        }

        if (opt_info->local_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_LOCADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->local_Address))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRS_LOCADDR, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->remote_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_REMADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->remote_Address))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRS_REMADDR, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->filters != NULL) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_FILTERS, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_string_list(data, datalength, opt_info->filters)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRS_FILTERS, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->routes != NULL) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_ROUTES, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_string_list(data, datalength, opt_info->routes)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   IRS_ROUTES, datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->mp_max_links != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, IRS_MPMAXLINKS, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER, opt_info->mp_max_links,
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, IRS_MPMAXLINKS,
                                   datalength)) == NULL)
                return(NULL);
        }
        data = fix_length(begin_header1, data, end_header1,
                          (ASN_CONSTRUCTOR | ASN_SET), datalength);
    }
    if ((data = fix_length(inforesphead, data, inforespbody, RACP_INFO_RESP,
                           datalength)) == NULL)
        return(NULL);
    
    return(fix_length(packet, data, savepduhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}


/*****************************************************************************
 *
 * NAME: racp_parse_info_resp()
 *
 * DESCRIPTION: Parses the information-response RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * any of the following can be NULL, in which case info for the corresponding
 * segment is lost
 * int *grantp - OUTPUT status of information grant
 * IRQ_PROFILE *opt_info - structure of pointers to additional info
 *
 * RETURN VALUE: next free space after PDU
 *
 * RESOURCE HANDLING: lower level routines malloc filters and routes.  They
 *   must be freed by racp_destroy_strlist_chain() when done
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *
 */
u_char *racp_parse_info_resp(data, datalength, grantp, opt_info)

u_char *data;
int datalength, *grantp;
IRQ_PROFILE *opt_info;
{
    u_char type =0;
    u_char command;
    u_char *temp;
    int strlength = ACP_MAXUSTRING;
    int length;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (data == NULL || grantp == NULL)
        return(NULL);

    if (opt_info != NULL) {
        opt_info->filters = NULL;
        opt_info->routes = NULL;
    }

    /* parsing segments from the ASN1 pdu */

    if ((data = asn_parse_int(data, &datalength, &type, grantp, intsize))
        == NULL)
        return(NULL);

    if (*grantp != REQ_GRANTED)
        return(NULL);

    if (datalength > 2) {
        length = datalength;
        if ((temp = asn_parse_header(data, &length, &type)) == NULL)
            return(NULL);
        datalength -= (int)(temp - data);
        data = temp;
        if (type != (ASN_SET | ASN_CONSTRUCTOR)) {
            return(NULL);
        }
    }
  
    while(data != NULL && datalength > 2) {
        length = datalength;
        if ((temp = asn_parse_header(data, &length, &command)) == NULL)
            return(NULL);
        datalength -= (int)(temp - data);
        data = temp;
        if (length == 0)
            continue;

        switch(command) {
          case IRS_ATPROFILE:
            if ((opt_info!= ((void *)NULL)) && opt_info->at_profile != NULL) {
                if ((data = parse_at_profile(data, &datalength, opt_info->at_profile))
                    == NULL) {
                    return(NULL);
                }
            }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_TEXT:
	    if ((opt_info!= ((void *)NULL)) && opt_info->text != NULL) {
                strlength = ACP_MAXUSTRING;
                if ((data = asn_parse_string(data, &datalength, &type, opt_info->text,
                                         &strlength)) == NULL)
                    return(NULL);

                opt_info->text[strlength] = 0;
	    }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_CODE:
	    if ((opt_info!= ((void *)NULL)) && opt_info->code != NULL) {
                if ((data = asn_parse_int(data, &datalength, &type, opt_info->code,
                                      intsize)) == NULL)
                    return(NULL);
	    }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_MAX_LOGON:
            if ((opt_info!= ((void *)NULL)) && opt_info->max_logon != NULL) {
                 if ((data = asn_parse_int(data, &datalength, &type,
                               opt_info->max_logon,intsize)) == NULL)
                   return(NULL);
               }
            else {
                 data += length;
                 datalength -= length;
               }
            break;
          case IRS_LOCADDR:
            if ((opt_info!= ((void *)NULL)) && opt_info->local_Address != NULL) {
                if ((data = parse_net_addr(data, &datalength, opt_info->local_Address))
                    == NULL)
                    return(NULL);
            }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_REMADDR:
            if ((opt_info!= ((void *)NULL)) && opt_info->remote_Address != NULL) {
                if ((data = parse_net_addr(data, &datalength, opt_info->remote_Address))
                    == NULL)
                    return(NULL);
            }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_FILTERS:
            if (opt_info != NULL && opt_info->filters == NULL) {
                if ((data = parse_string_list(data, &datalength, length,
                                              &opt_info->filters)) == NULL)
                    return(NULL);
            }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_ROUTES:
            if (opt_info != NULL && opt_info->routes == NULL) {
                if ((data = parse_string_list(data, &datalength, length,
                                              &opt_info->routes)) == NULL)
                    return(NULL);
            }
            else {
                data += length;
                datalength -= length;
            }
            break;
          case IRS_MPMAXLINKS:
	    if ((opt_info!= ((void *)NULL)) && opt_info->mp_max_links != NULL) {
                if ((data = asn_parse_int(data, &datalength, &type, opt_info->mp_max_links,
                                      intsize)) == NULL)
                    return(NULL);
	    }
            else {
                data += length;
                datalength -= length;
            }
            break;
            
          default:
            data += length;
            datalength -= length;
            break;
        }
    }

    return(data);
}


/*****************************************************************************
 *
 * NAME: racp_build_audit_log()
 *
 * DESCRIPTION: Builds the audit-log RACP ASN.1 PDU (without log id)
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * long service_from - service user is coming from
 * long service_request - service user requests to use
 * SECPORT *port_from - port user is on
 * long event - event type
 * u_long ctime - time value in seconds
 * any of the following can be NULL, in which case no segment is built
 * NetAddr *remote_Address - remote network address user is talking with
 *                           or coming from
 * char *user_name - name of the user
 * LOG_PORT_STATS *port_Stats - port statistics for this session, EVENT_ACCT
 * char *text - extra information (VisibleString)
 *
 * RETURN VALUE: next free space after audit-log PDU (without log id)
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
u_char *racp_build_audit_log(data, datalength, version, service_from,
                             service_request, port_from, event, ctime,
                             remote_Address, user_name, port_Stats, text)
u_char *data;
int *datalength;
u_long version;
long service_from;
long service_request;
SECPORT *port_from;
long event;
u_long ctime;
NetAddr *remote_Address;
char *user_name;
LOG_PORT_STATS *port_Stats;
char *text;
{
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);
    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
			      intsize)) == NULL)
        return(NULL);
    
    if ((data = asn_build_header(data, datalength, RACP_AUDIT_LOG, 0)) == NULL)
        return(NULL);
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_from,
			      intsize)) == NULL)
        return(NULL);

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_request,
			      intsize)) == NULL)
        return(NULL);
    
    if ((data = build_port(data, datalength, port_from)) == NULL)
        return(NULL);

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &event,
			      intsize)) == NULL)
        return(NULL);
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &ctime,
			      intsize)) == NULL)
        return(NULL);
    
    begin_header1 = data;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_CONSTRUCTOR | ASN_SET), 0)) == NULL)
      return(NULL);
    end_header1 = data;
    
    /**** BUILDING THE (OPTIONAL) AUDIT_LOG DATA SEGMENT OF THE PDU ****/
    if (user_name != ((void *)NULL) || port_Stats != ((void *)NULL) ||
        remote_Address != ((void *)NULL) || text != ((void*)NULL)) {
        if (user_name != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ALG_USERNAME, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         user_name, strlen(user_name)))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   ALG_USERNAME, datalength)) == NULL)
                return(NULL);
        }
        if (remote_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ALG_REMADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, remote_Address))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   ALG_REMADDR, datalength)) == NULL)
                return(NULL);
        }
        if (port_Stats != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ALG_PORTSTATS, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_port_stats(data, datalength, port_Stats))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
                                   ALG_PORTSTATS, datalength)) == NULL)
                return(NULL);
        }
        if (text != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ALG_TEXT, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, text,
                                         strlen(text))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ALG_TEXT,
                                   datalength)) == NULL)
                return(NULL);
        }
        if ((data = fix_length(begin_header1, data, end_header1,
                               (ASN_SET | ASN_CONSTRUCTOR), datalength))
            == NULL)
            return(NULL);
    }

    return(data);
}


/*****************************************************************************
 *
 * NAME: racp_add_logid()
 *
 * DESCRIPTION: Adds a logid to a log message PDU
 *
 * ARGUMENTS:
 * u_char *pdu - The log message
 * int pdulen - The current length of the log message
 * int size - The valid size of pdu
 * u_long log_sequence - log sequence id
 *
 * RETURN VALUE: EINVAL or ESUCCESS
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
errno_t racp_add_logid(pdu, pdulen, version, size, log_sequence)
u_char *pdu;
int *pdulen;
long version;
int size;
u_long log_sequence;
{
    int datalength = size;
    u_char *temp, *data, *seqhead, *datahead, *bodyhead;
    u_char type;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if ((seqhead = asn_parse_header(pdu, &datalength, &type)) == NULL)
        return(EINVAL);
    datalength = size;
    if ((datahead = asn_build_int(seqhead, &datalength, &type,
                                  &version, intsize))
        == NULL)
        return(EINVAL);
    datalength = size;
    if ((bodyhead = asn_parse_header(datahead, &datalength,
                                     &type)) == NULL)
        return(EINVAL);
    data = pdu + *pdulen;
        
    datalength = size - *pdulen;
    if ((temp = asn_build_int(data, &datalength, ASN_INTEGER,
                              &log_sequence, intsize))
        == NULL)
        return(EINVAL);
    if ((temp = fix_length(datahead, temp, bodyhead,
                           RACP_AUDIT_LOG, &datalength))
        == NULL)
        return(EINVAL);
    if ((temp = fix_length(pdu, temp, seqhead,
                           (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                           &datalength)) == NULL)
        return(EINVAL);

    *pdulen += (temp - data);
    return(ESUCCESS);
}  

/*****************************************************************************
 *
 * NAME: racp_parse_audit_log()
 *
 * DESCRIPTION: Parses the audit-log RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * long service_from - service user is coming from
 * long service_request - service user requests to use
 * SECPORT *port - port user is on
 * int *event - pointer to event type
 * u_long *ctime - time value in seconds
 * NetAddr *remote_Address - remote network address user is talking with
 *                           or coming from
 * char *user_name - name of the user
 * LOG_PORT_STATS *port_Stats - port statistics for this session, EVENT_ACCT
 * char *text - extra information (VisibleString)
 * unsigned long *logid - pointer to unique log id
 *
 * RETURN VALUE: next free space after audit-log PDU (without log id)
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
/* assumes all double pointers non-NULL and point to valid pointers which
 point to valid data */
u_char *racp_parse_audit_log(data, datalength, service_from, service_request,
                             port, event, ctime, remote_Address, user_name,
                             port_Stats, text, logid)
u_char *data;
int datalength, *service_from, *service_request;
SECPORT *port;
int *event;
u_long *ctime;
NetAddr **remote_Address;
char **user_name;
LOG_PORT_STATS **port_Stats;
char **text;
unsigned long *logid;
{
    u_char type =0;
    u_char command;
    u_char *temp;
    int length, setlength;
    int strlength = ACP_MAXSTRING;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif
    NetAddr *remaddr = *remote_Address;
    char *user = *user_name;
    LOG_PORT_STATS *ps = *port_Stats;
    char *txt = *text;

    bzero(remaddr, sizeof(NetAddr));
    *user = '\0';
    bzero(ps, sizeof(LOG_PORT_STATS));
    *txt = '\0';

    *remote_Address = NULL;
    *user_name = NULL;
    *port_Stats = NULL;
    *text = NULL;

    *logid = 0;

    if ((data = asn_parse_int(data, &datalength, &type, service_from,
                              intsize)) == NULL)
        return(NULL);

    if ((data = asn_parse_int(data, &datalength, &type, service_request,
                              intsize)) == NULL)
        return(NULL);
    
    if ((data = parse_port(data, &datalength, port)) == NULL)
        return(NULL);

    if ((data = asn_parse_int(data, &datalength, &type, event, intsize))
        == NULL)
        return(NULL);

    if ((data = asn_parse_int(data, &datalength, &type, ctime, intsize))
        == NULL)
        return(NULL);

    setlength = datalength;
    if ((temp = asn_parse_header(data, &setlength, &type)) == NULL)
      return(NULL);
    datalength -= (int)(temp - data);
    data = temp;

    while(setlength > 2) {

        length = datalength;
        if ((temp = asn_parse_header(data, &length, &command)) == NULL)
            return(NULL);
        datalength -= (int)(temp - data);
        setlength -= (int)(temp - data);
        data = temp;
        switch (command) {
          case ALG_USERNAME:
              strlength = ACP_MAXUSTRING;
            if ((temp = asn_parse_string(data, &datalength, &type, user,
                                         &strlength)) == NULL)
                return(NULL);
            user[strlength] = 0;
            *user_name = user;
            setlength -= (int)(temp - data);
            data = temp;
            break;
          case ALG_TEXT:
            strlength = ACP_MAXUSTRING * 2;
            if ((temp = asn_parse_string(data, &datalength, &type, txt,
                                         &strlength)) == NULL)
                return(NULL);
            txt[strlength] = 0;
            *text = txt;
            setlength -= (int)(temp - data);
            data = temp;
            break;
          case ALG_REMADDR:
            if ((temp = parse_net_addr(data, &datalength, remaddr))
                == NULL)
                return(NULL);
            *remote_Address = remaddr;
            setlength -= (int)(temp - data);
            data = temp;
            break;
          case ALG_PORTSTATS:
            if ((temp = parse_port_stats(data, &datalength, ps))
                == NULL)
                return(NULL);
            *port_Stats = ps;
            setlength -= (int)(temp - data);
            data = temp;
            break;
          default:
            data += length;
            datalength -= length;
            setlength -= length;
            break;
        } /* switch */
    } /* while */

    if (datalength > 2)
        data = asn_parse_int(data, &datalength, &type, logid, intsize);

    return(data);
}

/*****************************************************************************
 *
 * NAME: build_chap()
 *
 * DESCRIPTION: Builds the chap PDU segment
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength - INPUT/OUTPUT then space left in the buffer
 * CHAP_REQ *chap - INPUT the chap attributes
 *
 * RETURN VALUE: next free data space
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

u_char *build_chap(data, datalength, chap)
u_char *data;
u_long *datalength;
CHAP_REQ *chap;
{
    u_char *beginhead, *endhead;

    beginhead = data;
    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0))
        == NULL)
        return(NULL);

    endhead = data;

    if ((data = asn_build_string(data, datalength, ASN_OCTET_STR, &chap->id, 1))
        == NULL)
        return(NULL);
    
    if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                 chap->challenge, CHAP_CHAL_LEN)) == NULL)
        return(NULL);
    
    if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                 chap->response, CHAP_RESP_LEN)) == NULL)
        return(NULL);

    return(fix_length(beginhead, data, endhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}


/*****************************************************************************
 *
 * NAME: parse_chap()
 *
 * DESCRIPTION: Parses the chap PDU segment
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *pdulen - INPUT remaining length of this PDU
 * CHAP_REQ *chap - OUTPUT the chap attributes
 *
 * RETURN VALUE: next free space after PDU
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

u_char *parse_chap(data, pdulen, chap)
u_char *data;
int *pdulen;
CHAP_REQ *chap;
{
    u_char type;
    int strlen;
    int seglen = *pdulen;
    u_char *start = data;
    
    if ((data = asn_parse_header(data, &seglen, &type)) == NULL)
        return(NULL);

    strlen = 1;
    *pdulen -= (int)(data - start);
    if ((data = asn_parse_string(data, pdulen, &type, &chap->id, &strlen))
        == NULL)
        return(NULL);

    strlen = CHAP_CHAL_LEN;
    if ((data = asn_parse_string(data, pdulen, &type, chap->challenge,
                                 &strlen))
        == NULL)
        return(NULL);
    
    strlen = CHAP_RESP_LEN;
    if ((data = asn_parse_string(data, pdulen, &type, chap->response,
                                 &strlen))
        == NULL)
        return(NULL);

    return(data);
}


#ifdef ANNEX
/*****************************************************************************
 *
 * NAME: racp_build_auth_req()
 *
 * DESCRIPTION: Builds the authorization-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to put built data
 * int *datalength -  INPUT pointer to valid size of data
 *                    OUTPUT points to remaining valid size of data
 * u_long version -  INPUT racp version
 * long service_from - service user is coming from
 * long service_request - service user requests to use
 * SECPORT *port_from - port user is coming from
 * SECPORT *port_destination - port user is going out on
 * ARQ_PROFILE *opt_info - Pointer to optional information structure
 *
 * RETURN VALUE: next free space after PDU
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

u_char *racp_build_auth_req(data, datalength, version, service_from,
                            service_request, port_from, port_destination,
                            opt_info)
u_char *data;
int *datalength;
u_long version;
long service_from;
long service_request;
SECPORT *port_from;
SECPORT *port_destination;
ARQ_PROFILE *opt_info;
{
    u_char             *packet;
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);
    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
#if defined(ALPHA)
    int tempint;
#else
    long tempint;
#endif
    int intsize = sizeof(tempint);
    u_char             *savepduhead, *authreqhead, *authreqbody;

    /*building ASN1 object for ppp-security command*/
    packet = data;
    /*building ASN1 objects for port, direction and n
      etnum variables.*/

    if (data == NULL || datalength == NULL)
      return(NULL);

    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);

    savepduhead = data;

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
			      intsize)) == NULL)
        return(NULL);

    authreqhead = data;
    if ((data = asn_build_header(data, datalength, RACP_AUTH_REQ, 0)) == NULL)
        return(NULL);
    authreqbody = data;
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_from,
			      intsize)) == NULL)
        return(NULL);

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_request, 
			      intsize)) == NULL)
        return(NULL);

    if ((data = build_port(data, datalength, port_from)) == NULL)
        return(NULL);
    if ((data = build_port(data, datalength, port_destination)) == NULL)
        return(NULL);

    if (opt_info != ((void *)NULL)) {
        begin_header1 = data;
        if ((data = asn_build_header(data, datalength,
                                     (ASN_SET | ASN_CONSTRUCTOR), 0)) == NULL)
           return(NULL);
        end_header1 = data;

        if (opt_info->user_name != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_USERNAME, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         opt_info->user_name,
                                         strlen(opt_info->user_name))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_USERNAME,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->pass_word != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_PASSWORD, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         opt_info->pass_word,
                                         strlen(opt_info->pass_word))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_PASSWORD,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->phonenumber != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_PHONE, 0)) == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         opt_info->phonenumber,
                                         strlen(opt_info->phonenumber)))
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_PHONE,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->from_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_FROMADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->from_Address)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_FROMADDR,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->dest_Address != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_DESTADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->dest_Address)) 
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_DESTADDR,
                                   datalength)) == NULL)
                return(NULL);
        }
	if (opt_info->endpoint.valid != 0) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_ENDPOINT, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_mp_endpoint(data, datalength, &opt_info->endpoint)) 
                == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_ENDPOINT,
                                   datalength)) == NULL)
                return(NULL);
	}
        if (opt_info->chap_req != NULL) {

#ifdef DEBUG_TMS
    printf("racp_asn1.c: Dealing With The CHAP request()\n");
#endif
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_CHAP, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_chap(data, datalength, opt_info->chap_req)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ARQ_CHAP,
                                   datalength)) == NULL)
                return(NULL);
        }
        if (opt_info->called_number != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_CALLED_NUM, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR,
                                         opt_info->called_number,
                                         strlen(opt_info->called_number))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
				   ARQ_CALLED_NUM, datalength)) == NULL)
                return(NULL);
        }
	if (opt_info->ras_addr != 0) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ARQ_RAS_ADDR, 0))
                == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &opt_info->ras_addr,
				      sizeof(opt_info->ras_addr))) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2,
				   ARQ_RAS_ADDR, datalength)) == NULL)
                return(NULL);
	}
        if (opt_info->calling_number != NULL) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_CALLING_NUM,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  data = asn_build_string(data,datalength,ASN_VIS_STR,
				  opt_info->calling_number,
				  strlen(opt_info->calling_number));
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_CALLING_NUM,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->called_subaddress != NULL) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_CALLED_SUB,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  data = asn_build_string(data,datalength,ASN_VIS_STR,
				  opt_info->called_subaddress,
				  strlen(opt_info->called_subaddress));
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_CALLED_SUB,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->spb_name != NULL) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_SPB_NAME,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  data = asn_build_string(data,datalength,ASN_VIS_STR,
				  opt_info->spb_name,
				  strlen(opt_info->spb_name));
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_SPB_NAME,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->bearer_type != RACP_BT_NONE) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_BEARER_TYPE,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  tempint = opt_info->bearer_type;
	  data = asn_build_int(data,datalength,ASN_INTEGER,&tempint,intsize);
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_BEARER_TYPE,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->detected_l1 != RACP_L1_NONE) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_DETECT_L1,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  tempint = opt_info->detected_l1;
	  data = asn_build_int(data,datalength,ASN_INTEGER,&tempint,intsize);
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_DETECT_L1,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->detected_l2 != RACP_L2_NONE) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_DETECT_L1,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  tempint = opt_info->detected_l2;
	  data = asn_build_int(data,datalength,ASN_INTEGER,&tempint,intsize);
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_DETECT_L2,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->wan_index > 0) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_WAN_INDEX,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  tempint = opt_info->wan_index;
	  data = asn_build_int(data,datalength,ASN_INTEGER,&tempint,intsize);
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_WAN_INDEX,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
        if (opt_info->ds0_index > 0) {
	  begin_header2 = data;
	  data = asn_build_header(data,datalength,ARQ_DS0_INDEX,0);
	  if (data == NULL)
	    return(NULL);
	  end_header2 = data;
	  tempint = opt_info->ds0_index;
	  data = asn_build_int(data,datalength,ASN_INTEGER,&tempint,intsize);
	  if (data == NULL)
	    return(NULL);
	  data = fix_length(begin_header2,data,end_header2,ARQ_DS0_INDEX,
			    datalength);
	  if (data == NULL)
	    return(NULL);
        }
    }
    if (begin_header1)
        if ((data = fix_length(begin_header1, data, end_header1,
                               (ASN_SET | ASN_CONSTRUCTOR), datalength))
            == NULL)
            return(NULL);
    
    if ((data = fix_length(authreqhead, data, authreqbody, RACP_AUTH_REQ,
                           datalength)) == NULL)
        return(NULL);
    
    return(fix_length(packet, data, savepduhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}
#endif /*ANNEX*/


#ifndef ANNEX
/*****************************************************************************
 *
 * NAME: racp_build_auth_resp()
 *
 * DESCRIPTION: Builds the authorization-response RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 * ulong version - INPUT racp version
 * u_long grant - INPUT status of authorization grant
 * any of the following can be NULL, in which case no segment is built
 * u_long *cli_mask - INPUT pointer to returned CLI command mask
 * u_long *hooks_mask - INPUT pointer to HOOKS mask
 * char *user_name - INPUT username of user
 * char *domain - INPUT domain of user
 * tms_db_entry *tms_info - INPUT tunnel info if tunnel user
 *
 * RETURN VALUE: next free space after PDU
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

u_char *racp_build_auth_resp(data, datalength, version, grant, cli_mask,
                             hooks_mask, user_name, domain, tms_info)
u_char *data;
int *datalength;
u_long version;
u_long grant;
u_long *cli_mask;
u_long *hooks_mask;
char *user_name;
char *domain;
tms_db_entry *tms_info;
{
    u_char *packet = data;
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);
    u_char *savepduhead, *authresphead, *authrespbody;
    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if ((data = asn_build_header(data, datalength,
                (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);
    savepduhead = data;

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
        intsize)) == NULL)
        return(NULL);

    authresphead = data;
    if ((data = asn_build_header(data, datalength, RACP_AUTH_RESP, 0))
        == NULL)
        return(NULL);

    authrespbody = data; /*saving pointer to fix the length fields, later*/

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &grant,
                              intsize)) == NULL)
        return(NULL);

    if (user_name != ((void *)NULL) || cli_mask != ((void *)NULL) ||
        hooks_mask != ((void *)NULL) || tms_info != ((void *)NULL)) {
        begin_header1 = data;
        if ((data = asn_build_header(data, datalength,
                                     (ASN_CONSTRUCTOR | ASN_SET), 0)) == NULL)
            return(NULL);
        end_header1 = data;
    }

    if (user_name != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ARS_USERNAME, 0))
            == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_string(data, datalength,  ASN_VIS_STR,
                                     user_name, strlen(user_name))) == NULL)
            return(NULL);
        if ((data = fix_length(begin_header2, data, end_header2, ARS_USERNAME,
                               datalength)) == NULL)
            return(NULL);
    }

    if (cli_mask != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ARS_CLIMASK, 0))
            == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER, cli_mask,
				  intsize)) == NULL)
            return(NULL);
        if ((data = fix_length(begin_header2, data, end_header2, ARS_CLIMASK,
                               datalength)) == NULL)
            return(NULL);
    }

    if (hooks_mask != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ARS_HOOKMASK, 0))
            == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_int(data, datalength,  ASN_INTEGER, hooks_mask, 
				  intsize)) == NULL)
            return(NULL);
        if ((data = fix_length(begin_header2, data, end_header2, ARS_HOOKMASK,
                               datalength)) == NULL)
            return(NULL);
    }

    /*
     * handle tunnel information
     */
    if (tms_info != NULL) {
	UINT32 temp;

        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ARS_TMS_TE, 0)) == NULL)
            return(NULL);
        end_header2 = data;
	temp = ntohl(tms_info->td_te_addr.s_addr);
        if ((data = asn_build_int(data, datalength, ASN_INTEGER, 
				  &temp, intsize)) == NULL)
            return(NULL);
        if ((data = fix_length(begin_header2, data, end_header2, ARS_TMS_TE,
                               datalength)) == NULL)
            return(NULL);

	/* extensions added between 14.0 and 14.1 */
        begin_header2 = data;
        if ((data = asn_build_header(data,datalength, ARS_TMS_EXT1,0)) == NULL)
            return(NULL);
        end_header2 = data;
	temp = tms_info->td_tunnel_type;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				  intsize)) == NULL)
            return(NULL);
	if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
				     domain, strlen(domain))) == NULL)
	    return(NULL);
	temp = tms_info->td_server_loc;
	if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				  intsize)) == NULL)
	    return(NULL);
	if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
				 tms_info->td_passwd, TMS_PASSWD_LEN)) == NULL)
	    return(NULL);
        if ((data = fix_length(begin_header2, data, end_header2, ARS_TMS_EXT1,
                               datalength)) == NULL)
            return(NULL);

	if (tms_info->td_hw_type) {
	    begin_header2 = data;
	    if ((data = asn_build_header(data, datalength, ARS_TMS_HW, 0))
		== NULL)
		return(NULL);
	    end_header2 = data;
	    temp = tms_info->td_hw_type;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    temp = tms_info->td_hw_addr_len;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
					 tms_info->td_hw_addr, TMS_HWADDR_LEN))
		== NULL)
		return(NULL);
	    if ((data = fix_length(begin_header2, data, end_header2,
				   ARS_TMS_HW, datalength)) == NULL)
		return(NULL);
	}

	if (tms_info->td_auth_proto) {		/* actually, this is required*/
	    begin_header2 = data;
	    if ((data = asn_build_header(data, datalength, ARS_TMS_AUTH, 0))
		== NULL)
		return(NULL);
	    end_header2 = data;
	    temp = tms_info->td_auth_proto;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    temp = ntohl(tms_info->td_pauth_addr.s_addr);
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &temp, intsize)) == NULL)
		return(NULL);
	    temp = ntohl(tms_info->td_sauth_addr.s_addr);
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &temp, intsize)) == NULL)
		return(NULL);
	    if ((data = fix_length(begin_header2, data, end_header2,
				   ARS_TMS_AUTH, datalength)) == NULL)
		return(NULL);
	}

	if (tms_info->td_acct_proto) {
	    begin_header2 = data;
	    if ((data = asn_build_header(data, datalength, ARS_TMS_ACCT, 0))
		== NULL)
		return(NULL);
	    end_header2 = data;
	    temp = tms_info->td_acct_proto;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    temp = ntohl(tms_info->td_pacct_addr.s_addr);
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &temp, intsize)) == NULL)
		return(NULL);
	    temp = ntohl(tms_info->td_sacct_addr.s_addr);
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &temp, intsize)) == NULL)
		return(NULL);
	    if ((data = fix_length(begin_header2, data, end_header2,
				   ARS_TMS_ACCT, datalength)) == NULL)
		return(NULL);
	}

	if (tms_info->td_addr_proto) {
	    begin_header2 = data;
	    if ((data = asn_build_header(data, datalength, ARS_TMS_ADDR, 0))
		== NULL)
		return(NULL);
	    end_header2 = data;
	    temp = tms_info->td_addr_proto;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &tms_info->td_paddr_addr, intsize))
		== NULL)
		return(NULL);
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &tms_info->td_saddr_addr, intsize))
		== NULL)
		return(NULL);
	    if ((data = fix_length(begin_header2, data, end_header2,
				   ARS_TMS_ADDR, datalength)) == NULL)
		return(NULL);
	}

	if (tms_info->td_spi){
	    begin_header2 = data;
	    if ((data = asn_build_header(data, datalength, ARS_TMS_TAUTH, 0))
		== NULL)
		return(NULL);
	    end_header2 = data;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
				      &tms_info->td_spi, intsize)) == NULL)
		return(NULL);
	    temp = tms_info->td_ta_type;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    temp = tms_info->td_ta_mode;
	    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &temp,
				      intsize)) == NULL)
		return(NULL);
	    if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
					 tms_info->td_ta_key, TMS_KEY_LEN))
		== NULL)
		return(NULL);
	    if ((data = fix_length(begin_header2, data, end_header2,
				   ARS_TMS_TAUTH, datalength)) == NULL)
		return(NULL);
	}
    } /* if (tms_info) */

    if (begin_header1)
        if ((data = fix_length(begin_header1, data, end_header1,
                               (ASN_CONSTRUCTOR | ASN_SET), datalength))
            == NULL)
            return(NULL);
    if ((data = fix_length(authresphead, data, authrespbody, RACP_AUTH_RESP,
                           datalength)) == NULL)
        return(NULL);
    
    return(fix_length(packet, data, savepduhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}
#endif /*!ANNEX*/


#if defined(ANNEX) && (NUDAS > 0)
/*****************************************************************************
 *
 * NAME: racp_build_tms_req()
 *
 * DESCRIPTION: Builds the TMS-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data   - INPUT buffer to use
 * int datalength - INPUT valid size of buffer; OUTPUT bytes remaining
 * long version   - INPUT racp version
 * u_long rasid   - INPUT RAS IP address
 * char *domain	  - INPUT pointer to domain name
 * char *dnis	  - INPUT pointer to dnis
 *
 * RETURN VALUE: next free space after PDU
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

u_char *racp_build_tms_req(data, datalen, acp_version, rasid, domain, dnis)
u_char *data;
int *datalen;
long acp_version;
u_long rasid;
char *domain;
char *dnis;
{
    u_char *packet = data;
    u_char *pduhead, *tmsreqhead, *tmsreqbody;
    int dlen;

#ifdef DEBUG_TMS
    printf("racp_asn1.c: entering racp_build_tms_req()\n");
#endif

    /*
     * build the headers and common body of the response
     */
    *data = 0;
    if ((data = asn_build_header(data, datalen,
				 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);

    pduhead = data;
    if ((data = asn_build_int(data, datalen, ASN_INTEGER, &acp_version,
			      sizeof(acp_version))) == NULL)
	return(NULL);

    tmsreqhead = data;
    if ((data = asn_build_header(data, datalen, RACP_TMS_REQ, 0)) == NULL)
	return(NULL);

    tmsreqbody = data;		/* saving pointer to fix length fields later */

#ifdef DEBUG_TMS
    printf("racp_build_tms_req(): built request header\n");
#endif

    if ((data = asn_build_int(data, datalen, ASN_INTEGER, &rasid,
			      sizeof(rasid))) == NULL)
	return(NULL);

    if ((dlen = strlen(domain)) > TMS_DOMAIN_LEN) {
#ifdef DEBUG_TMS
	printf("racp_build_tms_req(): domain length too long (%d > %d)\n",
	       dlen, TMS_DOMAIN_LEN);
#endif
	return(NULL);
    }
    if ((data = asn_build_string(data, datalen, ASN_OCTET_STR, domain,
				 dlen)) == NULL)
	return(NULL);

    if ((dlen = strlen(dnis)) > TMS_DNIS_LEN) {
#ifdef DEBUG_TMS
	printf("racp_build_tms_req(): dnis length too long (%d > %d)\n",
	       dlen, TMS_DNIS_LEN);
#endif
	return(NULL);
    }
    if ((data = asn_build_string(data, datalen, ASN_OCTET_STR, dnis,
				 dlen)) == NULL)
	return(NULL);

    /*
     * fix the lengths and be done
     */
#ifdef DEBUG_TMS
    printf("racp_build_tms_req(): fixing packet lengths\n");
#endif
    if ((data = fix_length(tmsreqhead, data, tmsreqbody, RACP_TMS_REQ,
			   datalen)) == NULL)
	return(NULL);
    
    if ((data = fix_length(packet, data, pduhead,
			   (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalen)) == NULL)
	return(NULL);

#ifdef DEBUG_TMS
    printf("racp_build_tms_req(): exiting successfully\n");
#endif
    return(data);
}
#endif /*ANNEX*/


#ifndef ANNEX
/*****************************************************************************
 *
 * NAME: racp_parse_auth_req()
 *
 * DESCRIPTION: Parses the authorization-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *pdu - INPUT pdu to parse
 * int pdulen -  INPUT size of pdu
 * any of the following can be NULL, in which case no info is returned
 * long *service_from - service user is coming from
 * long *service_request - service user requests to use
 * SECPORT *port_from - port user is coming from
 * SECPORT *port_destination - port user is going out on
 * ARQ_PROFILE *opt_info - pointer to optional information structure
 *
 * RETURN VALUE: next free space after PDU
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
u_char *racp_parse_auth_req(pdu, pdulen, service_from, service_request,
                            port_from, port_destination, opt_info)
u_char *pdu;
int *pdulen;
long *service_from;
long *service_request;
SECPORT *port_from;
SECPORT *port_destination;
ARQ_PROFILE *opt_info;
{
    u_char type =0;
    u_char command;
    u_char *temp;
    u_char *data = (u_char*)pdu;
    int length;
    int strlength = ACP_MAXSTRING;
#if defined(ALPHA)
    int tempint;
#else
    long tempint;
#endif
    int intsize = sizeof(tempint);

    if ((data = asn_parse_int(data, pdulen, &type, service_from,
                              intsize)) == NULL)
        return(NULL);

    if ((data = asn_parse_int(data, pdulen, &type, service_request,
                              intsize)) == NULL)
        return(NULL);

    if ((data = parse_port(data, pdulen, port_from)) == NULL)
        return(NULL);
    if ((data = parse_port(data, pdulen, port_destination)) == NULL)
        return(NULL);
    
    if (*pdulen > 2) {
        length = *pdulen;
            
        if ((temp = asn_parse_header(data, &length, &type)) == NULL) {
            *pdulen = length;
            return(NULL);
        }
        *pdulen -= (int)(temp - data);
        data = temp;
        if (type != (ASN_SET | ASN_CONSTRUCTOR)) {
            return(NULL);
        }
    }

    while(data != NULL && *pdulen > 2) {
   
        length = *pdulen;
        if ((temp = asn_parse_header(data, &length, &command)) 
            == NULL) {
            return(NULL);
        }
        *pdulen -= (int)(temp - data);
        data = temp;
        switch (command) {
          case ARQ_USERNAME:
            strlength = ACP_MAXUSTRING;
            if ((data = asn_parse_string(data, pdulen, &type, opt_info->user_name,
                                         &strlength)) == NULL)
                return(NULL);
            if (opt_info->user_name)
              opt_info->user_name[strlength] = 0;
            break;
          case ARQ_PASSWORD:
            strlength = ACP_MAXSTRING;
            if ((data = asn_parse_string(data, pdulen, &type, opt_info->pass_word,
                                         &strlength)) == NULL)
                return(NULL);
            if (opt_info->pass_word)
              opt_info->pass_word[strlength] = 0;
            break;
          case ARQ_PHONE:
            strlength = ACP_MAXSTRING;
            if ((data = asn_parse_string(data, pdulen, &type, opt_info->phonenumber,
                                         &strlength)) == NULL)
                return(NULL);
            if (opt_info->phonenumber)
              opt_info->phonenumber[strlength] = 0;
            break;
          case ARQ_FROMADDR:
            if ((data = parse_net_addr(data, pdulen, opt_info->from_Address)) == NULL)
                return(NULL);
            break;
          case ARQ_DESTADDR:
            if ((data = parse_net_addr(data, pdulen, opt_info->dest_Address))
                == NULL)
                return(NULL);
            break;
          case ARQ_ENDPOINT:
            if ((data = parse_mp_endpoint(data, pdulen, &opt_info->endpoint))
                == NULL)
                return(NULL);
            break;
          case ARQ_CHAP:
            if ((data = parse_chap(data, pdulen, opt_info->chap_req)) == NULL)
                return(NULL);
            break;
          case ARQ_CALLED_NUM:
            strlength = ACP_MAXSTRING;
            if ((data = asn_parse_string(data, pdulen, &type,
					 opt_info->called_number,
                                         &strlength)) == NULL)
                return(NULL);
            if (opt_info->called_number)
	      opt_info->called_number[strlength] = 0;
            break;
	  case ARQ_RAS_ADDR:
	    if ((data = asn_parse_int(data, pdulen, &type, &opt_info->ras_addr,
				      sizeof(opt_info->ras_addr))) == NULL)
		return(NULL);
	    break;
	  case ARQ_CALLING_NUM:
            strlength = ACP_MAXSTRING;
            data = asn_parse_string(data,pdulen,&type,opt_info->calling_number,
				    &strlength);
	    if (data == NULL)
	      return(NULL);
            if (opt_info->calling_number)
	      opt_info->calling_number[strlength] = 0;
	    break;
	  case ARQ_CALLED_SUB:
            strlength = ACP_MAXSTRING;
            data = asn_parse_string(data,pdulen,&type,
				    opt_info->called_subaddress,&strlength);
	    if (data == NULL)
	      return(NULL);
            if (opt_info->called_subaddress)
	      opt_info->called_subaddress[strlength] = 0;
	    break;
	  case ARQ_SPB_NAME:
            strlength = ACP_MAXSTRING;
            data = asn_parse_string(data,pdulen,&type,opt_info->spb_name,
				    &strlength);
	    if (data == NULL)
	      return(NULL);
            if (opt_info->spb_name)
	      opt_info->spb_name[strlength] = 0;
	    break;
	  case ARQ_BEARER_TYPE:
	    data = asn_parse_int(data,pdulen,&type,&tempint,sizeof(tempint));
	    if (data == NULL)
	      return(NULL);
	    opt_info->bearer_type = (u_char) tempint;
	    break;
	  case ARQ_DETECT_L1:
	    data = asn_parse_int(data,pdulen,&type,&tempint,sizeof(tempint));
	    if (data == NULL)
	      return(NULL);
	    opt_info->detected_l1 = (u_short) tempint;
	    break;
	  case ARQ_DETECT_L2:
	    data = asn_parse_int(data,pdulen,&type,&tempint,sizeof(tempint));
	    if (data == NULL)
	      return(NULL);
	    opt_info->detected_l2 = (u_short) tempint;
	    break;
	  case ARQ_WAN_INDEX:
	    data = asn_parse_int(data,pdulen,&type,&tempint,sizeof(tempint));
	    if (data == NULL)
	      return(NULL);
	    opt_info->wan_index = (u_short) tempint;
	    break;
	  case ARQ_DS0_INDEX:
	    data = asn_parse_int(data,pdulen,&type,&tempint,sizeof(tempint));
	    if (data == NULL)
	      return(NULL);
	    opt_info->ds0_index = (u_short) tempint;
	    break;
   
          default:
            data += length;
            *pdulen -= length;
            break;
        }
   
    }

    return(data);
}
#endif /*!ANNEX*/


#ifdef ANNEX
/*****************************************************************************
 *
 * NAME: racp_parse_auth_reply()
 *
 * DESCRIPTION: Parses the authorization-reply RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int datalength -  INPUT valid size of data
 * any of the following can be NULL, in which case no info is retrieved
 * int *grant - OUTPUT status of authorization grant
 * char *user_name - OUTPUT username of user
 * long *cli_mask - OUTOUT pointer to returned CLI command mask
 * long *hooks_mask - OUTPUT pointer to HOOKS mask
 * tms_grant *tms_info; - OUTPUT pointer to tunnel information
 *
 * RETURN VALUE: next free space after PDU
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
u_char *racp_parse_auth_reply(data, datalength, grant, user_name, cli_mask,
                         hooks_mask, tms_info)
u_char *data;
int datalength;
int *grant;
char *user_name;
long *cli_mask, *hooks_mask;
tms_grant *tms_info;
{
    int length;
    u_char type = 0;
    u_char command;
    u_char *temp;
#if defined(ALPHA)
    int intsize = sizeof(int);
    unsigned tval;
#else
    int intsize = sizeof(long);
    u_long tval;
#endif

    if (data == NULL || grant == NULL)
        return(NULL);

    *grant = REQ_DENIED;

#if (NUDAS > 0)
    if (tms_info != NULL)
	bzero((char *)tms_info, sizeof(*tms_info));
#endif

    if ((data = asn_parse_int(data, &datalength, &type, grant, 
        intsize)) == NULL)
        return(NULL);

    if (datalength >= 2) {
        length = datalength;
        if ((temp = asn_parse_header(data, &length, &type)) == NULL)
            return(NULL);
        datalength -= (int)(temp - data);
        data = temp;
        if (type != (ASN_SET | ASN_CONSTRUCTOR))
            return(NULL);
    }

    while(data != NULL && datalength > 2) {
        length = datalength;
        if ((temp = asn_parse_header(data, &length, &command)) == NULL)
            return(NULL);
        datalength -= (int)(temp - data);
        data = temp;

        switch (command) {
          case ARS_USERNAME:
            length = ACP_MAXUSTRING;
            if ((data = asn_parse_string(data, &datalength, &type, 
                                         user_name, &length)) == NULL)
                return(NULL);
            if (user_name != NULL)
                user_name[length] ='\0';
            break;

          case ARS_CLIMASK:
            if ((data = asn_parse_int(data, &datalength, &type, 
                                      cli_mask, intsize)) == NULL)
                return(NULL);

            break;

          case ARS_HOOKMASK:
            if ((data = asn_parse_int(data, &datalength, &type, 
                                      hooks_mask, intsize)) == NULL)
                return(NULL);
            break;

#if (NUDAS > 0)
	  case ARS_TMS_TE:
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_te_addr, intsize)) == NULL)
                return(NULL);
	    tms_info->tg_te_addr.s_addr = htonl(tms_info->tg_te_addr.s_addr);
#ifdef DEBUG_TMS
	printf("racp_parse_auth_reply(): te_addr=%a\n",
	       tms_info->tg_te_addr.s_addr);
#endif
	    break;

	  /* extensions added between 14.0 and 14.1 */
	  case ARS_TMS_EXT1:
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
                return(NULL);
	    tms_info->tg_tunnel_type = tval;
	    if ((data = asn_parse_string(data, &datalength, &type,
					 tms_info->tg_domain, &length))== NULL)
                return(NULL);
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_server_loc = tval;
	    length = TMS_PASSWD_LEN;
	    if ((data = asn_parse_string(data, &datalength, &type,
					 tms_info->tg_passwd, &length)) ==NULL)
		return(NULL);
#ifdef DEBUG_TMS
	    printf("racp_parse_auth_reply(): tun_type=%d, domain=%s, srv_loc=%d\n",
		   tms_info->tg_tunnel_type, tms_info->tg_domain,
		   tms_info->tg_server_loc);
	    printf("  passwd=\"%.16s\"\n", tms_info->tg_passwd);
#endif
	    break;

	  case ARS_TMS_HW:
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_hw_type = tval;
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_hw_addr_len = tval;
#ifdef DEBUG_TMS
	    printf("racp_parse_auth_reply(): hw_type=%02x, hw_addr_len=%d\n",
		   tms_info->tg_hw_type, tms_info->tg_hw_addr_len);
#endif
	    length = TMS_HWADDR_LEN;
	    if ((data = asn_parse_string(data, &datalength, &type,
					 tms_info->tg_hw_addr, &length))
		== NULL)
		return(NULL);
#ifdef DEBUG_TMS
	    {
	    register i;
	    printf("  hw_addr=0x");
	    for (i = 0; i < tms_info->tg_hw_addr_len; i++)
		printf("%02x", tms_info->tg_hw_addr[i]);
	    printf("\n");
	    }
#endif
	    break;

	case ARS_TMS_AUTH:
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_auth_proto = tval;
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_pauth_addr, intsize))
		== NULL)
		return(NULL);
	    tms_info->tg_pauth_addr.s_addr =
	      htonl(tms_info->tg_pauth_addr.s_addr);
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_sauth_addr, intsize))
		== NULL)
		return(NULL);
	    tms_info->tg_sauth_addr.s_addr =
	      htonl(tms_info->tg_sauth_addr.s_addr);
#ifdef DEBUG_TMS
	    printf("racp_parse_auth_reply(): auth: proto=%d, paddr=%a, saddr=%a\n",
		    tms_info->tg_auth_proto, tms_info->tg_pauth_addr.s_addr,
		    tms_info->tg_sauth_addr.s_addr);
#endif
	    break;

	case ARS_TMS_ACCT:
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_acct_proto = tval;
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_pacct_addr, intsize))
		== NULL)
		return(NULL);
	    tms_info->tg_pacct_addr.s_addr =
	      htonl(tms_info->tg_pacct_addr.s_addr);
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_sacct_addr, intsize))
		== NULL)
		return(NULL);
	    tms_info->tg_sacct_addr.s_addr =
	      htonl(tms_info->tg_sacct_addr.s_addr);
#ifdef DEBUG_TMS
       printf("racp_parse_auth_reply(): acct: proto=%d, paddr=%a, saddr=%a\n",
	       tms_info->tg_acct_proto, tms_info->tg_pacct_addr.s_addr,
	       tms_info->tg_sacct_addr.s_addr);
#endif
	    break;

	case ARS_TMS_ADDR:
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_addr_proto = tval;
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_paddr_addr, intsize))
		== NULL)
		return(NULL);
	    tms_info->tg_paddr_addr.s_addr =
	      htonl(tms_info->tg_paddr_addr.s_addr);
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_saddr_addr, intsize))
		== NULL)
		return(NULL);
	    tms_info->tg_saddr_addr.s_addr =
	      htonl(tms_info->tg_saddr_addr.s_addr);
#ifdef DEBUG_TMS
       printf("racp_parse_auth_reply(): addr: proto=%d, paddr=%a, saddr=%a\n",
	       tms_info->tg_addr_proto, tms_info->tg_paddr_addr.s_addr,
	       tms_info->tg_saddr_addr.s_addr);
#endif
	    break;

	case ARS_TMS_TAUTH:
	    if ((data = asn_parse_int(data, &datalength, &type,
				      &tms_info->tg_spi, intsize)) == NULL)
		return(NULL);
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_ta_type = tval;
	    if ((data = asn_parse_int(data, &datalength, &type, &tval,
				      intsize)) == NULL)
		return(NULL);
	    tms_info->tg_ta_mode = tval;
#ifdef DEBUG_TMS
	  printf("racp_parse_auth_reply(): spi=%ld, ta_type=%d, ta_mode=%d\n",
		 tms_info->tg_spi, tms_info->tg_ta_type, tms_info->tg_ta_mode);
#endif
	    length = TMS_KEY_LEN;
	    if ((data = asn_parse_string(data, &datalength, &type,
					 tms_info->tg_ta_key, &length))
		== NULL)
		return(NULL);
#ifdef DEBUG_TMS
	    {
	    register i;
	    printf("  ta_key=0x");
	    for (i = 0; i < TMS_KEY_LEN; i++)
		printf("%02x", tms_info->tg_ta_key[i]);
	    printf("\n");
	    }
#endif
	    break;
#endif /*NUDAS*/

          default:
#ifdef DEBUG
	    printf("racp_parse_auth_reply(): unknown command %u\n", command);
#endif
            data += length;
            datalength -= length;
            break;
        }
    }

    return(data);
}
#endif /*ANNEX*/


#ifndef ANNEX
/*****************************************************************************
 *
 * NAME: racp_parse_tms_req()
 *
 * DESCRIPTION: Parses the TMS-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *pdu	- INPUT pointer to pdu to parse
 * int pdulen	- INPUT size of pdu
 * UINT32 *rasid - OUTPUT pointer to RAS IP address
 * tms_db_key *key - OUTPUT pointer to database key
 *
 * RETURN VALUE: next free space after PDU
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
u_char *racp_parse_tms_req(pdu, pdulen, rasid, key)
u_char *pdu;
int *pdulen;
UINT32 *rasid;
tms_db_key *key;
{
    u_char type;
    u_char *data = (u_char*)pdu;
    int length;
    ACP_USTRING username;
    char *user, *domain;

#ifdef DEBUG_TMS
    printf("racp_asn1.c: entering racp_parse_tms_req()\n");
    if (TMS_DOMAIN_LEN != 48)
	printf("CONSISTANCY WARNING: TMS_DOMAIN_LEN != 48 - check printf()\n");
    if (TMS_DNIS_LEN != 20)
	printf("CONSISTANCY WARNING: TMS_DNIS_LEN != 20 - check printf()\n");
#endif

    if ((data = asn_parse_int(data, pdulen, &type, rasid,
                              sizeof(*rasid))) == NULL)
	return(NULL);
#ifdef DEBUG_TMS
    printf("racp_parse_tms_req(): rasid = %08x\n", *rasid);
#endif

    bzero((char *)key, sizeof(*key));
    bzero(username, sizeof(username));

    length = ACP_MAXUSTRING;
    if ((data = asn_parse_string(data, pdulen, &type, username,
				 &length)) == NULL)
	return(NULL);
#ifdef DEBUG_TMS
    printf("racp_parse_tms_req(): user = %.48s\n", username);
#endif
    if (parse_domain(username, &user, &domain) != ESUCCESS)
    {
        return(NULL);
    }
    bcopy(domain, key->key_domain, strlen(domain));

    length = TMS_DNIS_LEN;
    if ((data = asn_parse_string(data, pdulen, &type, key->key_dnis,
				 &length)) == NULL)
	return(NULL);
#ifdef DEBUG_TMS
    printf("racp_parse_tms_req(): dnis = %.20s\n", key->key_dnis);
#endif

    return(data);
}
#endif /*!ANNEX*/


/*****************************************************************************
 *
 * NAME: racp_parse_exec_req()
 *
 * DESCRIPTION: Parses the execution-request RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int datalength -  INPUT valid size of data
 * any of the following can be NULL
 * int *servfrom - OUTPUT service user is coming from
 * int *servreq - OUTPUT service being requested
 * ERQ_PROFILE *opt_info - Pointer to structure of optional information
 *
 * RETURN VALUE: next free space after PDU
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
u_char *racp_parse_exec_req(data, datalength, servfrom, servreq, opt_info)
u_char *data;
int *datalength, *servfrom, *servreq;
ERQ_PROFILE *opt_info;
{
    u_char type =0;
    u_char command;
    u_char *temp;
    long length;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if ((data = asn_parse_int(data, datalength, &type, servfrom, intsize))
        == NULL)
        return(NULL);

    if ((data = asn_parse_int(data, datalength, &type, servreq, intsize))
        == NULL)
        return(NULL);

    if (*datalength > 2) {
        length = *datalength;
        if ((temp = asn_parse_header(data, &length, &type)) == NULL)
            return(NULL);
        *datalength -= (int)(temp - data);
        data = temp;
        if (type != (ASN_SET | ASN_CONSTRUCTOR))
            return(NULL);
    }

    while(data != NULL && *datalength > 2) {
        length = *datalength;
        if ((temp = asn_parse_header(data, &length, &command)) == NULL)
            return(NULL);
        *datalength -= (int)(temp - data);
        data = temp;

        switch (command) {
          case ERQ_USERNAME:
	    if (length >= sizeof(ACP_USTRING))
	      return NULL;
            if ((data = asn_parse_string(data, datalength, &type, opt_info->username,
                                         &length))
                == NULL)
                return(NULL);
            if (opt_info->username)
                opt_info->username[length] = '\0';
            break;
                        
          case ERQ_PHONE:
	    if (length >= sizeof(ACP_STRING))
	      return NULL;
            if ((data = asn_parse_string(data, datalength, &type, opt_info->phone,
                                         &length)) == NULL)
                return(NULL);
            if (opt_info->phone)
                opt_info->phone[length] = '\0';
            break;

          case ERQ_ACCESS:
	    if (length >= sizeof(ACP_STRING))
	      return NULL;
            if ((data = asn_parse_string(data, datalength, &type, opt_info->access,
                                         &length))
                == NULL)
                return(NULL);
            if (opt_info->access)
                opt_info->access[length] = '\0';
            break;
                        
          case ERQ_TEXT:
	    if (length >= sizeof(ACP_USTRING))
	      return NULL;
            if ((data = asn_parse_string(data, datalength, &type, opt_info->text,
                                         &length)) == NULL)
                return(NULL);
            if (opt_info->text)
                opt_info->text[length] = '\0';
            break;
                        
          case  ERQ_PORTMASK:
	    if (length > LEN_PORT_MASK*2)
	      return NULL;
            if ((data = asn_parse_string(data, datalength, &type, opt_info->portmask,
                                         &length))
                == NULL)
                return(NULL);
            break;

          case ERQ_FLAGS:
            if ((data = asn_parse_int(data, datalength, &type, opt_info->flags,
                                      intsize))
                == NULL)
                return(NULL);
            break;
                        
          case ERQ_TIMEOUT:
            if ((data = asn_parse_int(data, datalength, &type, opt_info->timeout,
                                      intsize)) == NULL)
                return(NULL);
            break;

          case ERQ_ECHO:
            if ((data = asn_parse_boolean(data, datalength, &type, opt_info->echo,
                                          intsize)) == NULL) {
                return(NULL);
            }
            break;

          case ERQ_DESTADDR:
            if (opt_info->destaddr) {
                if ((data = parse_net_addr(data, datalength, opt_info->destaddr))
                    == NULL)
                    return(NULL);
            }
            else {
                data += length;
                *datalength -= length;
            }
            break;

          case ERQ_CODE:
            if ((data = asn_parse_int(data, datalength, &type, 
                opt_info->code, intsize))
                == NULL)
                return(NULL);
            break;
           
          case  ERQ_JOB:
	    if (length >= sizeof(ACP_STRING))
	      return NULL;
            if ((data = asn_parse_string(data, datalength, &type, opt_info->job,
                                         &length))
                == NULL)
                return(NULL);
            break;

          case ERQ_PORT:
            if (opt_info->port_from) {
                if ((data = parse_port(data, datalength, opt_info->port_from)) == NULL)
                    return(NULL);
            }
            else {
                data += length;
                *datalength -= length;
            }
	    break;

          default:
            data += length;
            datalength -= length;
            break;
        }
    }

    return(data);
}


/*****************************************************************************
 *
 * NAME: racp_build_exec_reply()
 *
 * DESCRIPTION: Builds the execution-reply RACP ASN.1 PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to build PDU in
 * int *datalength -  INPUT poionter to valid size of data
 * u_long version - INPUT racp version
 * long grant - INPUT status of execution request grant
 * any of the following can be NULL, in which case segment not included
 * SECPORT *port - INPUT port request will be executed on
 * char *text - INPUT text answer (i.e. user entered text at prompt)
 * int *codep - OUTPUT code
 *
 * RETURN VALUE: next free space after PDU
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
u_char *racp_build_exec_reply(data, datalength, version, grant, port, flags,
                              text, codep)
u_char *data;
int *datalength;
u_long version;
long grant;
SECPORT *port;
long *flags;
char *text;
int *codep;
{
    u_char             *packet;
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);

    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
    u_char *execreplyhead, *execreplybody;
    u_char *savepduhead;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    packet = data;
    /*building ASN1 objects for port, direction and n
      etnum variables.*/
  
    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0)) == NULL)
        return(NULL);

    savepduhead = data;
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
                              intsize)) == NULL)
        return(NULL);

    execreplyhead = data;
    if ((data = asn_build_header(data, datalength, RACP_EXEC_REPLY, 0))
        == NULL)
        return(NULL);
    execreplybody = data;
    
    data = asn_build_int(data, datalength, ASN_INTEGER, &grant,
			 intsize);

    if (port != ((void *)NULL) || flags != ((void *)NULL) ||
        text != ((void *)NULL) || codep != NULL)    {
        begin_header1 = data;
        if ((data = asn_build_header(data, datalength,
                                     (ASN_SET | ASN_CONSTRUCTOR), 0)) == NULL)
            return(NULL);
        end_header1 = data;
    }
    if (text != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ERP_TEXT, 0)) == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_string(data, datalength, ASN_VIS_STR, text,
                                     strlen(text))) == NULL)
            return(NULL);
        data = fix_length(begin_header2, data, end_header2, ERP_TEXT,
                          datalength);
    }
    if (port != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ERP_PORT, 0)) == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = build_port(data, datalength, port)) == NULL)
            return(NULL);
        data = fix_length(begin_header2, data, end_header2, ERP_PORT,
                          datalength);
    }
    if (flags != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ERP_FLAGS, 0)) == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER, flags,
                                  intsize)) == NULL)
            return(NULL);
        data = fix_length(begin_header2, data, end_header2, ERP_FLAGS,
                          datalength);
    }
    if (codep != ((void *)NULL)) {
        begin_header2 = data;
        if ((data = asn_build_header(data, datalength, ERP_CODE, 0)) == NULL)
            return(NULL);
        end_header2 = data;
        if ((data = asn_build_int(data, datalength, ASN_INTEGER, codep,
                                  intsize)) == NULL)
            return(NULL);
        data = fix_length(begin_header2, data, end_header2, ERP_CODE,
                          datalength);
    }
    if (begin_header1)
        if ((data = fix_length(begin_header1, data, end_header1,
                               (ASN_CONSTRUCTOR | ASN_SET), datalength))
            == NULL)
            return(NULL);

    if ((data = fix_length(execreplyhead, data, execreplybody, RACP_EXEC_REPLY,
                      datalength)) == NULL)
        return(NULL);
    
    return(fix_length(packet, data, savepduhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
    
}


/*****************************************************************************
 *
 * NAME: racp_build_exec_req()
 *
 * DESCRIPTION: Builds an RACP execution-request PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to build PDU in
 * int *datalength -  INPUT poionter to valid size of data
 * u_long version - INPUT racp version
 * int service_from - INPUT service user is on
 * int service_req - INPUT execution service request
 * ERQ_PROFILE opt_info - INPUT pointer to structure of optional information
 *
 * RETURN VALUE: pointer to next free space after PDU
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

/* for now, execution request can only get response */
u_char *racp_build_exec_req(data, datalength, version, service_from,
                            service_req, opt_info )
u_char *data;
int *datalength;
u_long version;
int service_from, service_req;
ERQ_PROFILE *opt_info;
{
    u_char *start = data;
    u_char *savepduhead, *execreqhead, *execreqbody;
    u_char             *begin_header1 = ((void *)NULL);
    u_char             *begin_header2 = ((void *)NULL);

    u_char             *end_header1 = ((void *)NULL);
    u_char             *end_header2 = ((void *)NULL);
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0))
        == NULL) 
        return(NULL);
    savepduhead = data;

    /*building ASN1 packets for version */
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
                              intsize)) == NULL) 
        return(NULL);
    
    execreqhead = data;
    if ((data = asn_build_header(data, datalength, RACP_EXEC_REQ, 0)) == NULL)
        return(NULL);

    execreqbody = data; /*saving pointer to fix the length fields, later*/

    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_from,
                              intsize)) == NULL) 
        return(NULL);
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &service_req,
                              intsize)) == NULL) 
        return(NULL);

    if (opt_info != ((void *)NULL)) {
	begin_header1 = data;
        if ((data = asn_build_header(data, datalength, (ASN_CONSTRUCTOR | ASN_SET),
				     0)) == NULL) 
            return(NULL);

        end_header1 = data;

        if (opt_info->username != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_USERNAME, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->username,
                                         strlen(opt_info->username))) == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_USERNAME,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->phone != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_PHONE, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->phone,
                                         strlen(opt_info->phone))) == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_PHONE,
                                       datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->access != ((void *)NULL)) {
            begin_header2 = data;

            if ((data = asn_build_header(data, datalength, ERQ_ACCESS, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->access,
                                         strlen(opt_info->access))) == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_ACCESS,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->text != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_TEXT, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->text,
                                         strlen(opt_info->text))) == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_TEXT,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->job != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_JOB, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_VIS_STR, opt_info->job,
                                         strlen(opt_info->job))) == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_JOB,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->portmask != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_PORTMASK, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_string(data, datalength, ASN_OCTET_STR,
                                         opt_info->portmask, LEN_PORT_MASK)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_PORTMASK,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->flags != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_FLAGS, 0)) == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER, opt_info->flags,
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_FLAGS,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->timeout != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_TIMEOUT,0)) == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER, opt_info->timeout,
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_TIMEOUT,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->echo != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_ECHO, 0)) == NULL) 
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_boolean(data, datalength, ASN_BOOLEAN, opt_info->echo))
                == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_ECHO,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->destaddr != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_DESTADDR, 0)) == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_net_addr(data, datalength, opt_info->destaddr)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_DESTADDR,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->code != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_CODE, 0)) == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = asn_build_int(data, datalength, ASN_INTEGER, opt_info->code,
                                      intsize)) == NULL)
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_CODE,
                                   datalength)) == NULL) 
                return(NULL);
        }

        if (opt_info->port_from != ((void *)NULL)) {
            begin_header2 = data;
            if ((data = asn_build_header(data, datalength, ERQ_PORT, 0)) == NULL)
                return(NULL);
            end_header2 = data;
            if ((data = build_port(data, datalength, opt_info->port_from)) == NULL) 
                return(NULL);
            if ((data = fix_length(begin_header2, data, end_header2, ERQ_PORT,
                                   datalength)) == NULL) 
                return(NULL);
        }
    }

    if (begin_header1)
        if ((data = fix_length(begin_header1, data, end_header1,
                               (ASN_CONSTRUCTOR | ASN_SET), datalength)) == NULL)
            return(NULL);

    if ((data = fix_length(execreqhead, data, execreqbody, RACP_EXEC_REQ,
                           datalength)) == NULL) 
        return(NULL);
    if ((data = fix_length(start, data, savepduhead,
                           (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength)) == NULL)
        return(NULL);

    return(data);
}


/*****************************************************************************
 *
 * NAME: racp_parse_exec_reply()
 *
 * DESCRIPTION: Parses an RACP execution-reply PDU
 *
 * ARGUMENTS:
 * u_char *data - INPUT pointer to buffer to parse
 * int *datalength -  INPUT pointer to valid size of data
 * int *grant - OUTPUT status of authorization grant
 * any of the following can be NULL, in which case the relevant data is not
 * returned
 * SECPORT *portp - OUTPUT port execution will be performed on
 * int *flagsp - OUTPUT flag of execution options performed
 * char *text - OUTPUT text returned
 * int *codep - OUTPUT code
 *
 * RETURN VALUE: pointer to next free space after PDU
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

u_char *racp_parse_exec_reply(data, datalength, grantp, portp, flagsp, text,
                              codep)
u_char *data;
int *datalength, *grantp;
SECPORT *portp;
int *flagsp;
char *text;
int *codep;
{
    u_char command;
    int length;
    u_char type;
    u_char *temp;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    if (data == NULL || datalength == NULL || grantp == NULL)
        return(NULL);

    if ((data = asn_parse_int(data, datalength, &type, grantp, intsize))
        == NULL) {
        return(NULL);
    }

    if (*datalength >= 2) {
        length = *datalength;
        if ((temp = asn_parse_header(data, &length, &type)) == NULL)
            return(NULL);
        *datalength -= (int)(temp - data);
        data = temp;
        if (type != (ASN_SET | ASN_CONSTRUCTOR))
            return(NULL);
    }

    while(data != NULL && *datalength > 2) {
        length = *datalength;
            if ((temp = asn_parse_header(data, &length, &command)) 
            == NULL)
            return(NULL);
        *datalength -= (int)(temp - data);
        data = temp;
    
        switch (command) {
          case ERP_TEXT:
            length = ACP_MAXUSTRING;
            data = asn_parse_string(data, datalength, &type, text,
                                    &length);
            if (text != NULL)
                text[length] = 0;
            break;
          case ERP_PORT:
            if (portp)
                data = parse_port(data, datalength, portp);
            else {
                data += length;
                *datalength -= length;
            }
            break;
          case ERP_FLAGS:
            data = asn_parse_int(data, datalength, &type, flagsp, intsize);
            break;
          case ERP_CODE:
            data = asn_parse_int(data, datalength, &type, codep, intsize);
            break;
       
          default:
            data += length;
            *datalength -= length;
            break;
        }
    }

    return(data);
}

/*****************************************************************************
 *
 * NAME: racp_parse_ack()
 *
 * DESCRIPTION: Parses an audit-log-verification RACP PDU
 *
 * ARGUMENTS:
 * char *pdu - PDU ACK from remote ERPCD
 * int pdulen; - length of this PDU
 *
 * RETURN VALUE: the highest numbered log message written to remote ERPCD log
 *               or 0 if error
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: all messages on ACK queue are in order
 *
 */

char *racp_parse_ack(pdu, pdulen, ack)
char *pdu;
int pdulen;
UINT32 *ack;
{
    u_char type;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    *ack = 0;
    if ((pdu = (char*)asn_parse_header(pdu, &pdulen, &type)) == NULL)
        return(NULL);
    if (type != RACP_AUDIT_VER)
        return(NULL); /* discard */
    if ((pdu = (char*)asn_parse_int(pdu, &pdulen, &type, ack, intsize))
        == NULL)
        return(NULL);
    else
        return(pdu);
}


/*****************************************************************************
 *
 * NAME: racp_build_ack()
 *
 * DESCRIPTION: Builds an audit-log-verification RACP PDU
 *
 * ARGUMENTS:
 * char *data - INPUT buffer to build in
 * int *datalength - INPUT/OUTPUT number of valid bytes remaining
 * u_long version - INPUT racp version
 * u_long sequence - INPUT log sequence id
 *
 * RETURN VALUE: the next free space after PDU
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: all messages on ACK queue are in order
 *
 */

u_char *racp_build_ack(data, datalength, version, sequence)
u_char *data;
int *datalength;
u_long version;
u_long sequence;
{
    u_char *beginhead, *endhead;
    u_char *auditverhead, *auditverbody;
#if defined(ALPHA)
    int intsize = sizeof(int);
#else
    int intsize = sizeof(long);
#endif

    beginhead = data;
    data[0] = 0;
    if ((data = asn_build_header(data, datalength,
                                 (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0))
        == NULL)
        return(NULL);

    endhead = data;
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER, &version,
                              intsize)) == NULL)
        return(NULL);

    auditverhead = data;
    if ((data = asn_build_header(data, datalength, RACP_AUDIT_VER, 0))
        == NULL)
        return(NULL);
    auditverbody = data;
    
    if ((data = asn_build_int(data, datalength, ASN_INTEGER,
                              &sequence, intsize)) == NULL)
        return(NULL);

    if ((data = fix_length(auditverhead, data, auditverbody, RACP_AUDIT_VER,
                           datalength)) == NULL)
        return(NULL);

    return(fix_length(beginhead, data, endhead,
                      (ASN_SEQUENCE | ASN_CONSTRUCTOR), datalength));
}    
