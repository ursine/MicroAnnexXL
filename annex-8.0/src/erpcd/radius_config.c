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
 *
 *    Read in the erpcd.conf file and convert to radius server structs.
 *
 * Original Author: Murtaza Chiba    Created on: 3/29/96
 *
 *****************************************************************************
 */

/*
 *    Include Files
 */
#include "../inc/config.h"

#ifdef _WIN32
#include "../inc/rom/syslog.h"
#include "../inc/port/port.h"
#include "radius.h"
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <syslog.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "../inc/erpc/erpc.h"
#include "../inc/erpc/nerpcd.h"
#include "acp_policy.h"
#include "acp_regime.h"
#include "environment.h"

/*
 *    Global Defines
 */
#define MAX_BACKUP 1
#define BUFSIZE (1024)
#define MAXARGS             16
#define MAX_RADIUS_KEYWORDS 5
#define MAX_BACKUP_KEYWORDS 2
#define UNSUCCESSFUL 0
#define RADIUS_DEFAULT_TIMEOUT	4
#define RADIUS_DEFAULT_RETRIES	10


#ifdef _WIN32
#define SVR_NOT_FOUND	-1
#endif

/*
 *    Global Data Declarations
 */

#ifdef _WIN32
StructRadiusOption *RadiusOpt;	/* Handles logging options for Radius */
int radius_server_count;	/* number of servers read from registry */
#endif

/*
 *    Forward Routine Declarations
 */
#ifdef _WIN32

int syslog( int pri, const char *format, ...);
int find_server_in_array(char *hostname);
int radius_default_routine(char *buf, Radius_server *default_servers);
int extract_secret_data(char *string_p, Radius_serverinfo *server_info);
int extract_timeout_data(char *string_p, Radius_serverinfo *server_info);
int extract_retries_data(char *string_p, Radius_serverinfo *server_info);
int extract_backup_data(char *string_p, Radius_serverinfo *server_info);
int asciihex_to_char(char *buf, char *shared_secret);
void asciihex_to_hex(char *buf, int length);
int test_for_hex(char *buf, int length);
void set_both_addresses(char *hostname);
int get_inet(char *string, u_long *addr);
int nt_radius_default_routine(void);
UINT32 inet_address(char Host_string[]);

extern	void display_mem _((char *buf, int len));	 /* radius_parser.c */

#else  /* ndef _WIN32 */

int extract_auth_address();
int extract_acct_address();
int extract_host_data();
int extract_secret_data();
int extract_timeout_data();
int extract_retries_data();
int extract_backup_data();
void asciihex_to_hex();
void set_both_addresses();
UINT32 inet_address();

#endif/* _WIN32 */

/*
 *    Global Data Declarations
 */
#ifndef _WIN32
struct keywords_func radius_config_keywords[MAX_RADIUS_KEYWORDS] = {
  { "host=", extract_host_data, 5},
  { "secret=", extract_secret_data, 7},
  { "timeout=", extract_timeout_data, 8},
  { "retries=", extract_retries_data, 8},
  { "backup=", extract_backup_data, 7}
};

struct keywords_func radius_default_keywords[MAX_BACKUP_KEYWORDS] = {
  { "radius=", extract_auth_address, 7},
  { "accounting=", extract_acct_address, 11}
};
#endif /* _WIN32 */
/*
 *    External Data Declarations
 */
extern int debug;
extern char ebuff[];

extern Radius_server *default_servers;

#ifdef _WIN32
/* ----------------------------------------------
	This variable must only be changed under
	control of UseCriticalSection()
 */
extern CRITICAL_SECTION	GlobalCriticalSection;
/* ---------------------------------------------- */
#endif /* _WIN32 */
extern Radius_serverinfo *radius_head;

/*****************************************************************************
 *
 * NAME: create_radius_configs()
 *
 * DESCRIPTION: Opens the erpcd.conf file and then creates a linked list of
 *              structs in the memory each containing configuration info 
 *              for the radius servers
 *
 * ARGUMENTS:   None
 *
 * RETURN VALUE: a pointer to the head of the linked list of type 
 *               Radius_serverinfo *
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

Radius_serverinfo *
create_radius_configs()
{
  char hostname[MAXHOSTNAMELEN];
  Radius_serverinfo *server_info = NULL,
	       	    *prev = NULL,
		    *to_be_freed = NULL,
		    *check = NULL;

#ifndef _WIN32
  FILE *cnfg;
  char buf[BUFSIZ], *buf_p;
  int buf_length;
  u_char foradd[4];
  
  bzero(hostname, MAXHOSTNAMELEN);
  if (debug)
    printf("Reading %s\n", config_file);
  
  cnfg = fopen(config_file,"r");
  if (cnfg == NULL) {
    if (debug)
      printf("error opening %s = %d\n", config_file,errno);
    if (errno == ENOENT)
      syslog(LOG_NOTICE,"erpcd: No such file - %s\n", config_file);
    else
      syslog(LOG_ERR,"erpcd: Error opening %s = %d\n",config_file,errno);
    return NULL;
  }
  
  while (fgets(buf,BUFSIZ,cnfg) != NULL) {
    buf_length = strlen(buf);
    if ((buf_length == 0) ||
	((buf_length == 1) && (buf[0] = '\n')) ||
	(buf[0]=='#'))
      continue;
    
    buf_p = buf;
    if (buf[buf_length-1] == '\n') buf[buf_length - 1] = '\0';
    if (!strncasecmp(buf_p, "radius", 6)) {

      buf_p += 6;   /*skip over the radius keyword*/

      while(!isalpha(*buf_p)) /*skip over any white space*/
         ++buf_p;
	
      if (!strncasecmp(buf_p,"default", 7)){
	buf_p += 7;
	if(!default_servers){
	  default_servers = (Radius_server *)malloc(sizeof(Radius_server));
	  if(default_servers == NULL){
	    syslog(LOG_CRIT, "erpcd: unable to allocate memory");
	    return NULL;
	  }
	  switch(radius_default_routine(buf_p, default_servers)){
	  case -1:syslog(LOG_ERR, "erpcd: invalid server/s specified in entry \
               							= %s", buf);
	          free(default_servers);
	          default_servers = NULL;
	          continue;

	    /*This case is when only radius default is present in the file*/
	  case 0:set_both_addresses(hostname);
	         continue;

	    /*This is when only the authorization server is specified */
	  case 1:  default_servers->acct_server.s_addr = 
	                                  default_servers->auth_server.s_addr;
	           break;

	    /*This is when only the accounting server is specified */
	  case 2:  if(gethostname(hostname, MAXHOSTNAMELEN) !=0 ){
	              syslog(LOG_ERR, "erpcd: could not set radius default \
                                                 servers, sethostname failed");
	           free(default_servers);
	           default_servers = NULL;
	           }
	           else if((default_servers->auth_server.s_addr =
		                              inet_address(hostname)) == 0 ){
	                   syslog(LOG_ERR,"erpcd:could not set radius default \
                                                                servers");
	           free(default_servers);
	           default_servers = NULL;
	           }
	           continue;

	  default: break;
	    
	  }
	}
      }
      
      else if(!strncasecmp(buf_p,"server", 6)){
	buf_p += 6;    /*skip over the server keyword*/

	prev = server_info;
	server_info = (Radius_serverinfo *)malloc(sizeof(Radius_serverinfo));
	if(server_info == NULL){
	   syslog(LOG_CRIT, "erpcd: unable to allocate memory");    
	   to_be_freed = radius_head;
	   while(to_be_freed){
	     radius_head = radius_head->next;
	     free(to_be_freed);
	     to_be_freed = radius_head;
	   }
	   return radius_head;
	}
  	bzero((char *)server_info, sizeof(Radius_serverinfo));
	
	/*set defaults*/
	server_info->retries = RADIUS_DEFAULT_RETRIES;
	server_info->resp_timeout = RADIUS_DEFAULT_TIMEOUT;

	if(radius_head == NULL)
	   radius_head = server_info; 
	else 
	   prev->next = server_info;

	if((radius_config_routine(buf_p, server_info) & 3) != 3  ){
	   syslog(LOG_ERR, "erpcd: invalid entry in erpcd.config = %s\n",
                 buf);
           if(!prev)
              radius_head = NULL;
           else
	      prev->next = NULL;
	   free(server_info);
	   server_info = prev;
	   continue;
	}
	check = radius_head;
	while(check && (check != server_info)){
	   if(memcmp(&check->host_address, &server_info->host_address,
		     sizeof(struct in_addr)) == 0 ){
	      bcopy(&server_info->host_address, foradd, sizeof(foradd));
	      if(debug)
		fprintf(stderr, "Discarding additional entry found for server %u.%u.%u.%u\n", foradd[0], foradd[1], foradd[2], foradd[3]);
	      syslog(LOG_DEBUG, "Discarding additional entry found for server %u.%u.%u.%u", foradd[0], foradd[1], foradd[2], foradd[3]);
	      prev->next = NULL;
	      free(server_info);
	      server_info = prev;
	      continue;
           }
	   else
	      check = check->next;		
	}
      }
    } /* end if radius */
  } /* end while */

/*The following is when there is no default mentioned in the file*/
  if(default_servers == NULL){
    default_servers = (Radius_server *)malloc(sizeof(Radius_server));
    if(default_servers == NULL){
      syslog(LOG_CRIT, "erpcd: unable to allocate memory");
      return NULL;
    }
    set_both_addresses(hostname);
  }
  
  fclose(cnfg);
  
  if(debug)
    printf("%s read\n",config_file);
  
  return radius_head;

#else /* _WIN32  WIN32  WIN32  WIN32  WIN32  WIN32  WIN32  WIN32  WIN32  WIN32  */

	int ret_val;
	int i;
	char log_str[256];
	Radius_serverinfo *tmp_radius_head = NULL;

	bzero(hostname, MAXHOSTNAMELEN);
	if (debug)
		printf("Reading default radius servers from registry\n");

	if(!default_servers)
	{
		default_servers = (Radius_server *)malloc(sizeof(Radius_server));
		if(default_servers == NULL){
			sprintf(log_str, "erpcd: unable to allocate memory");
			if ( debug )
			{
				printf(log_str);
			}
			syslog(LOG_CRIT, log_str);
			return NULL;
		}
	}

	ret_val = nt_radius_default_routine();
	if (debug)
		printf("nt_radius_default_routine found %d servers.\n", ret_val );
	switch(ret_val)
	{
		/*This case is when no radius default servers are present in the registry*/
	case 0:
#ifdef USE_SYSLOG
		syslog(LOG_ERR, "erpcd: no default radius servers specified, using local host");
#endif
		set_both_addresses(hostname);
   		break;

        /* This is when only the authentication server is specified
         *  Use the local host for accounting (differs from Unix implementation
         *  In ntsupport.c, ReadRegistryParam() we parse the accounting server
         *  string to find out if it is <local> or <same as authentication>.
         *  If it is local, we set the RadiusOpt->RadiusAccountingServer to ""
         *  If it is same as authen., we copy the authen string into it.
         */
	case 1:
		if(gethostname(hostname, MAXHOSTNAMELEN) !=0 )
		{
			syslog(LOG_ERR, "erpcd: case_2: could not set radius default servers, gethostname failed");
			free(default_servers);
			default_servers = NULL;
		}
		else if ( get_inet(hostname,
                    &default_servers->acct_server.s_addr) != ESUCCESS )
		{

			syslog(LOG_ERR, "erpcd: case_2: could not set radius default servers, getinet failed.");
			free(default_servers);
			default_servers = NULL;
		}
		break;

		/* This is when only the accounting server is specified.
		   Attempt to identify the local host and use it as the
           authentication server
		 */
	  case 2:
		if(gethostname(hostname, MAXHOSTNAMELEN) !=0 )
		{
			syslog(LOG_ERR, "erpcd: case_2: could not set radius default servers, gethostname failed");
			free(default_servers);
			default_servers = NULL;
		}
		else if ( get_inet(hostname,
					&default_servers->auth_server.s_addr) != ESUCCESS )
		{

			syslog(LOG_ERR, "erpcd: case_2: could not set radius default servers, getinet failed.");
			free(default_servers);
			default_servers = NULL;
		}
		break;

		/*  Both servers are specified, attempt to get addresses for them */
	  case 3:
		break;

		/* Impossible value returned, terminate execution */
	  default:
    		syslog(LOG_EMERG, "erpcd: invalid value returned from radius_default_routine(): %d\n",
			 ret_val);
		free(default_servers);
		default_servers = NULL;
		ErpcdExit(1);	/* stop running, fatal error encountered */
	  	break;
	  }

	/* We now have the default info, get the server info for every
	   server in the server array.
	  */
	if (debug)
		printf("Radius server count = %d\n", radius_server_count);

	for ( i=0; i<radius_server_count; i++)
	{
		if (debug)
			fprintf(stderr,"extract_server_data %d, hostname '%s', ip '%s'\n",
				i, RadiusOpt->aServer[i].szHostName, RadiusOpt->aServer[i].szIPAddress);
		prev = server_info;
		server_info = (Radius_serverinfo *)calloc(1, sizeof(Radius_serverinfo));
		if(server_info == NULL)
		{
			syslog(LOG_CRIT, "erpcd: unable to allocate memory");
			to_be_freed = tmp_radius_head;
			while(to_be_freed)
			{
				tmp_radius_head = tmp_radius_head->next;
				free(to_be_freed);
				to_be_freed = tmp_radius_head;
			}
			return tmp_radius_head;
		}

		/* get the ip address of server from list.
		   If the ip address is missing, look up the host name and
		   resolve the ip address from that.  If it fails, discard
		   this entry
		 */

		if ( strlen(RadiusOpt->aServer[i].szIPAddress) == 0 )
		{
			/* IP address missing, try to get by name */
			if ( get_inet(RadiusOpt->aServer[i].szHostName,
					&server_info->host_address.s_addr) != ESUCCESS )
			{
				/* hostname won't resolve, report error, continue with next */
				syslog(LOG_ERR, "erpcd: unable to resolve hostname for server %d,'%s'",
						i, RadiusOpt->aServer[i].szHostName);
				free(server_info);	/* release the current block */
				continue;
			}
		}
		else
		{
			/* IP is here, try to convert to inet */
    			if ((server_info->host_address.s_addr =
                                inet_address(RadiusOpt->aServer[i].szIPAddress))
					== INADDR_NONE )
			{
				/* the IP address is bad, report error, continue with next */
				syslog(LOG_ERR, "erpcd: unable to resolve IP addr for server %d",
						i);
				free(server_info);	/* release the current block */
				continue;
			}
		}

		/* get shared secret from list */
		if ( extract_secret_data(RadiusOpt->aServer[i].szSecret, server_info) == UNSUCCESSFUL )
		{
			syslog(LOG_ERR, "erpcd: unable to extract secret for server %s",
					RadiusOpt->aServer[i].szHostName);
		}

		/* get retries from list */
		if ( extract_retries_data(RadiusOpt->aServer[i].szRetries, server_info) == UNSUCCESSFUL )
		{
		/*	syslog(LOG_ERR, "erpcd: unable to extract retries for server %s",
					RadiusOpt->aServer[i].szHostName);*/
		}

		/* get timeout value from list */
		if ( extract_timeout_data(RadiusOpt->aServer[i].szTimeout, server_info) == UNSUCCESSFUL )
		{
		/*	syslog(LOG_ERR, "erpcd: unable to extract timeout for server %s",
					RadiusOpt->aServer[i].szHostName);*/
		}

		/* get backup host name data from list and resolve the ip address */
		if ( extract_backup_data(RadiusOpt->aServer[i].szBackup, server_info) == UNSUCCESSFUL )
		{
			syslog(LOG_ERR, "erpcd: unable to extract backup for server %s",
					RadiusOpt->aServer[i].szHostName);
		}


		if(tmp_radius_head == NULL)
			tmp_radius_head = server_info;
		else
			prev->next = server_info;

	}
	if ( debug )
	{
		// Short term debugging only, can be removed at check-in
		Radius_serverinfo *test;
        test = get_serverinfo(default_servers->auth_server);
		//
        printf("Finished reading radius data from registry.\n");
	}

  return tmp_radius_head;
#endif /* _WIN32 */
}


#ifndef _WIN32
/*****************************************************************************
 *
 * NAME: radius_default_routine(buf, default_servers)
 *
 * DESCRIPTION: This routine uses the line read in to tokenize into keywords
 *              and then take the appropriate action based on a match.
 *              Note the action is described in the second field of the
 *              struct radius_default_keywords as declared in the Global
 *              Data Declarations field above.
 *            
 * ARGUMENTS:  buf - which is the line read in from the file erpcd.conf
 *             default_servers - the current dynamically allocated struct 
 *                               pointer of type Radius_server.
 *
 * RETURN VALUE: 0 if there was an error encountered, or, good_options
 *               which is the bit or of all successfully extracted data.
 *              
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: server_info refers to valid data space
 *
 */
int 
radius_default_routine(buf, default_servers)
     char *buf;
     Radius_server *default_servers;
{

  int keyword_index = -1, num_of_keywords;
  int good_options = FALSE, option_return = 0;

  num_of_keywords=sizeof(radius_default_keywords)/sizeof(struct keywords_func);
  
  while(*buf != '\0'){
    keyword_index = get_keyword_index(&buf, radius_default_keywords, num_of_keywords);
    if(keyword_index != -1){
      option_return = (*(radius_default_keywords[keyword_index].action))(&buf, default_servers);
      if (option_return > 0 )
	good_options |= option_return;
      else if(option_return < 0 ){
	if(debug)
	   fprintf(stderr,"Keywords are only allowed once in an environment\n");
	return -1;
      }
    }
    else{
      syslog(LOG_ERR, "Invalid keyword found: %s", buf);
      return -1;  /* bad keyword */
    }
  }
  return(good_options);
}

/*****************************************************************************
 *
 * NAME: radius_config_routine(buf, server_info)
 *
 * DESCRIPTION: This routine uses the line read in to tokenize into keywords
 *              and then take the appropriate action based on a match.
 *              Note the action is described in the second field of the
 *              struct radius_config_keywords as declared in the Global
 *              Data Declarations field above.
 *            
 * ARGUMENTS:  buf - which is the line read in from the file erpcd.conf
 *             server_info - the current dynamically allocated struct pointer
 *                           of type Radius_serverinfo.
 *
 * RETURN VALUE: 0 if there was an error encountered, or, good_options
 *               which is the bit or of all successfully extracted data.
 *              
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: server_info refers to valid data space
 *
 */
int 
radius_config_routine(buf, server_info)
     char *buf;
     Radius_serverinfo *server_info;
{

  int keyword_index = -1, num_of_keywords;
  int good_options = FALSE, option_return = 0;

  num_of_keywords =sizeof(radius_config_keywords)/sizeof(struct keywords_func);

  while(*buf != '\0'){
    keyword_index = get_keyword_index(&buf, radius_config_keywords, num_of_keywords);
    if(keyword_index != -1){
      option_return = (*(radius_config_keywords[keyword_index].action))(&buf, server_info);
      if (option_return)
	good_options |= option_return;
      else{
	if(debug)
	   fprintf(stderr,"Keywords are only allowed once in an environment\n");
	return(FALSE);
      }
    }
    else{
      syslog(LOG_ERR, "Invalid keyword found: %s", buf);
      return FALSE;  /* bad keyword */
    }
  }
  return(good_options);
}

/*****************************************************************************
 *
 * NAME: extract_auth_address(string_p, default_servers)
 *
 * DESCRIPTION: This function extracts the data into temp space and then 
 *              call on the function inet_address to resolve the IP addres
 *              if the string is not in IP address format.
 *            
 * ARGUMENTS:  string_p - pointer to the current line read in from erpcd.conf
 *             default_servers - Radius_server *
 *
 * RETURN VALUE: O on failure and GOT_AUTH on success
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
extract_auth_address(string_p, default_servers)
     char **string_p;
     Radius_server *default_servers;
{
  if (debug)
    fprintf(stderr,"extract_auth_address %s\n",*string_p);

  if (fill_field(string_p, ebuff, MAX_OPTION)){
    if((default_servers->auth_server.s_addr = inet_address(ebuff)) != 0 )
      return GOT_AUTH; 
  }
    return -1;
}

/*****************************************************************************
 *
 * NAME: extract_acct_address(string_p, default_servers)
 *
 * DESCRIPTION: This function extracts the data into temp space and then 
 *              call on the function inet_address to resolve the IP addres
 *              if the string is not in IP address format.
 *            
 * ARGUMENTS:  string_p - pointer to the current line read in from erpcd.conf
 *             default_servers - Radius_server *
 *
 * RETURN VALUE: O on failure and GOT_ACCT on success
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
extract_acct_address(string_p, default_servers)
     char **string_p;
     Radius_server *default_servers;
{
  if (debug)
    fprintf(stderr,"extract_acct_address %s\n",*string_p);

  if (fill_field(string_p, ebuff, MAX_OPTION)){
    if((default_servers->acct_server.s_addr = inet_address(ebuff)) != 0 )
      return GOT_ACCT; 
  }
    return -1;
}

/*****************************************************************************
 *
 * NAME: extract_host_data (string_p, server_info)
 *
 * DESCRIPTION: This function extracts the data into temp space and then 
 *              call on the function inet_address to resolve the IP addres
 *              if the string is not in IP address format.
 *            
 * ARGUMENTS:  string_p - pointer to the current line read in from erpcd.conf
 *             server_info - Radius_serverinfo *
 *
 * RETURN VALUE: O on failure and GOT_HOST on success
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
extract_host_data(string_p, server_info)
     char **string_p;
     Radius_serverinfo *server_info;
{
  if (debug)
    fprintf(stderr,"extract_host_data %s\n",*string_p);

  if (fill_field(string_p, ebuff, MAX_OPTION)){
    if((server_info->host_address.s_addr = inet_address(ebuff)) != 0 )
      return GOT_HOST; 
  }
    return UNSUCCESSFUL;
}
#endif/* ndef _WIN32 */

/*****************************************************************************
 *
 * NAME: extract_secret_data(string_p, server_info)
 *
 * DESCRIPTION: This function extracts the data into temp space and then
 *              if the string is in hex specification(i.e. has 0x at the 
 *              beggining) it calls on the asciihex_to_hex routine.  Else,
 *              it copies the string into shared_secret.
 *            
 * ARGUMENTS:  same as above
 *
 * RETURN VALUE: 0 on failure and GOT_SECRET on success
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
#ifdef _WIN32
int extract_secret_data(char *string_p, Radius_serverinfo *server_info)
{
	char **pString_p;
  	char *hexstart;

	if (debug)
		fprintf(stderr,"extract_shared_secret_data %s\n",string_p);

	pString_p = &string_p;
	if (fill_field(pString_p, ebuff, MAX_OPTION))
	{
		if(hexstart = strstr(ebuff, "0x"))
		{
			if(asciihex_to_char(hexstart, server_info->shared_secret))
			{
				return GOT_SECRET;
			}
		}
		else
		{
			strncpy(server_info->shared_secret, ebuff, 16);
			return GOT_SECRET;

		}
	}
	return UNSUCCESSFUL;
}
#else
int
extract_secret_data(string_p, server_info)
     char **string_p;
     Radius_serverinfo *server_info;
{
  char *hexstart=NULL;

  if (debug)
    fprintf(stderr,"extract_shared_data %s\n",*string_p);

  if (fill_field(string_p, ebuff, MAX_OPTION)){
    if(((hexstart = strstr(ebuff, "0x")) || (hexstart = strstr(ebuff, "0X"))) && (strlen(hexstart)==strlen(ebuff)) ){
      if(asciihex_to_char(hexstart, server_info->shared_secret)) {
	return GOT_SECRET;
      }
    }
    else{
        if(!hexstart){
           strncpy(server_info->shared_secret, ebuff, 16);	
           return GOT_SECRET;
        }
    }
  }
  return UNSUCCESSFUL;
}
#endif/* _WIN32 */

/*****************************************************************************
 *
 * NAME: extract_timeout_data (string_p, server_info)
 *
 * DESCRIPTION: extracts the data into temp space and then converts it to
 *              integer.
 *            
 * ARGUMENTS:  
 *
 * RETURN VALUE: 0 on failure and GOT_TIMEOUT on success
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
#ifdef _WIN32
int extract_timeout_data(char *string_p, Radius_serverinfo *server_info)
{
	char **pString_p;

	if (debug)
		fprintf(stderr,"extract_timeout_data %s\n",string_p);

	pString_p = &string_p;
	if (fill_field(pString_p, ebuff, MAX_OPTION))
	{
		server_info->resp_timeout = atoi(ebuff);
		return GOT_TIMEOUT;
	}
	return UNSUCCESSFUL;
}
#else
int
extract_timeout_data(string_p, server_info)
     char **string_p;
     Radius_serverinfo *server_info;
{
   
  if (debug)
    fprintf(stderr,"extract_timeout_data %s\n",*string_p);

  if (fill_field(string_p, ebuff, MAX_OPTION)){
    server_info->resp_timeout = atoi(ebuff);
    return GOT_TIMEOUT;
  }
  return UNSUCCESSFUL;
}
#endif /* _WIN32 */

/*****************************************************************************
 *
 * NAME: extract_retries_data (string_p, server_info)
 *
 * DESCRIPTION: extracts the data into temp space and then converts it to
 *              integer.
 *            
 * ARGUMENTS:  
 *
 * RETURN VALUE: 0 on failure and GOT_RETRIES on success
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
#ifdef _WIN32
int extract_retries_data(char *string_p, Radius_serverinfo *server_info)
{
	char **pString_p;
	if (debug)
    		fprintf(stderr,"extract_retries_data %s\n",string_p);

	pString_p = &string_p;
	if (fill_field(pString_p, ebuff, MAX_OPTION))
	{
		server_info->retries = atoi(ebuff);
     		return GOT_RETRIES;
   	}
   	return UNSUCCESSFUL;
}

#else

int
extract_retries_data(string_p, server_info)
     char **string_p;
     Radius_serverinfo *server_info;
{
   if (debug)
    fprintf(stderr,"extract_retries_data %s\n",*string_p);

   if (fill_field(string_p, ebuff, MAX_OPTION)){
     server_info->retries = atoi(ebuff);
     return GOT_RETRIES;
   }

   return UNSUCCESSFUL;
}
#endif /* _WIN32 */

/*****************************************************************************
 *
 * NAME: extract_backup_data (string_p, server_info)
 *
 * DESCRIPTION: This function extracts the data into temp space and then 
 *              call on the function inet_address to resolve the IP addres
 *              if the string is not in IP address format.
 *            
 * ARGUMENTS:  string_p - pointer to the current line read in from erpcd.conf
 *             server_info - Radius_serverinfo *
 *
 * RETURN VALUE: O on failure and GOT_BACKUP on success
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
#ifdef _WIN32
int extract_backup_data(char *string_p, Radius_serverinfo *server_info )
{
  	if (debug)
    		fprintf(stderr,"extract_backup_data %s\n",string_p);

    if ( (strcmp(string_p, "<none>") == 0) || (strlen(string_p) == 0) )
    {
        server_info->backup_address.s_addr = (unsigned long)-1;
    }
    else if ( get_inet(string_p, &server_info->backup_address.s_addr) != ESUCCESS )
	{
		/* backup name won't resolve, report error, continue with next */
		syslog(LOG_ERR, "erpcd: unable to resolve backup server name for server %s",
				string_p);
		return UNSUCCESSFUL;
	}
 	return GOT_BACKUP;
}
#else
int
extract_backup_data(string_p, server_info)
     char **string_p;
     Radius_serverinfo *server_info;
{
  if (debug)
    fprintf(stderr,"extract_host_data %s\n",*string_p);

  if (fill_field(string_p, ebuff, MAX_OPTION)){
    if((server_info->backup_address.s_addr = inet_address(ebuff)) != 0 )
      return GOT_BACKUP;
  }
    return UNSUCCESSFUL;
}
#endif/* _WIN32 */

/*****************************************************************************
 *
 * NAME: asciihex_to_char(buf, shared_secret)
 *
 * DESCRIPTION:This function converts the hex string representing the shared
 *             secret into 16 bytes of char. This function assumes that there  
 *             are a maximum of 32  bytes present.
 *            
 * ARGUMENTS:  
 *
 * RETURN VALUE: 0 on failure and 1 on success
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS: This function assumes that there are a maximum of 32  bytes
 *              present.
 */
int 
asciihex_to_char(buf, shared_secret)
    char *buf, *shared_secret;
{

   int length = 0, i;
   u_char lsn, msn, secret_index = 15, result;

   if (debug)
       fprintf(stderr, "asciihex_to_char %s\n", buf);
   length = strlen(buf);
   bzero(shared_secret, 16);
   if(!test_for_hex(buf, length)) {
      return UNSUCCESSFUL;    
   }

   asciihex_to_hex(buf, length);

   if(!length || length < 2 || length > 34) 
      return UNSUCCESSFUL;
 
   for(i=length; i-4 >= 0; i -= 2){    
      lsn = buf[i-1];
      msn = buf[i-2];
      result = (msn << 4) | lsn;
      shared_secret[secret_index--]= result;
   }

   if((length % 2) == 1){
      lsn = buf[i-1];
      msn = 0;
      result = msn | lsn;
      shared_secret[secret_index--]= result;
   } 
   return GOT_SECRET;
}   




/*****************************************************************************
 *
 * NAME: test_for_hex(buf, length)
 *
 * DESCRIPTION: The function makes sure that all characters in the string are
 *              hexadecimal.
 *            
 * ARGUMENTS:  buf - string 
 *             length - length of string
 *
 * RETURN VALUE: 0 on failure and 1 on success
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
test_for_hex(buf, length)
   char *buf;
   int length;
{


   int i;  

   for(i = length - 1; i >= 2; i--)
	if (!isxdigit(buf[i]))	
	   return FALSE;

   return TRUE;

}

/*****************************************************************************
 *
 * NAME:asciihex_to_hex(buf, length) 
 *
 * DESCRIPTION: This function converts the ascii character to its corresponding
 *              hex value.
 *            
 * ARGUMENTS:  
 *
 * RETURN VALUE: None
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
void
asciihex_to_hex(buf, length)
   char *buf;
   int length;
{
  int i ;

  for(i = length - 1; i >= 2; i-- ) {
     if(buf[i] >= '0' && buf[i] <= '9')
	buf[i] -=  '0';
     else{
         buf[i]=buf[i] & (~0x20);
         buf[i]=buf[i]-'A' + 10;
     }
  }
}

void dump_serverinfo(sinfo)
Radius_serverinfo *sinfo;
{
    u_char addr[4];

    fprintf(stderr, "Server info:\n");
    bcopy((char*)&sinfo->host_address, (char*)addr, 4);
    fprintf(stderr, "Internet Address %u.%u.%u.%u\n", addr[0], addr[1],
            addr[2], addr[3]);
    bcopy((char*)&sinfo->backup_address, (char*)addr, 4);
    fprintf(stderr, "Backup Address %u.%u.%u.%u\n", addr[0], addr[1],
            addr[2], addr[3]);
    fprintf(stderr, "Shared Secret\n");
    display_mem(sinfo->shared_secret, KEYSZ);
    fprintf(stderr, "Response Timeout %d seconds\n",
            sinfo->resp_timeout);
    fprintf(stderr, "Retries %d\n", sinfo->retries);
}

/*****************************************************************************
 *
 * NAME: get_serverinfo(ipaddress)
 *
 * DESCRIPTION: This function matches the ipaddress with the one stored in the
 *              linked list and returns  a pointer to the corresponding struct.
 *            
 * ARGUMENTS:  ipaddress -  a string.
 *
 * RETURN VALUE: Radius_serverinfo *
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

Radius_serverinfo *get_serverinfo(ipaddress)
	struct in_addr ipaddress;
{
   Radius_serverinfo *finder;

#ifdef _WIN32
	/* Request ownership of the critical section. */
	__try {
    	EnterCriticalSection(&GlobalCriticalSection);
#endif /* _WIN32 */

   		for(finder = radius_head; finder; finder = finder->next)
		{
     		if (memcmp(&ipaddress, &finder->host_address, sizeof(struct in_addr)) == 0)
           		break;
   		}

#ifdef _WIN32
	}
	__finally {
    	/* Release ownership of the critical section. */
    	LeaveCriticalSection(&GlobalCriticalSection);
	}
#endif /* _WIN32 */

   return(finder);

}

/*****************************************************************************
 *
 * NAME: set_both_addresses
 *
 * DESCRIPTION: This function sets the two default addresses 
 *
 *
 *            
 * ARGUMENTS:  hostname which is a char *
 *
 * RETURN VALUE: 
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
void 
set_both_addresses(hostname)
     char *hostname;
{
#ifdef _WIN32

  if(gethostname(hostname, MAXHOSTNAMELEN) !=0 )
  {
    	syslog(LOG_ERR, "erpcd: could not set radius default servers, sethostname failed");
    	free(default_servers);
    	default_servers = NULL;
  }
  else if ( get_inet(hostname,
			&default_servers->auth_server.s_addr) == ESUCCESS )
  {

	  default_servers->acct_server.s_addr =	default_servers->auth_server.s_addr;
  }
  else
  {
		syslog(LOG_ERR, "erpcd: could not set radius default servers");
    	free(default_servers);
    	default_servers = NULL;
  }
#else /* !def _WIN32 */

  if(gethostname(hostname, MAXHOSTNAMELEN) !=0 ){
    syslog(LOG_ERR, "erpcd: could not set radius default \
                                               servers, sethostname failed");
    free(default_servers);
    default_servers = NULL;
  }
  else if((default_servers->auth_server.s_addr = 
	   default_servers->acct_server.s_addr =
	   inet_address(hostname)) == 0 ){
    syslog(LOG_ERR, "erpcd: could not set radius default \
						       servers"); 
    free(default_servers);
    default_servers = NULL;
  }
#endif

}

#ifdef _WIN32
/*****************************************************************************
 *
 *	All remaining functions are for WIN32 only!
 */

/*****************************************************************************
 *
 * NAME: find_server_in_array
 *
 * DESCRIPTION: This function attempts to locate a server hostname in
 *		array of servers
 *
 *
 * ARGUMENTS:  hostname which is a char *
 *
 * RETURN VALUE:	array index or -1
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
int find_server_in_array(char *hostname)
{
	int i;
	int hostname_len;

	hostname_len = strlen(hostname);

	for ( i=0; i<MAX_RADIUS_SERVERS; i++)
	{
		if ( strncasecmp(hostname, RadiusOpt->aServer[i].szHostName, hostname_len) == 0 )
		{
			return(i);
		}
	}
	return -1;
}

/*****************************************************************************
 *
 * NAME: get_inet()
 *
 * DESCRIPTION: Convert a name or dotted ip address to a network address
 *
 * ARGUMENTS:
 *
 * RETURN VALUE: ESUCCESS if conversion works, SVR_NOT_FOUND if failure
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

int get_inet(char *string, u_long *addr)
{
    struct hostent *host;

/*
 * If the string begins with a digit, assume a "dot notation" inet
 * address; otherwise, assume a /etc/hosts name.
 */
    	if (isdigit(string[0]))
    	{
		*addr = inet_addr(string);
		if (*addr == (u_long)(-1))
		{
	    		if (strcmp(string,/*NOSTR*/"255.255.255.255")==0)
				return ESUCCESS;
	    		/* Otherwise, fall through and try gethostbyname */
	    	}
		else
	    		return ESUCCESS;
	}
    	if ((host = gethostbyname(string)) == NULL)
	    	return SVR_NOT_FOUND;

	bcopy(host->h_addr_list[0],(char *)addr,host->h_length);
    	return ESUCCESS;
}

/*****************************************************************************
 *
 * NAME: nt_radius_default_routine
 *
 * DESCRIPTION: Verify the existence of the default authorization and accouting
 *		servers
 *
 * ARGUMENTS:
 *
 * RETURN VALUE: 0 if no default servers, GOT_AUTH | GOT_ACCT if servers present
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

int nt_radius_default_routine(void)
{
	int i;
	int option_return = 0;

	if ( strlen(RadiusOpt->RadiusAuthenticationServer) != 0 )
	{
		if ( (i = find_server_in_array(RadiusOpt->RadiusAuthenticationServer)) != SVR_NOT_FOUND )
		{
			/* The auth server is in the list, try to get its IP address */
			if ( strlen(RadiusOpt->aServer[i].szIPAddress) == 0 )
			{
				 /* IP address missing, try to get by name */
				if ( get_inet(RadiusOpt->aServer[i].szHostName,
						&default_servers->auth_server.s_addr) == ESUCCESS )
					option_return = GOT_AUTH;
			}
			else
			{
				 /* IP is here, try to convert to inet */
    				if ((default_servers->auth_server.s_addr =
                                        inet_address(RadiusOpt->aServer[i].szIPAddress))
						!= INADDR_NONE )
				{
					/* the IP address was good */
					option_return = GOT_AUTH;
				}
			}
		}
	}
	if ( strlen(RadiusOpt->RadiusAccountingServer) != 0 )
	{
		if ( (i = find_server_in_array(RadiusOpt->RadiusAccountingServer)) != SVR_NOT_FOUND )
		{
			if ( strlen(RadiusOpt->aServer[i].szIPAddress) == 0 )
			{
				if ( get_inet(RadiusOpt->aServer[i].szHostName,
						&default_servers->acct_server.s_addr) == ESUCCESS )
					option_return |= GOT_ACCT;
			}
			else
			{
				 /* IP is here, try to convert to inet */
    				if ((default_servers->acct_server.s_addr =
                                        inet_address(RadiusOpt->aServer[i].szIPAddress))
						!= INADDR_NONE )
				{
					/* the IP address was good */
					option_return |= GOT_ACCT;
				}
			}
		}
	}
	return(option_return);
}

#endif /* defined(_WIN32) && defined(RADIUS) */
