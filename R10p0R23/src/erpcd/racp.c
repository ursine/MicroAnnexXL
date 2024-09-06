/*****************************************************************************
 *
 *        Copyright 1995, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use. 
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 * Detailed Design Specification:
 *
 *	DESIGN DETAILS
 *   This contains RACP utility functions that are opsys-specific
 *
 *	MODULE INITIALIZATION -
 *   
 *	PERFORMANCE CRITICAL FACTORS - 
 *      	Describe any special performance criteria pertaining to 
 *              this module.
 *
 *      RESOURCE USAGE -
 *
 *	SIGNAL USAGE -
 *
 *      SPECIAL EXECUTION FLOW - 
 *
 * 	SPECIAL ALGORITHMS - 
 *
 * Original Author: dfox	Created on: 09/26/95
 *
 *****************************************************************************
 */

/*
 *	Include Files
 */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/time.h>
#else
#include <process.h>
#define EINVAL   WSAEINVAL
#define ENOTCONN WSAENOTCONN
#define EACCES   WSAEACCES
#include "../ntsrc/acplog/acplogmsg.h"
#endif  /* _WIN32 */

#include <signal.h>

#include "../libannex/api_if.h"
#include "../inc/erpc/netadmp.h"

#include "../inc/port/install_dir.h"
#include "../inc/erpc/nerpcd.h"
#include "acp.h"
#include "acp_policy.h"
#include "../libannex/asn1.h"
#include "getacpuser.h"

#ifdef USE_SYSLOG
#ifdef _WIN32
#include "../inc/rom/syslog.h"
#else
#include <syslog.h>
#endif /* _WIN32 */
#endif /* USE_SYSLOG */

extern int alarm_flag;
extern int debug;
extern StructErpcdOption *ErpcdOpt;

/* External Routine Declarations */
#define DEF_LINGER_TIME 120

void inet_number();
void set_long();
void erpc_reject();
int dialout_srpc_open();
int srpc_return();
int srpc_callresp();
int api_open();
int api_bind();
int api_connect();
int api_recv();
int api_recvmsg();
int api_sendmsg ();
int api_send();
int api_rcvud();
int api_sndud();
int api_release();
int api_close();
int api_opt();

KEYDATA *make_table();
void generate_table();
int cipher();
void racp_timer();
void display();
void get_host_name();

#ifdef _WIN32
int syslog( int pri, const char *format, ...);
#endif

#ifdef FASTRETRY
#define TURNAROUND(t)	INPUT_POLL_TIMEOUT
#else
#define TURNAROUND(t)	t
#endif

extern ACP *globalacp;

void racp_close(acp)
ACP *acp;
{
  char *app_nam = "racp_close";

  api_release(acp->s, 2, app_nam);
  api_close(acp->s);
  acp->s = -1;
  SETCLOSED(acp->state);
}

errno_t racp_shutdown(acp)
ACP *acp;
{
	char *app_nam = "racp_shutdown";

   int socket = acp->s;

	api_release(socket, 2, app_nam);
	api_close(socket);
	acp->s = -1;
	return(ESUCCESS);
}

errno_t racp_connect(acp, hostaddr)
ACP *acp;
struct in_addr hostaddr;
{
	char *app_nam = "racp_connect";
	struct sockaddr_in sin;
	struct servent *sp;
	int rv;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = 0;

	if ((acp->s = api_open(IPPROTO_TCP, &sin, app_nam, TRUE)) < 0)
		return(DIAL_SOCK);
	
	api_opt(acp->s, API_TO_REUSE, TRUE, app_nam);
	api_opt(acp->s, API_TO_OOB, TRUE, app_nam);
	api_opt(acp->s, API_TO_LINGER, TRUE, app_nam);
	
	switch (api_bind(acp->s, NULL, &sin, app_nam, TRUE)) {
	  case 1:
	  case 2:
		racp_close(acp);
		return(DIAL_SOCK);
	  case 0:
	  default:
		break;
	}
	
    sin.sin_addr = hostaddr;
    sin.sin_family = AF_INET;
    sp = getservbyname("erpc", "tcp");
	sin.sin_port = (sp==0) ? htons((u_short)121) : sp->s_port;

	SETOPEN(acp->state);
	
	switch(api_connect(acp->s, &sin, IPPROTO_TCP, app_nam, TRUE)) {
	  case 1:
	  case 2:
		racp_close(acp);
		return(DIAL_REJ);
	  case 0:
	  default:
		break;
	}
		
	rv = racp_init_conn(acp);
	if (rv < 0) {
		racp_close(acp);
		return(DIAL_REJ);
	}

	return(rv);
}


/*****************************************************************************
 *
 * NAME: racp_recv_pdu
 *
 * DESCRIPTION:
 *  This is the high-level routine that reads and decrypts a RACP PDU.
 *  It will block until the entire PDU arrives.
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  buf - buffer to read data into, must be pre-allocated.
 *  bufsize - the size of the buf buffer
 *  *pdulen_p - returned length of the PDU
 *  **pdu - address of pointer to body of PDU
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

errno_t racp_recv_pdu(acp, buf, bufsize, pdulen_p, pdu)
ACP *acp;
char *buf;
int bufsize;
int *pdulen_p;
u_char **pdu;
{
	int totlen, nr, rcode;
	u_char *bp = (u_char*)buf;
	u_char nbr, asn_type;
	UINT32 version;

	/* sanity checks */
	if (acp == NULL || buf == NULL || bufsize < MAXPDUHEAD || !pdulen_p) {
		return(EINVAL);
	}
	if (acp->s < 0 || !ISCONN(acp->state)) {
		return(EINVAL);
	}

	bzero(buf, MAXPDUHEAD);

	errno = ESUCCESS;
	/* now sniff the header/length of the length */
	if ((rcode = api_recv(acp->s, bp, 2, TRUE, 0, TRUE, "erpcd")) <= 0) {
		if (errno == ESUCCESS)
			errno = ENOTCONN;
		return(errno);
	}
	if (debug > 2) {
	    printf("racp_recv_pdu: received %d octets\n", rcode);
	    if (debug > 3)
		display(bp, rcode);
	}
	
	/* now read any extra length bytes */
	bp++;
	if (*bp & ASN_LONG_LEN) {
	    nr = nbr = ((*bp & ((~ASN_LONG_LEN) & 0xff)) & 0xff);
	    for (bp++; nr > 0; nr -= rcode, bp += rcode) {
		if ((rcode = api_recv(acp->s, bp, nr, TRUE, 0, TRUE, "erpcd"))
		    <= 0) {
		    if (errno == ESUCCESS)
			errno = ENOTCONN;
		    return(errno);
		}
		if (debug > 2) {
		    printf("racp_recv_pdu: received %d octets\n", rcode);
		    if (debug > 3)
			display(bp, rcode);
		}
	    }
	}

	*pdulen_p = bufsize;
	/* now retrieve the length */
	bp = asn_parse_header((u_char*)buf, pdulen_p, &asn_type);
	if (bp == NULL) {
		return(EINVAL);
	}
	totlen = *pdulen_p + (int)(bp - (u_char*)buf);
	if (asn_type != (ASN_SEQUENCE | ASN_CONSTRUCTOR) || bufsize < totlen) {
		char hostname[32];
		
		get_host_name(hostname, acp->inet);
#ifdef USE_SYSLOG
		if (ErpcdOpt->UseSyslog)
		{
			syslog(LOG_ERR, "RACP: received bad header %x %x %x %x from %s",
			   (u_char)buf[0], (u_char)buf[1], (u_char)buf[2], (u_char)buf[3],
			   hostname);
		}
#endif
		return(EACCES);
	}

	/* mark where encryption begins */
	*pdu = (u_char*)bp;
	
	/* Now read the PDU */
	for (nr = *pdulen_p; nr > 0; nr -= rcode, bp += rcode) {
		if ((rcode = api_recv(acp->s, bp, nr, TRUE, 0, TRUE, "erpcd")) <= 0) {
			if (errno == ESUCCESS)
				errno = ENOTCONN;
			return(errno);
		}

	}

	/* decrypt the PDU */
	if (acp->key) {
		if (debug > 1) {
			printf("racp_recv_pdu: Received encrypted PDU:\n");
			display(buf, totlen);
		}
		cipher(*pdu, *pdu, *pdulen_p, acp->racp->rcv_key);
	}

	if (debug > 1) {
		printf("racp_recv_pdu: Received PDU:\n");
		display(buf, totlen);
	}

	/* sanity check on version number */
	/* we negotiated it, but if it is not what we negotiated, reject */
	*pdu = asn_parse_int(*pdu, pdulen_p, &asn_type, &version,
#if defined(ALPHA)
			     sizeof(int));
#else
			     sizeof(long));
#endif
	if (version != acp->racp->version) {
		*pdu = NULL;
		*pdulen_p = 0;
		return(EACCES);
	}
	
	return(ESUCCESS);
}


/*****************************************************************************
 *
 * NAME: racp_recv_raw
 *
 * DESCRIPTION:
 *  This is the high-level routine that reads raw RACP data.
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  buf - buffer to read data into, must be pre-allocated.
 *  datalength - the length of the data unit you wish to read
 *
 * RETURN VALUE:
 *  <0 error, 0 success
 *
 * RESOURCE HANDLING:
 *
 * SIDE EFFECTS:
 *
 * EXCEPTIONS:
 *
 * ASSUMPTIONS:
 *  Assumes buf is large enough to fit datalen bytes
 */

errno_t racp_recv_raw(socket, buf, datalen)
int socket;
char *buf;
int datalen;
{
  char *app_nam = "racp_recv_raw";
  int nr, rcode;
  char *bp = buf;

  /* sanity checks */
  if (socket < 0 || buf == NULL || datalen <= 0) {
	  return(EINVAL);
  }

  errno = ESUCCESS;
  for (nr = datalen; nr > 0; nr -= rcode, bp += rcode) {
	  if ((rcode = api_recv(socket, bp, nr, FALSE, 0, TRUE, app_nam)) <= 0) {
		  if (errno == ESUCCESS)
			  errno = ENOTCONN;
		  return(errno);
	  }
  }

  if (debug > 1) {
	  printf("racp_recv_raw: Received data:\n");
	  display(buf, datalen);
  }

  return(ACPU_ESUCCESS);
}


/*****************************************************************************
 *
 * NAME: racp_send_pdu
 *
 * DESCRIPTION:
 *  This is the high-level routine that encrypts and sends a RACP PDU.
 *
 * ARGUMENTS:
 *  acp - pointer to ACP structure for this connection
 *  buf - buffer of data to write
 *  datalen - the length of data to write
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

errno_t racp_send_pdu(acp, buf, datalen)
ACP *acp;
char *buf;
int datalen;
{
  int pdulen = datalen;
  u_char asn_type = 0;
  int nw, rcode;
  char *bp;
  
  /* sanity checks */
  if (acp == NULL || buf == NULL || pdulen <= 0) {
	  return(EINVAL);
  }
  if (acp->s < 0 || !ISCONN(acp->state)) {
	  return(EINVAL);
  }

  /* encrypt the PDU */
  bp = (char *)asn_parse_header((u_char *)buf, &pdulen, &asn_type);
  if (asn_type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
	  return(EINVAL);
  }

  /* encryption */
  if (acp->key) {
	  if (debug > 1) {
		  printf("racp_send_pdu: Sending PDU:\n");
		  display(buf, datalen);
	  }
	  cipher(bp, bp, pdulen, acp->racp->send_key);
  }

  errno = ESUCCESS;
  for (nw = datalen, bp = buf; nw > 0; nw -= rcode, bp += rcode) {
	  if ((rcode = api_send(acp->s, bp, nw, 0, "erpcd", TRUE)) <= 0) {
		  if (errno == ESUCCESS)
			  errno = ENOTCONN;
		  return(errno);
	  }
  }


  if (debug > 1) {
      if (acp->key) {
          printf("racp_send_pdu: Sent encrypted PDU:\n");
          display(buf, datalen);
      }
      else {
          printf("racp_send_pdu: Sent PDU:\n");
          display(buf, datalen);
      }
  }


  return(ESUCCESS);
}


/*****************************************************************************
 *
 * NAME: racp_send_raw
 *
 * DESCRIPTION:
 *  This is the high-level routine that reads raw RACP data.
 *
 * ARGUMENTS:
 *  socket - socket for this connection
 *  buf - buffer to read data from
 *  datalen - the length of the data being sent
 *
 * RETURN VALUE:
 *  <0 error, 0 success
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

errno_t racp_send_raw(socket, buf, datalen)
int socket;
char *buf;
int datalen;
{
  int ns, rcode;
  char *bp = buf;

  /* sanity checks */
  if (socket < 0 || buf == NULL || datalen <= 0) {
	  return(EINVAL);
  }

  errno = ESUCCESS;
  for (ns = datalen; ns > 0; ns -= rcode, bp += rcode) {
	  if ((rcode = api_send(socket, bp, ns, 0, "erpcd", TRUE)) <= 0) {
		  if (errno == ESUCCESS)
			  errno = ENOTCONN;
		  return(errno);
	  }
  }

  if (debug > 1) {
	printf("racp_send_raw: Sent data:\n");
	display(buf, datalen);
  }

  return(ESUCCESS);
}
