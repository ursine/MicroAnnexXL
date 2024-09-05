/*
 *        Copyright 1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.  Unauthorized
 * duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	This file contains the source code for the TMS facility in
 *	ERPCD.  The Design Specification, in Frame, for this code is in
 *	specifications/udas/tunnel-mgr_ds/spec.book
 *
 * Original Author: Gary Malkin
 * Created on: July 18, 1996
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../inc/vers.h"
#include "../inc/config.h"
#include "../inc/port/port.h"

#include <ctype.h>
#include <string.h>
#include <errno.h>

#include <syslog.h>

#include "../inc/erpc/acp_tms.h"
#include "tms.h"
#include "acp.h"
#include "acp_policy.h"

#include "../inc/courier/courier.h"
#include "../inc/erpc/erpc.h"
#include "../inc/erpc/nerpcd.h"

/*
 * externs
 */
extern int debug;		/* debugging switch set by erpcd -D */
#if !defined(FREEBSD) && !defined(BSDI)
extern char *sys_errlist[];	/* errno strings */
#endif

/*
 * forwards
 */
int tms_request();
#define REQUEST_INIT 1
#define REQUEST_TERM 2


/************************************************************
 *
 * Name:
 *	tms_req_init
 *
 * Description:
 *	This function is called by acp_auth_req() when the
 *	user is TMS rather than ACP.
 *
 * Inputs:
 *	rasid	- address of RAS to which user is connected
 *	domain	- domain name entered by user
 *	dnis	- called number
 *
 * Outputs:
 *	0	- success
 *	ACP_ERROR - failure; sets errno as follows:
 *		EINVAL	- racp_parse_tms_req() failed
 *		ENOENT	- user not in TMS database
 *		EIO	- error reading database
 *		EUSERS	- user denied; too many users
 *
 * Notes:
 *	none
 *
 ************************************************************/
int
tms_req_init(acp, rasid, domain, dnis, username)
  caddr_t acp;
  struct in_addr rasid;
  char *domain;
  char *dnis;
  char *username;
{
  tms_db_key key, *keyp = &key;

  bzero((char *)keyp, sizeof(key));
  bcopy(domain, key.key_domain, strlen(domain));
  bcopy(dnis, key.key_dnis, strlen(dnis));

  return(tms_request(acp, REQUEST_INIT, rasid, &key, username));
}


/************************************************************
 *
 * Name:
 *	tms_req_term
 *
 * Description:
 *	This function handles RACP_TMS_REQ packets from the Annex.
 *	It cleans up after a user disconnects (or is disconnected).
 *
 * Inputs:
 *	acp	- pointer to ACP structure (unexamined; merely passed)
 *	pdu	- pointer to received PDU (ASN.1 packet)
 *	pdulen	- length of PDU
 *
 * Outputs:
 *	0	- success
 *	ACP_ERROR - failure; sets errno as follows:
 *		EINVAL	- racp_parse_tms_req() failed
 *		ENOENT	- user not in TMS database
 *		EIO	- error reading database
 *		EUSERS	- user denied; too many users
 *
 * Notes:
 *	This is called from acp_tcp() in acp.c.  The return code is
 *	not checked.
 *
 ************************************************************/
int
tms_req_term(acp, pdu, pdulen)
  caddr_t acp;
  char *pdu;
  int pdulen;
{
  tms_db_key key;
  struct in_addr rasid;

  if (debug)
    printf("tms.c: entering tms_req_term()\n");

  /*
   * parse the request packet
   */
  if (racp_parse_tms_req(pdu, &pdulen, &rasid, &key) == NULL) {
    if (debug)
      printf("tms_req_term(): racp_parse_tms_req() returned NULL\n");
    syslog(LOG_WARNING,
	   "tms: could not honor or parse tms terminate request from %s",
	   inet_ntoa(rasid));
    errno = EINVAL;
    return(ACP_ERROR);
  }
  if (debug)
    printf("tms_req_term(): terminate request for \"%.64s/%.20s\" from %s\n",
	   key.key_domain, key.key_dnis, inet_ntoa(rasid));
  return(tms_request(acp, REQUEST_TERM, rasid, &key, NULL));
}


/************************************************************
 *
 * Name:
 *	tms_request
 *
 * Description:
 *	This function is the common code for tms_req_init()
 *	and tms_req_term()
 *
 * Inputs:
 *	acp	- pointer to ACP structure (unexamined; merely passed)
 *	pdu	- pointer to received PDU (ASN.1 packet)
 *	pdulen	- length of PDU
 *
 * Outputs:
 *	0	- success
 *	ACP_ERROR - failure; sets errno as follows:
 *		EINVAL	- racp_parse_tms_req() failed
 *		ENOENT	- user not in TMS database
 *		EIO	- error reading database
 *		EUSERS	- user denied; too many users
 *
 * Notes:
 *	This is called from acp_tcp() in acp.c.  The return code is
 *	checked for ENOENT only.  If ENOENT, then acp_tcp will check
 *	ACP for the user (including the domain name).  All other errors
 *	will be denied by this routine.
 *
 ************************************************************/
static int
tms_request(acp, req_type, rasid, keyp, username)
  caddr_t acp;
  int req_type;
  struct in_addr rasid;
  tms_db_key *keyp;
  char *username;
{
  u_char cbuff[MAXPDUSIZE];
  tms_db_entry entry;
  tms_db_ras ras;
  int rc, retcode = ESUCCESS;

  /*
   * REMOVE THE FOLLOWING THREE LINES OF
   * CODE IF YOU WANT TO USE DNIS VALUES
   */
  bzero((char *)keyp->key_dnis, sizeof(keyp->key_dnis));
  keyp->key_dnis[0] = '0';
  keyp->key_dnis[1] = '\0';

  /* *************************** */

  /*
   * lock the database entry for this user's domain
   */
  if ((rc = tms_db_lock(keyp)) != 0) {
    if (rc = -1) {
      if (debug)
	printf("tms_request(): could not lock\n");
      retcode = EIO;
      syslog(LOG_CRIT, "tms: could not lock \"%.64s/%.20s\"",
	     keyp->key_domain, keyp->key_dnis);
      goto send_deny;
    }
    if (debug)
      printf("tms_request(): broke lock held by %08x\n", rc);
    syslog(LOG_NOTICE, "tms: broke lock for \"%.64s/%.20s\"",
	   keyp->key_domain, keyp->key_dnis);
  }

  /*
   * read the database entry for this user's domain
   */
  errno = ESUCCESS;		/* be optimistic */
  ras.ras_addr.s_addr = htonl(rasid.s_addr);	/* ASN.1 gave us host order */
  if ((rc = tms_db_read(keyp, &entry, &ras)) != E_SUCCESS) {
    switch (rc) {
    case E_NOEXIST:
      if (debug)
	printf("tms_request(): no entry\n");
      syslog(LOG_NOTICE,
	     "tms: \"%.64s/%.20s\" domain/dnis not found in database",
	     keyp->key_domain, keyp->key_dnis);
      retcode = ENOENT;
      break;
    case E_GENERAL:
      if (debug)
	printf("tms_request(): error reading\n");
      syslog(LOG_ALERT, "tms: could not read database");
      retcode = EIO;
      break;
    case E_NOTMSDB:
      if (debug)
	printf("tms_request(): TMS database not found\n");
      syslog(LOG_ALERT, "tms: TMS database not found");
      retcode = EIO;
      break;
    case E_NORASDB:
      if (debug)
	printf("tms_request(): RAS database not found\n");
      syslog(LOG_CRIT, "tms: RAS database not found");
      retcode = EIO;
      break;
    default:
      if (debug)
	printf("tms_request(): PROGRAMMING ERROR: tms_db_read() rc=%d\n",
		rc);
      syslog(LOG_ERR, "tms: PROG ERR: tms_db_read() returned %d", rc);
      retcode = EIO;
      break;
    }
    goto req_unlock;
  }

  /*
   * update the information
   */
  switch (req_type) {
  case REQUEST_INIT:
    if (entry.td_users >= entry.td_maxusers) {
      if (debug)
	printf("tms_request(): too many users (%d >= %d)\n",
	       entry.td_users, entry.td_maxusers);
#if defined(SCO) || defined(SCO5)
      retcode = EADV;
#else
      retcode = EUSERS;
#endif
      syslog(LOG_NOTICE,
	     "tms: \"%.64s/%.20s\" user count reached maximum users",
	     keyp->key_domain, keyp->key_dnis);
      entry.td_denies++;
      break;
    }
    entry.td_grants++;
    entry.td_users++;
    ras.ras_count++;
    break;
  case REQUEST_TERM:
    if (entry.td_users > 0)
      entry.td_users--;
    else {
      if (debug)
	printf("tms_request(): WARNING: total users count already zero\n");
      syslog(LOG_NOTICE, "tms: \"%.64s/%.20s\" user count already zero",
	     keyp->key_domain, keyp->key_dnis);
    }
    if (ras.ras_count > 0)
      ras.ras_count--;
    else {
      if (debug)
	printf("tms_request(): WARNING: %s users count already zero\n",
	       inet_ntoa(rasid));
      syslog(LOG_NOTICE, "tms: \"%.64s/%.20s,\" RAS %s count already zero",
	     keyp->key_domain, keyp->key_dnis, inet_ntoa(rasid));
    }
    break;
  }

  /*
   * update the domain's database entry
   */
  if ((rc = tms_db_update(keyp, &entry, &ras)) != E_SUCCESS) {
    if (rc == E_GENERAL) {
      if (debug)
	printf("tms_request(): error updating\n");
    }
    else {
      if (debug)
	printf("tms_request(): PROGRAMMING ERROR: tms_db_update() rc=%d\n",
	      rc);
    }
    syslog(LOG_ALERT, "tms: could not update database");
    retcode = EIO;
  }

  /*
   * unlock the database entry for this user's domain
   */
req_unlock:
  if ((rc = tms_db_unlock(keyp)) != 0) {
    if (debug) {
      printf("tms_request(): lock was broken");
      if (rc != -1)
	printf(" by %08x", rc);
      putchar('\n');
    }
    syslog(LOG_NOTICE, "tms: lock was broken for \"%.64s/%.20s\"",
	   keyp->key_domain, keyp->key_dnis);
  }

  if (req_type == REQUEST_TERM)
    return(retcode);
  if (retcode != ESUCCESS)
    goto send_deny;

  /*
   * send a Grant message
   */
  if (debug)
    printf("tms_request(): sending grant\n");

  rc = racp_send_auth_resp(acp, cbuff, MAXPDUSIZE, REQ_GRANTED,
			   NULL, NULL, username, keyp->key_domain, &entry);
  if (debug && (rc != ESUCCESS))
    printf("tms_request(): grant racp_send_auth_resp() returned %d\n", rc);
  return(rc);

  /*
   * must send a Deny message
   */
send_deny:
  if (retcode == ENOENT)
  {
      if (debug)
        printf("tms_request(): returning - %s\n", sys_errlist[retcode]);
      return(retcode);
  }

  if (debug)
    printf("tms_request(): sending deny - %s\n", sys_errlist[retcode]);

  rc = racp_send_auth_resp(acp, cbuff, MAXPDUSIZE, REQ_DENIED,
			   NULL, NULL, NULL, NULL, NULL);
  if (debug && (rc != ESUCCESS))
    printf("tms_request(): deny racp_send_auth_resp() returned %d\n", rc);
  return((retcode != ESUCCESS) ? retcode : rc);
}


/************************************************************
 *
 * Name:
 *	tms_terminate
 *
 * Description:
 *	This function decrements the total user count by the RAS's
 *	user count then zeros a RAS's user count.
 *
 * Inputs:
 *	rasid - address of RAS
 *
 * Outputs:
 *	none
 *
 * Notes:
 *
 ************************************************************/
void
tms_terminate(rasid)
  struct in_addr rasid;
{
  static char failmsg[] =
    "tms_terminate(): failed for \"%.64s/%.20s\" - could not %s\n";

  register key_link *klp;
  key_link *old_klp;
  tms_db_entry entry;
  tms_db_ras ras;
  int rc, temp;

  if (debug)
    printf("tms.c: entering tms_terminate() - rasid=%s\n", inet_ntoa(rasid));

  /*
   * get the list of entries
   * an error probably means that TMS is not in use, so simply return
   * for each entry in the list:
   *	lock the entry
   *	read the entry
   *	if the RAS has a count, decrement the count and update the entry
   *	unlock the entry
   *	delete the list element
   */
  ras.ras_addr = rasid;
  if ((klp = tms_db_domains(0)) == (key_link *)(-1))
    return;

  syslog(LOG_INFO, "tms: decrementing user counts for RAS %s\n",
	 inet_ntoa(rasid));

  while (klp) {
  /* lock entry */
    if ((rc = tms_db_lock(&klp->entry)) != 0) {
      if (rc = -1) {
	if (debug)
	  printf(failmsg, klp->entry.key_domain, klp->entry.key_dnis, "lock");
	continue;
      }
      if (debug)
	printf("tms_terminate(): broke lock \"%.64s/%.20s\" held by %08x\n",
	       klp->entry.key_domain, klp->entry.key_dnis, rc);
    }

  /* read entry */
    if ((rc = tms_db_read(&klp->entry, &entry, &ras)) != E_SUCCESS) {
      if (debug)
	printf(failmsg, klp->entry.key_domain, klp->entry.key_dnis, "read");
      goto term_unlock;
    }

  /* check entry's count */
    if (ras.ras_count == 0) {
      if ((ras.ras_offset != -1) && (debug > 2))
	printf("tms_terminate(): RAS inactive for \"%.64s/%.20s\"\n",
	       klp->entry.key_domain, klp->entry.key_dnis);
      goto term_unlock;
    }

  /* update entry */
    entry.td_users -= ras.ras_count;
    temp = ras.ras_count;
    ras.ras_count = 0;
    if ((rc = tms_db_update(&klp->entry, &entry, &ras)) != E_SUCCESS) {
      if (debug)
	printf(failmsg, klp->entry.key_domain, klp->entry.key_dnis, "update");
      goto term_unlock;
    }
    if (debug > 1)
      printf("tms_terminate(): RAS had %d users for \"%.64s/%.20s\"\n",
	     temp, klp->entry.key_domain, klp->entry.key_dnis);

  /* unlock entry */
term_unlock:
    if ((rc = tms_db_unlock(&klp->entry)) != 0) {
      if (debug) {
	printf("tms_terminate(): lock \"%.64s/%.20s\" was broken",
	       klp->entry.key_domain, klp->entry.key_dnis);
	if (rc != -1)
	  printf(" by %08x", rc);
	putchar('\n');
      }
    }

  /* delete list entry */
    old_klp = klp;
    klp = klp->next;
    free(old_klp);
  } /*while*/

  if (debug)
    printf("tms_terminate(): exiting\n");
}
