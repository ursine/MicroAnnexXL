/* 
 *  Copyright (C) 1989 by the Massachusetts Institute of Technology
 * 
 *    Export of software employing encryption from the United States of
 *    America is assumed to require a specific license from the United
 *    States Government.  It is the responsibility of any person or
 *    organization contemplating export to obtain such a license before
 *    exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


/*
 * The following was extracted from the include/krb.h.sed file from the
 * final kerberos 4 distribution. This is available through anonymous ftp
 * (ftp athena-dist.mit.edu  /pub/kerberos/dist/921209/ksrc.tar.Z)
 * Only the definitions needed to compile and link erpcd with a stub
 * version of kerberos authentication were placed here.
 */



/* Only one time, please */
#ifndef	KRB_DEFS
#define KRB_DEFS


/* The maximum sizes for aname, realm */
#define 	ANAME_SZ	40
#define		REALM_SZ	40


/* General definitions */
#define		KSUCCESS	0
#define		KFAILURE	255


/* Default ticket lifetime 10 hrs */
#define		DEFAULT_TKT_LIFE	120


/* Ticket obtained */
#define		INTK_OK		0


/* Text describing error codes */
#define		MAX_KRB_ERRORS	256


/* KRB_REALM is the name of the realm. */
#define		KRB_REALM	"SITE_KRB_REALM"


#ifndef KRB_ERR_TXT
#define KRB_ERR_TXT
extern char *krb_err_txt[MAX_KRB_ERRORS];
#endif /* !KRB_ERR_TXT */


#endif	/* KRB_DEFS */

