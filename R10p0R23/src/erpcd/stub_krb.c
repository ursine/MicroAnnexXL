

/*
 **************************************************************************

This module contains code to produce a shared object that is a stub
version of Kerberos security.  By compiling this code and
dynamically linking the object to the erpcd command we will have an
erpcd that can "handle" the kerberos security regime.  Of course, this
code just handles it by returning data that will be caught as "user
not validated".  The idea is that the shared object produced with this
code can be replaced with a shared object containing the real
code to actually perform the Kerberos validation.

Another way of handling this situation of course is to actually have
the real Kerberos source code but someone else is in the business
to supply that, not us.

 **************************************************************************
 *
 */


/* Read in the acp_policy.h file to give a chance
 * for KERBEROS to be defined.
 */
#include "acp_policy.h"


#ifdef KERBEROS


/* We will be using stub code for the SecurId security regime.
 * Use the stub (generic) include files. These headers are placed
 * in the "stub" directory to lessen the chance that they may be
 * picked up with a -I<path> argument to the compiler when real
 * security code is compiled instead of the stub version.
 */

#include "../stub/krb.h"

#ifdef KRB_ERR_TXT
/* krb_err_txt was declared extern */
char *krb_err_txt[] = { "xxx" };
#else
extern char *krb_err_txt[];
#endif /* KRB_ERR_TXT */
#include "comdefs.h"


/* Have a message that can be grep'ed for directly in the file or
 * through the "strings" command that indicates that this is stub code.
 * The installation program will use this to ensure that it does not
 * overwrite a real shared library with a stub version. Do not change
 * the "XY defines: " part of the message without a change to install-annex.
 * Also note the \n for newlines in the message. Don't change that either.
 * P.S. This string be useful in debugging customer installations too.
 */

static char *krb_stub_msg = "\nXY defines: STUB_KRB\n";



/**********************************************************************
 * Here are the actual stubbed functions
 **********************************************************************
 */


int krb_get_lrealm(dummy1,dummy2)
char *dummy1;
int dummy2;
{
  return(UNAVAILABLE);
}

void krb_set_tkt_string(dummy)
char *dummy;
{
  return;
}

int krb_get_pw_in_tkt(dummy1,dummy2,dummy3,dummy4,dummy5,dummy6,dummy7)
char *dummy1,*dummy2,*dummy3,*dummy4,*dummy5,*dummy7;
int dummy6;
{
  return(INTK_OK + 1);
}

void dest_tkt() {
  return;
}


#endif /* KERBEROS */

