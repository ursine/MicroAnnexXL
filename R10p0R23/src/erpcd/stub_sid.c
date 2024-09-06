

/*
 **************************************************************************

This module contains code to produce a shared object that is a stub
version of SecurId security.  By compiling this code and
dynamically linking the object to the erpcd command we will have an
erpcd that can "handle" the securid security regime.  Of course, this
code just handles it by returning data that will be caught as "user
not validated".  The idea is that the shared object produced with this
code can be replaced with a shared object containing the real
code to actually perform the SecurId validation.

Another way of handling this situation of course is to actually have
the real SecurId source code but Security Dynamics is in the business
to supply that, not us.

 **************************************************************************
 *
 */


/* Read in the acp_policy.h file to give a chance
 * for SECURID_CARD to be defined.
 */
#include "acp_policy.h"


#ifdef SECURID_CARD


/* We will be using stub code for the SecurId security regime.
 * Use the stub (generic) include files. These headers are placed
 * in the "stub" directory to lessen the chance that they may be
 * picked up with a -I<path> argument to the compiler when real
 * security code is compiled instead of the stub version.
 */


/* Both ACE1_1 and ACE1_2 will use the same set of include files */

#include "../stub/sdi_athd.h"
#include "../stub/sdi_size.h"
#include "../stub/sdi_type.h"
#include "../stub/sdacmvls.h"
#include "../stub/sdconf.h"
union config_record configure;
#include "comdefs.h"

/* Have a message that can be grep'ed for directly in the file or
 * through the "strings" command that indicates that this is stub code.
 * The installation program will use this to ensure that it does not
 * overwrite a real shared library with a stub version. Do not change
 * the "XY defines: " part of the message without a change to install-annex.
 * Also note the \n for newlines in the message. Don't change that either.
 * P.S. This string be useful in debugging customer installations too.
 */

static char *sid_stub_msg = "\nXY defines: STUB_SID\n";



/**********************************************************************
 * Here are the actual stubbed functions
 **********************************************************************
 */

void creadcfg() {
  return;
}

void sd_pin(dummy1,dummy2,dummy3)
char *dummy1,*dummy3;
int dummy2;
{
  return;
}

int sd_init(dummy)
char *dummy;
{
  return(UNAVAILABLE);
}

int sd_check(dummy1,dummy2,dummy3)
char *dummy1,*dummy2,*dummy3;
{
  return(ACM_ACCESS_DENIED);
}

int sd_next(dummy1,dummy2)
char *dummy1,*dummy2;
{
  return(ACM_ACCESS_DENIED);
}

int sd_auth() {
  return(ACM_ACCESS_DENIED);
}



#endif /* SECURID_CARD */
