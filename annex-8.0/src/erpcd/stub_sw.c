
/*
 **************************************************************************

This module contains code to produce a shared object that is a stub
version of Enigma Safeword security.  By compiling this code and
dynamically linking the object to the erpcd command we will have an
erpcd that can "handle" the enigma security regime.  Of course, this
code just handles it by returning data that will be caught as "user
not validated".  The idea is that the shared object produced with this
code can be replaced with a shared object containing the real
code to actually perform the Safeword validation.

Another way of handling this situation of course is to actually have
the real Safeword source code but Enigma is in the business to supply
that, not us.

 **************************************************************************
 *
 */


/* Read in the acp_policy.h file to give a chance
 * for ENIGMA_SAFEWORD to be defined.
 */
#include "acp_policy.h"


#ifdef ENIGMA_SAFEWORD


/* We will be using stub code for the Enigma security regime.
 * Use the stub (generic) include files. These headers are placed
 * in the "stub" directory to lessen the chance that they may be
 * picked up with a -I<path> argument to the compiler when real
 * security code is compiled instead of the stub version.
 */
#include "../stub/custpb.h"
#include "../stub/custfail.h"
#include "comdefs.h"

/* Have a message that can be grep'ed for directly in the file or
 * through the "strings" command that indicates that this is stub code.
 * The installation program will use this to ensure that it does not
 * overwrite a real shared library with a stub version. Do not change
 * the "XY defines: " part of the message without a change to install-annex.
 * Also note the \n for newlines in the message. Don't change that either.
 * P.S. This string be useful in debugging customer installations too.
 */

static char *sw_stub_msg = "\nXY defines: STUB_SW\n";


/* Have an error message and the length of the message + 1 */
static int msg_len = 32;
static char *stub_msg = "Safeword validation not enabled";



/**********************************************************************
 * Here are the actual stubbed functions
 **********************************************************************
 */


void pbmain(pb)
struct pblk *pb;
{

  /* Fill message buffers */
  int i;
  for (i=0; i<msg_len; i++) {
    pb->msg1[i] = pb->msg2[i] = stub_msg[i];
  }

   /* Signal that the regime is unavailable */
    pb->pbresrv3 = UNAVAILABLE;

  /* Signal a failure.
   * Program Integrity seems a good choice for a stub.
   */
  pb->errcode = INTEGRITY;

   /* Here is a return status that should cause the calling code to
    * seek out more detail and catch that an error is being returned.
    */
  pb->status = NO_STATUS;

  /* If both of these are enabled then a failure may be caught.
   * Doing this just in case the calling code doesn't catch it
   * another way.
   */
  pb->dynpwdf = ENABLED;    /* dynamic pwd enabled flag */
  pb->fixpwdf = ENABLED;    /* fixed pwd enabled flag */

}


#endif /* ENIGMA_SAFEWORD */

