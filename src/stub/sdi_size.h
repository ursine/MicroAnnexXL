/* sdi_size.h */
/******************************************************************************
* COPYRIGHT (C) 1990-93 by   SECURITY DYNAMICS TECHNOLOGIES, INC.             *
*                         ---ALL RIGHTS RESERVED---                           *
*                                                                             *
* THIS SOFTWARE IS PROPRIETARY AND CONFIDENTIAL TO SECURITY DYNAMICS          *
* TECHNOLOGIES, INC., IS FURNISHED UNDER A LICENSE AND MAY BE USED AND COPIED *
* ONLY IN ACCORDANCE THE TERMS OF SUCH LICENSE AND WITH THE INCLUSION         *
* OF THE ABOVE COPYRIGHT NOTICE.  THIS SOFTWARE OR ANY OTHER COPIES THEREOF   *
* MAY NOT BE PROVIDED OR OTHERWISE MADE AVAILABLE TO ANY OTHER PERSON.  NO    *
* TITLE TO AND OWNERSHIP OF THE SOFTWARE IS HEREBY TRANSFERRED.               *
*                                                                             *
* THE INFORMATION IN THIS SOFTWARE IS SUBJECT TO CHANGE WITHOUT NOTICE AND    *
* SHOULD NOT BE CONSTRUED AS A COMMITMENT BY SECURITY DYNAMICS TECHNOLOGIES,  *
* INC.                                                                        *
******************************************************************************/
 
/* this file contains ACE Portability definitions. */
 
#ifndef _SDI_SIZE

#define LENID 6
#define LENPIN 12
#define LENSER 12
#define LENLOGID 32
#define LENPRNST 16
#define LENPATH 64
#define LENTITLE 40 
#define LENACMFILE 64
#define LENHOSTNAME 64
#define LENACMNAME 32 
#define LENUSERNAME 64
#define LENSECRET 16
#define LENMAXPIN 16
#define LENSEQNUM 8

#define LENPASCD 20             /* parsed passcode 8 + 1 + 8 + slop     */
#define LENSHELL LENACMNAME     /* better name for api users            */
#define LENCERTIFICATE 35

/* Length that user data gets hashed into */
#define CERT_USER_DATA_HASH_LEN 36
 

#define _SDI_SIZE
#endif

