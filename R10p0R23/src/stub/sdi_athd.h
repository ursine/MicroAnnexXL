/* sdi_athd.h - client includes */
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

#ifndef _SD_ATHD

#include "sdi_size.h"
#include "sdi_type.h"

struct stolen_store {
    INT32BIT key;
    char pin;
    char prn[LENPRNST];  };

struct SD_CLIENT {

    INT16BIT application_id;
    char username[LENACMNAME];
    INT32BIT passcode_time;
    char validated_passcode[LENPRNST];
    char shell[LENACMFILE];             /* outputs from acm_ok          */

    char ignition_key[16];              /* outputs from acm_pc_ok       */
    char new_key[16];
    char release_code;
    char protectdir[LENACMFILE];

    INT32BIT time_delta;                /* acm_time                     */
	/* next prn param */
    INT32BIT timeout;
	/* stolen card check storage */
    struct stolen_store steal_check[3];
	/* fixed size pin */
    char fixed_pin_size;
	/* new pin params */
    char system_pin[16];
    char min_pin_len;
    char max_pin_len;
    char user_selectable;
    char alphanumeric;
    };

#define _SDI_ATHD
#endif
