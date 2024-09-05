/* sdconf.h - configuration includes */
/******************************************************************************
* COPYRIGHT (C) 1993 by      SECURITY DYNAMICS TECHNOLOGIES, INC.             *
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

#ifndef _H_SDCONF

#define _H_SDCONF

/*
  The conf_record structure contains what used to be stored in the strconf.c
  file.  This data is now encrypted and is now called strconf.rec for
  hysteric reasons.  A version number is included, the array is structured
  as a union with another array, which is random filled before any data is
  put in the structure, further preserving the security of the data.
*/
struct configdef
    {
	INT32BIT version;			/* version number of config */
	INT32BIT acmmaxretries; 		/* Maximum number of retries */
	INT32BIT acmmaxservers;			/* Maximum number of servers */
	INT32BIT acmbasetimeout;		/* Base timeout value	     */
	INT32BIT use_des;			/* Use DES algorithm or ours */
	INT32BIT trusted;			/* Secure?		     */
	INT32BIT use_duress;			/* Physical security breach  */
	INT32BIT no_badprns;			/* Number of bad prns	     */
	INT32BIT no_badpins;			/* Number of bad pins	     */
	INT32BIT acmport;			/* port number (socket)      */
	INT32BIT sdpropd_port;			/* slave port number (socket)*/
	char acmservice[32];			/* /etc/services value string*/
	char acmprotocol[4];			/* protocol for /etc/services*/
	char name[4][LENHOSTNAME];		/* host name		     */
	long acm_servers[4];			/* long address value	     */
	unsigned char release_state;		/* release state */
	char filler[3];
    };

union config_record 
	{
	struct configdef config;
	char data[512];
	};
	
#endif
