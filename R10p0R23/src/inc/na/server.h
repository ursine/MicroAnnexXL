/*
 *****************************************************************************
 *
 *        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Include file description:
 *	Interpretation of server byte 
 *	(condensed from dfe/parmdfe.h)
 *
 * Original Author: Paul Mattes		Created on: 19. January 1988
 *
 ****************************************************************************
 */

#ifndef SERVER_H
#define SERVER_H

/* Server bit definitions */

#define SERVE_NONE	0
#define SERVE_IMAGE	0x01
#define SERVE_CONFIG	0x02
#define SERVE_MOTD	0x08
#define SERVE_ALL	0xff

#endif
