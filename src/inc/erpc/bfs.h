/*****************************************************************************
 *
 *        Copyright 1989-1996, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *        Copyright 1997, Bay Networks, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Bay Networks, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * File description:
 *   #defines for BFS
 *
 ****************************************************************************/

/*  bfs.h   2.0 12-Apr-84   jmt */

/* BFS block size */
#define BFS_BPBLOCK 512

/* Downline load ERPC remote program definitions. */
#define BFS_PROG    0x1
#define BFS_VER     0

/* BFS remote procedures */
#define BFS_OPEN    0
#define BFS_READ    1
#define BFS_WRITE   2
#define BFS_CLOSE   3
#define BFS_END     4
#define BFS_GETVER  5

/* u_short offsets to call arguments to BFS_OPEN */
#define BFS_MINVER  0
#define BFS_OPTIONS 1
#define BFS_NAMLEN  2
#define BFS_NAME    3

/* u_short offsets to call arguments to BFS_READ and BFS_WRITE */
#define BFS_BLOCK   0
#define BFS_DATALEN 1
#define BFS_DATA    2

/* values for the options argument to BFS_OPEN */
#define BFS_RECREATE    0	/* Create or recreate */
#define BFS_NORECREATE  1	/* Don't create and don't complain */
#define BFS_REQUIRE     2	/* Complain if it isn't there */

/* BFS abort error values */
#define BFS_ENOENT      0       /* No such file or directory */
#define BFS_OPENERR     1       /* Error opening file */
#define BFS_DUPLOPEN    2       /* Duplicate open request in session */
#define BFS_READERR     3       /* Read error */
#define BFS_EOF         4       /* End of file */
#define BFS_NOTOPEN     5       /* File not yet open */
#define BFS_ACTIVE      6       /* End session attempted while file open */
#define BFS_WRITERR     7       /* Write error */
#define BFS_TOOLONG     8       /* Write request for longer than one block */
#define BFS_UNSPEC      0xffff  /* Unspecified */
