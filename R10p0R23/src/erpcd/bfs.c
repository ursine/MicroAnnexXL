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
 * Module Function:
 *
 *	Block File Server
 *
 * Original Author: Jonathan Taylor      Created on: 84/07/05
 *
 *****************************************************************************/

/* Include Files */
#include "../inc/config.h"
#include "../inc/vers.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include "../libannex/api_if.h"

#ifndef _WIN32
#include <sys/wait.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <strings.h>
#else 
#include "../inc/port/xuio.h"
#include <direct.h>
#include <process.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>

#include <errno.h>
#include "../libannex/srpc.h"
#include "../inc/courier/courier.h"
#include "../inc/erpc/erpc.h"
#include "../inc/erpc/bfs.h"
#include "acp_policy.h"

/* External Data Declarations */

extern int debug;
extern int child_count;		/* defined in erpcd.c */
extern int child_max;		/* ibid */

/* Defines and Macros */

#ifdef UMAX_V
#define SYS_V
#endif

/* Session states */

#define IDLE    0
#define OPEN    1
#define CLOSED  2

#define MAX_TIME        90      /* Seconds allowed between valid requests */

#define BUFFSIZE        2048

#ifndef MAX
#define MAX(x, y) (x > y ? x : y)
#endif
#ifndef MIN
#define MIN(x, y) (x < y ? x : y)
#endif

#ifndef NULL
#define NULL 0
#endif

/* cachsize must be a multiple of BFS_BPBLOCK.  It works best as an even 
 * multiple.  Take care to insure that this number cannot go negative on
 * 16 bit machines like 80x86's.
 */
#define CACHESIZE       25 * BFS_BPBLOCK

#define UDP_SO_SUPPLY	3
#define PIPE_REQUEST	4

/* File name size and translation parameters */

#ifdef SYS_V
#define DUMP_PREFIX	"dump."
#endif

#if defined(EXOS) && !defined(ECONNREFUSED)
#define ECONNREFUSED 61
#endif


/* Structure Definitions */


/* Forward Routine Declarations */
#ifdef _WIN32
void RegistAlarmHandler();
void alarm();
#endif

UINT32	get_long();
void erpc_reject();
void erpc_abort ();
void erpc_return ();
void display();
int api_rcvud();
void cleanup_file();

/* Global Data Declarations */

char filename[128];
void timer();

/* Static Declarations */

/*
 * file cache used by bfs 
 */
static int  cachedfile;                 /* file descriptor of cached file */
static INT32 cachestart;		/* offset of first cached byte */
static int  cachedbytes;		/* Number of cached bytes */

#ifdef XENIX
/*
 * Static vars are put in DATA segment,
 * which means a huge object file, this circumvents
 */
char cache[CACHESIZE];
#else
static char cache[CACHESIZE];
#endif

static char open_filename[128];

#ifdef SYS_V
static char split_filename[21];	/* dump/255/255.255.255\0 */
static char dir1[6];		/* dump\0 */
static char dir2[17];		/* dump/255.255.255\0 */
#endif

static int  file_recreated;


void timer()
{
	/* Called on receive timeout. */
	if (debug)
       	    fprintf(stderr,"Session timeout\n");
	cleanup_file();
	ErpcdExit(1);
}	/* timer() */





void term_cache()
{
        (void)close(cachedfile);
}       /* term_cache() */

void cleanup_file()
{

        if (file_recreated && lseek(cachedfile, 0L, 2) == 0L)
#ifdef SYS_V
	    (void)unlink(split_filename);
#else
            (void)unlink(open_filename);
#endif
	else
	    term_cache();
}       /* cleanup_file */


read_block(block, ppc)
u_short    block;
char       **ppc;
{
    
    INT32 offset;

    /* Return a pointer to up to BFS_BPBLOCK bytes in the cache
     * corresponding to the argument byte offset.  If the byte requested
     * is not in the saved area already, fill the cache starting at the
     * requested byte.  
     */

    offset = BFS_BPBLOCK * (INT32)block;
    if (offset < cachestart || offset >= cachestart + cachedbytes)
    {
	if(debug)
		fprintf(stderr,"about to lseek offset: %d\n", offset);
	if (lseek(cachedfile, offset, 0) == -1)
	{
	    if (debug)
		    perror ("bfs: read_block(): lseek");
	    return -1;
	}
	
	cachedbytes = read(cachedfile, cache, sizeof(cache));
	
	if (cachedbytes == -1)
	{
	    if (debug)
		    perror ("bfs: read_block(): read");
	    cachedbytes = 0;
	    return cachedbytes;
	}
	
	cachestart = offset;
    }
    
    /* Pass back pointer to requested byte, and return bytecount. */
    
    if(debug) {
    	fprintf(stderr,"offset: %lx\ndata:", offset);
	display (&cache[offset - cachestart], 16);
    }
    *ppc = &cache[offset - cachestart];
    
    return MIN(BFS_BPBLOCK, cachedbytes - (offset - cachestart));

}       /* read_block */


write_block(block, length, Pdata)

u_short block;
short   length;
char    *Pdata;

{

        int bytes_written, overlap_length;
        INT32 offset;
        char *Psource, *Pdest;

        /* Write the data to the disk file. */

        offset = BFS_BPBLOCK * (INT32)block;

        if (lseek(cachedfile, offset, 0) == -1)
	    {
	    if (debug)
		fprintf(stderr,"lseek error\n");
            return -1;
	    }

        if ((bytes_written = write(cachedfile, Pdata, length)) == -1)
	    {
	    if (debug)
		fprintf(stderr,"write error\n");
            return -1;
	    }

        /* If the data overlaps the data that is currently cached, copy
           the data into the cache. */

        if (cachedbytes > 0)
            {
            overlap_length = MIN(offset + length, cachestart + cachedbytes) -
             MAX(offset, cachestart);

            if (overlap_length > 0)
                {
                Psource = Pdata + MAX(0, cachestart - offset);
                Pdest = cache + MAX(0, offset - cachestart);
                bcopy(Psource, Pdest, overlap_length);
                }
            }

        /* Return the number of bytes written. */

        return bytes_written;

} /* write_block */

/*
 * Eliminate absolute pathnames (those beginning with '/') as well as
 * any paths containing references to the parent directory "..".
 * Note, of course, that names like "..a" are legal and safe.
 */
int
pathcheck(name)
char *name;
{
  if (name[0] == '/' || (name[0] == '.' && name[1] == '\0'))
    return 1;
  while (name[0] != '\0')
    if (name[0] == '.' && name[1] == '.' &&
	(name[2] == '/' || name[2] == '\0'))
      return 1;
    else if ((name = index(name,'/')) == NULL)
      break;
    else
      name++;
  return 0;
}

int
init_cache(name, options)

        char *name;
        int options;

{
    int old_umask;
	/*int i; */
#ifdef SYS_V
	int length;
#endif 

    if (pathcheck(name))
      return -1;

        cachestart = cachedbytes = 0;

        /* Change umask in case it's weirded out. */

        old_umask = umask(022);

#ifdef SYS_V
	/*
	 * System V limits us to 14-character file names.  Dump files
	 * names can be up to 20 characters long; we'll split the name
	 * if necessary here
	 */

	if(debug)
	    fprintf(stderr,"Request to open '%s'\n", name);

	/*
	 * Some broken machines (NCR) implement string macros in assembly
	 * and don't allow nested assembler macro calls (gak!)
	 */
	length = strlen(DUMP_PREFIX);
	if((options == BFS_RECREATE) &&
	   !strncmp(name, DUMP_PREFIX, length) &&
	   index(name, '/') == 0)
	    {
	    if(split_name(name) == -1)	/* Didn't work */
		(void)strcpy(split_filename, name);
	    }
	else				/* Doesn't need splitting */
	    (void)strcpy(split_filename, name);

        /* Open requested file. */

        cachedfile = open(split_filename,
         options == BFS_RECREATE ? O_RDWR | O_TRUNC | O_CREAT : O_RDONLY, 0666);

#else

        /* Open requested file. */
#ifndef O_BINARY
#define O_BINARY 0
#endif

        cachedfile = open(name,
         options == BFS_RECREATE ? O_RDWR | O_TRUNC | O_CREAT | O_BINARY : O_RDONLY | O_BINARY , 0666);

#endif

	if (cachedfile < 0 && debug)
		perror(name);

        file_recreated = (cachedfile != -1 && options == BFS_RECREATE);

        /* Change umask back. */

        (void)umask(old_umask);

        return cachedfile;
}       /* init_cache() */


/*********************************************************************
*  Block File Server.
*  Created by ERPC listener daemon to handle BFS request.
* 
*  files are assumed open as follows:
* 
*       0,1,2   stdin, stdout, stderr from erpcd.
*       s       service supplying UDP socket connected to requester.
*********************************************************************/

bfs(s, message, mlen)

	int	s;		/*  file descriptor of a socket	*/
	char	*message;	/*  pointer to first message	*/
	int	mlen;		/*  length of indicated message	*/
{

	char			cbuff[BUFFSIZE];
	register struct chdr	*ch = (struct chdr *)cbuff;
	register u_short	*carg = (u_short *)(cbuff + CHDRSIZE);
	int			state = IDLE,
				first_time = TRUE;
	static char 		*appl_nam="bfs";


        /* Set our root to load image directory to keep bogus "requesters"
           from sniffing around the file system. */

        if (chdir(root_dir) < 0)
            {
            perror("bfs: chdir");
            ErpcdExit(1);
            }

#ifdef notdef
/* possibly change uid to daemon here? */
        if (setuid(???) < 0)
            {
            perror("bfs: setuid");
            ErpcdExit(1);
            }
#endif

#ifdef _WIN32
		RegistAlarmHandler(timer);
#else
        (void)signal(SIGALRM, timer);
#endif

        /* Keep receiving requests on the UDP socket until an end
         * session request is received or a timeout occurs.
         * Either event causes us to exit. 
	 */


        for (;;)    /* forever */
            {
            int cc, result;
            UINT32 pid;
	    UINT32 rpnum;

	    /* First time, copy message to global area*/

	    if (first_time) {
		bcopy(message, cbuff, mlen);
		cc = mlen;
		first_time = FALSE;
	    } else {

            /* Await next call message with timeout. */

		(void)alarm(MAX_TIME);	

		if (debug)
		    fprintf(stderr,"bfs:  pid %d going to receive.\n",
			getpid());

		/* Receive User data */
		cc = sizeof(cbuff);
		result = api_rcvud(&cc,(int *)0,s,NULL,cbuff,appl_nam, TRUE,
				   (struct sockaddr_in *)0);
		switch (result) {
		    case 1:
			cleanup_file();		/* cleanup socket */
			ErpcdExit(1);
		    case 2:
			ErpcdExit(-1);
		    case 3:
			continue;
		    default:
			break;
		}

		(void)alarm(0);	


	    }

            /* Verify that packet length is at least long enough to
             * contain required information.  If not, the packet is
             * just ignored, since we can't be sure of the info to
             * use in sending a reject.  
	     */
            if (cc < CHDRSIZE)
                {
	        if (debug)
		    {
                    fprintf(stderr,"Message ignored: too short to be valid.\n");
                    display(cbuff, cc);
	            }
                continue;       /* for (;;) */
                }

            /* Make sure the client type is for the ERPC protocol
             * and this is a courier CALL request. 
	     */
            if (ntohs(ch->ch_client) != PET_ERPC)
                {
	        if (debug)
		    {
                    fprintf(stderr,
			"Message ignored: %x is not a valid client type.\n",
			ntohs(ch->ch_client));
                    display(cbuff, cc);
	            }
                continue;       /* for (;;) */
                }

	    /* 
	     * obtain packet ID (also known as PEP ID) number.
	     * the return message must contain this number
	     */
	    if (debug)
		    fprintf(stderr,"bfs: ch_id[0]=%x  ch_id[1]=%x\n",
			ch->ch_id[0], ch->ch_id[1]);

	    pid = get_long(&ch->ch_id[0]);

            if (ntohs(ch->ch_type) != C_CALL || ch->ch_tid)
                {
                (void)erpc_reject(s, NULL, pid, CMJ_UNSPEC, 0, 0);
	        if (debug)
		    {
                    fprintf(stderr,
			"Message rejected: %x is an invalid cmc type.\n",
			ntohs(ch->ch_type));
                    display(cbuff, cc);
	            }
                continue;       /* for (;;) */
                }

	    rpnum = get_long (&ch->ch_rpnum[0]);

            if (rpnum != BFS_PROG)
                {
                (void)erpc_reject(s, NULL, pid, CMJ_NOPROG, 0, 0);
	        if (debug)
		    {
                    fprintf(stderr,
			"Message rejected:  %lx is an invalid cmc rpnum.\n",
			rpnum);
                    display(cbuff, cc);
	            }
                continue;       /* for (;;) */
                }

            if (ntohs(ch->ch_rpver) != BFS_VER)
                {
                (void)erpc_reject(s, NULL, pid, CMJ_NOVERS, BFS_VER,
				  BFS_VER);
	        if (debug)
		    {
                    fprintf(stderr,
			"Message rejected:  %x is an invalid cmc rpver.\n",
			ntohs(ch->ch_rpver));
                    display(cbuff, cc);
	            }
                continue;       /* for (;;) */
                }

	    /* well formed courier call message
	     */
            switch(ntohs(ch->ch_rproc))
                {
                case BFS_OPEN:
                    {
                    int namelen, options,
                        args_length = cc - CHDRSIZE;

		    /* open message; make sure arguments are valid
		     */
                    if (args_length < 3 * sizeof(u_short))
                        {
                        (void)erpc_reject(s, NULL, pid, CMJ_INVARG, 0, 0);
	                if (debug)
		            {
                            fprintf(stderr,
				"Message rejected: missing arguments.\n");
                            display(cbuff, cc);
	                    }
                        break;  /* from switch (ch->ch_rproc) */
                        }

                    namelen = ntohs(carg[BFS_NAMLEN]);
                    if (namelen > 128 ||
                     namelen > args_length - 3 * (int)sizeof(u_short))
                        {
                        (void)erpc_reject(s, NULL, pid, CMJ_INVARG, 0, 0);
	                if (debug)
		            {
                            fprintf(stderr,
				"Message rejected: filename too short.\n");
                            display(cbuff, cc);
	                    }
                        break;  /* from switch (ch->ch_rproc) */
                        }

                    options = ntohs(carg[BFS_OPTIONS]);
                    if (options != BFS_RECREATE &&
		        options != BFS_NORECREATE &&
			options != BFS_REQUIRE)
                        {
                        (void)erpc_reject(s, NULL, pid, CMJ_INVARG, 0, 0);
	                if (debug)
		            {
                            fprintf(stderr,
				"Message rejected: invalid open options.\n");
                            display(cbuff, cc);
	                    }
                        break;  /* from switch (ch->ch_rproc) */
                        }

                    (void)strncpy(filename, (char *)&carg[BFS_NAME], namelen);
                    filename[namelen] = '\0';

                    switch(state)
                        {
                        case CLOSED:
                        case IDLE:
                            (void)strcpy(open_filename, filename);

                            /* Try to open the file indicated in the courier
                             * call part of the packet.  If it can't be found,
                             * abort the request.  
			     */
                            if (init_cache(filename, options) < 0)
                                {
	                        if (debug || options == BFS_REQUIRE)
		                    {
	                            /* Only send an ABORT if the CALL was
				     * uni-cast or we're debugging.
				     */
				    if (debug)
						fprintf(stderr, "BFS_OPEN: couldn't open %s.\n",filename);
                    (void)erpc_abort(s, NULL, pid, errno == ENOENT ?
			       				 (u_short)BFS_ENOENT : (u_short)BFS_OPENERR,
								  0, (struct iovec *)0);

	                        }
							return(1);
                            }

                            state = OPEN;
			    /* send return message indicating success
			     * the file is open
			     */
			    if (debug)
				fprintf(stderr,
				    "bfs: sending open return message\n");
                            (void)erpc_return(s, NULL, pid, 0,
					      (struct iovec *)NULL);

                            break;  /* from switch (state) */

                        case OPEN:
                            /* check to make sure same file 
			     */
                            if (strcmp(filename, open_filename) != 0)
                                {
	                        if (debug)
                                    fprintf(stderr,
					"BFS_OPEN: another file is open.\n");
                                (void)erpc_abort(s, NULL, pid,
				 	   BFS_DUPLOPEN, 0, (struct iovec *)0);
							return(1);
                                }
                            else
                                (void)erpc_return(s, NULL, pid, 0,
				 		  (struct iovec *)NULL);

                            break;  /* from switch (state) */
                        }       /* switch (state) */

                    break; /* from switch(ntohs(ch->ch_rproc)) */

                    }       /* internal block under case BFS_OPEN */

                case BFS_READ:

                    /* Read and return requested block to the requestor */

                    switch(state)
                        {
                        case OPEN:
                            {
                            int nbytes,
                                args_length = cc - CHDRSIZE;
                            u_short netnbytes;
                            struct iovec iov[3];
                            char *block;

                            if (args_length < sizeof(u_short))
                                {
                                (void)erpc_reject(s, NULL, pid, CMJ_INVARG, 0,0);
	                        if (debug)
		                    {
                                    fprintf(stderr,
				     "Message rejected: missing arguments.\n");
                                    display(cbuff, cc);
	                            }
                                break;  /* from switch (state) */
                                }
                            if ((nbytes = read_block((u_short)ntohs(carg[BFS_BLOCK]),
                             &block)) == 0)
                                {
	                        if (debug)
                                    fprintf(stderr,
					"BFS_READ aborted: eof in block %d.\n",
					ntohs(carg[BFS_BLOCK]));
                                (void)erpc_abort(s, NULL, pid, BFS_EOF, 0,
						 (struct iovec *)0);
                                break;  /* from switch (state) */
                                }

                            if (nbytes == -1)
                                {
	                        if (debug)
                                    fprintf(stderr,
					"BFS_READ aborted: read error in block %d.\n",
                                        ntohs(carg[BFS_BLOCK]));
                                (void)erpc_abort(s, NULL, pid, BFS_READERR, 0,
						 (struct iovec *)0);
                                break;  /* from switch (state) */
                                }

                            netnbytes = ntohs((u_short)nbytes);

                            iov[1].iov_base = (caddr_t)&netnbytes;
                            iov[1].iov_len = sizeof(u_short);
                            iov[2].iov_base = (caddr_t)block;
                            iov[2].iov_len = (u_short)nbytes;

                            (void)erpc_return(s, NULL, pid, 2, iov);

                            break;  /* from switch (state) */
                            }       /* internal block under case OPEN */

                        default:
	                    if (debug)
                                fprintf(stderr,
				    "BFS_READ aborted: file not open.\n");
                            (void)erpc_abort(s, NULL, pid, BFS_NOTOPEN, 0,
					     (struct iovec *)0);
                            break;  /* from switch (state) */
                        }       /* switch (state) */

                    break; /* from switch(ntohs(ch->ch_rproc)) */

                case BFS_WRITE:
                    switch (state)
                        {
                        case OPEN:
                            {
                            int datalen,
                                args_length = cc - CHDRSIZE;

                            if (args_length < 2 * sizeof(u_short))
                                {
                                (void)erpc_reject(s, NULL, pid, CMJ_INVARG, 0,0);
	                        if (debug)
		                    {
                                    fprintf(stderr,
				        "Message rejected: missing arguments.\n");
                                    display(cbuff, cc);
	                            }
                                break;  /* from switch (state) */
                                }

                            datalen = ntohs(carg[BFS_DATALEN]);
                            if (datalen > args_length - 2 * (int)sizeof(u_short))
                                {
                                (void)erpc_reject(s, NULL, pid, CMJ_INVARG, 0,0);
	                        if (debug)
		                    {
                                    fprintf(stderr,
				     "Message rejected: data too short.\n");
                                    display(cbuff, cc);
	                            }
                                break;  /* from switch (state) */
                                }

                            if (datalen > BFS_BPBLOCK)
                                {
	                        if (debug)
                                    fprintf(stderr,
					"BFS_WRITE aborted: data too long.\n");
                                (void)erpc_abort(s, NULL, pid, BFS_TOOLONG, 0,
						 (struct iovec *)0);
                                break;  /* from switch (state) */
                                }

                            if ((write_block((u_short)ntohs(carg[BFS_BLOCK]), 
					     datalen,
					     (char *)&carg[BFS_DATA])) == -1)
                                {
	                        if (debug)
                                    fprintf(stderr,
					"BFS_WRITE aborted: write error.\n");
                                (void)erpc_abort(s, NULL, pid, BFS_WRITERR, 0,
						 (struct iovec *)0);
                                break;  /* from switch (state) */
                                }

                            (void)erpc_return(s, NULL, pid, 0,
					      (struct iovec *)NULL);
                            }

                            break;  /* from switch (state) */

                        default:
	                    if (debug)
                                fprintf(stderr,
				    "BFS_WRITE aborted: file not open.\n");
                            (void)erpc_abort(s, NULL, pid, BFS_NOTOPEN, 0,
					     (struct iovec *)0);
                            break;  /* from switch (state) */
                        }       /* switch (state) */

                    break;  /* from switch (ch->ch_rproc) */

                case BFS_CLOSE:

                    switch (state)
                        {
                        case OPEN:
                            term_cache();
                            state = CLOSED;

                            /* fall thru */

                        case CLOSED:
                            (void)erpc_return(s, NULL, pid, 0,
					      (struct iovec *)NULL);

                            break; /* from switch (state) */

                        default:
	                    if (debug)
                                fprintf(stderr,
				    "BFS_CLOSE aborted: file not open.\n");
                            (void)erpc_abort(s, NULL, pid, BFS_NOTOPEN, 0,
					     (struct iovec *)0);
                            break; /* from switch (state) */
                        }       /* switch (state) */

                    break; /* from switch(ntohs(ch->ch_rproc)) */

                case BFS_END:
                    switch (state)
                        {
                        case IDLE:
                        case CLOSED:
	                    if (debug)
                                fprintf(stderr,
				    "Session ended successfully.\n");

			    cleanup_file();
						return 1;

                        default:
	                    if (debug)
                                fprintf(stderr,
				    "BFS_END aborted: file is open.\n");
                            (void)erpc_abort(s, NULL, pid, BFS_ACTIVE, 0,
					     (struct iovec *)0);
                            break; /* from switch (state) */
                        }       /* switch (state) */

                    break; /* from switch(ntohs(ch->ch_rproc)) */

                case BFS_GETVER: {
#ifdef _WIN32
		    static char reply[] =
			"NT Version: %s (%s)";
#else
		    static char reply[] =
			"Version: %s (%s), Pid: %d, Children: %d out of %d";
#endif
		    char buff[sizeof(reply)+sizeof(VERSION)+sizeof(RELDATE)+8];
		    struct iovec iov[2];

		    if (debug > 1)
			fprintf(stderr, "Got version request\n");

#ifdef _WIN32
		    sprintf(buff, reply, VERSION, RELDATE);
#else
		    sprintf(buff, reply, VERSION, RELDATE, getppid(),
			    child_count, child_max);
#endif
		    iov[1].iov_base = (caddr_t)buff;
		    iov[1].iov_len = (u_short)strlen(buff) + 1;
		    erpc_return(s, NULL, pid, 1, iov);
		    return(1);
		}

                default:
                    (void)erpc_reject(s, NULL, pid, CMJ_NOPROC, 0, 0);
	            if (debug)
		        {
                        fprintf(stderr,
			    "Message rejected: %x is an invalid rproc value.\n",
			    ntohs(ch->ch_rproc));
                        display(cbuff, cc);
	                }
                    break;  /* from switch (ch->ch_rproc) */

                }       /* switch(ntohs(ch->ch_rproc)) */
            }       /* for (;;) */
}       /* main() */


#ifdef SYS_V

/*
 * This function will parse the dump file name, validate it, and attempt to
 * create the necessary directories for the split name.  If anything goes
 * wrong, it will NOT delete the directories it created (they may be useful
 * later).
 */

split_name(name)
char *name;
{
	u_short netbyte[4];
	int i;
	char c;
	int error;

        if(debug)
	    fprintf(stderr,"Name '%s' should be split\n", name);

	for(i = 0; i < 4; ++i) netbyte[i] = 0;

	/* We know the name starts with "dump." and has no slashes. */

	name += strlen(DUMP_PREFIX);
	i = 0;

	while(c = *name++)
	    {
	    if(c >= '0' && c <= '9')
		{
	        netbyte[i] = netbyte[i] * 10 + (c - '0');
		if(netbyte[i] > 255)
		    return(-1);
		}
	    else if(c == '.')
		{
		if(++i >= 4)
		    return(-1);
		}
	    else
	        return(-1);
	    }

	sprintf(dir1, "dump");

	if(netbyte[0] < 128)		/* Class A */
	    {
	    sprintf(dir2, "dump/%d", netbyte[0]);
	    sprintf(split_filename, "dump/%d/%d.%d.%d",
		    netbyte[0], netbyte[1], netbyte[2], netbyte[3]);
	    }
	else if(netbyte[0] < 192)	/* Class B */
	    {
	    sprintf(dir2, "dump/%d.%d", netbyte[0], netbyte[1]);
	    sprintf(split_filename, "dump/%d.%d/%d.%d",
		    netbyte[0], netbyte[1], netbyte[2], netbyte[3]);
	    }
	else				/* Class C/D/E */
	    {
	    sprintf(dir2, "dump/%d.%d.%d", netbyte[0], netbyte[1], netbyte[2]);
	    sprintf(split_filename, "dump/%d.%d.%d/%d",
		    netbyte[0], netbyte[1], netbyte[2], netbyte[3]);
	    }

	if(debug)
	    fprintf(stderr,"split file name is '%s'\n", split_filename);


	/* Make sure directory #1 exists */

	error = make_a_dir(dir1);
	if(error != 0) return(error);

	/* Make sure directory #2 exists */

	error = make_a_dir(dir2);
	return(error);
	
}	/* split_name */

make_a_dir(name)
char *name;
{
	struct stat buf;
	int error;
#ifdef SYS_V_2
	char prefix[32];	/* Prefix part of pathname, starting with . */
	char newname[32];	/* Name built up for . and .. */
	char *b, *slash;
#endif

	/* See if it exists already */

	error = stat(name, &buf);
	if(error != -1) {
	    if(buf.st_mode & S_IFDIR)
		return(0);
	    else
		return(-1);
	    }

	/* Otherwise, try to create it */

#ifdef SYS_V
#ifndef SYS_V_2

	/* System V Release 3 has a BSD-like mkdir() call */

	error = mkdir(name, 0755);
	if(error == -1) {
	    if(debug)
		fprintf(stderr,"Error from mkdir of '%s': %d\n", name, errno);
	    }
#else /*SYS_V_2*/

	/* Older versions must do it by hand */

	error = mknod(name, S_IFDIR | 0755, 0);
	if(error == -1) {
	    if(debug)
		fprintf(stderr,"Error from mknod of '%s': %d\n", name, errno);
	    return(error);
	    }

	/* Make the links to ./ and ../ */

	(void)strcpy(newname, name);
	(void)strcat(newname, "/.");
	error = link(name, newname);
	if(error) {
	    if(debug)
		fprintf(stderr,"Error from link of '%s' to '%s': %d\n",
		    name, newname, errno);
	    return(error);
	    }

	slash = (char *)0;
	for(b = name; *b; ++b)
	    if(*b == '/')
		slash = b;
	if(slash) {
	    (void)strncpy(prefix, name, slash - name);
	    prefix[slash - name] = '\0';
	    }
	else
	    (void)strcpy(prefix, ".");

	(void)strcat(newname, ".");
	error = link(prefix, newname);
	if(error == -1) {
	    if(debug)
		fprintf(stderr,"Error from link of '%s' to '%s': %d\n",
		    prefix, newname, errno);
	    return(error);
	    }

#endif /*SYS_V_2*/
#endif /*SYS_V*/

	return(error);
}
#endif


