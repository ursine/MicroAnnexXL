/*****************************************************************************
 *
 *        Copyright 1997, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 *      Portable setproctitle routine to set process name
 *
 * Original Author: Berkeley
 *
 *****************************************************************************
 *
 * Copyright (c) 1988, 1993 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

#ifndef SPT_TYPE
#define SPT_TYPE SPT_NONE
#endif

#ifdef __FreeBSD_
# include <libutil.h> /* freebsd needs this */
#endif

/*
 * Tested under:
 *
 *  SunOS 4.1.3_U1 5 sun4m	(vulcan)
 *  FreeBSD 2.2.1		(dewline)
 *  Linux 2.0.29 i386		(asylum)
 *  SCO 3.2 2 i386		(scourge)
 *  SunOS 5.5.1 sun4m		(beaker)
 *  Ultrix 4.3 0 RISC		(vanna)
 *  HP-UX A.09.05		(hppo)
 *  OSF/1 V3.2 214 alpha	(alpha)
 *  AIX 2 4			(lacroix)
 *  BSDi (BSD/OS) 2.0.1		(pooh)
 * 
 */

/* OSF/1 (Digital Unix) for the Alpha will only show as much
 * proctitle as the length of the args passed to the program.
 * So, if you only type "erpcd" to start it, the proctitle will
 * never be longer than 5 characters. If you type "././././erpcd"
 * you then get 13, and "erpcd foobar" will give you 12.
 */

/*
 * If you're trying to make setproctitle work on an unsupported OS
 * SPT_REUSEARGV works more often than others.
 */

/* this is the string that gets put at the head of every proctitle	*/
#define PROCTITLEHEAD "erpcd: "

/* compiler doesn't understand const? */
# define const

#define SPACELEFT(buf, ptr) (sizeof buf - ((ptr) - buf))

/****************************************************************/

/*
 * Linux
 *  HASSNPRINTF = true
 *  SPT_TYPE = SPT_REUSEARGV
 * HP/UX
 *  SPT_TYPE = SPT_PSTAT
 * AIX
 *  SPT_PADCHAR = '\0'
 *  SPT_TYPE = SPT_REUSEARGV
 * DG/UX
 *  SPT_TYPE = SPT_NONE
 * ULTRIX
 *  SPT_TYPE = SPT_REUSEARGV
 * OSF/1
 *  SPT_TYPE = SPT_REUSEARGV
 * BSDi (BSD/OS)
 *  SPT_TYPE = SPT_BUILTIN	 (v 1.1 and later?)
 *  HASSNPRINTF = TRUE
 *  HASSTRERROR = TRUE
 *  link with -lutil
 * FreeBSD
 *  HASSNPRINTF = 1
 *  HASSTRERROR = 1
 *  SPT_TYPE = SPT_BUILTIN (2.2 and later?)
 *  Link with -lutil
 *  SPT_TYPE = SPT_REUSEARGV (other)
 * SCO
 *  SPT_TYPE = SPT_SCO
 * SEQUENT
 *  SPT_TYPE = SPT_NONE
 * APOLLO
 *  SPT_TYPE = SPT_NONE
 * NCR
 *  SPT_TYPE = SPT_NONE
 * SOLARIs
 *  SPT_TYPE = SPT_REUSEARGV
 * SUNOS
 *  SPT_TYPE = SPT_REUSEARGV
 */

#ifdef __bsdi__
# if defined(_BSDI_VERSION) && _BSDI_VERSION <= 199312 /* Before v 1.1 */
#  undef SPT_TYPE
#  define SPT_TYPE	SPT_REUSEARGV
# endif
#endif

#if defined(__FreeBSD__)
# if __FreeBSD__ == 2
#  include <osreldate.h>		/* and this works */
#  if __FreeBSD_version >= 199512	/* 2.2-current right now */
#   undef SPT_TYPE
#   define SPT_TYPE	SPT_BUILTIN
#  endif
# endif
#endif


#if defined(__STDC__) || defined(__cplusplus)
# ifndef __P
#  define	__P(protos)	protos		/* full-blown ANSI C */
# endif
#define	__STRING(x)	#x

#define	__const		const		/* define reserved names to standard */
#define	__signed	signed
#define	__volatile	volatile
#if defined(__cplusplus)
#define	__inline	inline		/* convert to C++ keyword */
#else
#ifndef __GNUC__
#define	__inline			/* delete GCC keyword */
#endif /* !__GNUC__ */
#endif /* !__cplusplus */

#else	/* !(__STDC__ || __cplusplus) */
#define	__P(protos)	()		/* traditional C preprocessor */
/*#define	__CONCAT(x,y)	x/ ** /y*/
#define	__STRING(x)	"x"

#ifndef __GNUC__
#define	__const				/* delete pseudo-ANSI C keywords */
#define	__inline
#define	__signed
#define	__volatile

/*
 * In non-ANSI C environments, new programs will want ANSI-only C keywords
 * deleted from the program and old programs will want them left alone.
 * When using a compiler other than gcc, programs using the ANSI C keywords
 * const, inline etc. as normal identifiers should define -DNO_ANSI_KEYWORDS.
 * When using "gcc -traditional", we assume that this is the intent; if
 * __GNUC__ is defined but __STDC__ is not, we leave the new keywords alone.
 */
#ifndef	NO_ANSI_KEYWORDS
#define	const				/* delete ANSI C keywords */
#define	inline
#define	signed
#define	volatile
#endif
#endif	/* !__GNUC__ */
#endif	/* !(__STDC__ || __cplusplus) */

/****************************************************************/

/*
 *  Arrange to use either varargs or stdargs
 */

# ifdef __STDC__

# include <stdarg.h>

# define VA_LOCAL_DECL	va_list ap;
# define VA_START(f)	va_start(ap, f)
# define VA_END		va_end(ap)

# else

# include <varargs.h>

# define VA_LOCAL_DECL	va_list ap;
# define VA_START(f)	va_start(ap)
# define VA_END		va_end(ap)

# endif

/* should be defines in <paths.h> */
#ifndef _PATH_KMEM
#define _PATH_KMEM "/dev/kmem"
#endif

/*
**  SETPROCTITLE -- set process title for ps
**
**	Parameters:
**		fmt -- a printf style format string.
**		a, b, c -- possible parameters to fmt.
**
**	Returns:
**		none.
**
**	Side Effects:
**		Clobbers argv of our main procedure so ps(1) will
**		display the title.
*/

#define MAXLINE 2048

#define SPT_NONE	0	/* don't use it at all */
#define SPT_REUSEARGV	1	/* cover argv with title information */
#define SPT_BUILTIN	2	/* use libc builtin */
#define SPT_PSTAT	3	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_PSSTRINGS	4	/* use PS_STRINGS->... */
#define SPT_SYSMIPS	5	/* use sysmips() supported by NEWS-OS 6 */
#define SPT_SCO		6	/* write kernel u. area */
#define SPT_CHANGEARGV	7	/* write our own strings into argv[] */

#if SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN

# if SPT_TYPE == SPT_PSTAT
#  include <sys/pstat.h>
# endif
# if SPT_TYPE == SPT_PSSTRINGS
#  include <machine/vmparam.h>
#  include <sys/exec.h>
#  ifndef PS_STRINGS	/* hmmmm....  apparently not available after all */
#   undef SPT_TYPE
#   define SPT_TYPE	SPT_REUSEARGV
#  else
#   ifndef NKPDE			/* FreeBSD 2.0 */
#    define NKPDE 63
typedef unsigned int	*pt_entry_t;
#   endif
#  endif
# endif

# if SPT_TYPE == SPT_PSSTRINGS || SPT_TYPE == SPT_CHANGEARGV
#  define SETPROC_STATIC	static
# else
#  define SETPROC_STATIC
# endif

# if SPT_TYPE == SPT_SYSMIPS
#  include <sys/sysmips.h>
#  include <sys/sysnews.h>
# endif

# if SPT_TYPE == SPT_SCO
#  include <sys/immu.h>
#  include <sys/dir.h>
#  include <sys/user.h>
#  include <sys/fs/s5param.h>
#  if PSARGSZ > MAXLINE
#   define SPT_BUFSIZE	PSARGSZ
#  endif
# endif

# ifndef SPT_PADCHAR
#  define SPT_PADCHAR	' '
# endif

# ifndef SPT_BUFSIZE
#  define SPT_BUFSIZE	MAXLINE
# endif

#endif /* SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN */

/*
**  Pointers for setproctitle.
**	This allows "ps" listings to give more useful information.
*/

char		**Argv = NULL;		/* pointer to argument vector */
char		*LastArgv = NULL;	/* end of argv */

#if SPT_TYPE != SPT_NONE

char	*
newstr(s)
char	*s;
{
    char	*p;

    if ((p = malloc(strlen(s) + 1)) == NULL)
	return NULL;

    strcpy(p, s);
    return p;
}
#endif

void
initsetproctitle(argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
#if SPT_TYPE != SPT_NONE

	register int i;
	extern char **environ;

	/*
	**  Move the environment so setproctitle can use the space at
	**  the top of memory.
	*/

	for (i = 0; envp[i] != NULL; i++)
		continue;
	environ = (char **) malloc(sizeof (char *) * (i + 1));
	if (environ == NULL)
	    return;	/* properly handle this failure! - mason	*/
	for (i = 0; envp[i] != NULL; i++)
		environ[i] = newstr(envp[i]);
	environ[i] = NULL;

	/*
	**  Save start and extent of argv for setproctitle.
	*/

	Argv = argv;
	if (i > 0)
		LastArgv = envp[i - 1] + strlen(envp[i - 1]);
	else
		LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
#endif	/* SPT_TYPE != SPT_NONE	*/
}

#if SPT_TYPE != SPT_BUILTIN


/*VARARGS1*/
void
# ifdef __STDC__
setproctitle(const char *fmt, ...)
# else
setproctitle(fmt, va_alist)
	const char *fmt;
	va_dcl
# endif
{
# if SPT_TYPE != SPT_NONE
	register char *p;
	register int i;
	SETPROC_STATIC char buf[SPT_BUFSIZE];
	VA_LOCAL_DECL
#  if SPT_TYPE == SPT_PSTAT
	union pstun pst;
#  endif
#  if SPT_TYPE == SPT_SCO
	off_t seek_off;
	static int kmem = -1;
	static int kmempid = -1;
	struct user u;
#  endif

	p = buf;

	/* print sendmail: heading for grep */
	(void) strcpy(p, PROCTITLEHEAD);
	p += strlen(p);

	/* print the argument string */
	VA_START(fmt);
	(void) vsnprintf(p, SPACELEFT(buf, p), fmt, ap);
	VA_END;

	i = strlen(buf);

#  if SPT_TYPE == SPT_PSTAT
	pst.pst_command = buf;
	pstat(PSTAT_SETCMD, pst, i, 0, 0);
#  endif
#  if SPT_TYPE == SPT_PSSTRINGS
	PS_STRINGS->ps_nargvstr = 1;
	PS_STRINGS->ps_argvstr = buf;
#  endif
#  if SPT_TYPE == SPT_SYSMIPS
	sysmips(SONY_SYSNEWS, NEWS_SETPSARGS, buf);
#  endif
#  if SPT_TYPE == SPT_SCO
	if (kmem < 0 || kmempid != getpid())
	{
		if (kmem >= 0)
			close(kmem);
		kmem = open(_PATH_KMEM, O_RDWR, 0);
		if (kmem < 0)
			return;
		(void) fcntl(kmem, F_SETFD, 1);
		kmempid = getpid();
	}
	buf[PSARGSZ - 1] = '\0';
	seek_off = UVUBLK + (off_t) u.u_psargs - (off_t) &u;
	if (lseek(kmem, (off_t) seek_off, SEEK_SET) == seek_off)
		(void) write(kmem, buf, PSARGSZ);
#  endif
#  if SPT_TYPE == SPT_REUSEARGV
	if (i > LastArgv - Argv[0] - 2)
	{
		i = LastArgv - Argv[0] - 2;
		buf[i] = '\0';
	}
	(void) strcpy(Argv[0], buf);
	p = &Argv[0][i];
	while (p < LastArgv)
		*p++ = SPT_PADCHAR;
	Argv[1] = NULL;
#  endif
#  if SPT_TYPE == SPT_CHANGEARGV
	Argv[0] = buf;
	Argv[1] = 0;
#  endif
# endif /* SPT_TYPE != SPT_NONE */
}

#endif /* SPT_TYPE != SPT_BUILTIN */


#if SPT_TYPE != SPT_NONE

/*
**  SNPRINTF, VSNPRINT -- counted versions of printf
**
**	These versions have been grabbed off the net.  They have been
**	cleaned up to compile properly and support for .precision and
**	%lx has been added.
*/

/**************************************************************
 * Original:
 * Patrick Powell Tue Apr 11 09:48:21 PDT 1995
 * A bombproof version of doprnt (sm_dopr) included.
 * Sigh.  This sort of thing is always nasty do deal with.  Note that
 * the version here does not include floating point...
 *
 * snprintf() is used instead of sprintf() as it does limit checks
 * for string length.  This covers a nasty loophole.
 *
 * The other functions are there to prevent NULL pointers from
 * causing nast effects.
 **************************************************************/

/*static char _id[] = "$Id: snprintf.c,v 1.2 1995/10/09 11:19:47 roberto Exp $";*/
static void	sm_dopr();
static char	*DoprEnd;
static int	SnprfOverflow;

#if !HASSNPRINTF

/* VARARGS3 */
int
# ifdef __STDC__
snprintf(char *str, size_t count, const char *fmt, ...)
# else
snprintf(str, count, fmt, va_alist)
	char *str;
	size_t count;
	const char *fmt;
	va_dcl
#endif
{
	int len;
	VA_LOCAL_DECL

	VA_START(fmt);
	len = vsnprintf(str, count, fmt, ap);
	VA_END;
	return len;
}


# ifndef luna2
int
vsnprintf(str, count, fmt, args)
	char *str;
	size_t count;
	const char *fmt;
	va_list args;
{
	str[0] = 0;
	DoprEnd = str + count - 1;
	SnprfOverflow = 0;
	sm_dopr( str, fmt, args );
	if (count > 0)
		DoprEnd[0] = 0;
#if 0
mason
	if (SnprfOverflow && tTd(57, 2))
		printf("\nvsnprintf overflow, len = %d, str = %s",
			count, shortenstring(str, 203));
#endif
	return strlen(str);
}

# endif /* !luna2 */
#endif /* !HASSNPRINTF */

/*
 * sm_dopr(): poor man's version of doprintf
 */

static void fmtstr __P((char *value, int ljust, int len, int zpad, int maxwidth));
static void fmtnum __P((long value, int base, int dosign, int ljust, int len, int zpad));
static void dostr __P(( char * , int ));
static char *output;
static void dopr_outch __P(( int c ));
static int	SyslogErrno;

static void
sm_dopr( buffer, format, args )
       char *buffer;
       const char *format;
       va_list args;
{
       int ch;
       long value;
       int longflag  = 0;
       int pointflag = 0;
       int maxwidth  = 0;
       char *strvalue;
       int ljust;
       int len;
       int zpad;
# if !HASSTRERROR && !defined(ERRLIST_PREDEFINED)
	extern char *sys_errlist[];
	extern int sys_nerr;
# endif


       output = buffer;
       while( (ch = *format++) ){
	       switch( ch ){
	       case '%':
		       ljust = len = zpad = maxwidth = 0;
		       longflag = pointflag = 0;
	       nextch:
		       ch = *format++;
		       switch( ch ){
		       case 0:
			       dostr( "**end of format**" , 0);
			       return;
		       case '-': ljust = 1; goto nextch;
		       case '0': /* set zero padding if len not set */
			       if(len==0 && !pointflag) zpad = '0';
		       case '1': case '2': case '3':
		       case '4': case '5': case '6':
		       case '7': case '8': case '9':
			       if (pointflag)
				 maxwidth = maxwidth*10 + ch - '0';
			       else
				 len = len*10 + ch - '0';
			       goto nextch;
		       case '*': 
			       if (pointflag)
				 maxwidth = va_arg( args, int );
			       else
				 len = va_arg( args, int );
			       goto nextch;
		       case '.': pointflag = 1; goto nextch;
		       case 'l': longflag = 1; goto nextch;
		       case 'u': case 'U':
			       /*fmtnum(value,base,dosign,ljust,len,zpad) */
			       if( longflag ){
				       value = va_arg( args, long );
			       } else {
				       value = va_arg( args, int );
			       }
			       fmtnum( value, 10,0, ljust, len, zpad ); break;
		       case 'o': case 'O':
			       /*fmtnum(value,base,dosign,ljust,len,zpad) */
			       if( longflag ){
				       value = va_arg( args, long );
			       } else {
				       value = va_arg( args, int );
			       }
			       fmtnum( value, 8,0, ljust, len, zpad ); break;
		       case 'd': case 'D':
			       if( longflag ){
				       value = va_arg( args, long );
			       } else {
				       value = va_arg( args, int );
			       }
			       fmtnum( value, 10,1, ljust, len, zpad ); break;
		       case 'x':
			       if( longflag ){
				       value = va_arg( args, long );
			       } else {
				       value = va_arg( args, int );
			       }
			       fmtnum( value, 16,0, ljust, len, zpad ); break;
		       case 'X':
			       if( longflag ){
				       value = va_arg( args, long );
			       } else {
				       value = va_arg( args, int );
			       }
			       fmtnum( value,-16,0, ljust, len, zpad ); break;
		       case 's':
			       strvalue = va_arg( args, char *);
			       if (maxwidth > 0 || !pointflag) {
				 if (pointflag && len > maxwidth)
				   len = maxwidth; /* Adjust padding */
				 fmtstr( strvalue,ljust,len,zpad, maxwidth);
			       }
			       break;
		       case 'c':
			       ch = va_arg( args, int );
			       dopr_outch( ch ); break;
                       case 'm':
#if HASSTRERROR
                               dostr(strerror(SyslogErrno), 0);
#else
                               if (SyslogErrno < 0 || SyslogErrno > sys_nerr) 
                               {
                                   dostr("Error ", 0);
                                   fmtnum(SyslogErrno, 10, 0, 0, 0, 0);
                               }
                               else 
                                   dostr(sys_errlist[SyslogErrno], 0);
#endif
			       break;

		       case '%': dopr_outch( ch ); continue;
		       default:
			       dostr(  "???????" , 0);
		       }
		       break;
	       default:
		       dopr_outch( ch );
		       break;
	       }
       }
       *output = 0;
}

static void
fmtstr(  value, ljust, len, zpad, maxwidth )
       char *value;
       int ljust, len, zpad, maxwidth;
{
       int padlen, strlen;     /* amount to pad */

       if( value == 0 ){
	       value = "<NULL>";
       }
       for( strlen = 0; value[strlen]; ++ strlen ); /* strlen */
       if (strlen > maxwidth && maxwidth)
	 strlen = maxwidth;
       padlen = len - strlen;
       if( padlen < 0 ) padlen = 0;
       if( ljust ) padlen = -padlen;
       while( padlen > 0 ) {
	       dopr_outch( ' ' );
	       --padlen;
       }
       dostr( value, maxwidth );
       while( padlen < 0 ) {
	       dopr_outch( ' ' );
	       ++padlen;
       }
}

static void
fmtnum(  value, base, dosign, ljust, len, zpad )
       long value;
       int base, dosign, ljust, len, zpad;
{
       int signvalue = 0;
       unsigned long uvalue;
       char convert[20];
       int place = 0;
       int padlen = 0; /* amount to pad */
       int caps = 0;

       /* DEBUGP(("value 0x%x, base %d, dosign %d, ljust %d, len %d, zpad %d\n",
	       value, base, dosign, ljust, len, zpad )); */
       uvalue = value;
       if( dosign ){
	       if( value < 0 ) {
		       signvalue = '-';
		       uvalue = -value;
	       }
       }
       if( base < 0 ){
	       caps = 1;
	       base = -base;
       }
       do{
	       convert[place++] =
		       (caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
	       uvalue = (uvalue / (unsigned)base );
       }while(uvalue);
       convert[place] = 0;
       padlen = len - place;
       if( padlen < 0 ) padlen = 0;
       if( ljust ) padlen = -padlen;
       /* DEBUGP(( "str '%s', place %d, sign %c, padlen %d\n",
	       convert,place,signvalue,padlen)); */
       if( zpad && padlen > 0 ){
	       if( signvalue ){
		       dopr_outch( signvalue );
		       --padlen;
		       signvalue = 0;
	       }
	       while( padlen > 0 ){
		       dopr_outch( zpad );
		       --padlen;
	       }
       }
       while( padlen > 0 ) {
	       dopr_outch( ' ' );
	       --padlen;
       }
       if( signvalue ) dopr_outch( signvalue );
       while( place > 0 ) dopr_outch( convert[--place] );
       while( padlen < 0 ){
	       dopr_outch( ' ' );
	       ++padlen;
       }
}

static void
dostr( str , cut)
     char *str;
     int cut;
{
  if (cut) {
    while(*str && cut-- > 0) dopr_outch(*str++);
  } else {
    while(*str) dopr_outch(*str++);
  }
}

static void
dopr_outch( c )
       int c;
{
#if 0
       if( iscntrl(c) && c != '\n' && c != '\t' ){
	       c = '@' + (c & 0x1F);
	       if( DoprEnd == 0 || output < DoprEnd )
		       *output++ = '^';
       }
#endif
       if( DoprEnd == 0 || output < DoprEnd )
	       *output++ = c;
       else
		SnprfOverflow++;
}

char	*
ipaddr_string(a)
int	a;
{
    static	char	s[18];

    sprintf(s, "%d.%d.%d.%d",
	(a >> 24) & 0xFF,
	(a >> 16) & 0xFF,
	(a >>  8) & 0xFF,
	(a >>  0) & 0xFF);

    return s;
}

#endif	/* SPT_TYPE != SPT_NONE	*/

#ifdef SPT_DEBUG

main(argc, argv, envp)
int	argc;
char	**argv;
char	**envp;
{

    initsetproctitle(argc, argv, envp);

    setproctitle("%s", "breaker one-nine!");

    sleep(60);
}


#endif
