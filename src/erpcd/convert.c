/*
 *****************************************************************************
 *
 *        Copyright 1993, Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Description::
 *
 * 	Convert back and forth between BSD passwd and AT&T
 *	passwd/shadow forms.
 *
 * Original Author: James Carlson	Created on: 20JAN93
 *
 * Module Reviewers:
 *
 *	%$(reviewers)$%
 *
 *****************************************************************************
 */


/*
 * Convert the password file between its various forms.
 * This program should not be suid!  It should be used by the owner with
 * write permission on both acp_passwd and acp_shadow, or by root.
 */

/*
 *	Include Files
 */
#include "../inc/config.h"
#include "../inc/vers.h"

#include "port/port.h"
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>

#include "../libannex/srpc.h"
#include "port/install_dir.h"
#include "acp_policy.h"

#ifdef USESHADOW
#ifdef NATIVESHADOW
#include <shadow.h>
#else
#include <ashadow.h>
#endif
#endif

int	debug = 0;	/* global needed for functions in env_parser.c */

char *myname;
char *install_dir = INSTALL_DIR;

#ifndef NATIVEPASSWD
#ifndef NATIVESHADOW
#ifdef USESHADOW

extern int errno;

#define MAXUNAMES	32

char *unames[MAXUNAMES];
int ucount = 0;
INT32 today;

typedef struct passwd_entry PasswdEntry;
typedef struct shadow_entry ShadowEntry;

struct passwd_entry {
    PasswdEntry *next;
    struct passwd passwd;
};

struct shadow_entry {
    ShadowEntry *next;
    struct spwd spwd;
};

PasswdEntry *passwd_root = NULL;
ShadowEntry *shadow_root = NULL,*shadow_tail = NULL;

int
check_uname(nam)
char *nam;
{
    int i;

    for (i = 0; i < ucount; i++)
	if (strcmp(nam,unames[i]) == 0)
	    return 1;
    return 0;
}

int
read_in_passwd()
{
    struct passwd *pwd;
    PasswdEntry *newent,*last;
    int namelen,passlen,geclen,dirlen;

    if (setacppw(NULL)) {          
	if (errno == ENOENT)
	    return 0;
	perror(passwd_name);
	return 1;
    }
    last = (PasswdEntry *)NULL;
    while ((pwd = getacppw()) != NULL) {
	namelen = strlen(pwd->pw_name);
	passlen = strlen(pwd->pw_passwd);
	geclen = strlen(pwd->pw_gecos);
	dirlen = strlen(pwd->pw_dir);
	newent = (PasswdEntry *)malloc(sizeof(PasswdEntry) +
	    namelen+passlen+geclen+dirlen + strlen(pwd->pw_shell) + 5);
	if (newent == (PasswdEntry *)NULL) {
	    perror("read_in_passwd");
	    return 1;
	}
	if (last != (PasswdEntry *)NULL)
	    last->next = newent;
	else
	    passwd_root = newent;
	newent->passwd = *pwd;
	newent->next = (PasswdEntry *)NULL;
	newent->passwd.pw_name = (char *)(newent+1);
	strcpy(newent->passwd.pw_name,pwd->pw_name);
	newent->passwd.pw_passwd = newent->passwd.pw_name+namelen+1;
	strcpy(newent->passwd.pw_passwd,pwd->pw_passwd);
	newent->passwd.pw_gecos = newent->passwd.pw_passwd+passlen+1;
	strcpy(newent->passwd.pw_gecos,pwd->pw_gecos);
	newent->passwd.pw_dir = newent->passwd.pw_gecos+geclen+1;
	strcpy(newent->passwd.pw_dir,pwd->pw_dir);
	newent->passwd.pw_shell = newent->passwd.pw_dir+dirlen+1;
	strcpy(newent->passwd.pw_shell,pwd->pw_shell);
	last = newent;
    }
    endacppw();
    return 0;
}

int
read_in_shadow()
{
    struct spwd *spw;
    ShadowEntry *newent;
    int namelen;

    if (setacpsp()) {
		if (errno == ENOENT)
		    return 0;
		perror(shadow_name);
		return 1;
    }
    while ((spw = getacpsp()) != NULL) {
	namelen = strlen(spw->sp_namp);
	newent = (ShadowEntry *)malloc(sizeof(ShadowEntry) +
	    namelen + strlen(spw->sp_pwdp) + 2);
	if (newent == (ShadowEntry *)NULL) {
	    perror("read_in_shadow");
	    return 1;
	}
	if (shadow_tail != (ShadowEntry *)NULL)
	    shadow_tail->next = newent;
	else
	    shadow_root = newent;
	newent->spwd = *spw;
	newent->next = (ShadowEntry *)NULL;
	newent->spwd.sp_namp = (char *)(newent+1);
	strcpy(newent->spwd.sp_namp,spw->sp_namp);
	newent->spwd.sp_pwdp = newent->spwd.sp_namp+namelen+1;
	strcpy(newent->spwd.sp_pwdp,spw->sp_pwdp);
	shadow_tail = newent;
    }
    endacpsp();
    return 0;
}

ShadowEntry *
add_shadow_entry()
{
    ShadowEntry *newent;

    newent = (ShadowEntry *)malloc(sizeof(ShadowEntry));
    if (newent == (ShadowEntry *)NULL)
	perror("add_shadow_entry");
    else {
	bzero(newent,sizeof(*newent));
	if (shadow_tail != (ShadowEntry *)NULL)
	    shadow_tail->next = newent;
	else
	    shadow_root = newent;
	newent->spwd.sp_namp = newent->spwd.sp_pwdp = "";
	newent->next = (ShadowEntry *)NULL;
	shadow_tail = newent;
    }
    return newent;
}

ShadowEntry *
check_shadow(nam,pass)
char *nam,*pass;
{
    ShadowEntry *she;

    for (she = shadow_root; she != NULL; she = she->next)
	if (strcmp(she->spwd.sp_namp,nam) == 0 &&
	    (pass == NULL || strcmp(she->spwd.sp_pwdp,pass) == 0))
	    break;
    return she;
}

void
convert_to_shadow()
{
    FILE *pwdout,*shout;
    PasswdEntry *pwd;
    ShadowEntry *she;
    char line[256];
    INT32 shoff,pwoff;

    if (lckacpf()) {
	fprintf(stderr,"%s:  Unable to lock password file.\n",myname);
	exit(1);
    }

    /* Password file should be globally readable. */
    (void)umask(0333);
    if ((pwdout = fopen(ptmp_name,"w+")) == NULL) {
	if (errno == EEXIST) {
	    fprintf(stderr,"%s:  Temporary file already exists.\n",
		myname);
	    fprintf(stderr,"Remove %s to continue.\n",ptmp_name);
	} else
	    perror(ptmp_name);
	(void)ulckacpf();
	exit(1);
    }

    /* Shadow file should readable by root only. */
    (void)umask(0377);
    unlink(stmp_name);
    if ((shout = fopen(stmp_name,"w+")) == NULL) {
	perror(stmp_name);
	goto error_exit;
    }

    if (read_in_passwd())
	goto error_exit;
    if (read_in_shadow())
	goto error_exit;

    for (pwd = passwd_root; pwd != NULL; pwd = pwd->next) {

    /* If we should be looking at this entry, then examine it. */
	if (ucount == 0 || check_uname(pwd->passwd.pw_name)) {

	/* If it's set to use a shadow password, then check that. */
	    if (strcmp(pwd->passwd.pw_passwd,"x") == 0) {

	    /* If no shadow password is there, then lock it out. */
	    /* Otherwise, keep current shadow entry. */
		if (check_shadow(pwd->passwd.pw_name,NULL) == NULL) {
		    she = add_shadow_entry();
		    if (she != NULL) {
			she->spwd.sp_namp = pwd->passwd.pw_name;
			she->spwd.sp_pwdp = "NONE";
			she->spwd.sp_lstchg = today;
		    }
		}

/* Convert over existing passwd entry to shadow entry, if none yet. */
	    } else if (check_shadow(pwd->passwd.pw_name,
		pwd->passwd.pw_passwd) == NULL) {
		she = add_shadow_entry();
		if (she != NULL) {
		    she->spwd.sp_namp = pwd->passwd.pw_name;
		    she->spwd.sp_pwdp = pwd->passwd.pw_passwd;
		    she->spwd.sp_lstchg = today;
		    pwd->passwd.pw_passwd = "x";
		}
	    }
	}
	if (write_out_passwd(pwdout,&pwd->passwd) < 0)
	    goto error_exit;
    }

    for (she = shadow_root; she != NULL; she = she->next)
	if (write_out_shadow(shout,&she->spwd) < 0) {
	    perror(stmp_name);
	    goto error_exit;
	}

    shoff = ftell(shout);
    pwoff = ftell(pwdout);

    if (fclose(shout)) {
	perror(stmp_name);
	shout = NULL;
	goto error_exit;
    }
    shout = NULL;
    if (fclose(pwdout)) {
	perror(ptmp_name);
	pwdout = NULL;
	goto error_exit;
    }
    pwdout = NULL;

    if (shoff == 0) {
	printf("No data in new shadow file; removing it.\n");
	unlink(stmp_name);
    } else if (rename(stmp_name,shadow_name)) {
	perror(shadow_name);
	goto error_exit;
    }
    if (pwoff == 0) {
	printf("No data in new password file; removing it.\n");
	unlink(passwd_name);
	unlink(ptmp_name);
    } else if (rename(ptmp_name,passwd_name)) {
	perror(passwd_name);
	goto error_exit;
    }

    if (shoff == 0)
	unlink(shadow_name);

    if (ulckacpf())
	fprintf(stderr,"%s:  Unable to unlock password file.\n",myname);

    return;

error_exit:
    if (shout != NULL)
	fclose(shout);
    if (pwdout != NULL)
	fclose(pwdout);
    unlink(stmp_name);
    unlink(ptmp_name);
    (void)ulckacpf();
    exit(1);
}

void
remove_shadow(she)
ShadowEntry *she;
{
	ShadowEntry *sp;

	if (she == shadow_root)
		shadow_root = she->next;
	else for (sp = shadow_root; sp != NULL; sp = sp->next)
		if (sp->next == she) {
			sp->next = she->next;
			break;
		}
}

PasswdEntry *
check_passwd(nam)
char *nam;
{
	PasswdEntry *pwd;

	for (pwd = passwd_root; pwd != NULL; pwd = pwd->next)
		if (strcmp(pwd->passwd.pw_name,nam) == 0)
			break;
	return pwd;
}

void
convert_from_shadow()
{
    FILE *pwdout;
    PasswdEntry *pwd;
    ShadowEntry *she;
    INT32 pwoff;

    if (lckacpf()) {
	fprintf(stderr,"%s:  Unable to lock password file.\n",myname);
	exit(1);
    }

    /* Password file should be globally readable. */
    (void)umask(0333);
    if ((pwdout = fopen(ptmp_name,"w+")) == NULL) {
	if (errno == EEXIST) {
	    fprintf(stderr,"%s:  Temporary file already exists.\n",
		myname);
	    fprintf(stderr,"Remove %s to continue.\n",ptmp_name);
	} else
	    perror(ptmp_name);
	(void)ulckacpf();
	exit(1);
    }

    if (read_in_passwd())
	goto error_exit;
    if (read_in_shadow())
	goto error_exit;

    for (pwd = passwd_root; pwd != NULL; pwd = pwd->next) {

    /* If we should be looking at this entry, then examine it. */
	if (ucount == 0 || check_uname(pwd->passwd.pw_name)) {

	/* If it's set to use a shadow password, then check that. */
	    if (strcmp(pwd->passwd.pw_passwd,"x") == 0) {

	    /* If there's a shadow entry, then copy out the password. */
		she = check_shadow(pwd->passwd.pw_name,NULL);
		if (she != NULL) {
		    pwd->passwd.pw_passwd = she->spwd.sp_pwdp;
		    remove_shadow(she);
		}
	    }
	}
	if (write_out_passwd(pwdout,&pwd->passwd) < 0)
	    goto error_exit;
    }

/*
 * Look through the remaining shadow entries.  Those that are named in
 * the passwd file should be written as duplicate entries now.  Those
 * that aren't wouldn't have been accessible to the system anyway, so
 * they are ignored.
 */
    for (she = shadow_root; she != NULL; she = she->next) {
	if ((pwd = check_passwd(she->spwd.sp_namp)) != NULL) {
	    pwd->passwd.pw_passwd = she->spwd.sp_pwdp;
	    if (write_out_passwd(pwdout,&pwd->passwd) < 0)
		goto error_exit;
	} else
	    printf("Dropping user %s -- in shadow file only.\n",
		she->spwd.sp_namp);
    }

    pwoff = ftell(pwdout);

    if (fclose(pwdout)) {
	perror(ptmp_name);
	pwdout = NULL;
	goto error_exit;
    }
    pwdout = NULL;

    if (pwoff == 0) {
	printf("No data in new password file; removing it.\n");
	unlink(passwd_name);
	unlink(ptmp_name);
    } else if (rename(ptmp_name,passwd_name)) {
	perror(passwd_name);
	goto error_exit;
    }

    if (ulckacpf())
	fprintf(stderr,"%s:  Unable to unlock password file.\n",myname);

    return;

error_exit:
    if (pwdout != NULL)
	fclose(pwdout);
    unlink(ptmp_name);
    (void)ulckacpf();
    exit(1);
}

#endif /* USESHADOW */
#endif /* !NATIVESHADOW */
#endif /* !NATIVEPASSWD */

void
usage()
{
    fprintf(stderr,"Usage:\n\t%s [-v] -fr [users...]\n\n",myname);
    fprintf(stderr,"\t-v\t\t- print software version number and exit.\n");
    fprintf(stderr,"\t-f\t\t- convert BSD passwd to shadow and passwd files.\n");
    fprintf(stderr,"\t-r\t\t- convert back from shadow to BSD passwd file.\n");
    fprintf(stderr,"\t[users...]\t- convert only named users.\n");
    exit(1);
}

int
main(argc, argv)
int argc;
char **argv;
{
    char *cp,chr;
    int forwardmode = 0,reversemode = 0;

    myname = *argv++;
    argc--;

#ifdef NATIVEPASSWD
    return fprintf(stderr,
	"%s:  Should not change system passwd file!\n",myname);
#else /* !NATIVEPASSWD */
#ifdef NATIVESHADOW
    return fprintf(stderr,
	"%s:  Should not change system shadow file!\n",myname);
#else /* !NATIVESHADOW */
#ifndef USESHADOW
    return fprintf(stderr,
	"%s:  Compiled without access to shadow file!\n",
	myname);
#else /* USESHADOW */
    today = DAY_NOW;

#ifndef NATIVEPASSWD
    ACP_PASSWD(passwd_name);

    ACP_PTMP(ptmp_name);

    ACP_LOCKFILE(lock_name);
#else
    ACP_NATIVEPASSWD(passwd_name);
    ACP_NATIVEPTMP(ptmp_name);
    ACP_NATIVELOCKFILE(lock_name);
#endif /* !NATIVEPASSWD */
    
#ifndef NATIVESHADOW
    ACP_SHADOW(shadow_name);
    ACP_STMP(stmp_name);
#else
    ACP_NATIVESHADOW(shadow_name);
    ACP_NATIVESTMP(stmp_name);
#endif /* !NATIVESHADOW */

    while (argc > 0) {
	if ((cp = *argv++) == NULL)
	    break;
	argc--;
	if (*cp == '-') {
	    if (*++cp == '\0') {
		fprintf(stderr,
		    "%s:  Illegal switch format.\n",
		    myname);
		usage();
	    }
	    while ((chr = *cp++) != '\0') switch (chr) {
	    case 'f':
		forwardmode = 1;
		break;
	    case 'r':
		reversemode = 1;
		break;
	    case 'v':
		printf("convert host tool version %s, released %s\n",
		       VERSION,RELDATE);
		exit(0);
		break;
	    default:
		fprintf(stderr,"%s:  Unknown switch -- %c.\n",
		    myname,chr);
		usage();
	    }
	} else if (ucount < MAXUNAMES)
	    unames[ucount++] = cp;
	else {
	    fprintf(stderr,
		"%s:  Too many user names specified (%d max).\n",
		myname,MAXUNAMES);
	    usage();
	}
    }

    if (forwardmode+reversemode != 1)
	usage();

    if (forwardmode)
	convert_to_shadow();
    else
	convert_from_shadow();

    return 0;
#endif /* USESHADOW */
#endif /* !NATIVESHADOW */
#endif /* !NATIVEPASSWD */
}
