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
 * Module Description::
 *
 * 	%$(Description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 * Module Reviewers:
 *
 *	%$(reviewers)$%
 *
 *****************************************************************************
 */


/*
 *	Include Files
 */

#include "../inc/config.h"
#include "../inc/port/port.h"
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <syslog.h>
#include "../libannex/srpc.h"
#include "port/install_dir.h"
#include "acp_policy.h"

#ifdef USENATIVESHADOW
#include <shadow.h>
#else
#include <ashadow.h>
#endif

char passwd_name[PATHSZ],ptmp_name[PATHSZ];
char shadow_name[PATHSZ],stmp_name[PATHSZ];
char lock_name[PATHSZ];

extern int errno;

static char *
pwskip(p)
register char *p;
{
	register char pc;

	while ((pc = *p) != '\0')
		if (pc == ':' || pc == '\n' || pc == ',') {
			*p++ = '\0';
			break;
		} else
			p++;
	return(p);
}


static FILE *pwf = NULL;

int
setacppw(alt_passwd)
char *alt_passwd;
{
   	char *passwd_file = passwd_name;

        /* Check if the alternate file should be used */
	if (alt_passwd)
        {
           passwd_file = alt_passwd;
	}
      	else
	{
	   /* Use default file */
   	   passwd_file = passwd_name;
	}

	if (pwf != NULL) {
		rewind(pwf);
		return 0;
	}

	pwf = fopen(passwd_file,"r");
	if (pwf != NULL)
		return 0;
	syslog(LOG_ERR, "Could not open passwd_file: %s", passwd_file);
	return -1;
}

void
endacppw()
{
	if (pwf != NULL) {
		fclose(pwf);
		pwf = NULL;
	}
}

struct passwd *
getacppw()
{
	register char *p;
	static struct passwd passwd;
	static char line[BUFSIZ+1];

	if (pwf == NULL && setacppw(NULL) != 0) 
		return (struct passwd *)NULL;
	p = fgets(line, BUFSIZ, pwf);
	if (p == NULL)
		return (struct passwd *)NULL;
	line[BUFSIZ] = '\0';
	passwd.pw_name = p;
	p = pwskip(p);
	passwd.pw_passwd = p;
	p = pwskip(p);
	passwd.pw_uid = atoi(p);
	p = pwskip(p);
	passwd.pw_gid = atoi(p);

	/* comment and quota bypassed for compatibility */

	p = pwskip(p);
	passwd.pw_gecos = p;
	p = pwskip(p);
	passwd.pw_dir = p;
	p = pwskip(p);
	passwd.pw_shell = p;
	while(*p && *p != '\n') p++;
	*p = '\0';
	return &passwd;
}



int
lckacpf()
{
    FILE *lf;
    int retry = 15;

    (void)umask(0333);
    for (;;) {
        lf = fopen(lock_name,"w+");
	if (lf != NULL) {
	    fclose(lf);
	    return 0;
	}
	if (retry-- < 0)
	    break;
	sleep(1);
    }
    return -1;
}

int
ulckacpf()
{
    return unlink(lock_name);
}

#ifdef USESHADOW

static FILE *shf = NULL;

int
setacpsp()
{
	if (shf != NULL) {
		rewind(shf);
		return 0;
	}
	shf = fopen(shadow_name,"r");
	if (shf != NULL)
		return 0;
	return -1;
}

void
endacpsp()
{
	if (shf != NULL) {
		fclose(shf);
		shf = NULL;
	}
}

struct spwd *
getacpsp()
{
	register char *p;
	static struct spwd spwd;
	static char line[BUFSIZ+1];

	if (shf == NULL && setacpsp() != 0)
		return (struct spwd *)NULL;
	p = fgets(line, BUFSIZ, shf);
	if (p == NULL)
		return (struct spwd *)NULL;
	line[BUFSIZ] = '\0';
	spwd.sp_namp = p;
	p = pwskip(p);
	spwd.sp_pwdp = p;
	p = pwskip(p);
	spwd.sp_lstchg = atoi(p);
	p = pwskip(p);
	if (*p == 0)
	  spwd.sp_min = -1;
	else
	  spwd.sp_min = atoi(p);
	p = pwskip(p);
	if (*p == 0)
	  spwd.sp_max = -1;
	else
	  spwd.sp_max = atoi(p);
	p = pwskip(p);
#ifndef SCO
	if (*p == 0)
	  spwd.sp_warn = -1;
	else
	  spwd.sp_warn = atoi(p);
	p = pwskip(p);
	if (*p == 0)
	  spwd.sp_inact = -1;
	else
	  spwd.sp_inact = atoi(p);
	p = pwskip(p);
	if (*p == 0)
	  spwd.sp_expire = -1;
	else
	  spwd.sp_expire = atoi(p);
	p = pwskip(p);
	if (*p == 0)
	  spwd.sp_flag = -1;
	else
	  spwd.sp_flag = atoi(p);
#endif
	return &spwd;
}

#endif /* USESHADOW */


/*
 * char *test_password(char *pass)
 *
 * Insure password is of reasonable length and composition.  If we
 * really wanted to make things sticky, we could check the dictionary
 * for common words, but then things would really be slow.
 */

char *
test_password(pass)
char *pass;
{
    int flags = 0, pwlen = 0;
    char c;

    while (c = *pass++) {
	pwlen++;
	if (islower(c))
	    flags |= 2;
	else if (isupper(c))
	    flags |= 4;
	else if (isdigit(c))
	    flags |= 1;
	else
	    flags |= 8;
    }
/* At least 4 characters of mixed case with numerics or special chars */
    if (flags >= 7 && pwlen >= 4)
	return NULL;
/* At least 5 characters of mixed case, or with numerics */
    if (((flags&1) || flags == 6) && pwlen >= 5)
	return NULL;
/* At least 6 characters of mono-case */
    if ((flags == 2 || flags == 4) && pwlen >= 6)
	return NULL;
    if (flags == 1)
	return "Please use at least one non-numeric character.\n";
    return "Please use a longer password.\n";
}

#ifdef USESHADOW

static void
add_number(str,num)
char *str;
INT32 num;
{
    str += strlen(str);	/* point to the null */
    *str++ = ':';
    if (num != -1)
	sprintf(str,"%ld",num);
    else
	*str = '\0';
}

int
write_out_shadow(shout,shp)
FILE *shout;
struct spwd *shp;
{
    char line[256];

    sprintf(line,"%s:%s",shp->sp_namp,shp->sp_pwdp);
    add_number(line,shp->sp_lstchg);
    add_number(line,shp->sp_min);
    add_number(line,shp->sp_max);
#ifndef SCO
    add_number(line,shp->sp_warn);
    add_number(line,shp->sp_inact);
    add_number(line,shp->sp_expire);
    add_number(line,shp->sp_flag);
#endif
    return fprintf(shout,"%s\n",line);
}

static char *
change_shadow(user,opass,pass,shout)
char *user,*opass,*pass;
FILE *shout;
{
    int passset = 0, i;
    struct spwd *shp,newpwd;
    char *err = NULL;
    INT32 today;

    today = DAY_NOW;
    setacpsp();
    while ((shp = getacpsp()) != NULL) {
	if (strcmp(shp->sp_namp,user) == 0 &&
	    (opass == NULL || strcmp(shp->sp_pwdp,opass) == 0)) {
	    if (passset)
		continue;
	    if (shp->sp_lstchg != -1 && shp->sp_min != -1 &&
		today < shp->sp_lstchg + shp->sp_min) {
		err = " Password isn't old enough yet.\n";
		break;
	      }
	    passset = 1;
	    shp->sp_lstchg = today;
	    shp->sp_pwdp = pass;
	  }
	if (write_out_shadow(shout,shp) < 0) {
	    err = stmp_name;
	    break;
	}
    }
    i = errno;
    endacpsp();
    errno = i;
    if (err != NULL)
	return err;
    if (!passset) {
	newpwd.sp_namp = user;
	newpwd.sp_pwdp = pass;
	newpwd.sp_lstchg = DAY_NOW;
	newpwd.sp_min = newpwd.sp_max = 
#ifndef SCO
            newpwd.sp_warn =
	    newpwd.sp_inact = newpwd.sp_expire = newpwd.sp_flag 
#endif
	-1;
	if (write_out_shadow(shout,&newpwd) < 0)
	    return stmp_name;
    }
    return NULL;
}

#endif /* USESHADOW */

int
write_out_passwd(pwdout,pwd)
FILE *pwdout;
struct passwd *pwd;
{
    return fprintf(pwdout,"%s:%s:%d:%d:%s:%s:%s\n",pwd->pw_name,
	pwd->pw_passwd,pwd->pw_uid,pwd->pw_gid,pwd->pw_gecos,
	pwd->pw_dir,pwd->pw_shell);
}

/*
 * This function changes the given user's password.  If "opass" is
 * given, then just this password (if more than one is set) is changed.
 * If it is not given, then only the first password is changed and all
 * others are deleted.
 *
 * Returned pointer to string either points to some text that should be
 * given to perror(), or to a text string beginning with a space.
 */

char *
change_password(user,opass,pass)
char *user,*opass,*pass;
{
    static char alphabet[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    INT32 salt;
    char saltc[2],*err = NULL;
    int pwchanged = 0, passset = 0, nonmatch = 0;
    int uid,i;
    struct passwd *pwd;
    FILE *pwdout;
#ifdef USESHADOW
    FILE *shout = NULL;
    int shchanged = 0;
#endif

    uid = getuid();
    time(&salt);
    salt += 9 * getpid();
    saltc[0] = alphabet[salt%64];
    saltc[1] = alphabet[(salt/64)%64];
    strcpy(pass,crypt(pass,saltc));
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
#ifndef SYS_V 
    signal(SIGTSTP, SIG_IGN);
#endif
    if (lckacpf())
	return " Unable to lock password file for update.\n";

    /* Password file should be globally readable. */
    (void)umask(0333);
    if ((pwdout = fopen(ptmp_name,"w+")) == NULL) {
	if (errno == EEXIST)
	    err = " Temporary file already exists.\n";
	else
	    err = ptmp_name;
	goto error_exit;
    }

#ifdef USESHADOW
    /* Shadow file should readable by root only. */
    (void)umask(0377);
    (void)unlink(stmp_name);
    if ((shout = fopen(stmp_name,"w+")) == NULL) {
	err = stmp_name;
	goto error_exit;
    }
#endif

/*
 * Copy passwd to temp, replacing matching lines with new password.
 */
    setacppw(NULL);      /*6131*/
    while ((pwd = getacppw()) != NULL) {
	if (strcmp(pwd->pw_name,user) == 0) {
	    if (uid != 0 && uid != pwd->pw_uid) {
		nonmatch = 1;
		goto writethisentry;
	    }
	    if (opass != NULL) {
#ifdef USESHADOW
		if (strcmp(pwd->pw_passwd,"x") == 0) {
		    if (passset) {
			pwchanged = 1;
			continue;
		    }
		    err = change_shadow(user,opass,pass,shout);
		    if (err != NULL)
			goto error_exit;
		    passset = 1;
		    shchanged = 1;
		    goto writethisentry;
		}
#endif
		if (strcmp(pwd->pw_passwd,opass) != 0)
		    goto writethisentry;
	    }
	    pwchanged = 1;
	    if (passset)
		continue;
	    passset = 1;
	    pwd->pw_passwd = pass;
	}
writethisentry:
	if (write_out_passwd(pwdout,pwd) < 0) {
	    err = ptmp_name;
	    goto error_exit;
	}
    }
    endacppw();

    if (!passset) {
	if (nonmatch)
	    err = " Permission denied.\n";
	else
	    err = " Unable to locate password entry.\n";
	goto error_exit;
    }

    i = fclose(pwdout);
    pwdout = NULL;
    if (pwchanged) {
	if (i < 0 || rename(ptmp_name,passwd_name) < 0) {
	    err = ptmp_name;
	    goto error_exit;
	}
    } else
	(void)unlink(ptmp_name);

#ifdef USESHADOW
    i = fclose(shout);
    shout = NULL;
    if (shchanged) {
	if (i < 0 || rename(stmp_name,shadow_name) < 0) {
	    err = stmp_name;
	    goto error_exit;
	}
    } else
	(void)unlink(stmp_name);
#endif
    if (ulckacpf())
	return " Failed to unlock password file.\n";

    return NULL;

error_exit:
    i = errno;
    if (pwdout != NULL)
	(void)fclose(pwdout);
    (void)unlink(ptmp_name);
#ifdef USESHADOW
    if (shout != NULL)
	(void)fclose(shout);
    (void)unlink(stmp_name);
#endif
    (void)ulckacpf();
    errno = i;
    return err;
}

