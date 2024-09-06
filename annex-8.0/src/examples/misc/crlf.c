/*
 * crlf.c --	Carriage Return / Line Feed conversion utility
 *
 *	This filter can be used in conjunction with aprint to convert
 *	Unix files to normal line-printer files or PC files to Unix
 *	files.  Simply type "make crlf" to build the executable version.
 *
 *	The command line interface is similar to the Unix "cat" command,
 *	except that one flag is permitted -- "-r" to reverse the
 *	direction of the conversion.  The follow conversion is done:
 *
 *	Normal mode:
 *		<LF> -> <CR><LF>
 *	Reverse mode:
 *		<CR><LF> -> <LF>
 *		<CR><anything-other-than-LF> -> <CR>
 *
 *	(Sequences not listed above are copied as-is.)
 *
 *	Copyright (c) 1993 by Xylogics, Inc.  All rights reserved.
 *	Initial version 07DEC93 by James Carlson.
 */

#include <stdio.h>
#include <string.h>

int reverse_mode = 0;

void
echoout(fp)
FILE *fp;
{
	int chr,crskipped = 0;

	while ((chr=getc(fp)) != EOF) {
		if ((chr == '\n' && !reverse_mode) ||
		    (chr != '\n' && crskipped))
			putchar('\r');
		if (chr == '\r' && reverse_mode)
			crskipped = 1;
		else {
			crskipped = 0;
			putchar(chr);
		}
	}
	if (crskipped)
		putchar('\r');
}

int
main(argc,argv)
int argc;
char **argv;
{
	char *name,*myname;
	FILE *fp;

	myname = *argv++;
	if (argc > 1 && strcmp(*argv,"-r") == 0) {
		reverse_mode = 1;
		argv++;
		argc--;
	}
	if (argc < 2)
		echoout(stdin);
	else
	
		while ((name = *argv++) != NULL)
			if ((fp = fopen(name,"r")) == NULL)
				perror(name);
			else {
				echoout(fp);
				fclose(fp);
			}
	(void)fflush(stdout);
	if (ferror(stdout)) {
		perror(myname);
		return 1;
	}
	return 0;
}
