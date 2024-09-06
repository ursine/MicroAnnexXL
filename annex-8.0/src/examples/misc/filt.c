/*##################################################
*#
*# filt.c from Network Administrators Guide
*# 
*# Release 7.0, Book A, Printers Chapter
*#
*###################################################
*/
#include <stdio.h>
#define SEPARATOR	'.'
#define APRINT		"/usr/annex/aprint"
/*
 * Usage of the filt.c program:
 *
 * 1. Edit filt.c to reflect your system's location of aprint 
 *    and choose a filter.
 * 2. Compile this filt.c .
 *    e.g. % make filt
 * 3. Copy the created "filt" file to annex-name.port-number.
 *    e.g. % cp filt annex1.1
 *
 *  note: Annex 1 port 1 should be in slave mode. See the Network
 *        Administrator's Guide for configuration information.
 *
 * Possible FILTER definition to expand end-of-line to <cr><lf>:
 *
 * #define FILTER "/usr/bin/awk '{printf(\"%s\\r\\n\",$0) }' | /usr/ucb/expand |"
 */

#define FILTER ""

main(argc,argv)
int argc;
char *argv[];
{
    char	annex[20];	/* name of annex */
    char 	port[20];	/* annex port number */
    char	line[120];
    char	*basename;
    char	*p;
    int		length;

    basename = (char *)strrchr(argv[0],'/');
    if (basename == (char *)NULL) {
        basename = argv[0];
    } else {
        basename++;
    }

    p = (char *)strrchr(argv[0],SEPARATOR);
    if ( p == (char *)NULL) {
        fprintf(stderr, "Error: name not of form annex%cport\n", SEPARATOR);
        exit(1);
    }
    length = (int)(p - basename);

    strncpy(annex,basename,length);
    annex[length] = '\0';
    strcpy(port,p+1);

    sprintf(line,"%s %s -f -A%s -L%s",FILTER,APRINT,annex,port) ;
    system(line);

    /* Always return OK to the spooler daemon */
    exit(0);
}

