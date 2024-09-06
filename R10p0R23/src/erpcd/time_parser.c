#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include "../inc/config.h"
#include "time_parser.h"

int get_hourmin();
int get_table();

/* This #define enables compilation of the debug messages into the code,
 * but the debug (-D) flag must still be given on the cmd line to 
 * cause the messages to be printed.
 */
#define DEBUG_TIME 1

#ifndef TRUE
#define FALSE 0
#define TRUE  1
#endif

#define SPACE  ' '
#define TAB    '\t'
#define FF     '\f'
#define HYPHEN '-'
#define COLON  ':'

#define DOS_WS     0x01
#define DOS_ALPHA  0x02
#define DOS_DIGIT  0x04
#define DOS_HYPHEN 0x08
#define DOS_COLON  0x10

#define MAX_WEEKDAYS    7
#define MAX_MONTHS      12

static char *weekdays[MAX_WEEKDAYS] = {
        "Sunday", 
	"Monday", 
	"Tuesday", 
	"Wednesday", 
	"Thursday", 
	"Friday", 
	"Saturday"
};

static char *months[MAX_MONTHS] = {
        "January",      "February",     "March",        "April",
        "May",          "June",         "July",         "August",
        "September",    "October",      "November",     "December"
};

extern int debug;	/* Global flag set in main to enable debug msgs */

/************************************************************************
 * time_print_range
 * print a range specified by two tm structs
 * IN  tm1_p		low end of range
 * IN  tm2_p		high end of range
 * IN  tm_format	time format specifier
 * Results: pointer to ASCII representation of time data
 * NOTE: Data is placed in static array that is overwritten by each call.
 */
char *time_print_range(tm1_p, tm2_p, tm_format)
struct tm *tm1_p;
struct tm *tm2_p;
int tm_format;
{
	static char time_buf[64];	/* Return buffer for output data */

	/* tm_format determines which time format is specified. */

	switch(tm_format) {
		case TIME_FMT_DAYS_ONLY:
			(void) sprintf(time_buf, "%s-%s", 
				weekdays[tm1_p->tm_wday], 
				weekdays[tm2_p->tm_wday]);
			break;

		case TIME_FMT_DAY_TIMES:
			(void) sprintf(time_buf, "%d:%02d-%d:%02d %s-%s",
				tm1_p->tm_hour, tm1_p->tm_min, tm2_p->tm_hour,
				tm2_p->tm_min, weekdays[tm1_p->tm_wday],
				weekdays[tm2_p->tm_wday]);
			break;

		case TIME_FMT_LONG_TIME:
			(void) sprintf(time_buf, "%d:%02d %s-%d:%02d %s",
				tm1_p->tm_hour, tm1_p->tm_min,
				weekdays[tm1_p->tm_wday], tm2_p->tm_hour,
				tm2_p->tm_min, weekdays[tm2_p->tm_wday]);
			break;

		case TIME_FMT_MONTH_DAYS:
			(void) sprintf(time_buf, "%d:%02d %s %d-%d:%02d %s %d",
				tm1_p->tm_hour, tm1_p->tm_min, 
				months[tm1_p->tm_mon], tm1_p->tm_mday,
				tm2_p->tm_hour, tm2_p->tm_min, 
				months[tm2_p->tm_mon], tm2_p->tm_mday);
			break;
	}

	/* Now just return the result */
	return(time_buf);
	
} /* print_time_range */

/************************************************************************
 *
 * FUNCTION:
 *   rm_ws - Remove whitespace from a string.
 *
 * DESCRIPTION:
 *   This routine will remove all whitespace from a string.
 *
 * INPUT:
 *      l1      Line of input
 *
 * RETURNS:
 *      void
 */
void
rm_ws(l1)
char *l1;
{
    char *l2;
    for (l2 = l1;;) {
        char c = *l2;
        if ((c == SPACE) || (c == TAB) || (c == FF)) {
                l2++;
        }
        else {
                *l1++ = *l2++;
        }
        if (c == '\0')
                return;
    }
}


/************************************************************************
 *
 * FUNCTION:
 *   lex_scan - Lexical scan of per-user environment strings
 *
 * DESCRIPTION:
 *   This routine is used by the parser to properly scan strings.
 *   It will stop at a certain character, and skip over specified
 *   characters.
 *
 * INPUT:
 *	l		Inputted string (most likely will be adjusted)
 *	stop_at		Stop at this character
 *	skip		Skip over these characters
 *
 * RETURNS:
 *      int	        TRUE  - scan successful	
 *		        FALSE - scan failed
 */

int
lex_scan(l, stop_at, skip)
char    **l;		/* Inputted string 		*/
int     stop_at;	/* What to stop scanning at 	*/
int	skip;		/* What to skip over 		*/
{

#ifdef DEBUG_TIME
  if(debug)
	fprintf(stderr,"dls: stop_at = %d, skip = %d\n", stop_at, skip);
#endif

  for (;;) {

	int ws = ((**l == SPACE) || (**l == TAB) || (**l == FF));

#ifdef DEBUG_TIME
	if(debug)
		fprintf(stderr,"*l **l = hex: %x  char: %c  ws = %d\n",
			*l, **l, **l, ws);
#endif

	if (**l == '\0')
	{
	   return (FALSE);
	}

	if (**l == stop_at) 
        {

		/*
		 * When a particular character is requested, go
		 * one past that character.
		 */
		(*l)++;
		return (TRUE);
	}
	if (
		(ws		&& (skip & DOS_WS))	||
		(isalpha(**l)	&& (skip & DOS_ALPHA))	||
		(isdigit(**l)	&& (skip & DOS_DIGIT))	||
		(**l == HYPHEN	&& (skip & DOS_HYPHEN))	||
		(**l == COLON	&& (skip & DOS_COLON))	||
		(skip == 0)
	   ) 
        {
		(*l)++;
	}
	else 
        {
               	return (FALSE);
	}
  }
}

/************************************************************************
 *
 * FUNCTION:
 *   get_time_entry - Get environment time entry.
 *
 * DESCRIPTION:
 *   This routine will fill in all necessary information pertaining
 *   to the disabled period currently being parsed.
 *
 * INPUT:
 *      line    Line of input
 *      tm1,tm2 Time structs
 *
 * RETURNS:
 *      int TRUE  - retrieved the time(s)
 *          FALSE - failed to retrieve the time(s) 
 */

int
get_time_entry(tm1,tm2, line2)
struct tm *tm1, *tm2;
char	*line2;
{
int   err_ret;

    int flag = FALSE;

    rm_ws(line2);
#ifdef DEBUG_TIME
    if(debug)
       	fprintf(stderr, "RMed %s\n",line2);
#endif

    if (isdigit(*line2)) 
    {
#ifdef DEBUG_TIME
	if(debug)
           fprintf(stderr, "starts with a digit %s\n",line2);
#endif

	get_hourmin(&line2, tm1);

#ifdef DEBUG_TIME
	if(debug)
           fprintf(stderr, "After gethourmin %s\n",line2);
#endif

    	if (*line2 == HYPHEN) 
        {
		char **table = weekdays;
		line2++;
		if (get_hourmin(&line2, tm2) != TRUE)
			return (FALSE);

                if(*line2 != '\0'){
                  err_ret = get_table(&line2, tm1, table);
		  if (*line2 != HYPHEN)
			goto error;
		  line2++;
                  err_ret = get_table(&line2, tm2, weekdays);
	       }
		  flag = TIME_TYPE2;
	}
    	else if (isalpha(*line2)) 
	{
		char **table = weekdays;
		char *line3;
		line3 = line2;
		err_ret = get_table(&line2, tm1, weekdays);
		if (err_ret == FALSE) {
			table = months;
			line2 = line3;
			if (get_table(&line2, tm1, months) != TRUE)
				goto error;
			tm1->tm_mday = atoi(line2);
        		if (!isdigit(*line2) || (tm1->tm_mday < 0) || 
				(tm1->tm_mday > 31))
				goto error;
			lex_scan(&line2,0, DOS_DIGIT);
			flag = TIME_TYPE4;
		}
		else {
			flag = TIME_TYPE3;
		}
		if (*line2 != HYPHEN)
			goto error;
		line2++;
		if (get_hourmin(&line2, tm2) != TRUE)
				goto error;
		if (table == weekdays) {
			if (get_table(&line2, tm2, table) != 0)
				goto error;
		}
		else {
			err_ret = get_table(&line2, tm2, months);
			tm2->tm_mday = atoi(line2);
        		if (!isdigit(*line2) || (tm2->tm_mday < 0) || 
				(tm2->tm_mday > 31))
				goto error;
		}
	}
    }
    else 
    {
	if (get_table(&line2, tm1, weekdays) == TRUE)
        {
	   flag = TIME_TYPE1;
	   if (*line2 == '\0') {
		tm2->tm_wday = tm1->tm_wday;
		goto error;
	   }
	   if (*line2 != HYPHEN)
		goto error;
	   line2++;
	   err_ret = get_table(&line2, tm2, weekdays);
       }
    }

error:
    return(flag);
}

/************************************************************************
 *
 * FUNCTION:
 *   get_hourmin - Read hours and minutes from disabled field.
 *
 * DESCRIPTION:
 *   This routine read the hours and minutes (and AM/PM)
 *   from a disabled field.
 *
 * INPUT:
 *      line    Line of input
 *      tm      Time struct
 *
 * RETURNS:
 *      void
 */
int
get_hourmin(line, tm)
char	**line;
struct tm *tm;
{
  int ampmfmt = 0;

        tm->tm_hour = atoi(*line);
        if (tm->tm_hour < 0 || tm->tm_hour > 23)
		return (FALSE);


        lex_scan(line, 0, DOS_DIGIT);

        if (lex_scan(line, COLON, DOS_WS) != TRUE)
		return (FALSE);

        tm->tm_min        = atoi(*line);
        if (tm->tm_min < 0 || tm->tm_min > 59)
		return (FALSE);

        lex_scan(line, 0, DOS_DIGIT);

	if (**line == 'p' || **line == 'P') {
           if (tm->tm_hour > 12 || tm->tm_hour <= 0)
	      return (FALSE);
	   if (tm->tm_hour != 12)
	     tm->tm_hour += 12;
	   ampmfmt = 1;
	} else if (**line == 'a' || **line == 'A') {
        	if (tm->tm_hour > 12 || tm->tm_hour <= 0)
			return (FALSE);
		if (tm->tm_hour == 12)
		  tm->tm_hour = 0;
		ampmfmt = 1;
	}

	if (ampmfmt) {
	  (*line)++;
	  if (**line == 'm' || **line == 'M')
	    (*line)++;
	}

	return (TRUE);
}


/************************************************************************
 *
 * FUNCTION:
 *   get_table - Read disabled period, scanning through pre-defined
 *   tables.
 *
 * DESCRIPTION:
 *   This routine will read a disabled period when a table entry
 *   has been detected.  Table entry = "Monday, Tuesday..." or
 *   "January", "February", etc.
 *
 * INPUT:
 *      line    Line of input
 *      tm      Time struct
 *	table	either weekdays or months
 *
 * RETURNS:
 *      void
 */
int 
get_table(line, tm, table)
char	**line;
struct tm *tm;
char	**table;
{
	int err_ret = FALSE;
	int i, len, max_ents=0, *fill=(int *)0;
	char *line2, *line3, c;

	line2 = *line;
	lex_scan(line, 0, DOS_ALPHA);
	line3 = *line;
	c = *line3;
	*line3 = '\0';

        
	if (table == weekdays) {
		max_ents = MAX_WEEKDAYS;
		fill = &tm->tm_wday;
	}
	else if (table == months) {
		max_ents = MAX_MONTHS;
		fill = &tm->tm_mon;
	}

	len = strlen(line2);	
	for (i=0; i < max_ents; i++) {
		if (!strncasecmp(line2, table[i], len)) {
			*fill = i;
			err_ret = TRUE;
			break;
		}
	}

	*line3 = c;
	*line = line3;
	return (err_ret);
}
