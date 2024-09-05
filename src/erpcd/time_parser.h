/**********************************************************************
 * time_parser.h
 * Supporting definitions for the API defined in time_parser.c
 */

#ifndef _TIME_PARSER_H_
#define _TIME_PARSER_H_

/**********************************************************************
 * The four legal time types.
 * TIME_TYPE1 - TIME_TYPE4 are retained for compatibility, but their
 * use is discouraged.  New defines with the same values are provided
 * for future use (the TIME_FMT_ defines).
 */

#define TIME_FMT_DAYS_ONLY	1	/* Ex:  "Mon-Fri" */
#define TIME_TYPE1 1			/* OBS: Same as TIME_FMT_DAYS_ONLY */
#define TIME_FMT_DAY_TIMES	2	/* Ex:  "9:00-5:00 Mon-Fri" */
#define TIME_TYPE2 2			/* OBS: Same as TIME_FMT_DAY_TIMES */
#define TIME_FMT_LONG_TIME	3	/* Ex:  "9:00 Mon-5:00 Fri" */
#define TIME_TYPE3 3			/* OBS: Same as TIME_FMT_LONG_TIME */
#define TIME_FMT_MONTH_DAYS	4	/* Ex:  "9:00 Jan 31 - 10:00 Jan 20 */
#define TIME_TYPE4 4			/* OBS:  Same as TIME_FMT_MONTH_DAYS */

int get_time_entry();

/**********************************************************************
 * time_print_range
 * print a range specified by two tm structs
 * IN  tm1_p            low end of range 
 * IN  tm2_p            high end of range
 * IN  tm_format        time format specifier
 * Results: pointer to ASCII representation of time data
 * NOTE: Data is placed in static array that is overwritten by each call.
 */
char *time_print_range();

#endif
