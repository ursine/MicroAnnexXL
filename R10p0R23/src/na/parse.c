/*
 *****************************************************************************
 *
 *        Copyright 1989,1990 Xylogics, Inc.  ALL RIGHTS RESERVED.
 *
 * ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
 * This software is made available solely pursuant to the terms of a
 * software license agreement which governs its use.
 * Unauthorized duplication, distribution or sale are strictly prohibited.
 *
 * Module Function:
 * 	%$(Description)$%
 *
 * Original Author: %$(author)$%	Created on: %$(created-on)$%
 *
 *****************************************************************************
 */

/*
 *	Include Files
 */
#include "../inc/config.h"

#include "../inc/port/port.h"
#include <sys/types.h>
#include "../libannex/api_if.h"
#include <time.h>		/* we only want "struct tm" */

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <sys/uio.h>
#else 
#endif 

#include <setjmp.h>
#include "../inc/erpc/netadmp.h"
#include <stdio.h>
#include "../inc/na/na.h"
#define CMD_H_PARAMS_ONLY
#include "../inc/na/cmd.h"
#include "../inc/na/displaytext.h"
#include "../inc/na/interface.h"
#include "../netadm/netadm_err.h"

/*
 *	External Definitions
 */

extern char *annex_params[];
extern char *port_params[];
extern char *interface_params[];
extern char *printer_params[];
extern char *t1_all_params[];
extern char *t1_ds0_params[];
extern char *wan_all_params[];
extern char *wan_chan_params[];
extern char *modem_params[];

extern parameter_table annexp_table[];
extern parameter_table portp_table[];
extern parameter_table interfacep_table[];
extern parameter_table printp_table[];
extern parameter_table t1p_table[];
extern parameter_table t1ds0p_table[];
extern parameter_table prip_table[];
extern parameter_table pribp_table[];
extern parameter_table modemp_table[];

#if NPRI > 0
extern int port_sync_parm_list[];
#endif

extern char *display_sw_id();
extern void convert_bit_to_num();
extern int get_internal_vers();
extern void encode(), decode();

extern char		*split_string();

extern time_t		time();
extern struct tm	*localtime();
#ifndef _WIN32
extern char		*ctime(), *malloc();
extern UINT32		inet_addr();
#endif
extern char *getlogin();
extern int		Sp_support_check();

/*
 *	Defines and Macros
 */
#ifndef _WIN32
#define isdigit(x) (x >= '0' && x <= '9')
#endif

#define SIZE_BLOCK_32_X_4 128
#define SIZE_BLOCK_32_X_6 192
#define UNASSIGNED -1

/* interface type define */
#define ETH_TYPE  	0
#define ASY_TYPE 	1
#define SYNC_TYPE 	2

int  	if_offset;
int	if_type;
int	if_ptr = 0;

#ifdef SPLIT_LINES

int	wrap = 0;

#define MAX_SPLIT_STRING 16

#define INITWRAP	wrap = 0

#define LONGWRAP(x) { if (strlen(x) > MAX_SPLIT_STRING) { \
		      if (wrap) printf("\n"); else wrap = 1;} }

#define WRAP { if (wrap) { printf("\n"); wrap = 0;} else wrap = 1; }

#define WRAP_END { if (wrap) printf("\n"); wrap = 0; }

#define FMT	"%20s: %-17s"

#else	/* no SPLIT_LINES */

#define INITWRAP
#define LONGWRAP(x)
#define WRAP
#define WRAP_END
#define FMT	"%28s: %s\n"

#endif

/*
 *	Local structures
 */

struct options {	/* structure for passing an array of information */
    u_short len;		/* string length */
    u_char lat;			/* lat info passed */
    u_char self_boot;		/* self_boot info passed */
    u_char vhelp;		/* can vhelp disable */
    u_char dec;			/* is DEC version */
#define MISC_LEN (LONGPARAM_LENGTH - 4)
    char misc[MISC_LEN];	/* leaving room for the future */
};

/*
 *	Forward Routine Definitions
 */
#ifdef NA
void punt();
#endif

void annex_show_header();
void port_show_header();
void interface_show_header();
void port_group();
int lex();
int annex_name();
void printer_group();
void interface_group();
void port_group();
void port_list();
void printer_list();
void interface_list();
void pri_list();
void pri_range();
void port_range();
void printer_range();
void interface_range();
void free_show_list();
void free_set_list();
int str_to_inet();
int get_annex_rev();
int get_port_eib();
int get_port_count();
int get_sync_count();
int get_printer_count();
void token_error();
int match();
int Anyp_support();
int	Ap_support_check();
void annex_show_sub();
int get_dla_param();
void netadm_error();
void do_show_port();
int get_ln_param();
void do_show_printer();
void do_show_interface();
int get_if_param();
int Ip_support_check();
char *get_password();	/* prompt for a password from /dev/tty */
int	annex_set_sub();
int set_dla_param();
int	do_set_port();
int	port_set_sub();
int set_ln_param();
int get_annex_opt();
int	printer_set_sub();
int	do_set_interface();
int	interface_set_sub();
int set_if_param();
void prompt();
void t1_group();
int set_t1_param();
int get_t1_param();
int get_t1_count();
void intmod_group();
void t1_reset_decode();
void intmod_list();
void intmod_range();
void ds0_range();
void do_show_t1();
int do_set_t1();
int t1_set_sub();
void single_t1();
void free_t1_set();
void t1_set();
void do_copy_t1();
void port_range(), port_list(), dor_list();
void modem_set(),pri_set(),modem_group(),pri_group(),modem_list(),b_list();
unsigned short pri_number(),b_number();
void modem_range(),dor_range(),pri_reset_decode(),b_range(),single_modem();
void single_pri(),modem_show_list(),modem_show_header(),modem_show_sub();
void do_show_modem(),pri_show_list(),pri_show_header(),pri_show_sub();
void do_show_pri();
int modem_pair_list(),do_set_modem(),modem_set_sub();
int pri_pair_list(),do_set_pri(),pri_set_sub();

/*
 *	Global Data Declarations
 */

UINT32 masks[] =  /* masks[i] == 2**(i-1) for 1 <= i <= 32 */
{
    0x00000000,
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x00000100, 0x00000200, 0x00000400, 0x00000800,
    0x00001000, 0x00002000, 0x00004000, 0x00008000,
    0x00010000, 0x00020000, 0x00040000, 0x00080000,
    0x00100000, 0x00200000, 0x00400000, 0x00800000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000
};

int first_broadcast = TRUE;

char header[100] = "\007\n*** NA Broadcast from ";

static char ds0_spaces[] = "                      ";


/*
 * Functions to decode and define port/sync/printer/interface sets
 */

void port_set(PPport_set, PPport_tail, virtual_ok)
PORT_SET **PPport_set,
	 **PPport_tail;
int      virtual_ok;
{
    port_group(PPport_set, PPport_tail, virtual_ok);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing port identifier", (char *)NULL);
	port_set(PPport_set, PPport_tail, virtual_ok);
    }
}

void
modem_set(PPmodem_set, PPmodem_tail)
MODEM_SET **PPmodem_set,
	 **PPmodem_tail;
{
    modem_group(PPmodem_set, PPmodem_tail);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing modem identifier", (char *)NULL);
	modem_set(PPmodem_set, PPmodem_tail);
    }
}

void printer_set(PPprinter_set, PPprinter_tail)
PRINTER_SET **PPprinter_set,
	    **PPprinter_tail;
{
    printer_group(PPprinter_set, PPprinter_tail);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing printer identifier", (char *)NULL);
	printer_set(PPprinter_set, PPprinter_tail);
    }
}

void interface_set(PPinterface_set, PPinterface_tail)
INTERFACE_SET **PPinterface_set,
	      **PPinterface_tail;
{
    interface_group(PPinterface_set, PPinterface_tail);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing interface identifier", (char *)NULL);
	interface_set(PPinterface_set, PPinterface_tail);
    }
}

void t1_set(PPt1_set, PPt1_tail)
T1_SET **PPt1_set,
       **PPt1_tail;
{
    t1_group(PPt1_set, PPt1_tail);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing t1 identifier", (char *)NULL);
	t1_set(PPt1_set, PPt1_tail);
    }
}

void
pri_set(PPpri_set, PPpri_tail)
PRI_SET **PPpri_set,
       **PPpri_tail;
{
    pri_group(PPpri_set, PPpri_tail);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing WAN interface identifier", (char *)NULL);
	pri_set(PPpri_set, PPpri_tail);
    }
}

void intmod_set(PPintmod_set, PPintmod_tail)
INTMOD_SET **PPintmod_set,
	   **PPintmod_tail;
{
    intmod_group(PPintmod_set, PPintmod_tail);
    if (symbol_length == 1 && symbol[0] == ';') {
	(void)lex();
	if (eos)
	    punt("missing internal modem identifier", (char *)NULL);
	intmod_set(PPintmod_set, PPintmod_tail);
    }
}


/*
 * Functions to decode port/modem/printer/interface groups (called from above)
 */

void port_group(PPport_set, PPport_tail, virtual_ok)
PORT_SET **PPport_set,
	 **PPport_tail;
int      virtual_ok;
{
    PORT_SET *Port_s;
    
    /* Add a new PORT_SET structure to the end of the port set
       pointed to by the given head and tail pointers. */
    
    Port_s = (PORT_SET *)malloc(sizeof(PORT_SET));
    Port_s->next = NULL;
    
    if (!*PPport_set)
	*PPport_set = Port_s;
    else
	(*PPport_tail)->next = Port_s;
    
    *PPport_tail = Port_s;
    
    Port_s->ports.pg_bits = 0;
    
    bzero(Port_s->ports.serial_ports,
	  sizeof(Port_s->ports.serial_ports));
    
    port_list(&Port_s->ports, virtual_ok);
    
    if (symbol_length == 1 && symbol[0] == '@') {
	(void)lex();
	if (eos)
	    punt(NO_BOX, (char *)NULL);
	(void)annex_name(&Port_s->annex_id,
			 Port_s->name, 0);
    }
    else
	Port_s->annex_id.addr.sin_addr.s_addr = 0;
}

void
modem_group(PPmodem_set, PPmodem_tail)
MODEM_SET **PPmodem_set,
	 **PPmodem_tail;
{
    MODEM_SET *modem_s;
    int	p;
    
    /* Add a new MODEM_SET structure to the end of the modem set
       pointed to by the given head and tail pointers. */
    
    modem_s = (MODEM_SET *)malloc(sizeof(MODEM_SET));
    modem_s->next = NULL;
    
    if (!*PPmodem_set)
	*PPmodem_set = modem_s;
    else
	(*PPmodem_tail)->next = modem_s;
    
    *PPmodem_tail = modem_s;
    
    modem_s->modems.mg_bits = 0;
    
    bzero(modem_s->modems.modems, sizeof(modem_s->modems.modems));
    
    modem_list(&modem_s->modems);
    
    if (symbol_length == 1 && symbol[0] == '@') {
	(void)lex();
	if (eos)
	    punt(NO_BOX, (char *)NULL);
	(void)annex_name(&modem_s->annex_id,
			 modem_s->name, 0);
    }
    else
	modem_s->annex_id.addr.sin_addr.s_addr = 0;
}

void printer_group(PPprinter_set, PPprinter_tail)
PRINTER_SET **PPprinter_set,
	    **PPprinter_tail;
{
    PRINTER_SET *Print_s;
    
    /* Add a new PRINTER_SET structure to the end of the printer set
       pointed to by the given head and tail pointers. */
    
    Print_s = (PRINTER_SET *)malloc(sizeof(PRINTER_SET));
    Print_s->next = NULL;
    
    if (!*PPprinter_set)
	*PPprinter_set = Print_s;
    else
	(*PPprinter_tail)->next = Print_s;
    
    *PPprinter_tail = Print_s;
    
    Print_s->printers.pg_bits = 0;
    
    bzero(Print_s->printers.ports,
	  sizeof(Print_s->printers.ports));
    
    printer_list(&Print_s->printers);
    
    if (symbol_length == 1 && symbol[0] == '@') {
	(void)lex();
	if (eos)
	    punt(NO_BOX, (char *)NULL);
	(void)annex_name(&Print_s->annex_id,
			 Print_s->name, 0);
    }
    else
	Print_s->annex_id.addr.sin_addr.s_addr = 0;
}

void interface_group(PPinterface_set, PPinterface_tail)
INTERFACE_SET **PPinterface_set,
	      **PPinterface_tail;
{
    INTERFACE_SET *Interf_s;
    
    /* Add a new INTERFACE_SET structure to the end of the Interface set
       pointed to by the given head and tail pointers. */
    
    Interf_s = (INTERFACE_SET *)malloc(sizeof(INTERFACE_SET));
    Interf_s->next = NULL;
    
    if (!*PPinterface_set)
	*PPinterface_set = Interf_s;
    else
	(*PPinterface_tail)->next = Interf_s;
    
    *PPinterface_tail = Interf_s;
    
    Interf_s->interfaces.pg_bits = 0;
    
    bzero(Interf_s->interfaces.interface_ports,
	  sizeof(Interf_s->interfaces.interface_ports));
    
    interface_list(&Interf_s->interfaces);
    
    if (symbol_length == 1 && symbol[0] == '@') {
	(void)lex();
	if (eos)
	    punt(NO_BOX, (char *)NULL);
	(void)annex_name(&Interf_s->annex_id,
			 Interf_s->name, 0);
    }
    else
	Interf_s->annex_id.addr.sin_addr.s_addr = 0;
}

void t1_group(PPt1_set, PPt1_tail)
T1_SET **PPt1_set,
       **PPt1_tail;
{
    T1_SET *T1_s;
    
    /* Add a new T1_SET structure to the end of the t1 set
       pointed to by the given head and tail pointers. */
    
    T1_s = (T1_SET *)malloc(sizeof(T1_SET));
    T1_s->next = NULL;
    
    if (!*PPt1_set)
	*PPt1_set = T1_s;
    else
	(*PPt1_tail)->next = T1_s;
    
    *PPt1_tail = T1_s;
    
    bzero(T1_s->t1s.engines, sizeof(T1_s->t1s.engines));
    SETPORTBIT(T1_s->t1s.engines, 1);  /* Allow only 1 engine for now!!! */

    /* Clear DS0s */
    bzero(T1_s->ds0s.ds0s, sizeof(T1_s->ds0s.ds0s));

    /* CHECK FOR BLAH t1=1@ip_address SYNTAX */
    if (symbol_length == 1 && symbol[0] == '@') 
    {
        /* PICK UP ip_address */
	(void)lex();

	/* IF NONE, INCORRECT SYNTAX SO GIT OUT */
	if (eos)
	    punt(NO_BOX, (char *)NULL);

	/* RECORD ip_address */
	(void)annex_name( &T1_s->annex_id, T1_s->name, 0);
    }
    else
	T1_s->annex_id.addr.sin_addr.s_addr = 0;
}

void
pri_group(PPpri_set, PPpri_tail)
PRI_SET **PPpri_set,
       **PPpri_tail;
{
    PRI_SET *Pri_s;
    int	p;
    
    /* Add a new PRI_SET structure to the end of the PRI set
       pointed to by the given head and tail pointers. */
    
    Pri_s = (PRI_SET *)malloc(sizeof(PRI_SET));
    Pri_s->next = NULL;
    
    if (!*PPpri_set)
	*PPpri_set = Pri_s;
    else
	(*PPpri_tail)->next = Pri_s;
    
    *PPpri_tail = Pri_s;
    
    bzero(Pri_s->pris.modules, sizeof(Pri_s->pris.modules));
    pri_list(&Pri_s->pris);

    /* Clear Bs */
    bzero(Pri_s->bs.bs, sizeof(Pri_s->bs.bs));

    /* CHECK FOR BLAH pri=1@ip_address SYNTAX */
    if (symbol_length == 1 && symbol[0] == '@') 
    {
        /* PICK UP ip_address */
	(void)lex();

	/* IF NONE, INCORRECT SYNTAX SO GIT OUT */
	if (eos)
	    punt(NO_BOX, (char *)NULL);

	/* RECORD ip_address */
	(void)annex_name( &Pri_s->annex_id, Pri_s->name, 0);
    }
    else
	Pri_s->annex_id.addr.sin_addr.s_addr = 0;
}

void intmod_group(PPintmod_set, PPintmod_tail)
INTMOD_SET **PPintmod_set,
	      **PPintmod_tail;
{
    INTMOD_SET *Intmod_s;
    
    /* Add a new INTMOD_SET structure to the end of the internal modem set
       pointed to by the given head and tail pointers. */
    
    Intmod_s = (INTMOD_SET *)malloc(sizeof(INTMOD_SET));
    Intmod_s->next = NULL;
    
    if (!*PPintmod_set)
	*PPintmod_set = Intmod_s;
    else
	(*PPintmod_tail)->next = Intmod_s;
    
    *PPintmod_tail = Intmod_s;
    
    /* Default is hard reset */
    Intmod_s->intmods.reset_type = RESET_INTMODEM_HARD;
    bzero(Intmod_s->intmods.intmods,
	  sizeof(Intmod_s->intmods.intmods));
    
    intmod_list(&Intmod_s->intmods);
    
    if (symbol_length == 1 && symbol[0] == '@') {
	(void)lex();
	if (eos)
	    punt(NO_BOX, (char *)NULL);
	(void)annex_name(&Intmod_s->annex_id,
			 Intmod_s->name, 0);
    }
    else
	Intmod_s->annex_id.addr.sin_addr.s_addr = 0;
}


/*
 * Functions to decode port/modem/printer/interface lists (called from above)
 */

void port_list(Pports, virtual_ok)
PORT_GROUP *Pports;
int        virtual_ok;
{
    port_range(Pports, virtual_ok);
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing port identifier", (char *)NULL);
	port_list(Pports, virtual_ok);
    }
}

void
modem_list(Pports)
MODEM_GROUP *Pports;
{
    modem_range(Pports);
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing modem identifier", (char *)NULL);
	modem_list(Pports);
    }
}

void
dor_list(Pdors, range_included)
u_char  *Pdors;
u_short *range_included;
{
    dor_range(Pdors, range_included);
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing dialout route identifier", (char *)NULL);
	dor_list(Pdors, range_included);
    }
}

void printer_list(Pprinters)
PRINTER_GROUP *Pprinters;
{
    printer_range(Pprinters);
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing printer identifier", (char *)NULL);
	printer_list(Pprinters);
    }
}

void interface_list(Pinterfaces)
INTERFACE_GROUP *Pinterfaces;
{
    interface_range(Pinterfaces); 
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing interface identifier", (char *)NULL);
	interface_list(Pinterfaces);
    }
}

void pri_list(Ppris)
PRI_GROUP *Ppris;
{
    pri_range(Ppris); 
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing WAN identifier", (char *)NULL);
	pri_list(Ppris);
    }
}

void intmod_list(Pintmods)
INTMOD_GROUP *Pintmods;
{
    intmod_range(Pintmods); 
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing internal modem identifier", (char *)NULL);
	intmod_list(Pintmods);
    }
}

void ds0_list(Pds0s)
DS0_GROUP *Pds0s;
{
    ds0_range(Pds0s); 
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing ds0 identifier", (char *)NULL);
	ds0_list(Pds0s);
    }
}

void
b_list(Pbs)
B_GROUP *Pbs;
{
    b_range(Pbs); 
    if (symbol_length == 1 && symbol[0] == ',') {
	(void)lex();
	if (eos)
	    punt("missing B-channel identifier", (char *)NULL);
	b_list(Pbs);
    }
}

/*
 * Range chacking for port/modem/printer/interface number (called from below)
 */

unsigned short
port_number()
{
    unsigned short value = 0;
    int            loop;
    
#ifdef INVALID_TEST_FOR_ASY_CONSTRUCT
    if (symbol_length > 2)
	punt("invalid port identifier: ", symbol);
#endif    
    for (loop = 0; loop < symbol_length; loop++) {
	if (((strncmp(symbol, "asy", 3)) == 0))
	    loop+=3;
	if (!index("0123456789", symbol[loop]))
	    punt("invalid port identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_PORTS)
	punt("invalid port identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
modem_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 2)
	punt("invalid modem port identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid modem port identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_MODEMS)
	punt("invalid modem port identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
dor_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 4)
	punt("invalid dialout route identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid dialout route identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_DORS)
	punt("invalid dialout route identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
printer_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 1)
	punt("invalid printer identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid printer identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_PRINTERS)
	punt("invalid printer identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
interface_number(parse_token)
int	parse_token;
{
    unsigned short value = 0;
    int            loop;

    /* 
     * parse the interface type token, indicate the type
     * and logical offset for later processing
     */ 
    if (parse_token) {
        if (strcmp(symbol,"port") == 0) {
	  lex();
	  return 2;
	}
	if (!strncmp(symbol, "en",2)) {
	    if_ptr = 2;			/* offset to the digit */
	    if_type = ETH_TYPE;		/* interface type */
	    if_offset = M_ETHERNET;	/* interface index offset */
	}
	else if (!strncmp(symbol, "asy",3)) {
	    if_ptr = 3;
	    if_type = ASY_TYPE;
	    if_offset = M_ETHERNET;
	}
	else if (!strncmp(symbol, "syn",3)) {
	    if_ptr = 3;
	    if_type = SYNC_TYPE;
	    if_offset = M_ETHERNET + ALL_PORTS;
	}
	else 
	    punt("invalid interface identifier: ", symbol);
    }
    /* 
     * now parse the numeric digit
     */ 
    for (loop = if_ptr; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid interface identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    /* 
     * check the range for each interface type 
     */ 
    switch (if_type) {
	case ETH_TYPE:
	    if (value > 0)
		punt("invalid interface identifier: ", symbol);
	    break;
	case ASY_TYPE:
	    if (value > M_SLUS || value < 1)
		punt("invalid interface identifier: ", symbol);
	    break;
	case SYNC_TYPE:
	    if (value > M_SYNC || value < 1)
		punt("invalid interface identifier: ", symbol);
	    break;
    }
    
    /* adjust the offset into r2rom index */
    value = value + if_offset;
    if (value < 1 || value > (unsigned short)ALL_INTERFACES)
	punt("invalid interface identifier: ", symbol);
    
    /* reset the pointer */ 
    if_ptr = 0;
    (void)lex();
    return value;
}

unsigned short
t1_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 2)
	punt("invalid t1 identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid port identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_T1S)
	punt("invalid t1 identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
pri_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 2)
	punt("invalid WAN interface identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid WAN interface identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_PRIS)
	punt("invalid WAN interface identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
intmod_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 2)
	punt("invalid internal modem identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid internal modem identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_INTMODS)
	punt("invalid internal modem identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
ds0_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 2)
	punt("invalid ds0 identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid ds0 identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_DS0S)
	punt("invalid ds0 identifier: ", symbol);
    (void)lex();
    return value;
}

unsigned short
b_number()
{
    unsigned short value = 0;
    int            loop;
    
    if (symbol_length > 2)
	punt("invalid B channel identifier: ", symbol);
    
    for (loop = 0; loop < symbol_length; loop++) {
	if (!index("0123456789", symbol[loop]))
	    punt("invalid B channel identifier: ", symbol);
	value = value * 10 + symbol[loop] - '0';
    }
    
    if (value < 1 || value > ALL_BS)
	punt("invalid B channel identifier: ", symbol);
    (void)lex();
    return value;
}

/*
 * Calculates ranges ala 1-3,12-22
 */

void port_range(Pports, virtual_ok)
PORT_GROUP *Pports;
int	   virtual_ok;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    int assume_all = 0;

    if (symbol_length >= 1 && symbol_length <= 7 &&
	strncmp(symbol, "virtual", symbol_length) == 0) {
	if (!virtual_ok)
	  punt("virtual invalid in this context", (char *)NULL);
	(void)lex();
	Pports->pg_bits |= PG_VIRTUAL;
	assume_all = 1;
    } else if (symbol_length >= 1 && symbol_length <= 6 &&
	     strncmp(symbol, "serial", symbol_length) == 0) {
	(void)lex();
	Pports->pg_bits |= PG_SERIAL;
	assume_all = 1;
    } else if (symbol_length >= 1 && symbol_length <= 11 &&
	     strncmp(symbol, "synchronous", symbol_length) == 0) {
	(void)lex();
	Pports->pg_bits |= PG_SYNC;
	assume_all = 1;
    } else if (symbol_length >= 1 && symbol_length <= 3 &&
	     strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	Pports->pg_bits |= PG_ALL;
	for(p=1; p <= ALL_PORTS; p++)
	    SETPORTBIT(Pports->serial_ports,p);
	return;
    }

    if (eos)
      if (assume_all) {
	for(p=1; p <= ALL_PORTS; p++)
	    SETPORTBIT(Pports->serial_ports,p);
	return;
      } else {
	punt("missing port identifier", (char *)NULL);
      }

    high = low = port_number();
	
    if (symbol_length == 1 && symbol[0] == '-') {
      (void)lex();

      if (eos)
	punt("missing port identifier", (char *)NULL);
      high = port_number();
      if (low > high)
	punt("invalid upper boundary on port range: ", symbol);
    }

    for (loop = (int)low; loop <= (int)high; loop++)
      SETPORTBIT(Pports->serial_ports,loop);
}

void
modem_range(Pports)
MODEM_GROUP *Pports;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	Pports->mg_bits |= MG_ALL;
	for(p=1; p <= ALL_PORTS; p++)
	    SETPORTBIT(Pports->modems,p);
    }
    else {
	low = modem_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing modem identifier", (char *)NULL);
	    
	    high = modem_number();
	    if (low > high)
		punt("invalid upper boundary on modem port range: ", symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETPORTBIT(Pports->modems,loop);
	}
	else
	    SETPORTBIT(Pports->modems,(int)low);
    }
}

void
dor_range(Pdors, range_included)
u_char  *Pdors;
u_short *range_included;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    /* If next symbol begins with non-numeric character, then no range
       was specified. Set all the dialout route bits. */
    if (!isdigit(symbol[0])) {
        *range_included = FALSE;
    }
    else {
        *range_included = TRUE;
	low = dor_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing dialout route identifier", (char *)NULL);
	    
	    high = dor_number();
	    if (low > high)
		punt("invalid upper boundary on dialout route range: ", symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETBIT(Pdors,(loop-1));
	}
	else
	    SETBIT(Pdors,(int)(low-1));
    }
}

void printer_range(Pprinters)
PRINTER_GROUP *Pprinters;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	Pprinters->pg_bits |= PG_ALL;
	for(p=1; p <= ALL_PRINTERS; p++)
	    SETPRINTERBIT(Pprinters->ports,p);
    }
    else {
	low = printer_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing printer identifier", (char *)NULL);
	    
	    high = printer_number();
	    if (low > high)
		punt("invalid upper boundary on printer range: ", symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETPRINTERBIT(Pprinters->ports,loop);
	}
	else
	    SETPRINTERBIT(Pprinters->ports,(int)low);
    }
}

void
pri_range(Ppris)
PRI_GROUP *Ppris;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	for(p=1; p <= ALL_PRIS; p++)
	    SETPORTBIT(Ppris->modules,p);
    }
    else {
	low = pri_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing modem identifier", (char *)NULL);
	    
	    high = pri_number();
	    if (low > high)
		punt("invalid upper boundary on WAN range: ", symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETPORTBIT(Ppris->modules,loop);
	}
	else
	    SETPORTBIT(Ppris->modules,(int)low);
    }
}

void interface_range(Pinterfaces)
INTERFACE_GROUP *Pinterfaces;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	Pinterfaces->pg_bits |= PG_ALL;
	
	/* example for micro-annex M_SLUS = 16
	 *		calling SETINTERFACEBIT(xxx, 1)  sets en0
	 *		calling SETINTERFACEBIT(xxx, 2)  sets asy1
	 *		calling SETINTERFACEBIT(xxx, 18) sets syn1
	 */
	for(p=1; p <= ALL_INTERFACES; p++)
	    SETINTERFACEBIT(Pinterfaces->interface_ports,p); 
    }
    else {
	low = interface_number(1);
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing port identifier", (char *)NULL);
	    high = interface_number(0);
	    if (low > high)
		punt("invalid upper boundary on interface range: ", symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETINTERFACEBIT(Pinterfaces->interface_ports,loop); 
	}
	else
	    SETINTERFACEBIT(Pinterfaces->interface_ports,(int)low);  
    }
    if_offset = 0;
    if_type = 0;
}

void t1_reset_decode(Pt1s)
     T1_SET *Pt1s;
{
  int reset_type;

  if (symbol_length >= 1 && symbol_length <= 3 &&
      strncmp(symbol, "esf", symbol_length) == 0)
    reset_type = 1;
  else if (symbol_length >= 1 && symbol_length <= 4 &&
      strncmp(symbol, "soft", symbol_length) == 0)
    reset_type = 2;
  else if (symbol_length >= 1 && symbol_length <= 4 &&
      strncmp(symbol, "hard", symbol_length) == 0)
    reset_type = 3;
  else {
    punt("invalid t1 reset type: ", symbol);
  }
  (void)lex();
  for (;Pt1s != NULL; Pt1s = Pt1s->next)
    Pt1s->t1s.reset_type = reset_type;
}

void
pri_reset_decode(Ppris)
     PRI_SET *Ppris;
{
  for (;Ppris != NULL; Ppris = Ppris->next)
    Ppris->pris.reset_type = 1; 
}

void intmod_range(Pintmods)
INTMOD_GROUP *Pintmods;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	for(p=1; p <= ALL_INTMODS; p++)
	    SETPORTBIT(Pintmods->intmods,p); 
    }
    else {
	low = intmod_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing internal modem identifier", (char *)NULL);
	    high = intmod_number();
	    if (low > high)
		punt("invalid upper boundary on internal modem range: ", 
		     symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETPORTBIT(Pintmods->intmods,loop); 
	}
	else
	    SETPORTBIT(Pintmods->intmods,(int)low);  
    }
}

void ds0_range(Pds0s)
DS0_GROUP *Pds0s;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	for(p=1; p <= ALL_DS0S; p++)
	    SETPORTBIT(Pds0s->ds0s,p); 
    }
    else {
	low = ds0_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing ds0 identifier", (char *)NULL);
	    high = ds0_number();
	    if (low > high)
		punt("invalid upper boundary on ds0 range: ", 
		     symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETPORTBIT(Pds0s->ds0s,loop); 
	}
	else
	    SETPORTBIT(Pds0s->ds0s,(int)low);  
    }
}

void
b_range(Pbs)
B_GROUP *Pbs;
{
    unsigned short low,
		   high;
    int            loop,
		   p;
    
    if (symbol_length >= 1 && symbol_length <= 3 &&
	strncmp(symbol, "all", symbol_length) == 0) {
	(void)lex();
	for(p=1; p <= ALL_BS; p++)
	    SETPORTBIT(Pbs->bs,p); 
    }
    else {
	low = b_number();
	if (symbol_length == 1 && symbol[0] == '-') {
	    (void)lex();
	    
	    if (eos)
		punt("missing B channel identifier", (char *)NULL);
	    high = b_number();
	    if (low > high)
		punt("invalid upper boundary on B channel range: ", 
		     symbol);
	    
	    for (loop = (int)low; loop <= (int)high; loop++)
		SETPORTBIT(Pbs->bs,loop); 
	}
	else
	    SETPORTBIT(Pbs->bs,(int)low);  
    }
}

/*
 * to parse single port/etc numbers... user by the copy command.
 */

void single_port(Pport_number, Pannex_id)
unsigned short     *Pport_number;
ANNEX_ID	   *Pannex_id;
{
    *Pport_number = port_number();
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}

void
single_modem(Pmodem_number, Pannex_id)
unsigned short     *Pmodem_number;
ANNEX_ID	   *Pannex_id;
{
    *Pmodem_number = modem_number();
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}

void single_printer(Pprinter_number, Pannex_id)
unsigned short     *Pprinter_number;
ANNEX_ID	   *Pannex_id;
{
    *Pprinter_number = printer_number();
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}

void single_interface(Pinterface_number, Pannex_id)
unsigned short     *Pinterface_number;
ANNEX_ID	   *Pannex_id;
{
    *Pinterface_number = interface_number(1);
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}

void single_virtual(Pannex_id)
ANNEX_ID	   *Pannex_id;
{
    /* This is only called when the symbol "virtual" has already been
       seen, so don't bother looking at it again. */
    (void)lex();
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}

void single_t1(Pt1_number, Pannex_id)
unsigned short     *Pt1_number;
ANNEX_ID	   *Pannex_id;
{
    *Pt1_number = t1_number();
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}

void
single_pri(Ppri_number, Pannex_id)
unsigned short     *Ppri_number;
ANNEX_ID	   *Pannex_id;
{
    *Ppri_number = pri_number();
    
    if (symbol_length == 1 && symbol[0] == '@')
	(void)lex();
    else
	punt(NO_BOX, (char *)NULL);
    if (!eos)
	(void)annex_name(Pannex_id, (char *)NULL, 0);
    else
	punt(NO_BOX, (char *)NULL);
}


/*
 * parse a list of annexnames.
 */

void annex_list(PPannex_list, PPannex_tail)
ANNEX_LIST **PPannex_list,
    **PPannex_tail;
{
    int        error;
    ANNEX_LIST *Annex_l;
    
    for (;;) {

	if (symbol_length == 1 && symbol[0] == ',') {
	    (void)lex();
	    printf("Null box name ignored.\n");
	    continue;
	}

	/* Add a new ANNEX_LIST structure to the end of the annex list
	   pointed to by the given head and tail pointers. */
	
	if ((Annex_l = (ANNEX_LIST *)malloc(sizeof(ANNEX_LIST))) == NULL)
	    punt("No memory - malloc() failed", (char *)NULL);
	
	error = annex_name(&Annex_l->annex_id, Annex_l->name,
			   -1);
	if (!error) {
	    Annex_l->next = NULL;
	    
	    if (!*PPannex_list)
		*PPannex_list = Annex_l;
	    else
		(*PPannex_tail)->next = Annex_l;
	    
	    *PPannex_tail = Annex_l;
	} else
	    free((char *)Annex_l);
	
	if (symbol_length == 1 && symbol[0] == ',') {
	    (void)lex();
	    
	    if (eos) {
		printf("Null trailing box name ignored.\n");
		break;
	    }
	} else
	    break;
    }
    if (!*PPannex_list)
	punt(BOX, " list was empty - ignored");
}

/*
 * or how about just one name at a time?
 */

int
annex_name(Pannex_id, copy_dest, oblivious)
ANNEX_ID	*Pannex_id;
char            *copy_dest;
int		oblivious;			/* print errors */
{
    int			error;
    int         i;
    u_short		eib = 0;
    struct options	options;
    char		*str;
    
    bzero(Pannex_id, sizeof(ANNEX_ID));
    
    while (*Psymbol && !index(TERMINATORS, *Psymbol))
	symbol[symbol_length++] = *Psymbol++;
    
    symbol[symbol_length] = '\0';
    if (symbol_length > BOX_LMAX) {
	printf("%s\n",LONG_BOX);
	error = -1;
	goto oops;
    }
    if (symbol_length <= 0) {
	printf("Missing hostname or internet address\n");
	error = -2;
	goto oops;
    }
    if (error = str_to_inet(symbol, &Pannex_id->addr.sin_addr.s_addr, FALSE,
			    oblivious)) {
	printf("%s: invalid hostname or internet address\n", symbol);
	error = -1;
	goto oops;
    }
    
    Pannex_id->addr.sin_family = AF_INET;
    Pannex_id->addr.sin_port = erpc_port;
    
    /* Determine the software rev and hardware type */
    error = get_annex_rev(&Pannex_id->addr, LONG_CARDINAL_P,
			  (caddr_t)&(Pannex_id->sw_id));
    switch (error) {
	case 0:
	    if (get_internal_vers(Pannex_id->sw_id,
			      (UINT32 *)&Pannex_id->version,
			      (UINT32 *)&Pannex_id->hw_id,
			      (UINT32 *)&Pannex_id->flag, TRUE)) {
		oblivious = 1;
		goto oops;
	    }
	    break;
	case NAE_PROC:
	    Pannex_id->version = VERS_1;
	    Pannex_id->hw_id = ANX_I;
	    break;
	default:
	    goto err_oops;
	    break;
    }
    
    /* Determine if it has ennhanced interface hardware */
    error = get_port_eib(&Pannex_id->addr, CARDINAL_P, (caddr_t)&eib);
    switch (error) {
	case 0:
	    if ((eib & ANX_IIE) && Pannex_id->hw_id == ANX_II)
		Pannex_id->hw_id = ANX_II_EIB;
	    Pannex_id->flag |= eib;
	    break;
	case NAE_PROC:
	    break;
	default:
	    goto err_oops;
	    break;
    }
    
    /* Determine the number of ports */
    error = get_port_count(&Pannex_id->addr, CARDINAL_P,
			   (caddr_t)&(Pannex_id->port_count));
    switch (error) {
	case 0:
	    break;
	case NAE_PROC:
	    Pannex_id->port_count = 16;
	    break;
	default:
	    goto err_oops;
	    break;
    }

    /* Determine the number of sync ports */
    error = get_sync_count(&Pannex_id->addr, CARDINAL_P, 
			   (caddr_t)&(Pannex_id->sync_count));
    switch (error) {
	case 0:
	    break;
	case NAE_PROC:
	    Pannex_id->sync_count = 0;
	    break;
	default:
	    goto err_oops;
	    break;
    }

    /* Determine the number of printers */
    
    error = get_printer_count(&Pannex_id->addr, CARDINAL_P,
			      (caddr_t)&(Pannex_id->printer_count));
    switch (error) {
	case 0:
	    break;
	case NAE_PROC:
	    if (Pannex_id->hw_id == ANX_MICRO)
		Pannex_id->printer_count = 0;
	    else
		Pannex_id->printer_count = 1;
	    break;
	default:
	    goto err_oops;
	    break;
    }
    
    /* Determine the number of T1 engines */
    
    error = get_t1_count(&Pannex_id->addr, CARDINAL_P,
			      (caddr_t)&(Pannex_id->t1_count));
    switch (error) {
	case 0:
	    break;
	case NAE_PROC:
	    Pannex_id->t1_count = 0;
	    break;
	default:
	    goto err_oops;
	    break;
    }

    /* Determine the number of WAN interfaces */
    error = get_pri_count(&Pannex_id->addr, CARDINAL_P,
			  (caddr_t)&(Pannex_id->pri_count));
    switch (error) {
	case 0:
	    break;
	case NAE_PROC:
	    Pannex_id->pri_count = 0;
	    break;
	default:
	    goto err_oops;
	    break;
    }

    /* Determine the number of B channels usable if this is PRI */
    /* (T1 could use this, but doesn't.) */
    if (Pannex_id->pri_count > 0) {

      if (Pannex_id->pri_count == 1) {
	error = get_b_count(&Pannex_id->addr, CARDINAL_P,
			    (caddr_t)&Pannex_id->b_count[1]);
      }
      else {
	/* new routine to get all the b counts. */
	error = get_all_b_counts(&Pannex_id->addr, STRING_P,
				 (caddr_t)&Pannex_id->b_count[0]);
           /* Convert each returned count to CARDINAL_P order */
           for (i = 0; i < MAX_MODULES; ++i){
               Pannex_id->b_count[i] = ntohs(Pannex_id->b_count[i]);
           }
      }
      switch (error) {
      case 0:
	break;
      case NAE_PROC:
	bzero((char *)&Pannex_id->b_count[0], sizeof(Pannex_id->b_count));
	break;
      default:
	goto err_oops;
	break;
      }
    }

    /* Determine the number of integral TA ports */
    error = get_ta_count(&Pannex_id->addr, CARDINAL_P, 
	(caddr_t)&Pannex_id->ta_count);
    switch (error) {
	case 0:
	    break;
	case NAE_PROC:
	    Pannex_id->ta_count = 0;
	    break;
	default:
	    goto err_oops;
	    break;
    }

    if (Pannex_id->version >= VERS_6) {
	error = get_annex_opt(&Pannex_id->addr, STRING_P, (caddr_t)&options);
	switch(error) {
	    case 0:
	        Pannex_id->lat = options.lat;
		Pannex_id->self_boot = options.self_boot;    
		Pannex_id->vhelp = options.vhelp;
		break;
	    case NAE_PROC:
		break;
	    default:
		goto err_oops;
		break;
	}
    }

    /* print status string for the annex. */

    printf("%s: %s%s, %d async",symbol,
	(str=display_sw_id(Pannex_id->sw_id, Pannex_id->hw_id)),
	(Pannex_id->lat ? " w/LAT" : ""), Pannex_id->port_count);

    if (Pannex_id->sync_count > 0)
	printf(", %d sync", Pannex_id->sync_count);

    if (Pannex_id->ta_count > 0)
	printf(", %d ta", Pannex_id->ta_count);

    if (Pannex_id->printer_count > 0)
	printf(", %d printer", Pannex_id->printer_count);

    printf(" ports");

    if (Pannex_id->t1_count > 0 || Pannex_id->pri_count > 0) {
      printf(", and");
      if (Pannex_id->t1_count > 0)
	printf(" %d T1 engine",Pannex_id->t1_count);
      if (Pannex_id->pri_count > 0)
	printf(" %d WAN interface",Pannex_id->pri_count);
    }
    printf("\n");

    if (strcmp("ANNEX-802.5",str) == 0)
	Pannex_id->flag |= ANX_802_5;
    
    if (copy_dest)
	(void)strcpy(copy_dest, symbol);
    
    (void)lex();


    return 0;

    /* If error, punt if requested, or return error (-1) */
err_oops:
    token_error(error);
    error = -1;
oops:
    if(oblivious) {
	printf("Warning: %s has been dropped from the list\n", symbol);
	(void)lex();
	return error;
    }
    else
	punt((char *)NULL, (char *)NULL);
    return 0;
}


/*
 * Small lexical parser
 */

void lex_string()
{
    while (*Psymbol && !index(WHITE_SPACE, *Psymbol))
	symbol[symbol_length++] = *Psymbol++;
    symbol[symbol_length] = '\0';
}

void lex_end()
{
    while (*Psymbol && *Psymbol != ' ')
	symbol[symbol_length++] = *Psymbol++;
    symbol[symbol_length] = '\0';
}

/*
 * Finally some real functionality.
 */

/*
 * Annex level functionality
 */

void annex_show_list(Pannex_list)
ANNEX_LIST	*Pannex_list;
{
    SHOW_LIST	*Show_l;
    int		p_num, parm;
    
    free_show_list();

    while (!eos) {
	p_num = match(symbol, annex_params, BOX_PARM_NAME);
	if (Ap_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "port parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SHOW_LIST structure to the end of the show list
	   pointed to by the given head and tail pointers. */
	
	Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
	Show_l->next = NULL;
	Show_l->param_num = p_num;
	
	if (!Pshow_list)
	    Pshow_list = Show_l;
	else
	    Pshow_tail->next = Show_l;
	Pshow_tail = Show_l;
	(void)lex();
    }
    
    /* Print the per-annex parameters (from the show list) for each annex
       on the given annex list. */
    
    while(Pannex_list) {
	WRAP_END;
	printf("\n\t\t%s Name:  %s\n\n", Box, Pannex_list->name);
	Show_l = Pshow_list;
	do {				/* for each "show annex" parameter */
	    
	    if(!Show_l)		/* default */
		parm = UNASSIGNED;	
	    else
		parm = Show_l->param_num;
	    
	    if((parm != UNASSIGNED) &&
	       ((Ap_category(parm) == LAT_CAT ||
		 ((Ap_category(parm) == GRP_CAT) &&
		  (Ap_catid(parm) == LAT_CAT)))
		&& !Pannex_list->annex_id.lat)) {
		printf("\t%s does not support %s\n",Pannex_list->name,
		       annex_params[parm]);
		if (Show_l)
		    Show_l = Show_l->next;
		continue;
	    }
	    
	    if((parm != UNASSIGNED) &&
	       (Ap_category(parm) == DLA_CAT || 
		Ap_category(parm) == LAT_CAT ||
		Ap_category(parm) == ARAP_CAT ||
		Ap_category(parm) == RIP_CAT ||
		Ap_category(parm) == DFE_CAT)) {
		if(Anyp_support(&Pannex_list->annex_id,parm,annexp_table) &&
		   Ap_support_check(&Pannex_list->annex_id,parm))
		    annex_show_sub(&Pannex_list->annex_id, parm);
		else
		    printf("\t%s does not support %s\n",
			   Pannex_list->name, annex_params[parm]);
	    } 
	    else {
		
		/*
		 * The default will show only generic category parameters.
		 */
		if (parm == UNASSIGNED) { /* default */
		    for(p_num = 0; Ap_index(p_num) != -1; p_num++) {
			
			if (Anyp_support(&Pannex_list->annex_id,p_num,annexp_table) &&
			    Ap_support_check(&Pannex_list->annex_id,
					     p_num) &&
			    ((Ap_displaycat(p_num)==B_GENERIC_CAT))) {
			    annex_show_sub(&Pannex_list->annex_id,p_num);
			}
		    }
		    
		    /* else annex category list */
		}
		else if (Ap_category(parm) == GRP_CAT) {
		    
		    for (p_num = 0; Ap_index(p_num) != -1; p_num++) {
			if (Anyp_support(&Pannex_list->annex_id,p_num,annexp_table) &&
			    Ap_support_check(&Pannex_list->annex_id,
					     p_num) &&
			    ((Ap_displaycat(p_num)==Ap_catid(parm))
			     || (Ap_catid(parm) == ALL_CAT)) &&
			    ((Ap_category(p_num) != LAT_CAT
			      || Pannex_list->annex_id.lat))) {
			    annex_show_header(p_num);
			    annex_show_sub(&Pannex_list->annex_id,p_num);
			}
		    }
		}
	    }
	    if(Show_l)
		Show_l = Show_l->next;
	    
	}	while(Show_l);
	
	Pannex_list = Pannex_list->next;
    }
    printf("\n");
}

/*
 * Output the annex category headers.
 */

void 
annex_show_header(p_num) 
int		p_num;
{
    switch (p_num) {
	case BOX_GENERIC_GROUP:	WRAP_END;	printf(hdr_fmt, box_generic);
	break;
	case BOX_VCLI_GROUP:	WRAP_END;	printf(hdr_fmt, box_vcli);
	break;
#if NNAME_SERVERS > 0
	case BOX_NAMESERVER_GROUP:WRAP_END; printf(hdr_fmt, box_nameserver);
	  break;
#endif
	case BOX_SECURITY_GROUP:WRAP_END;	printf(hdr_fmt, box_security);
	break;
	case BOX_TIME_GROUP:	WRAP_END;	printf(hdr_fmt, box_time);
	break;
	case BOX_SYSLOG_GROUP:	WRAP_END;	printf(hdr_fmt, box_syslog);
	break;
#if NLAT > 0
	case BOX_LAT_GROUP:	WRAP_END;	printf(hdr_fmt, box_lat);
	break;
#endif
#if NARAP > 0
	case BOX_ARAP_GROUP:	WRAP_END;	printf(hdr_fmt, box_arap);
	break;
#endif
	case BOX_RIP_GROUP:	WRAP_END;	printf(hdr_fmt, box_rip);
	break;
#if NKERB > 0
	case BOX_KERBEROS_GROUP:WRAP_END;	printf(hdr_fmt, box_kerberos);
	break;
#endif
#if NIPXOPT > 0
	case BOX_IPX_GROUP: WRAP_END; printf(hdr_fmt, box_ipx); break;
#endif
#if NDEC > 0
	case BOX_VMS_GROUP: WRAP_END; printf(hdr_fmt, box_vms);	break;
#endif
#if NTMUX > 0
	case BOX_TMUX_GROUP: WRAP_END; printf(hdr_fmt, box_tmux); break;
#endif
#if NDHCPCLIENT > 0
	case BOX_DHCP_GROUP: WRAP_END; printf(hdr_fmt, box_dhcp); break;
#endif
#if NCMUSNMP > 0
	case BOX_SNMP_GROUP: WRAP_END; printf(hdr_fmt, box_snmp); break;
#endif
	default:
	break;
    }
}

/*
 * Show the parameter
 */

void annex_show_sub(Pannex_id, p_num)
ANNEX_ID	   *Pannex_id;
int		   p_num;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type;		/*  Data type	    */
    int		   error;
    long	   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   external[LINE_LENGTH];		/*  Human format    */
    char	   *start_delim;
    
    /* Print the value of an annex parameter. */
    category = Ap_category(p_num);
    
    if (category == DLA_CAT || category == DFE_CAT || category == LAT_CAT ||
	category == ARAP_CAT || category == RIP_CAT) {

	id = Ap_catid(p_num);
	type = Ap_type(p_num);
	error = get_dla_param(&Pannex_id->addr, (u_short)category,
				 (u_short)id, (u_short)type, internal);
	if (error != 0) 
	    netadm_error(error);
	else {
	    decode(Ap_convert(p_num), internal, external,Pannex_id);
	    LONGWRAP(external);
	    if (start_delim = split_string(annex_params[p_num], FALSE))
		printf(FMT, start_delim, external);
	    else
		printf(FMT, annex_params[p_num], external);
	    WRAP;
	}
    }
}

/*
 * Asynchronous port level functionality
 */

void port_show_list(Pport_set)
PORT_SET	*Pport_set;
{
    ANNEX_LIST	*Annex_l;
    SHOW_LIST	*Show_l;
    int		p_num;
    
    free_show_list();
    
    while(!eos) {
	p_num = match(symbol, port_params, "port parameter name");
	if (Sp_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "port parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SHOW_LIST structure to the end of the show list
	   pointed to by the given head and tail pointers. */
	
	Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
	Show_l->next = NULL;
	Show_l->param_num = p_num;
	
	if (!Pshow_list)
	    Pshow_list = Show_l;
	else
	    Pshow_tail->next = Show_l;
	Pshow_tail = Show_l;
	(void)lex();
    }
    
    /* Print the serial port parameters (from the show list) for each
       port in the given port set. */
    
    while (Pport_set) {
	/* If an annex id was specified, use it; otherwise, use the
	   default annex list. */
	if (Pport_set->annex_id.addr.sin_addr.s_addr)
	    do_show_port(&Pport_set->annex_id, Pport_set->name,
			 &Pport_set->ports);
	else
	    if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l; Annex_l=Annex_l->next)
		    do_show_port(&Annex_l->annex_id, Annex_l->name,
				 &Pport_set->ports);
	    else
		punt(NO_BOXES, (char *)NULL);
	
	Pport_set = Pport_set->next;
    }
    printf("\n");
}

void 
port_show_header(p_num, ispri) 
int		p_num;
int		ispri;
{
    switch (p_num) {
	case PORT_GENERIC_GROUP:WRAP_END;	printf(hdr_fmt, port_generic);
	break;

	case PORT_FLOWCONTROL_GROUP: WRAP_END;	printf(hdr_fmt, port_flow);
	break;
	case PORT_FLOWCONTROL_GROUP+1:
	if (ispri) {
	    WRAP_END;
	    printf(hdr_fmt, port_flow);
	}
	break;

	case PORT_TIMER_GROUP:	WRAP_END;	printf(hdr_fmt, port_timers);
	break;
	case PORT_LOGINUSR_GROUP:WRAP_END;	printf(hdr_fmt, port_login);
	break;
	case PORT_SECURITY_GROUP:WRAP_END;	printf(hdr_fmt, port_security);
	break;
	case PORT_CHAR_GROUP:	WRAP_END;	printf(hdr_fmt, port_edit);
	break;
	case PORT_NETADDR_GROUP:WRAP_END;    printf(hdr_fmt, port_serialproto);
	break;
	case PORT_SLIP_GROUP:	WRAP_END;	printf(hdr_fmt, port_slip);
	break;
	case PORT_PPP_GROUP:	WRAP_END;	printf(hdr_fmt, port_ppp);
	break;
	case PORT_ARAP_GROUP:	WRAP_END;	printf(hdr_fmt, port_arap);
	break;
	case PORT_TN3270_GROUP:	WRAP_END;	printf(hdr_fmt, port_tn3270);
	break;
	case PORT_LAT_GROUP:	WRAP_END;	printf(hdr_fmt, port_lat);
	break;
	default:
	break;
    }
}

void port_show_sub(Pannex_id, port, p_num)
ANNEX_ID	   *Pannex_id;
unsigned short     port;
int                p_num;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type,		/*  Data type	    */
		   convert;		/*  Conversion type */
    int		   error;
    long	   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   external[LINE_LENGTH];		/*  Human format    */
    char	   latter = FALSE;
    char	   *start_delim;
    
    /* Print the value of a serial port parameter. */
    category = Sp_category(p_num);
    if(category == INTF_CAT || category == DEV_CAT || category == EDIT_CAT ||
       category == DEV2_CAT || category == SLIP_CAT) {

	id = (u_short) Sp_catid(p_num);
	type = (u_short) Sp_type(p_num);
	convert = (u_short) Sp_convert(p_num);

#ifdef NA
	if (category == DEV_CAT && id == DEV_ATTN) {
	    if((Pannex_id->version < VERS_6_2)||(Pannex_id->hw_id < ANX3)) {
		convert = CNV_PRINT;
		type = CARDINAL_P;
		latter = TRUE;
	    }
	}
	if (category == DEV_CAT && id == DEV_BANNER) {
            if((Pannex_id->version < VERS_14_0)) {
	      convert = CNV_DFT_Y;
	      type = BOOLEAN_P;
	    }
	  }

#endif
	error = get_ln_param(&Pannex_id->addr, (u_short)SERIAL_DEV, port,
				(u_short)category, (u_short)id, (u_short)type,
                         internal);

    /* If we are talking with an annex that uses 16 character username */
    /* fields, then we want to get the username as a 16 character string */
    if (error && ((id == DEV_NAME) || (id == PPP_UNAMERMT)))
    {
        if (id == DEV_NAME)
            id = DEV_NAME_OLD;
        else
            id = PPP_UNAMERMT_OLD;
        convert = CNV_STRING;
        type = STRING_P;
        error = get_ln_param(&Pannex_id->addr, (u_short)SERIAL_DEV, port,
                             (u_short)category, (u_short)id, (u_short)type,
                             internal);
    }
    
    if (error)    
        netadm_error(error);
	else {
	    decode(convert,internal,external,Pannex_id);
	    LONGWRAP(external);
	    if (start_delim = split_string(port_params[p_num], latter))
		printf(FMT, start_delim, external);
	    else
		printf(FMT, port_params[p_num], external);
	    WRAP;
	}
    }
    return;    
}

void do_show_port(Pannex_id, name, Pports)
ANNEX_ID	  	*Pannex_id;
char			name[];
PORT_GROUP 		*Pports;
{
    SHOW_LIST	*Show_l;
    int		parm,
		p_num,
    		loop,
		shown = 0,
    		pcount, ispri;

    pcount = Pannex_id->port_count;
    ispri = Pannex_id->hw_id == ANX_PRIMATE;
    if (ispri)
      pcount = 1;
    
    if (pcount <= 0) {
	printf("\n%s %s no asynchronous ports\n", BOX, name);
	return;
    }

    /* Print the value of the serial port parameter for each port
       whose bit is set in the port mask. */
    
    for (loop = 1; loop <= pcount; loop++) {
	if (ispri || PORTBITSET(Pports->serial_ports, loop)) {
	    shown++;
	    WRAP_END;
	    if (ispri)
	      printf("\n%s %s global port:\n", BOX, name);
	    else
	      printf("\n%s %s port asy%d:\n", BOX, name, loop);
	    Show_l = Pshow_list;
	    do {			/* for each "show port" parameter */

		if(!Show_l)		/* default */
		    p_num = UNASSIGNED;		/* to all  */
		else
		    p_num = Show_l->param_num;
		
		if((p_num == UNASSIGNED) || (Sp_category(p_num) == GRP_CAT)) {
		    
		    if (Sp_catid(p_num) == P_SYNC_CAT)
		      if (ispri) {
			int i,j;
			for (i = 0; (j=port_sync_parm_list[i]) >= 0; i++) {
			  port_show_header(j, ispri);
			  port_show_sub(Pannex_id, loop, j);
			}
		      } else
			printf("\t%s does not support %s\n",name,
			       port_params[p_num]);
		    else
		    for(parm = 0; Sp_index(parm) != -1; parm++) {

			/*
			 * Only add those parms of this category
			 * exception:
			 *	 "show port slip" shows slip and serial cats.
			 *       "show port ppp" shows ppp and serial cats.
			 */
			if(Anyp_support(Pannex_id, parm,portp_table) &&
			   Sp_support_check(Pannex_id, parm)) {

			    if((p_num == UNASSIGNED) ||
			       (Sp_catid(p_num) == ALL_CAT) ||
			       (Sp_displaycat(parm) == Sp_catid(p_num)) ||
			       ((Sp_displaycat(parm) == P_SERIAL_CAT) && 
				Sp_index(p_num) == PORT_SLIP) ||
			       ((Sp_displaycat(parm) == P_SERIAL_CAT) && 
				Sp_index(p_num) == PORT_PPP) ||
			       ((Sp_catid(p_num) == DEV_CAT) &&
				(Sp_category(parm) == DEV2_CAT))) {

				/*
				 * don't display LAT group code if LAT is off
				 */
				if (Pannex_id->lat == 0 &&
				    Sp_displaycat(parm) == P_LAT_CAT)
				    ;
				else {
				    /*
				     * The default will show only generic and
				     * flow category parameters.
				     */
				    if (p_num == UNASSIGNED) {
					if (Sp_displaycat(parm) == P_GENERIC_CAT                                    || Sp_displaycat(parm) == P_FLOW_CAT) {
					    port_show_header(parm, ispri);
					    port_show_sub(Pannex_id, loop, parm);
					}
				    }
				    else {
					port_show_header(parm, ispri);
					port_show_sub(Pannex_id, loop, parm);
				    }
				}
			    }
			}
		    }
		}
		else {
		    if (Anyp_support(Pannex_id,p_num,portp_table) &&
			Sp_support_check(Pannex_id,p_num)) {
			/*
			 * don't display authorized_groups and
			 * latb_enable if LAT is off 
			 */
			if (Pannex_id->lat == 0 &&
			    Sp_displaycat(p_num) == P_LAT_CAT)
			    printf("\t%s does not support %s\n",name,
				   port_params[p_num]);
			else
			    port_show_sub(Pannex_id, (u_short)loop, p_num);
		    }
		    else
			printf("\t%s does not support %s\n", name,
			       port_params[p_num]);
		}
		if(Show_l)
		    Show_l = Show_l->next;
		
	    } while(Show_l);
	}
    }
    if (shown == 0)
	printf("\n%s %s asynchronous port set has not been defined\n", BOX,
	       name);
    return;    
}

/*
 * Integrated modem support.
 */

void
modem_show_list(Pmodem_set)
MODEM_SET	*Pmodem_set;
{
    ANNEX_LIST	*Annex_l;
    SHOW_LIST	*Show_l;
    int		p_num;
    
    free_show_list();
    
    while(!eos) {
	p_num = match(symbol, modem_params, "modem parameter name");
	if (Modemp_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "modem port parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SHOW_LIST structure to the end of the show list
	   pointed to by the given head and tail pointers. */
	
	Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
	Show_l->next = NULL;
	Show_l->param_num = p_num;
	
	if (!Pshow_list)
	    Pshow_list = Show_l;
	else
	    Pshow_tail->next = Show_l;
	Pshow_tail = Show_l;
	(void)lex();
    }
    
    /* Print the modem port parameters (from the show list) for each
       port in the given port set. */
    while (Pmodem_set) {
	/* If an annex id was specified, use it; otherwise, use the
	   default annex list. */
	if (Pmodem_set->annex_id.addr.sin_addr.s_addr)
	    do_show_modem(&Pmodem_set->annex_id, Pmodem_set->name,
			 &Pmodem_set->modems);
	else
	    if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l; Annex_l=Annex_l->next)
		    do_show_modem(&Annex_l->annex_id,
				 Annex_l->name,
				 &Pmodem_set->modems);
	    else
		punt(NO_BOXES, (char *)NULL);
	
	Pmodem_set = Pmodem_set->next;
    }
    printf("\n");
}

void 
modem_show_header(p_num) 
int		p_num;
{
#if 0
  /* There's only one group for now, so don't bother. */
    switch (p_num) {
	case MODEM_GENERIC_GROUP:WRAP_END;	printf(hdr_fmt, modem_generic);
	break;
    }
#endif
}

void
modem_show_sub(Pannex_id, port, p_num)
ANNEX_ID	   *Pannex_id;
unsigned short     port;
int                p_num;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type,		/*  Data type	    */
		   convert;		/*  Conversion type */
    int		   error;
    long	   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   external[LINE_LENGTH],		/*  Human format    */
		   *cp;
    char	   latter = FALSE;
    char	   *start_delim;
    
    /* Print the value of a serial port parameter. */
    category = Modemp_category(p_num);
    if(category == MODEM_CAT) {

	id = (u_short) Modemp_catid(p_num);
	type = (u_short) Modemp_type(p_num);
	convert = (u_short) Modemp_convert(p_num);
	if(error = get_modem_param(&Pannex_id->addr, (u_short)MODEM_DEV, port,
				(u_short)category, (u_short)id, (u_short)type,
				internal))
	    netadm_error(error);
	else {
	    decode(convert,internal,external,Pannex_id);
	    LONGWRAP(external);
	    if (start_delim = split_string(modem_params[p_num], latter))
		printf(FMT, start_delim, external);
	    else
		printf(FMT, modem_params[p_num], external);
	    WRAP;
	}
    }
}

void
do_show_modem(Pannex_id, name, Pmodems)
ANNEX_ID	  	*Pannex_id;
char			name[];
MODEM_GROUP 		*Pmodems;
{
    SHOW_LIST	*Show_l;
    int		p_num,
		parm,
		loop,
		shown = 0;

    if (Pannex_id->port_count == 0 || Pannex_id->hw_id != ANX_PRIMATE) {
	printf("\n%s %s has no internal modems\n", BOX, name);
	return;
    }

    /* Print the value of the serial port parameter for each port
       whose bit is set in the port mask. */
    for (loop = 1; loop <= Pannex_id->port_count; loop++) {
	if (PORTBITSET(Pmodems->modems, loop)) {
	    WRAP_END;
	    printf("\n%s %s modem %d:\n", BOX, name, loop);
	    Show_l = Pshow_list;
	    do {			/* for each "show modem" parameter */

		shown++;
		if(!Show_l)		/* default */
		    parm = UNASSIGNED;		/* to all  */
		else
		    parm = Show_l->param_num;
		
		if((parm == UNASSIGNED) || (Modemp_category(parm) == GRP_CAT)) {
		    for(p_num = 0; Modemp_index(p_num) != -1; p_num++)
			
			if(Anyp_support(Pannex_id,p_num,modemp_table)){

				    modem_show_header(p_num);
				    modem_show_sub(Pannex_id, loop, p_num);
			    }
		}
		else
		    if(Anyp_support(Pannex_id,parm,modemp_table)) {
			modem_show_sub(Pannex_id, (u_short)loop, parm);
		    }
		    else
			printf("\t%s does not support %s\n",name,
			       modem_params[parm]);
		if(Show_l)
		    Show_l = Show_l->next;
		
	    } while(Show_l);
	}
    }
    if (shown == 0)
	printf("\n%s %s modem set has not been defined\n", BOX,name);
    return;
}

/*
 *  Printer port level functionality
 */

void printer_show_list(Pprinter_set)
PRINTER_SET	*Pprinter_set;
{
    ANNEX_LIST	*Annex_l;
    SHOW_LIST	*Show_l;
    int		p_num;
    
    free_show_list();
    
    while(!eos) {
	p_num = match(symbol, printer_params, "printer parameter name");
	if (Cp_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "printer parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SHOW_LIST structure to the end of the show list
	   pointed to by the given head and tail pointers. */
	
	Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
	Show_l->next = NULL;
	Show_l->param_num = p_num;
	
	if (!Pshow_list)
	    Pshow_list = Show_l;
	else
	    Pshow_tail->next = Show_l;
	Pshow_tail = Show_l;
	(void)lex();
    }
    
    /* Print the serial printer parameters (from the show list) for each
       printer in the given printer set. */
    
    while (Pprinter_set) {
	/* If an annex id was specified, use it; otherwise, use the
	   default annex list. */
	if (Pprinter_set->annex_id.addr.sin_addr.s_addr)
	    do_show_printer(&Pprinter_set->annex_id, Pprinter_set->name,
			    &Pprinter_set->printers);
	else
	    if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l; Annex_l=Annex_l->next)
		    do_show_printer(&Annex_l->annex_id, Annex_l->name,
				    &Pprinter_set->printers);
	    else
		punt(NO_BOXES, (char *)NULL);
	
	Pprinter_set = Pprinter_set->next;
    }
    printf("\n");
}

void printer_show_sub(Pannex_id, printer, p_num)
ANNEX_ID	   *Pannex_id;
unsigned short     printer;
int                p_num;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type;       		/*  Data type	    */
    int		   error;
    long	   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   external[LINE_LENGTH];		/*  Human format    */
    char	   *start_delim;
    
    /* Print the value of a printer (parallel) port parameter. */
    category = Cp_category(p_num);
    if(category == LP_CAT) {

	id = Cp_catid(p_num);
	type = Cp_type(p_num);
    if (error = get_ln_param(&Pannex_id->addr, (u_short)P_PRINT_DEV,
                         (u_short)printer, (u_short)category, 
                         (u_short)id, (u_short)type, internal))
        netadm_error(error);
	else {
	    decode(Cp_convert(p_num), internal, external, Pannex_id);
	    LONGWRAP(external);
	    if (start_delim=split_string(printer_params[p_num], FALSE))
		printf(FMT, start_delim, external);
	    else
		printf(FMT, printer_params[p_num], external);
	    WRAP;
	}
    }
    return;    
}

void do_show_printer(Pannex_id, name, Pprinters)
ANNEX_ID	  	*Pannex_id;
char			name[];
PRINTER_GROUP 		*Pprinters;
{
    SHOW_LIST	*Show_l;
    int		p_num,
		parm,
		loop,
		shown = 0;
    
    /* Print the value of the printer parameter for each printer
       whose bit is set in the printer mask. */
    
    if(Pannex_id->printer_count == 0) {
	printf("\n%s %s no printer ports\n", BOX, name);
	return;
    }

    for (loop = 1; loop <= Pannex_id->printer_count; loop++) {
	if (PRINTERBITSET(Pprinters->ports,loop)) {
	    shown++;
	    WRAP_END;
	    printf("\n%s %s printer %d:\n", BOX, name, loop);
	    Show_l = Pshow_list;
	    do {		/* for each "show printer" parameter */
		
		if(!Show_l)		/* default */
		    parm = UNASSIGNED;		/* to all  */
		else
		    parm = Show_l->param_num;
		
		if((parm == UNASSIGNED) || (Cp_category(parm) == GRP_CAT)) {
		    for(p_num = 0; Cp_index(p_num) != -1; p_num++) {
			if(Anyp_support(Pannex_id,p_num,printp_table)) {
			    if((parm == UNASSIGNED) ||
			       (Cp_catid(parm) == ALL_CAT) ||
			       (Cp_category(p_num) == Cp_catid(parm))) {
				printer_show_sub(Pannex_id, loop, p_num);
			    }
			}
		    }
		}
		else
		    if(Anyp_support(Pannex_id,parm,printp_table))
			printer_show_sub(Pannex_id, (u_short)loop, parm);
		    else
			printf("\t%s does not support %s\n",name,
			       printer_params[parm]);
		if(Show_l)
		    Show_l = Show_l->next;
		
	    } while(Show_l);
	}
    }
    if (shown == 0)
	printf("\n%s %s printer set has not been defined\n", BOX, name);
    return;    
}

/*
 *  Interface level functionality
 */

void interface_show_list(Pinterface_set)
INTERFACE_SET	*Pinterface_set;
{
    ANNEX_LIST	*Annex_l;
    SHOW_LIST	*Show_l;
    int		p_num;
    
    free_show_list();
    
    while(!eos) {
	p_num =match(symbol, interface_params, "interface parameter name");
	if (Ip_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "interface parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SHOW_LIST structure to the end of the show list
	   pointed to by the given head and tail pointers. */
	
	Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
	Show_l->next = NULL;
	Show_l->param_num = p_num;
	
	if (!Pshow_list)
	    Pshow_list = Show_l;
	else
	    Pshow_tail->next = Show_l;
	Pshow_tail = Show_l;
	(void)lex();
    }
    
    /* Print the interface parameters (from the show list) for each
       interface in the given interface set. */
    
    while (Pinterface_set) {
	/* If an annex id was specified, use it; otherwise, use the
	   default annex list. */
	if (Pinterface_set->annex_id.addr.sin_addr.s_addr)
	    do_show_interface(&Pinterface_set->annex_id, Pinterface_set->name,
			      &Pinterface_set->interfaces);
	else
	    if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l; Annex_l=Annex_l->next)
		    do_show_interface(&Annex_l->annex_id, Annex_l->name,
				      &Pinterface_set->interfaces);
	    else
		punt(NO_BOXES, (char *)NULL);
	
	Pinterface_set = Pinterface_set->next;
    }
    printf("\n");
}

void 
interface_show_header(p_num) 
int	p_num;
{
    switch (p_num) {
	
	case INTERFACE_RIP_GROUP:WRAP_END;	printf(hdr_fmt, interface_rip);
	break;
	default:
	break;
    }
}

void interface_show_sub(Pannex_id, Interface, p_num)
ANNEX_ID	   *Pannex_id;
unsigned short     Interface;
int                p_num;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type,		/*  Data type	    */
		   convert;		/*  Conversion type */
    int		   error;
    long	   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   external[LINE_LENGTH];		/*  Human format    */
    char	   latter = FALSE;
    char	   *start_delim;
    
    /* Print the value of an Interface parameter. */
    category = Ip_category(p_num);
    if(category == IF_CAT) {

	id = (u_short) Ip_catid(p_num);
	type = (u_short) Ip_type(p_num);
	convert = (u_short) Ip_convert(p_num);
	if(error = get_if_param(&Pannex_id->addr, (u_short)INTERFACE_DEV,
				Interface, (u_short)category, (u_short)id,
				(u_short)type, internal))
	    netadm_error(error);
	else {
	    decode(convert,internal,external,Pannex_id);
	    LONGWRAP(external);
	    if (start_delim = split_string(interface_params[p_num], latter))
		printf(FMT, start_delim, external);
	    else
		printf(FMT, interface_params[p_num], external);
	    WRAP;
	}
    }
}

void do_show_interface(Pannex_id, name, Pinterfaces)
ANNEX_ID	  	*Pannex_id;
char			name[];
INTERFACE_GROUP 	*Pinterfaces;
{
    SHOW_LIST	*Show_l;
    int		p_num,
		parm,
		loop, loop_limit,
		asy_end,
		syn_end,
		if_num,
		shown = 0, ispri;
    char	ifname[32];
    
    /* Print the value of the each interface parameter for each interface 
       whose bit is set in the interface mask. */
    
    asy_end = (int)Pannex_id->port_count + 1;
    syn_end = (int)Pannex_id->sync_count + 1 + ALL_PORTS;
    loop_limit = ALL_INTERFACES;

    ispri = Pannex_id->hw_id == ANX_PRIMATE;
    if (ispri) {
      asy_end = loop_limit = 2;
      if (!(Pinterfaces->pg_bits & PG_ALL)) {
	for (loop = 3; loop <= ALL_INTERFACES; loop++)
	  if (INTERFACEBITSET(Pinterfaces->interface_ports,loop))
	    break;
	if (loop <= ALL_INTERFACES) {
	  printf("\nIllegal interface set for %s %s; set ignored.\n",BOX,name);
	  return;
	}
      }
    }

    for (loop = 1; loop <= loop_limit; loop++) {
	
	if ((loop <= asy_end) || ((loop > ALL_PORTS+1) && (loop <= syn_end))) {
	    
	    if (INTERFACEBITSET(Pinterfaces->interface_ports,loop)) {
		
	    	/*
	     	 * Convert the logical index into async interface
	     	 * number to make sure within the port range.
	     	 */
		if_num = loop;
		
		if (if_num > (M_ETHERNET + ALL_PORTS)) {
		    if_num = if_num - M_ETHERNET - ALL_PORTS;
		    if (if_num > (int)Pannex_id->sync_count) {
			printf("\n%s %s does not have an synchronous interface %d\n",
			       BOX, name, if_num);
			continue;
		    }
		} else if (!ispri && if_num > M_ETHERNET) {
		  if_num = if_num - M_ETHERNET;
		  if (if_num > (int)Pannex_id->port_count) {
		    printf("\n%s %s does not have an asynchronous interface %d\n",
			   BOX, name, if_num);
		    continue;
		  }
		}
		WRAP_END;
		
		/* convert the interface logical index into human-eye form */
		get_if_name(ifname,loop,ispri);
		printf("\n%s %s interface %s:\n", BOX, name, ifname);
		
	        Show_l = Pshow_list;
	        do {		/* for each "show interface" parameter */
		    
		    shown++;
		    if(!Show_l)		/* default */
			parm = UNASSIGNED;	/* to all  */
		    else
			parm = Show_l->param_num;
		    
		    if((parm == UNASSIGNED) ||(Ip_category(parm) == GRP_CAT)) {

			for(p_num = 0; Ip_index(p_num) != -1; p_num++) {
			    if(Anyp_support(Pannex_id,p_num,interfacep_table) && Ip_support_check(Pannex_id, p_num)) {
				if((parm == UNASSIGNED) ||
				   (Ip_catid(parm) == ALL_CAT) ||
				   (Ip_category(p_num) == Ip_catid(parm))) {
				    interface_show_header(p_num); 
				    interface_show_sub(Pannex_id, loop, p_num);
				}
			    }
			}
		    }
		    else
			if(Anyp_support(Pannex_id,parm,interfacep_table) && Ip_support_check(Pannex_id, parm))
			    interface_show_sub(Pannex_id, (u_short)loop, parm);
			else
			    printf("\t%s does not support %s\n",name,
				   interface_params[parm]);
		    if(Show_l)
			Show_l = Show_l->next;
		    
		} while(Show_l);
	    }
	}
    }
    if (shown == 0)
	printf("\n%s %s interface set has not been defined\n", BOX, name);
    return;    
}

/*
 * T1 level functionality
 */

void t1_show_list(Pt1_set)
T1_SET	*Pt1_set;
{
    ANNEX_LIST	*Annex_l;
    SHOW_LIST	*Show_l;
    int		p_num;
    char        **t1_params = t1_all_params;

    free_show_list();
    
    if(Pt1_set) {
	for (p_num = 1; p_num<=ALL_DS0S; p_num++)
	    CLRPORTBIT(Pt1_set->ds0s.ds0s, p_num);	
	}

    while(!eos) {
      if (!strncmp(symbol,"ds0",strlen(symbol))) {
	/* ds0 sub classification */
	(void)lex();

	if (symbol_length == 1 && symbol[0] == '=') {
	  (void)lex();
	  if (eos)
	    punt("missing ds0 identifier", (char *)NULL);
	  else {
	    for (p_num = 1; p_num<=ALL_DS0S; p_num++)
	      CLRPORTBIT(Pt1_set->ds0s.ds0s, p_num);	
	    ds0_list(&Pt1_set->ds0s);
	  }
	} else {
	  for (p_num = 1; p_num<=ALL_DS0S; p_num++)
	    SETPORTBIT(Pt1_set->ds0s.ds0s, p_num);	/* all ds0's */
	}

	/* Setup t1 table to use */
	t1_params = t1_ds0_params;

	if (eos)
	  break;
      }

      p_num = match(symbol, t1_params, "t1 parameter name");
      if (T1p_category(p_num) == VOID_CAT) {
	/* obsolete parameter */
	char error_msg[80];
	error_msg[0] = '\0';
	(void)strcat(error_msg, "t1 parameter name: ");
	(void)strcat(error_msg, symbol);
	punt("invalid ", error_msg);
      }
	
      /* Add a new SHOW_LIST structure to the end of the show list
	 pointed to by the given head and tail pointers. */
      
      Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
      Show_l->next = NULL;
      Show_l->param_num = p_num;
      
      if (!Pshow_list)
	Pshow_list = Show_l;
      else
	Pshow_tail->next = Show_l;
      Pshow_tail = Show_l;
      (void)lex();
    }
    
    /* Print the T1 parameters (from the show list) for each
       port in the given port set. */
    while (Pt1_set) {
	/* If an annex id was specified, use it; otherwise, use the
	   default annex list. */
	if (Pt1_set->annex_id.addr.sin_addr.s_addr)
	    do_show_t1(&Pt1_set->annex_id, Pt1_set->name,
			 &Pt1_set->t1s, &Pt1_set->ds0s, t1_params);
	else
	    if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l; Annex_l=Annex_l->next)
		    do_show_t1(&Annex_l->annex_id,
				 Annex_l->name,
				 &Pt1_set->t1s, &Pt1_set->ds0s, t1_params);
	    else
		punt(NO_BOXES, (char *)NULL);
	
	Pt1_set = Pt1_set->next;
    }
    printf("\n");
}

void 
t1_show_header(p_num) 
int		p_num;
{
    switch (p_num) {
	case T1_GENERIC_GROUP:WRAP_END;	printf(hdr_fmt, t1_generic);
	break;
	case T1_DS0_MAP:WRAP_END;	printf(hdr_fmt, t1_ds0_map);
	break;
	case T1_DS0_SIGPROTO:WRAP_END;	printf(hdr_fmt, t1_ds0_sig);
	break;
	case T1_DS0_RING:WRAP_END;	printf(hdr_fmt, t1_ds0_ring);
	break;
	default:
	break;
    }
}

void t1_show_sub(Pannex_id, engine_no, p_num, Pds0s, t1_params)
ANNEX_ID	   *Pannex_id;
unsigned short     engine_no;
int                p_num;
DS0_GROUP 	   *Pds0s;
char               **t1_params;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type,		/*  Data type	    */
		   convert,		/*  Conversion type */
                   i;
    int		   error;
    long	   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
                   *external;		                /*  Human format    */
    char	   latter = FALSE;
    char	   *start_delim,
                   tmp_buf[4];
    char	   tot_ds0s, skip_print=FALSE;
    
    /* Get external buffer */
    external = malloc(ALL_DS0S * LINE_LENGTH);
 
    /* Print the value of a t1 parameter. */
    if (t1_params == t1_all_params)
      category = T1p_category(p_num);
    else
      category = T1ds0p_category(p_num);

    /* how many ds0's were selected? */
    tot_ds0s=0;
    for(i=0;i<ALL_DS0S;i++)
      if (PORTBITSET(Pds0s->ds0s, i+1))
	tot_ds0s++;

    if(category == T1_CAT) {

	id = (u_short) T1p_catid(p_num);
	type = (u_short) T1p_type(p_num);
	convert = (u_short) T1p_convert(p_num);
	if(error = get_t1_param(&Pannex_id->addr, (u_short)T1_DEV, engine_no,
				(u_short)category, (u_short)id, (u_short)type,
				internal))
	    netadm_error(error);
	else {
	  switch (p_num) {
	  case T1_DS0_MAP:
	  case T1_DS0_SIGPROTO:
	    if(tot_ds0s == 0) {
		/* no ds0's selected */
		skip_print = TRUE;
		break;
		}
	    *external = 0;
	    for(i=0;i<ALL_DS0S;i++)
	      if (PORTBITSET(Pds0s->ds0s, i+1))
		{
		/* ds0 map encoding: <channel number> <mode> <modem number> */
		/* ds0 proto encoding:<channel number> <in proto> <out proto> */
		  tmp_buf[0] = i+1;
		  tmp_buf[1] = internal[2*i];
		  tmp_buf[2] = internal[2*i+1];
		  if(strlen(external))
		    (void)strcat(external, ds0_spaces);
		  decode(convert,tmp_buf,&external[strlen(external)],
			 Pannex_id);
		}
	    break;
	  case T1_DS0_RING:
	    if(tot_ds0s == 0) {
		/* no ds0's selected */
		skip_print = TRUE;
		break;
		}
	    *external = 0;
	    for(i=0;i<ALL_DS0S;i++)
	      if (PORTBITSET(Pds0s->ds0s, i+1))
		{
		/* ds0 ring encoding: <channel number> <ring flag in bit 0> */
		  tmp_buf[0] = i+1;
		  tmp_buf[1] = internal[i];
		  if(strlen(external))
		    (void)strcat(external, ds0_spaces);
		  decode(convert,tmp_buf,&external[strlen(external)],
			 Pannex_id);
		}
	    break;
	  default:
	    /* generic t1 parameter, no ds0's (T1_GENERIC_GROUP) */
	    skip_print = FALSE;
	    decode(convert,internal,external,Pannex_id);
	    break;
	  }
	  if(skip_print == FALSE) {
	  LONGWRAP(external);
	  if (start_delim = split_string(t1_params[p_num], latter))
	    printf(FMT, start_delim, external);
	  else
	    printf(FMT, t1_params[p_num], external);
	  WRAP;
	  }
	}
    }
    
    /* Free up buffer */
    free(external);
}

void do_show_t1(Pannex_id, name, Pt1s, Pds0s, t1_params)
ANNEX_ID	  	*Pannex_id;
char			name[];
T1_GROUP 		*Pt1s;
DS0_GROUP 		*Pds0s;
char                    **t1_params;
{
    SHOW_LIST	*Show_l;
    int		p_num,
		parm,
		loop,
		shown = 0;

    if (Pannex_id->t1_count == 0) {
	printf("\n%s %s has no t1 engines\n", BOX, name);
	return;
    }

    /* Print the value of the t1 parameter for each port
       whose bit is set in the port mask. */
    for (loop = 1; loop <= Pannex_id->t1_count; loop++) {
	if (PORTBITSET(Pt1s->engines,loop)) {
	    shown++;
	    WRAP_END;
	    printf("\n%s %s t1 engine %d:\n", BOX, name, loop);
	    Show_l = Pshow_list;
	    do {		/* for each "show t1" parameter */
		
		if(!Show_l) {		/* default */
		    parm = UNASSIGNED;		/* to all  */
		  }
		else {
		  parm = Show_l->param_num;
		  
		  /* Set ds0 mask if showing all parameters */
		  if ((t1_params == t1_all_params) &&
		      ((parm == ALL_T1DS0P) || (parm == ALL_T1P) ||
		       (parm == T1_MAP_D) || (parm == T1_SIGPROTO_D) ||
#ifdef OBSOLETE_T1_PARAM
		       (parm == T1_PROTO_ARG_D) ||
#endif /*OBSOLETE_T1_PARAM*/
		       (parm == T1_RING_D))) {
		    for(p_num=1;p_num<=ALL_DS0S;p_num++)
		      SETPORTBIT(Pds0s->ds0s, p_num);
		  }
		}

		if((parm == UNASSIGNED) || 
		   (T1p_category(parm) == T1_GEN_CAT) ||
		   (parm == ALL_T1DS0P) || (parm == ALL_T1P)) {
		    for(p_num = 0; T1p_index(p_num) != -1; p_num++) {
			if(Anyp_support(Pannex_id,p_num,t1p_table)) {
			    if((parm == UNASSIGNED) ||
			       (T1p_catid(parm) == ALL_CAT) ||
			       (parm == ALL_T1DS0P) || (parm == ALL_T1P) ||
			       (T1p_category(p_num) == T1p_catid(parm))) {
				t1_show_sub(Pannex_id, loop, p_num, 
					    Pds0s, t1_params);
			    }
			}
		    }
		}
		else
		    if(Anyp_support(Pannex_id,parm,t1p_table))
			t1_show_sub(Pannex_id, (u_short)loop, parm, 
				    Pds0s, t1_params);
		    else
			printf("\t%s does not support %s\n",name,
			       t1_params[parm]);
		if(Show_l)
		    Show_l = Show_l->next;
		
	    } while(Show_l);
	}
    }
    if (shown == 0)
	printf("\n%s %s t1 set has not been defined\n", BOX, name);
}

/*
 * PRI level functionality
 */

void
pri_show_list(Ppri_set)
PRI_SET	*Ppri_set;
{
    ANNEX_LIST	*Annex_l;
    SHOW_LIST	*Show_l;
    int		p_num;
    char        **pri_params = wan_all_params;

    free_show_list();
    
    if(Ppri_set) {
	for (p_num = 1; p_num<=ALL_BS; p_num++)
	  CLRPORTBIT(Ppri_set->bs.bs, p_num);
	/* SETPORTBIT(Ppri_set->bs.bs, p_num); */
	}

    while(!eos) {
      if ((!strncmp(symbol,"b",strlen(symbol))) ||
	  (!strncmp(symbol,"ds0",strlen(symbol)))) {
	/* b-channel sub classification */
	(void)lex();

	if (symbol_length == 1 && symbol[0] == '=') {
	  (void)lex();
	  if (eos)
	    punt("missing b-channel identifier", (char *)NULL);
	  else {
	    for (p_num = 1; p_num<=ALL_BS; p_num++)
	      CLRPORTBIT(Ppri_set->bs.bs, p_num);	
	    b_list(&Ppri_set->bs);
	  }
	} else {
	  for (p_num = 1; p_num<=ALL_BS; p_num++)
	    SETPORTBIT(Ppri_set->bs.bs, p_num);	/* all b's */
	}

	/* Setup PRI table to use */
	pri_params = wan_chan_params;

	if (eos)
	  break;
      }

      p_num = match(symbol, pri_params, "WAN parameter name");
      if (Prip_category(p_num) == VOID_CAT) {
	/* obsolete parameter */
	char error_msg[80];
	error_msg[0] = '\0';
	(void)strcat(error_msg, "WAN parameter name: ");
	(void)strcat(error_msg, symbol);
	punt("invalid ", error_msg);
      }
	
      /* Add a new SHOW_LIST structure to the end of the show list
	 pointed to by the given head and tail pointers. */
      
      Show_l = (SHOW_LIST *)malloc(sizeof(SHOW_LIST));
      Show_l->next = NULL;
      Show_l->param_num = p_num;
      
      if (!Pshow_list)
	Pshow_list = Show_l;
      else
	Pshow_tail->next = Show_l;
      Pshow_tail = Show_l;
      (void)lex();
    }
    
    /* Print the PRI parameters (from the show list) for each
       port in the given port set. */
    while (Ppri_set) {
	/* If an annex id was specified, use it; otherwise, use the
	   default annex list. */
	if (Ppri_set->annex_id.addr.sin_addr.s_addr)
	    do_show_pri(&Ppri_set->annex_id, Ppri_set->name,
			 &Ppri_set->pris, &Ppri_set->bs, pri_params);
	else
	    if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l; Annex_l=Annex_l->next)
		    do_show_pri(&Annex_l->annex_id,
				 Annex_l->name,
				 &Ppri_set->pris, &Ppri_set->bs, pri_params);
	    else
		punt(NO_BOXES, (char *)NULL);
	
	Ppri_set = Ppri_set->next;
    }
    printf("\n");
}

void 
pri_show_header(p_num) 
int		p_num;
{
    switch (p_num) {
	case WAN_GENERIC_GROUP: WRAP_END; printf(hdr_fmt, wan_generic);
	break;
	case WAN_CHANNEL_GROUP: WRAP_END; printf(hdr_fmt, wan_channel_group);
	break;
	default:
	break;
    }
}

void
pri_show_sub(Pannex_id, module_no, p_num, Pbs, pri_params)
ANNEX_ID	   *Pannex_id;
unsigned short     module_no;
int                p_num;
B_GROUP 	   *Pbs;
char               **pri_params;
{
    int		   category,		/*  Param category  */
		   id,			/*  Number w/in cat */
		   type,		/*  Data type	    */
		   convert,		/*  Conversion type */
                   i,bcnt,perline;
    int		   b_chans;
    int		   error;
    long	   align_internal[SIZE_BLOCK_32_X_6/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
                   *external,		                /*  Human format    */
		   *cp;
    char	   latter = FALSE;
    char	   *start_delim;
    long           tmp_buf[2];
    char	   tot_bs, skip_print=FALSE;
    
    /* Get external buffer */
    external = malloc(ALL_BS * LINE_LENGTH);
 
    /* Print the value of a pri parameter. */
    if (pri_params == wan_all_params)
      category = Prip_category(p_num);
    else
      category = Pribp_category(p_num);

    /* how many B-channels were selected? */
    tot_bs = 0;
    b_chans = Pannex_id->b_count[module_no];

    for (i = 0; i < b_chans; i++)
      if (PORTBITSET(Pbs->bs, i+1))
	tot_bs++;

    if (category == WAN_CAT) {

	id = (u_short) Prip_catid(p_num);
	type = (u_short) Prip_type(p_num);
	convert = (u_short) Prip_convert(p_num);
	if(error = get_pri_param(&Pannex_id->addr, (u_short)PRI_DEV, module_no,
				(u_short)category, (u_short)id, (u_short)type,
				internal))
	    netadm_error(error);
	else {
	  switch (id) {
	  case WAN_SIGPROTO:
	  case WAN_RINGBACK:
	  case WAN_IPX_NODE:
	  case WAN_REMOTE_ADDRESS:
	  case WAN_IPX_NETWORK:

	    /* select display fields per param */
	    switch (id) {
		case WAN_SIGPROTO:		bcnt = 2; perline = 6; break;
		case WAN_RINGBACK:		bcnt = 1; perline = 24; break;
		case WAN_REMOTE_ADDRESS:
		case WAN_IPX_NETWORK:		bcnt = 4; perline = 4; break;
		case WAN_IPX_NODE:		bcnt = 6; perline = 3; break;
	    }
	    if (tot_bs == 0) {
		/* no b's selected */
		skip_print = TRUE;
		break;
	    }
	    *external = 0;
	    for (i = 0; i < b_chans; i++)
	      if (PORTBITSET(Pbs->bs, i+1)) {
		/* b remote_address */
		bcopy(internal+(bcnt*i),(char *)tmp_buf,bcnt);
		if (external[0] != '\0')
		  (void)strcat(external,
			       (i%perline)==0?"\n\t\t":" ");
		decode(convert,(char *)tmp_buf,external+strlen(external),
		       Pannex_id);
	      }
	    break;
	  default:
	    /* generic PRI parameter, no b's (WAN_GENERIC_GROUP) */
	    skip_print = FALSE;
	    decode(convert,internal,external,Pannex_id);
	    break;
	  }
	  if (!skip_print) {
	    pri_show_header(p_num);
	    LONGWRAP(external);
	    if (start_delim = split_string(pri_params[p_num], latter))
	      printf(FMT, start_delim, external);
	    else
	      printf(FMT, pri_params[p_num], external);
	    WRAP;
	  }
	}
    }
    
    /* Free up buffer */
    free(external);
}

void
do_show_pri(Pannex_id, name, Ppris, Pbs, pri_params)
ANNEX_ID	  	*Pannex_id;
char			name[];
PRI_GROUP 		*Ppris;
B_GROUP 		*Pbs;
char                    **pri_params;
{
    SHOW_LIST	*Show_l;
    int		p_num,
		parm,
		loop,
		shown = 0;

    if (Pannex_id->pri_count == 0) {
	printf("\n%s %s has no WAN interfaces\n", BOX, name);
	return;
    }

    /* Print the value of the PRI parameter for each port
       whose bit is set in the port mask. */
    for (loop = 1; loop <= Pannex_id->pri_count; loop++) {
	if (PORTBITSET(Ppris->modules,loop)) {
	    shown++;
	    WRAP_END;
	    printf("\n%s %s WAN interface %d:\n", BOX, name, loop);
	    Show_l = Pshow_list;
	    do {		/* for each "show pri" parameter */
		
		if(!Show_l) {		/* default */
		    parm = UNASSIGNED;		/* to all  */
		  }
		else {
		  parm = Show_l->param_num;
		  
		  /* Set b mask if showing all parameters */
		  if (pri_params == wan_all_params &&
		      parm == ALL_WANCHANP || parm == ALL_WANP)
		    for (p_num = 1; p_num <= ALL_BS; p_num++)
		      SETPORTBIT(Pbs->bs, p_num);
		}

		if((parm == UNASSIGNED) || 
		   (Prip_category(parm) == WAN_GEN_CAT) ||
		   (parm == ALL_WANCHANP) || (parm == ALL_WANP)) {
		    for(p_num = 0; Prip_index(p_num) != -1; p_num++) {
			if(Anyp_support(Pannex_id,p_num,prip_table)) {
			    if((parm == UNASSIGNED) ||
			       (Prip_catid(parm) == ALL_CAT) ||
			       (parm == ALL_WANCHANP) || (parm == ALL_WANP) ||
			       (Prip_category(p_num) == Prip_catid(parm))) {
				pri_show_sub(Pannex_id, loop, p_num, 
					    Pbs, pri_params);
			    }
			}
		    }
		}
		else
		    if(Anyp_support(Pannex_id,parm,prip_table))
			pri_show_sub(Pannex_id, (u_short)loop, parm, 
				    Pbs, pri_params);
		    else
			printf("\t%s does not support %s\n",name,
			       pri_params[parm]);
		if(Show_l)
		    Show_l = Show_l->next;
		
	    } while(Show_l);
	}
    }
    if (shown == 0)
	printf("\n%s %s WAN set has not been defined\n", BOX, name);
}

/*
 * The following section is all set code.
 */

/*
 * Set annex functions.
 */

int
annex_pair_list(Pannex_list)
ANNEX_LIST	*Pannex_list;
{
    SET_LIST	*Set_l;
    ANNEX_LIST	*Annex_l;
    int		len;
    int	        p_num, vcli_passwd_parm;
    int		error,terror;
    char        *pass, nullstring = 0;
    char 	dont_lex = FALSE;
    
    free_set_list();
    while (!eos) {
	vcli_passwd_parm = !strcmp(symbol, "vcli_password");
	p_num = match(symbol, annex_params, BOX_PARM_NAME);
	if (Ap_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "port parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	
	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	
	(void)lex();
	
	if (eos)
	    if (vcli_passwd_parm) {
		if (script_input)
		    pass = &nullstring;
		else {
		    pass = (char *)get_password((struct in_addr *)0);
		    (void)strcpy(Set_l->value, pass);
		    break;
		}
	    }
	    else  
		punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);
	
	if (((Ap_catid(p_num) == LAT_GROUP_CODE) ||
	     (Ap_catid(p_num) == LAT_VCLI_GROUPS)) &&
	    (Ap_category(p_num) == LAT_CAT)) {
	    (void)lex();
	    if (!eos) {
		len = strlen(Set_l->value);
                if (strcmp(Set_l->value,"none")==0  ||
                     strcmp(Set_l->value,"all")==0) {
                    if (strcmp(symbol,"enable")==0 || 
                      strcmp(symbol,"disable")==0){ 
		       Set_l->value[len++] = ' ';
		       Set_l->value[len] = '\0';
		       (void)strcpy(&Set_l->value[len], symbol);
                    }
                    else /* didn't get enable or disable */  {
                      Set_l->value[len++] = ' ';
                      Set_l->value[len] = '\0';
                      dont_lex = TRUE;
                    }
                }
                else {
                     Set_l->value[len++] = ' ';
                     Set_l->value[len] = '\0';
                     (void)strcpy(&Set_l->value[len], symbol);
	        }
            }
	}
	if (dont_lex == FALSE)
	   (void)lex();
        else
	   dont_lex = FALSE;
    }
    
    /* Assign the per-annex parameters (from the set list) for each
       annex in the annex list. */
    error = -1;
    for (Set_l = Pset_list;Set_l; Set_l = Set_l->next) {
	for (Annex_l = Pannex_list; Annex_l; Annex_l = Annex_l->next) {

	    /* If any succeed, then return success. */
	    terror = annex_set_sub(&Annex_l->annex_id, Set_l, Annex_l->name);
	    if (error != 0)
		error = terror;
	}
    }
    return(error);
}

int
annex_set_sub(Pannex_id, Set_l, name)
ANNEX_ID	   *Pannex_id;
SET_LIST           *Set_l;
char		   name[];
{
    int	   category,		/*  Param category  */
	   p_num;		/*  Parameter num.  */
    long   align_internal[(MAX_STRING_128 + 4)/sizeof(long) + 1];
    char   *internal = (char *)align_internal,	/*  Machine format  */
	   *external;				/*  Human format    */
    int	   error = -1;
    int aptype;

    /* Assign a per-annex parameter. */
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = Ap_category(p_num);
    
    if (category == DLA_CAT || category == DFE_CAT || category == LAT_CAT ||
	category == ARAP_CAT || category == RIP_CAT) {
	if (Anyp_support(Pannex_id,p_num,annexp_table)) {
	    encode(Ap_convert(p_num), external, internal, Pannex_id);
	    aptype = Ap_type(p_num);
	    /* use type STRING_P when writing to old annexes */
	    if ((Pannex_id->hw_id <= ANX_II_EIB ||
		 Pannex_id->hw_id == X25 ||
		 Pannex_id->hw_id == ANX_MICRO_ELS) &&
		aptype == STRING_P_128)
	      aptype = STRING_P;
	    error = set_dla_param(&Pannex_id->addr, (u_short)category,
				  (u_short)Ap_catid(p_num),
				  (u_short)aptype, internal);
	    if (error != 0)
            netadm_error(error);
	} else
	    printf("\t%s does not support parameter: %s\n\n", name,
		   annex_params[p_num]);
    } else
	printf("\t%s is not a settable annex parameter:\n\n",
	       annex_params[p_num]);
    return(error);
}

/*
 * Set Asynchronous port functions.
 */

int
port_pair_list(Pport_set)
PORT_SET	*Pport_set;
{
    ANNEX_LIST	*Annex_l;
    PORT_SET	*Port_s;
    SET_LIST	*Set_l;
    int	        p_num,
		pt_passwd_parm;
    char        *pass,
		nullstring = 0;
    int		error,
		terror;
    char        dont_lex = FALSE;
    
    free_set_list();
    while (!eos) {
	pt_passwd_parm = !strcmp(symbol, "port_password");
	p_num = match(symbol, port_params, "port parameter name");
	if (Sp_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "port parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	
	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	(void)lex();
	
	if (eos)
	    if (pt_passwd_parm) {
		if (script_input)
		    pass = &nullstring;
		else {
		    pass = (char *)get_password((struct in_addr *)0);
		    (void)strcpy(Set_l->value, pass);
		    break;
		}
	    }
	    else
		punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);

	if (Sp_displaycat(p_num) == P_LAT_CAT) {
	    (void)lex();
	    if (!eos) {
		int len = strlen(Set_l->value);
                if (strcmp(Set_l->value,"none")==0  ||
                     strcmp(Set_l->value,"all")==0) {
                    if (strcmp(symbol,"enable")==0 || 
                      strcmp(symbol,"disable")==0){ 
		       Set_l->value[len++] = ' ';
		       Set_l->value[len] = '\0';
		       (void)strcpy(&Set_l->value[len], symbol);
                    }
                    else /* didn't get enable or disable */  {
                      Set_l->value[len++] = ' ';
                      Set_l->value[len] = '\0';
                      dont_lex = TRUE;
                    }
                }
                else {
                     Set_l->value[len++] = ' ';
                     Set_l->value[len] = '\0';
                     (void)strcpy(&Set_l->value[len], symbol);
	        }
            }
	}
	if (dont_lex == FALSE)
	   (void)lex();
        else
	   dont_lex = FALSE;
    }
    
    /* Assign the serial port parameters (from the set list) for each
       port in the given port set.  If an annex id was specified, use it;
       otherwise, use the default annex list. */
    
    error = -1;
    for (Set_l = Pset_list;Set_l; Set_l = Set_l->next) {
	for (Port_s = Pport_set; Port_s; Port_s = Port_s->next) {
	    if (Port_s->annex_id.addr.sin_addr.s_addr) {
		terror = do_set_port(&Port_s->annex_id, &Port_s->ports,Set_l,
				     Port_s->name);
		if (error != 0)
		    error = terror;
	    }
	    else if (Pdef_annex_list != NULL)
		for (Annex_l = Pdef_annex_list; Annex_l != NULL;
		     Annex_l = Annex_l->next) {
		    terror = do_set_port(&Annex_l->annex_id, &Port_s->ports,
					Set_l, Annex_l->name);
		    if (error != 0)
			error = terror;
		}
	    else
		punt(NO_BOXES, (char *)NULL);
	}
    }
    return error;
}

int
do_set_port(Pannex_id, Pports, Set_l, name)
ANNEX_ID	  	*Pannex_id;
PORT_GROUP		*Pports;
SET_LIST		*Set_l;
char			name[];
{
    int	loop,
	param = Set_l->param_num,
	error = -1,
	terror, pcount, ispri;
    
    /* Assign serial port parameters to each port whose bit is set
       in the port mask. */

    pcount = Pannex_id->port_count;
    ispri = Pannex_id->hw_id == ANX_PRIMATE;
    if (ispri)
      pcount = 1;

    if(Anyp_support(Pannex_id,param,portp_table)) {
	for (loop = 1; loop <= pcount; loop++)
	    if (ispri || PORTBITSET(Pports->serial_ports,loop)) {
		terror = port_set_sub(Pannex_id,(u_short)loop, Set_l);
		if (error != 0)
		    error = terror;
	    }
    }
    else
	printf("\t%s does not support parameter: %s\n\n", name,
	       port_params[Set_l->param_num]);
    return error;
}

int
port_set_sub(Pannex_id, port, Set_l)
ANNEX_ID	   *Pannex_id;
unsigned short     port;
SET_LIST           *Set_l;
{
    int	   category,		/*  Param category  */
	   p_num;		/*  Parameter num.  */
    long   align_internal[MAX_STRING_128/sizeof(long) + 1];
    char   *internal = (char *)align_internal,	/*  Machine format  */
	   *external;				/*  Human format    */
    int	   error = -1;
    
    /* Assign a serial port parameter. */
    
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = Sp_category(p_num);
    
    if(category == INTF_CAT || category == DEV_CAT || category == DEV2_CAT ||
       category == EDIT_CAT || category == SLIP_CAT || category == NET_CAT) {

	u_short id,type,convert;
	id = (u_short)Sp_catid(p_num);
	type = (u_short)Sp_type(p_num);
	convert = (u_short) Sp_convert(p_num);
#ifdef NA
	if (category == DEV_CAT && id == DEV_ATTN) {
	    if((Pannex_id->version < VERS_6_2)||(Pannex_id->hw_id < ANX3)) {
		convert = CNV_PRINT;
		type = CARDINAL_P;
	    }
	}
	if (category == DEV_CAT && id == DEV_BANNER) {
            if((Pannex_id->version < VERS_14_0)) {
	      convert = CNV_DFT_Y;
	      type = BOOLEAN_P;
	    }
	  }
#endif
	encode(convert, external, internal, Pannex_id);
	
	error = set_ln_param(&Pannex_id->addr, (u_short)SERIAL_DEV,
                         (u_short)port, (u_short)category, id, type,
                         internal);
    
    /* If we are talking to an annex that uses 16 char username fields */
    /* then we want to set the username of a type string */
    if (error && ((id == DEV_NAME) || (id == PPP_UNAMERMT)))
    {
        if (id == DEV_NAME)
            id = DEV_NAME_OLD;
        else
            id = PPP_UNAMERMT_OLD;
        convert = CNV_STRING;
        type = STRING_P;
        error = set_ln_param(&Pannex_id->addr, (u_short)SERIAL_DEV,
                             (u_short)port, (u_short)category, id, type,
                             internal);
    }

    if (error)
	    netadm_error(error);
    }
    
    return error;
}

/*
 * Set modem functions.
 */

int
modem_pair_list(Pmodem_set)
MODEM_SET	*Pmodem_set;
{
    ANNEX_LIST	*Annex_l;
    MODEM_SET	*Modem_s;
    SET_LIST	*Set_l;
    int	        p_num,
		pt_passwd_parm;
    char        *pass,
		nullstring = 0;
    int		error,
		terror;
    
    free_set_list();
    
    while (!eos) {
	pt_passwd_parm = !strcmp(symbol, "port_password");
	p_num = match(symbol, modem_params, "modem parameter name");
	if (Modemp_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "modem port parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	
	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	
	(void)lex();
	
	if (eos)
	    if (pt_passwd_parm) {
		if (script_input)
		    pass = &nullstring;
		else {
		    pass = (char *)get_password((struct in_addr *)0);
		    (void)strcpy(Set_l->value, pass);
		    break;
		}
	    }
	    else
		punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);
	(void)lex();
    }
    
    /* Assign the modem port parameters (from the set list) for each
       port in the given port set.  If an annex id was specified, use it;
       otherwise, use the default annex list. */
    
    error = -1;
    for (Set_l = Pset_list; Set_l; Set_l = Set_l->next) {
	for (Modem_s = Pmodem_set; Modem_s; Modem_s = Modem_s->next) {
	    if (Modem_s->annex_id.addr.sin_addr.s_addr) {
		terror = do_set_modem(&Modem_s->annex_id, &Modem_s->modems, Set_l,
				     Modem_s->name);
		if (error != 0)
		    error = terror;
	    }
	    else if (Pdef_annex_list != NULL)
		for (Annex_l = Pdef_annex_list; Annex_l != NULL;
		     Annex_l = Annex_l->next) {
		    terror = do_set_modem(&Annex_l->annex_id, &Modem_s->modems,
					 Set_l, Annex_l->name);
		    if (error != 0)
			error = terror;
		}
	    else
		punt(NO_BOXES, (char *)NULL);
	}
    }
    return error;
}

int
do_set_modem(Pannex_id, Pmodems, Set_l, name)
ANNEX_ID	  	*Pannex_id;
MODEM_GROUP		*Pmodems;
SET_LIST		*Set_l;
char			name[];
{
    int	loop,
	param,
	error,
	terror;
    
    /* Assign modem port parameters to each port whose bit is set
       in the port mask. */
    param = Set_l->param_num;
    error = -1;

    if (Pannex_id->port_count == 0 || Pannex_id->hw_id != ANX_PRIMATE) {
	printf("\n%s %s has no internal modems\n", BOX, name);
	return NAE_TYPE;
    }

    if(Anyp_support(Pannex_id,param,modemp_table)) {
	for (loop = 1; loop <= Pannex_id->port_count; loop++) {
	    if (PORTBITSET(Pmodems->modems,loop)) {
		terror = modem_set_sub(Pannex_id, (u_short)loop, Set_l);
		if (error != 0)
		    error = terror;
	    }
	}
    }
    else
	printf("\t%s does not support parameter: %s\n\n",name,
	       modem_params[Set_l->param_num]);
    return error;
}

int
modem_set_sub(Pannex_id, port, Set_l)
ANNEX_ID	   *Pannex_id;
unsigned short     port;
SET_LIST           *Set_l;
{
    int	    category,		/*  Param category  */
	    p_num;		/*  Parameter num.  */
    long   align_internal[MAX_STRING_128/sizeof(long) + 1];
    char   *internal = (char *)align_internal,	/*  Machine format  */
	    *external;				/*  Human format    */
    int	    error = -1;
    
    /* Assign a modem port parameter. */
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = Modemp_category(p_num);
    
    if(category == MODEM_CAT) {
	u_short id,type,convert;
	id = (u_short)Modemp_catid(p_num);
	type = (u_short)Modemp_type(p_num);
	convert = (u_short) Modemp_convert(p_num);
	
	encode(convert, external, internal, Pannex_id);
	if(error = set_modem_param(&Pannex_id->addr, (u_short)MODEM_DEV,
				(u_short)port, (u_short)category, id, type, internal))
	    netadm_error(error);
    }
    return error;
}

/*
 * Set Printer port functions.
 */

int
do_set_printer(Pannex_id, Pprinters, Set_l, name)
ANNEX_ID	  	*Pannex_id;
PRINTER_GROUP		*Pprinters;
SET_LIST		*Set_l;
char			name[];
{
    int	loop,
	error = -1,
	terror;
    
    /* Assign serial printer parameters to each printer whose bit is set
       in the printer mask. */
    
    if (Anyp_support(Pannex_id, Set_l->param_num,printp_table)) {
	for (loop = 1; loop <= Pannex_id->printer_count; loop++) {
	    if (PRINTERBITSET(Pprinters->ports,loop)) {
		terror = printer_set_sub(Pannex_id,Set_l, (u_short)loop);
		if (error != 0)
		    error = terror;
	    }
	}
    } else
	printf("\t%s does not support parameter: %s\n\n",name,
	       printer_params[Set_l->param_num]);
    return error;
}

int
    printer_pair_list(Pprinter_set)
PRINTER_SET	*Pprinter_set;
{
    ANNEX_LIST	*Annex_l;
    PRINTER_SET	*Print_s;
    SET_LIST	*Set_l;
    int	         p_num, pt_passwd_parm;
    char            *pass, nullstring = 0;
    int		error,terror;
    
    free_set_list();
    
    while (!eos) {
	pt_passwd_parm = !strcmp(symbol, "printer_password");
	p_num = match(symbol, printer_params, "printer parameter name");
	
	if (Cp_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "printer parameter name: ");
	    (void)strcat(error_msg, symbol);
	    
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	
	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	
	(void)lex();
	
	if (eos)
	    if (pt_passwd_parm) {
		if (script_input)
		    pass = &nullstring;
		else {
		    pass = (char *)get_password((struct in_addr *)0);
		    (void)strcpy(Set_l->value, pass);
		    break;
		}
	    }
	    else
		punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);
	
	(void)lex();
    }
    
    /* Assign the serial printer parameters (from the set list) for each
       printer in the given printer set.  If an annex id was specified, use it;
       otherwise, use the default annex list. */
    
    error = -1;
    for (Set_l = Pset_list; Set_l; Set_l = Set_l->next)
	for (Print_s = Pprinter_set; Print_s; Print_s = Print_s->next)
	    if (Print_s->annex_id.addr.sin_addr.s_addr) {
		terror = do_set_printer(&Print_s->annex_id,
					&Print_s->printers,
					Set_l,Print_s->name);
		if (error != 0)
		    error = terror;
	    }
	    else if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l;
		     Annex_l = Annex_l->next) {
		    terror = do_set_printer(
					    &Annex_l->annex_id,
					    &Print_s->printers,
					    Set_l,Annex_l->name);
		    if (error != 0)
			error = terror;
		}
	    else
		punt(NO_BOXES, (char *)NULL);
    return error;
}	/* printer_pair_list() */

int
    printer_set_sub(Pannex_id, Set_l, name)
ANNEX_ID	   *Pannex_id;
SET_LIST           *Set_l;
char		   name[];
{
    int		   category,		/*  Param category  */
    p_num;		/*  Parameter num.  */
    long	   align_internal[MAXVALUE/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   *external;				/*  Human format    */
    int		   error = -1;
    
    /* Assign a centronics port parameter. */
    
    /* Check for existance of a printer */
    if (Pannex_id->printer_count < 1) {
	punt("\n%s does not have a printer\n", name);
    }
    
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = Cp_category(p_num);
    
    if(category == LP_CAT)
	if(Anyp_support(Pannex_id,p_num,printp_table)) {
	    encode(Cp_convert(p_num), external, internal, Pannex_id);
	    if(error = set_ln_param(&Pannex_id->addr, 
				    (u_short)P_PRINT_DEV, (u_short)name, (u_short)category,
				    (u_short)Cp_catid(p_num), (u_short)Cp_type(p_num),
				    internal))
            netadm_error(error);
        
	}
	else
	    printf("\t%s does not support parameter: %s\n\n",name,
		   printer_params[p_num]);
    return error;
}	/* printer_set_sub() */

/*
 * Set Interface functions.
*/

int
    interface_pair_list(Pinterface_set)
INTERFACE_SET	*Pinterface_set;
{
    ANNEX_LIST	*Annex_l;
    INTERFACE_SET	*Interf_s;
    SET_LIST	*Set_l;
    int	         p_num, pt_passwd_parm;
    char            *pass, nullstring = 0;
    int		len,error,terror;
    free_set_list();
    while (!eos) {
	pt_passwd_parm = !strcmp(symbol, "interface_password");
	p_num = match(symbol, interface_params, "interface parameter name");
	
	if (Ip_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "interface parameter name: ");
	    (void)strcat(error_msg, symbol);
	    
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	
	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	
	(void)lex();
	
	if (eos)
	    if (pt_passwd_parm) {
		if (script_input)
		    pass = &nullstring;
		else {
		    pass = (char *)get_password((struct in_addr *)0);
		    (void)strcpy(Set_l->value, pass);
		    break;
		}
	    }
	    else 
		punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);
	
	/* 
	 * The parameter format of rip_accept and rip_advertise
	 * is a bit different from the rest of parameters.    
	 * include/exclude xx.xx.xx.xx,xx.xx.xx.xx .....
	 */ 
	if ( ((Ip_catid(p_num) == IF_RIP_ACCEPT) ||
	      (Ip_catid(p_num) == IF_RIP_ADVERTISE)) && 
              (!strncmp(symbol,"include",strlen(symbol)) || !strncmp(symbol,"exclude",strlen(symbol))) ){
	    (void)lex();
	    /*
	     * concatenate the rest of line into the buffer, the
	     * encode routine will do the parsing
	     */
	    if (!eos) {
		(void)lex_end(); 
		len = strlen(Set_l->value);
		Set_l->value[len++] = ' ';
		Set_l->value[len] = '\0';
		(void)strcpy(&Set_l->value[len], symbol);
	    }
	}
	
	(void)lex();
    }
    
    /* Assign the interface parameters (from the set list) for each
       interface in the given interface set.  If an annex id was specified,
       use it; otherwise, use the default annex list. */
    
    error = -1;
    for (Set_l = Pset_list; Set_l; Set_l = Set_l->next)
	for (Interf_s = Pinterface_set; Interf_s; Interf_s = Interf_s->next)
	    if (Interf_s->annex_id.addr.sin_addr.s_addr) {
		terror = do_set_interface(&Interf_s->annex_id,
					 &Interf_s->interfaces, Set_l,
					 Interf_s->name);
		if (error != 0)
		    error = terror;
	    }
	    else if (Pdef_annex_list)
		for (Annex_l = Pdef_annex_list; Annex_l;
		     Annex_l = Annex_l->next) {
		    terror = do_set_interface(&Annex_l->annex_id,
					      &Interf_s->interfaces,
					      Set_l, Annex_l->name);
		    if (error != 0)
			error = terror;
		}
	    else
		punt(NO_BOXES, (char *)NULL);
    return error;
}	/* interface_pair_list() */

int
do_set_interface(Pannex_id, Pinterfaces, Set_l, name)
ANNEX_ID	  	*Pannex_id;
INTERFACE_GROUP		*Pinterfaces;
SET_LIST		*Set_l;
char			name[];
{
    int 	loop, loop_limit, param;
    int	if_num, asy_end,syn_end;
    int	error = -1,terror,ispri;
    
    /* Assign interface parameters to each interface whose bit is set
       in the interface mask. */
    
    /* en0 plus asy */
    asy_end = (int)Pannex_id->port_count + 1;
    syn_end = (int)Pannex_id->sync_count + 1 + ALL_PORTS;
    loop_limit = ALL_INTERFACES;

    ispri = Pannex_id->hw_id == ANX_PRIMATE;
    if (ispri) {
      loop_limit = asy_end = 2;
      if (!(Pinterfaces->pg_bits & PG_ALL)) {
	for (loop = 3; loop <= ALL_INTERFACES; loop++)
	  if (INTERFACEBITSET(Pinterfaces->interface_ports,loop))
	    break;
	if (loop <= ALL_INTERFACES) {
	  printf("\nIllegal interface set for %s %s; set ignored.\n",BOX,name);
	  return 1;
	}
      }
    }

    param = Set_l->param_num;
    
    if (Anyp_support(Pannex_id,param,interfacep_table)) {
	for (loop = 1; loop <= loop_limit; loop++)

	    if ((loop <= asy_end) || ((loop > ALL_PORTS+1) &&
				      (loop <= syn_end))) {
		
		if (INTERFACEBITSET(Pinterfaces->interface_ports,loop)) {
		    
		    /*
		     * Convert the logical index into async interface
		     * number to make sure within the port range.
		     */
		    if_num = loop;
		    
		    
               	    if (if_num > (M_ETHERNET + ALL_PORTS)) {
		      if_num = if_num - M_ETHERNET - ALL_PORTS;
		      if (if_num > (int)Pannex_id->sync_count) {
			printf("\n%s %s does not have a synchronous interface %d\n",
			       BOX, name, if_num);
			continue;
		      }
                    } else if (!ispri && if_num > M_ETHERNET) {
		      if_num = if_num - M_ETHERNET;
		      if (if_num > (int)Pannex_id->port_count) {
			printf("\n%s %s does not have an asynchronous interface %d\n",
			       BOX, name, if_num);
			continue;
		      }
		    }
		    
		    
	            terror = interface_set_sub(Pannex_id,(u_short)loop,
					       Set_l);
		    if (error != 0)
			error = terror;
		}
	    }
    }
    else
	printf("\t%s does not support parameter: %s\n\n",
	       name,interface_params[Set_l->param_num]);
    return error;
}	/* do_set_interface() */

int
    interface_set_sub(Pannex_id, Interface, Set_l)
ANNEX_ID	   *Pannex_id;
unsigned short     Interface;
SET_LIST           *Set_l;
{
    int		   category,		/*  Param category  */
    p_num;		/*  Parameter num.  */
    long	   align_internal[MAX_STRING_128/sizeof(long) + 1];
    char	   *internal = (char *)align_internal,	/*  Machine format  */
		   *external;				/*  Human format    */
    int		   error = -1;
    
    
    
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = Ip_category(p_num);
    
    if (category == IF_CAT) {
	u_short id,type,convert;
	
	id = (u_short)Ip_catid(p_num);
	type = (u_short)Ip_type(p_num);
	convert = (u_short) Ip_convert(p_num);
	
	encode(convert, external, internal, Pannex_id);
	
	if(error = set_if_param(&Pannex_id->addr, (u_short)INTERFACE_DEV,
				(u_short)Interface, (u_short)category, id, type, internal))
	    netadm_error(error);
    }
    return error;
}	/* interface_set_sub() */


/*
 * Set T1 functions.
 */

int
t1_pair_list(Pt1_set)
T1_SET	*Pt1_set;
{
    ANNEX_LIST	*Annex_l;
    T1_SET	*T1_s;
    SET_LIST	*Set_l;
    int	        p_num;
    char       	nullstring = 0;
    int		loop, len;
    int		error,
		terror,
		num_ds0s;
    char        **t1_params = t1_all_params;
    
    free_set_list();

    /*
     * Clear ds0 set before setting it (there are no default settings)
     */
    for (p_num = 1; p_num<=ALL_DS0S; p_num++)
	CLRPORTBIT(Pt1_set->ds0s.ds0s, p_num);	
    
    if (!strncmp(symbol,"ds0",strlen(symbol))) {

	/* ds0 sub classification */
	(void)lex();

	if (symbol_length == 1 && symbol[0] == '=') {
	  (void)lex();
	  if (eos)
	    punt("missing ds0 identifier", (char *)NULL);
	  else {
	    ds0_list(&Pt1_set->ds0s);
	  }
	} else {
	  for (p_num = 1; p_num<=ALL_DS0S; p_num++)
	    SETPORTBIT(Pt1_set->ds0s.ds0s, p_num);	/* all ds0's */
	}

	/* Setup t1 table to use */
	t1_params = t1_ds0_params;
    }

    while (!eos) {
	p_num = match(symbol, t1_params, "t1 parameter name");

	if (T1p_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "t1 parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
        bzero((char *)Set_l, sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	bcopy(Pt1_set->ds0s.ds0s, Set_l->t1ds0s.ds0s, sizeof(DS0_GROUP));
	
	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	
	(void)lex();
	
	if (eos)
	  punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);
	(void)lex();

        /*
         * determine if the next symbol is
         * the next parameter, or the second argument
         * for the current parameter.
         */
        len=strlen(symbol);
        if((eos == FALSE) && (len != 0))
            {
            for(loop=0;t1_ds0_params[loop];loop++)
                {
                if(strncasecmp(symbol,t1_ds0_params[loop],len) == 0)
                  /* it's a parameter, do nothing */
                  break;
                }
            if(t1_ds0_params[loop] == 0)
                {
                /* no match, must be the second argument */
                /* for the previous parameter.           */
                /* consumed 2 args, adjust input string  */
	        (void)strcat(Set_l->value, " ");
	        (void)strcat(Set_l->value, symbol);
	        (void)lex();
                }
            }
    }
    
    /* Assign the t1 parameters (from the set list) for each
       port in the given port set.  If an annex id was specified, use it;
       otherwise, use the default annex list. */
    
    error = -1;
    for (Set_l = Pset_list; Set_l; Set_l = Set_l->next) {
	for (T1_s = Pt1_set; T1_s; T1_s = T1_s->next) {
	    if (T1_s->annex_id.addr.sin_addr.s_addr) {
		terror = do_set_t1(&T1_s->annex_id, &T1_s->t1s, Set_l,
				     T1_s->name);
		if (error != 0)
		    error = terror;
	    }
	    else if (Pdef_annex_list != NULL)
		for (Annex_l = Pdef_annex_list; Annex_l != NULL;
		     Annex_l = Annex_l->next) {
		    terror = do_set_t1(&Annex_l->annex_id, &T1_s->t1s,
					 Set_l, Annex_l->name);
		    if (error != 0)
			error = terror;
		}
	    else
		punt(NO_BOXES, (char *)NULL);
	}
    }
    return error;
}

int
do_set_t1(Pannex_id, Pt1s, Set_l, name)
ANNEX_ID	  	*Pannex_id;
T1_GROUP		*Pt1s;
SET_LIST		*Set_l;
char			name[];
{
    int	loop,
	param,
	error,
	terror;
    
    param = Set_l->param_num;
    error = -1;

    if (Pannex_id->t1_count == 0) {
	printf("\n%s %s has no t1 engines\n", BOX, name);
	return error;
    }

    /* Assign t1 parameters to each t1 engine whose bit is set
       in the engine mask. Only one engine is being used. */

    if(Anyp_support(Pannex_id,param,t1p_table)) {
	for (loop = 1; loop <= Pannex_id->t1_count; loop++) {
	    if (PORTBITSET(Pt1s->engines,loop)) {
		terror = t1_set_sub(Pannex_id, (u_short)loop, Set_l);
		if (error != 0)
		    error = terror;
	    }
	}
    }
    else
	printf("\t%s does not support parameter: %s\n\n",name,
	       t1_all_params[Set_l->param_num]);
    return error;
}

int
t1_set_sub(Pannex_id, engine_no, Set_l)
ANNEX_ID	   *Pannex_id;
unsigned short     engine_no;
SET_LIST           *Set_l;
{
    int	    category,		/*  Param category  */
	    p_num;		/*  Parameter num.  */
    long   align_internal[MAX_STRING_128/sizeof(long) + 1];
    char   *internal = (char *)align_internal,	/*  Machine format  */
	    *external;				/*  Human format    */
    int	    error = -1;
    char    *encode_ptr;
    int     ds0_ch;
    short   tmp_sh;
    u_char  modem_number=0;
    T1_DS0_INFO *ds0_ptr=(T1_DS0_INFO *)internal;
    
    /* Assign a T1 parameter. */
    bzero(internal, MAX_STRING_128);
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = T1p_category(p_num);
    
    if(category == T1_CAT) {
	u_short id,type,convert;
	id = (u_short)T1p_catid(p_num);
	type = (u_short)T1p_type(p_num);
	convert = (u_short) T1p_convert(p_num);
	
        encode_ptr = internal;
        switch(id) {
        case T1_MAP:
            /* this is a per-ds0 param, encode one ds0 cell at a time */
	    bcopy(Set_l->t1ds0s.ds0s, ds0_ptr->t1_ds0mask,
				sizeof(ds0_ptr->t1_ds0mask));
            for (ds0_ch = 1; ds0_ch<=ALL_DS0S; ds0_ch++, encode_ptr+=2)
                if(PORTBITSET(Set_l->t1ds0s.ds0s, ds0_ch)) {
	            encode(convert, external, encode_ptr, Pannex_id);
                    if(encode_ptr[1] != 0) {
                        /* modem number was set in second arg */
                        if(modem_number == 0)
                            /* first time: use specified modem number */
                            /* increment modem number for next time   */
                            modem_number = encode_ptr[1] + 1;
                        else if(modem_number <= ALL_DS0S)
                            /* use sequential numbers for     */
                            /* set t1 ds0=<range> arg mod_num */
                            encode_ptr[1] = modem_number++;
                        else
                            break;
                        if(modem_number > ALL_DS0S)
                            break;
                        }
                    }
            break;
        case T1_SIGPROTO:
            /* this is a per-ds0 param, encode one ds0 cell at a time */
	    bcopy(Set_l->t1ds0s.ds0s, ds0_ptr->t1_ds0mask,
				sizeof(ds0_ptr->t1_ds0mask));
            for (ds0_ch = 1; ds0_ch<=ALL_DS0S; ds0_ch++, encode_ptr+=2)
                if(PORTBITSET(Set_l->t1ds0s.ds0s, ds0_ch)) {
	            encode(convert, external, encode_ptr, Pannex_id);
                    }
            break;
        case T1_RING:
            /* this is a per-ds0 param, encode one ds0 cell at a time */
	    bcopy(Set_l->t1ds0s.ds0s, ds0_ptr->t1_ds0mask,
				sizeof(ds0_ptr->t1_ds0mask));
            for (ds0_ch = 1; ds0_ch<=ALL_DS0S; ds0_ch++, encode_ptr++)
                if(PORTBITSET(Set_l->t1ds0s.ds0s, ds0_ch)) {
                    /* encode routines use u_short's */
	            encode(convert, external, &tmp_sh, Pannex_id);
                    *encode_ptr = (char)tmp_sh;
                    }
            break;
        default:
	    encode(convert, external, internal, Pannex_id);
            break;
            }

	if(error = set_t1_param(&Pannex_id->addr, (u_short)T1_DEV,
				(u_short)engine_no, (u_short)category, id, 
				type, internal))
	    netadm_error(error);
    }
    return error;
}

/*
 * Set PRI functions.
 */

int
pri_pair_list(Ppri_set)
PRI_SET	*Ppri_set;
{
    ANNEX_LIST	*Annex_l;
    PRI_SET	*Pri_s;
    SET_LIST	*Set_l;
    int	        p_num;
    char        *pass,
		nullstring = 0;
    int		loop, len;
    int		error,
		terror,
		num_bs;
    char        **pri_params = wan_all_params;
    
    free_set_list();
    
    /*
     * Clear ds0 set before setting it (there are no default settings)
     */
    for (p_num = 1; p_num<=ALL_BS; p_num++)
	CLRPORTBIT(Ppri_set->bs.bs, p_num);	
    
    if ((!strncmp(symbol,"b",strlen(symbol))) ||
	  (!strncmp(symbol,"ds0",strlen(symbol)))) {

	/* ds0 sub classification */
	(void)lex();

	if (symbol_length == 1 && symbol[0] == '=') {
	  (void)lex();
	  if (eos)
	    punt("missing b-channel identifier", (char *)NULL);
	  else {
	    b_list(&Ppri_set->bs);
	  }
	} else {
	  for (p_num = 1; p_num<=ALL_BS; p_num++)
	    SETPORTBIT(Ppri_set->bs.bs, p_num);	/* all b's */
	}

	/* Setup PRI table to use */
	pri_params = wan_chan_params;
    }

    while (!eos) {
	p_num = match(symbol, pri_params, "WAN parameter name");

	if (Prip_category(p_num) == VOID_CAT) {
	    /* obsolete parameter */
	    char error_msg[80];
	    error_msg[0] = '\0';
	    (void)strcat(error_msg, "WAN parameter name: ");
	    (void)strcat(error_msg, symbol);
	    punt("invalid ", error_msg);
	}
	
	/* Add a new SET_LIST structure to the end of the set list
	   pointed to by the given head and tail pointers. */
	
	Set_l = (SET_LIST *)malloc(sizeof(SET_LIST));
        bzero((char *)Set_l, sizeof(SET_LIST));
	Set_l->next = NULL;
	Set_l->param_num = p_num;
	bcopy(Ppri_set->bs.bs, Set_l->pribs.bs, sizeof(B_GROUP));

	if (!Pset_list)
	    Pset_list = Set_l;
	else
	    Pset_tail->next = Set_l;
	Pset_tail = Set_l;
	
	(void)lex();
	
	if (eos)
	  punt("missing parameter value", (char *)NULL);
	
	lex_string();
	(void)strcpy(Set_l->value, symbol);
	(void)lex();

	lex_string();

        /*
         * determine if the next symbol is
         * the next parameter, or the second argument
         * for the current parameter.
         */
        len=strlen(symbol);
        if((eos == FALSE) && (len != 0))
            {
            for(loop=0;wan_chan_params[loop];loop++)
                {
                if(strncasecmp(symbol,wan_chan_params[loop],len) == 0)
                  /* it's a parameter, do nothing */
                  break;
                }
            if(wan_chan_params[loop] == 0)
                {
                /* no match, must be the second argument */
                /* for the previous parameter.           */
                /* consumed 2 args, adjust input string  */
	        (void)strcat(Set_l->value, " ");
	        (void)strcat(Set_l->value, symbol);
	        (void)lex();
                }
            }
    }
    
/*
 * Assign the PRI parameters (from the set list) for each port in the
 * given port set.  If an annex id was specified, use it; otherwise,
 * use the default annex list.
 */
    
    error = -1;
    for (Set_l = Pset_list; Set_l; Set_l = Set_l->next) {
	for (Pri_s = Ppri_set; Pri_s; Pri_s = Pri_s->next) {
	    if (Pri_s->annex_id.addr.sin_addr.s_addr) {
		terror = do_set_pri(&Pri_s->annex_id, &Pri_s->pris, Set_l,
				     Pri_s->name);
		if (error != 0)
		    error = terror;
	    }
	    else if (Pdef_annex_list != NULL)
		for (Annex_l = Pdef_annex_list; Annex_l != NULL;
		     Annex_l = Annex_l->next) {
		    terror = do_set_pri(&Annex_l->annex_id, &Pri_s->pris,
					 Set_l, Annex_l->name);
		    if (error != 0)
			error = terror;
		}
	    else
		punt(NO_BOXES, (char *)NULL);
	}
    }
    return error;
}

int
do_set_pri(Pannex_id, Ppris, Set_l, name)
ANNEX_ID	  	*Pannex_id;
PRI_GROUP		*Ppris;
SET_LIST		*Set_l;
char			name[];
{
    int	loop,
	param,
	error,
	terror;
    
    param = Set_l->param_num;
    error = -1;

    if (Pannex_id->pri_count == 0) {
	printf("\n%s %s has no WAN Interfaces\n", BOX, name);
	return;
    }

    /* Assign PRI parameters to each PRI module whose bit is set
       in the module mask. Only one module is being used. */

    if(Anyp_support(Pannex_id,param,prip_table)) {
	for (loop = 1; loop <= Pannex_id->pri_count; loop++) {
	    if (PORTBITSET(Ppris->modules,loop)) {
		terror = pri_set_sub(Pannex_id, (u_short)loop, Set_l);
		if (error != 0)
		    error = terror;
	    }
	}
    }
    else
	printf("\t%s does not support parameter: %s\n\n",name,
	       wan_all_params[Set_l->param_num]);
    return error;
}

int
pri_set_sub(Pannex_id, module_no, Set_l)
ANNEX_ID	   *Pannex_id;
unsigned short     module_no;
SET_LIST           *Set_l;
{
    int	    category,		/*  Param category  */
	    p_num;		/*  Parameter num.  */
    long   align_internal[SIZE_BLOCK_32_X_6/sizeof(long) + 1];
    long    temp_internal[3];
    char   *internal = (char *)align_internal,	/*  Machine format  */
	    *external;				/*  Human format    */
    char    *encode_ptr;
    int	    error = -1;
    int     b_ch;
    int     b_chans;
    int     num_bs;
    PRI_B_INFO *b_ptr=(PRI_B_INFO *)internal;
    
    /* Assign a PRI parameter. */
    bzero(internal, SIZE_BLOCK_32_X_6);
    external = Set_l->value;
    p_num = Set_l->param_num;
    category = Prip_category(p_num);
    
    if (category == WAN_CAT) {
	u_short id,type,convert;
	id = (u_short)Prip_catid(p_num);
	type = (u_short)Prip_type(p_num);
	convert = (u_short) Prip_convert(p_num);
	b_chans = Pannex_id->b_count[module_no];
	
	/*
	 * check to see we've got channel numbers to work on
	 */
        switch (id) {
        case WAN_REMOTE_ADDRESS:
        case WAN_IPX_NETWORK:
	case WAN_IPX_NODE:
	case WAN_SIGPROTO:
	case WAN_RINGBACK:
	    num_bs = 0;
            for (b_ch = 1; b_ch <= b_chans; b_ch++) {
	      if (PORTBITSET(Set_l->pribs.bs, b_ch)) {
		num_bs++;
		break;
	      }
	    }
	    if (num_bs == 0)
		punt("missing B-channel identifier", (char *)NULL);
	}

        switch (id) {
        case WAN_REMOTE_ADDRESS:
        case WAN_IPX_NETWORK:
     /* this is a per-b-channel param, encode one b channel at a time */
	    bcopy(Set_l->pribs.bs, b_ptr->pri_bmask,
		  sizeof(b_ptr->pri_bmask));
	    encode(convert, external, temp_internal, Pannex_id);
            for (b_ch = 1; b_ch <= b_chans; b_ch++)
	      if (PORTBITSET(Set_l->pribs.bs, b_ch)) {
		align_internal[b_ch-1] = temp_internal[0];
		temp_internal[0] += temp_internal[1];
	      }
            break;
	case WAN_IPX_NODE:
     /* this is a per-b-channel param, encode one b channel at a time */
	    bcopy(Set_l->pribs.bs, b_ptr->pri_bmask,
		  sizeof(b_ptr->pri_bmask));
	    encode(convert, external, temp_internal, Pannex_id);
            for (b_ch = 1; b_ch <= b_chans; b_ch++)
	      if (PORTBITSET(Set_l->pribs.bs, b_ch)) {
		int carry,sum,i;
		u_char *bpt,*bpf;

		bcopy((char *)temp_internal,
		      ((char *)align_internal)+6*(b_ch-1),6);
		carry = 0;
		bpt = (u_char *)temp_internal + 5;
		bpf = bpt+6;
		for (i = 5; i >= 0; i--) {
		  sum = *bpt + *bpf + carry;
		  carry = sum > 255 ? 1 : 0;
		  *bpt = sum;
		  --bpt, --bpf;
		}
	      }
            break;
	case WAN_SIGPROTO:
     /* this is a per-b-channel param, encode one b channel at a time */
	    encode_ptr = internal;
	    bcopy(Set_l->pribs.bs, b_ptr->pri_bmask,
		  sizeof(b_ptr->pri_bmask));
            for (b_ch = 1; b_ch <= b_chans; b_ch++, encode_ptr+=2)
		if (PORTBITSET(Set_l->pribs.bs, b_ch)) {
		    encode(convert, external, encode_ptr, Pannex_id);
		}
	    break;
	case WAN_RINGBACK:
	    encode_ptr = internal;
	    bcopy(Set_l->pribs.bs, b_ptr->pri_bmask,
		  sizeof(b_ptr->pri_bmask));
	    for (b_ch = 1; b_ch <= b_chans; b_ch++, encode_ptr++)
		if (PORTBITSET(Set_l->pribs.bs, b_ch)) {
		    encode(convert, external, encode_ptr, Pannex_id);
		}
            break;
        default:
	    encode(convert, external, internal, Pannex_id);
            break;
        }

	if(error = set_pri_param(&Pannex_id->addr, (u_short)PRI_DEV,
				(u_short)module_no, (u_short)category, id, 
				type, internal))
	    netadm_error(error);
    }
    return error;
}

/*
 * Do a message!
 */

void message(text)
char text[];
{
    time_t time_val;
    
    if (first_broadcast) {
	char *Pusername,
	hostname[33];
	
	Pusername = getlogin();
	
	if (Pusername) {
	    (void)strncat(header, Pusername, 32);
	    (void)strcat(header, "@");
	}
	else
	    (void)strcat(header, "unknown@");
	
	(void)gethostname(hostname, 32);
	
	if (strlen(hostname))
	    (void)strcat(header, hostname);
	else
	    (void)strcat(header, "unknown");
	
	(void)strcat(header, " [");
	time_val = time((time_t *)0);
	(void)strcat(header,ctime(&time_val));
	header[strlen(header)-1] = '\0'; /* Remove the \n from ctime() */
	(void)strcat(header, "] ***\n\n");
	
	first_broadcast = FALSE;
    }
    
    text[0] = '\0';
    
    (void)strcat(text, header);
    
    (void)strcat(text, symbol);
    
    (void)strcat(text, Psymbol);
    
    eos = TRUE;
    
    if ((int)strlen(text) > 1)
	while (text[strlen(text) - 2] == '\\') {
	    text[strlen(text) - 2] = '\n';
	    text[strlen(text) - 1] = '\0';
	    
	    prompt("\tcontinue", NULLSP, TRUE);
	    
	    if ((int)(strlen(text) + strlen(command_line)) > ADM_MAX_BCAST_MSG)
		punt("message too long", (char *)NULL);
	    
	    (void)strcat(text, command_line);
	    
	    eos = TRUE;
	}
    
}	/* message() */

/* warning_message :  takes the current symbol and the rest of the
 *                    input up to WARNING_LENGTH and places them
 *		      into text.  It assumes a lex called was
 *		      made prior to calling.
 */
void warning_message(text)
char text[];
{
    text[0] = '\0';
    
    (void)strcat(text, symbol);
    (void)strcat(text, Psymbol);
    
    eos = TRUE;
    
    if ((int)strlen(text) > 1)
	while (text[strlen(text) - 2] == '\\') {
	    text[strlen(text) - 2] = '\n';
	    text[strlen(text) - 1] = '\0';
	    prompt("\tcontinue", NULLSP, TRUE);
	    
	    if((int)(strlen(text) + strlen(command_line)) > WARNING_LENGTH)
		punt("warning too long", (char *)NULL);
	    
	    (void)strcat(text, command_line);
	    
	    eos = TRUE;
	}
    
}	/* warning_message() */

/*
 * free linked lists
 */

void free_show_list()
{
    SHOW_LIST *Show_l;
    
    while(Pshow_list) {
	Show_l = Pshow_list;
	Pshow_list = Pshow_list->next;
	free((char *)Show_l);
    }
    INITWRAP;
}

void free_set_list()
{
    SET_LIST *Set_l;
    
    while(Pset_list) {
	Set_l = Pset_list;
	Pset_list = Pset_list->next;
	free((char *)Set_l);
    }
}

/*
 * Reads the [+][HH:]MM time format and returns it in boot_time.
 * The abs_only flag will cause it to not accept the [+] offset
 * time format and only search for absolute time.
 */

time_t
    delay_time(abs_only)
u_short abs_only;
{
    time_t
	tim,
	t = 0,
	t1 = 0;
    struct tm
	*lt;
    int
	i = 0,
	hhmm = 0;
    
    if(symbol_length < 1)
	return (BADTIME);
    if(symbol[i] == '+') {                 
	i++;
	while(isdigit(symbol[i])) {
	    t = t * 10 + (symbol[i] - '0');
	    i++;
	}
	
	if (symbol[i] == ':') {   /* get the minutes */
	    i++;
	    hhmm = 1;    /*time in hhmm format */
	    while(isdigit(symbol[i])) {
		t1 = t1 * 10 + (symbol[i] - '0');
		i++;
	    }
	} /* of read minutes */
	
	if (symbol[i] != '\0')   /*extra junk BADTIME */
	    return (BADTIME);
	
	if (hhmm)  /*range check the values*/
	    if ((t>99) || (t1 > 59))
		return (BADTIME);
	    else 
		tim = (t * 3600) + (t1 * 60);
	else
	    if (t>59)
		return (BADTIME);
	    else 
		tim = (t * 60);
	if(abs_only)
	    return (BADTIME);
	return (tim);  /* good time */
    }  /* end +[HH:]MM format */
    
    /* look for absolute time format HH:MM */
    if (!isdigit(symbol[i]))
	return (BADTIME);
    
    while (isdigit(symbol[i])) {            /* get hours */
	t = t * 10 + symbol[i] - '0';
	i++;
    }
    
    if (symbol[i] == ':')
	i++;
    if (t > 23)
	return (BADTIME);
    t1 = t*60;   /* convert hours to minutes */
    t = 0;
    
    while (isdigit(symbol[i])) {            /* get minutes */
	t = t * 10 + symbol[i] - '0';
	i++;
    }
    
    if (t > 59)
	return (BADTIME);
    t1+= t; 			/* add minutes and hours */
    t1 *= 60;                       /* convert total to seconds */
    tim = time((time_t *)0);
    lt = localtime(&tim);
    t = (lt->tm_min*60) + (lt->tm_hour*3600); /* seconds past midnight */
    if (t>t1)	/* boot past midnight */
	tim = (24 * 3600) - t + t1;
    else
	tim =  t1 - t;
    if (symbol[i] != '\0')   /*extra junk BADTIME */
	return (BADTIME);
    return (tim); 
    /*NOTREACHED*/
} /* delay_time */
