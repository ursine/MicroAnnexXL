#############################################################################
#
#        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
#
# ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
# This software is made available solely pursuant to the terms of a
# software license agreement which governs its use.
# Unauthorized duplication, distribution or sale are strictly prohibited.
#
# Makefile description:
#	Makes netadm library routines
#
# Original Author: Roger Parker	Created on: 1/5/87
#
# Revision Control Information:
#
# $Header: /annex/common/src/./netadm/RCS/Makefile,v 1.24 1995/08/08 00:27:23 deluca Exp $
#
# This file created by RCS from
# $Source: /annex/common/src/./netadm/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
#############################################################################
#
#  DATE:	$Date: 1995/08/08 00:27:23 $
#  REVISION:	$Revision: 1.24 $
#

OFILES = boot.o reset_all.o reset_line.o set_inet_add.o \
	read_memory.o get_da_param.o set_da_param.o get_ln_param.o \
	set_ln_param.o broadcast.o get_anx_rev.o get_anx_opt.o \
	get_port_cnt.o get_tr_cnt.o init_socket.o verify_resp.o \
	return_param.o set_if_param.o get_if_param.o get_if_cnt.o \
	rpc.o reset_annex.o get_port_eib.o get_prnt_cnt.o dialout.o \
	get_sync_cnt.o reset_t1.o reset_intmod.o set_t1_param.o \
	get_t1_param.o get_t1_cnt.o get_ta_cnt.o get_pri_cnt.o \
	reset_pri.o set_pri_param.o get_pri_param.o set_modem_param.o \
	get_modem_param.o get_b_cnt.o

CFILES = boot.c reset_all.c reset_line.c set_inet_add.c \
	read_memory.c get_da_param.c set_da_param.c get_ln_param.c \
	set_ln_param.c broadcast.c get_anx_rev.c get_anx_opt.c get_port_cnt.c \
	get_tr_cnt.c init_socket.c verify_resp.c return_param.c \
	set_if_param.c get_if_param.c get_if_cnt.c \
	rpc.c reset_annex.c get_port_eib.c get_prnt_cnt.c dialout.c \
	get_sync_cnt.c \
        reset_t1.c reset_intmod.c set_t1_param.c get_t1_param.c get_t1_cnt.c \
	get_ta_cnt.c get_pri_cnt.c reset_pri.c set_pri_param.c \
	get_pri_param.c set_modem_param.c get_modem_param.c get_b_cnt.c

AFILES = netadm.a

all:
	$(MAKE) -f ../make.config -f Makefile ${AFILES}

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

cleanup:
	${RM} -f ${OFILES} ${AFILES}

.c.o:
	${CC} ${CFLAGS} -c $<

${OFILES}:	../make.config

netadm.a:	${OFILES}
	${AR} ${ARFLAGS} netadm.a $(OFILES)
	${RANLIB} netadm.a

install:	all

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

boot.o: boot.c ../inc/config.h ../inc/courier/courier.h ../inc/erpc/netadmp.h
boot.o: netadm.h netadm_err.h ../inc/port/port.h
broadcast.o: broadcast.c ../inc/config.h ../inc/erpc/netadmp.h
broadcast.o: ../inc/courier/courier.h netadm.h netadm_err.h
dialout.o: dialout.c ../libannex/api_if.h ../libannex/srpc.h
dialout.o: ../inc/erpc/netadmp.h ../inc/port/port.h
get_anx_rev.o: get_anx_rev.c ../inc/config.h ../inc/courier/courier.h
get_anx_rev.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_anx_opt.o: get_anx_opt.c ../inc/config.h ../inc/courier/courier.h
get_anx_opt.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_da_param.o: get_da_param.c ../inc/config.h ../inc/courier/courier.h
get_da_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_da_stat.o: get_da_stat.c ../inc/config.h ../inc/courier/courier.h
get_da_stat.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_ln_param.o: get_ln_param.c ../inc/config.h ../inc/courier/courier.h
get_ln_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_if_param.o: get_if_param.c ../inc/config.h ../inc/courier/courier.h
get_if_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_ln_stat.o: get_ln_stat.c ../inc/config.h ../inc/courier/courier.h
get_ln_stat.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_port_cnt.o: get_port_cnt.c ../inc/config.h ../inc/courier/courier.h
get_port_cnt.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_prnt_cnt.o: get_prnt_cnt.c ../inc/config.h ../inc/courier/courier.h
get_prnt_cnt.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_sync_cnt.o: get_sync_cnt.c ../inc/config.h ../inc/courier/courier.h
get_sync_cnt.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_tr_cnt.o: get_tr_cnt.c ../inc/config.h ../inc/courier/courier.h
get_tr_cnt.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_test.o: get_test.c ../inc/config.h ../inc/courier/courier.h
get_test.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_test.o: ../inc/port/port.h
init_socket.o: init_socket.c ../inc/config.h ../inc/courier/courier.h
init_socket.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
read_memory.o: read_memory.c ../inc/config.h ../inc/courier/courier.h
read_memory.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
read_memory.o: ../inc/port/port.h
reset_all.o: reset_all.c ../inc/config.h ../inc/courier/courier.h
reset_all.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
reset_annex.o: reset_annex.c ../inc/config.h ../inc/courier/courier.h
reset_annex.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
reset_line.o: reset_line.c ../inc/config.h ../inc/courier/courier.h
reset_line.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
return_param.o: return_param.c ../inc/config.h ../inc/courier/courier.h
return_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
return_param.o: ../inc/port/port.h
rpc.o: rpc.c ../inc/config.h ../inc/courier/courier.h ../inc/erpc/netadmp.h
rpc.o: netadm.h netadm_err.h ../libannex/srpc.h ../inc/port/port.h
set_da_param.o: set_da_param.c ../inc/config.h ../inc/courier/courier.h
set_da_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_da_param.o: ../inc/port/port.h
set_inet_add.o: set_inet_add.c ../inc/config.h ../inc/courier/courier.h
set_inet_add.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_ln_param.o: set_ln_param.c ../inc/config.h ../inc/courier/courier.h
set_ln_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_ln_param.o: ../inc/port/port.h
set_if_param.o: set_if_param.c ../inc/config.h ../inc/courier/courier.h
set_if_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_if_param.o: ../inc/port/port.h
get_if_cnt.o: get_if_cnt.c ../inc/config.h ../inc/courier/courier.h
get_if_cnt.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_test.o: set_test.c ../inc/courier/courier.h ../inc/erpc/netadmp.h netadm.h
set_test.o: netadm_err.h ../inc/port/port.h
verify_resp.o: verify_resp.c ../inc/config.h ../inc/courier/courier.h
verify_resp.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_ta_cnt.o: ../inc/config.h ../libannex/api_if.h
get_ta_cnt.o: ../inc/courier/courier.h ../inc/erpc/netadmp.h netadm.h
get_ta_cnt.o: netadm_err.h
get_modem_param.o: ../inc/config.h ../inc/courier/courier.h
get_modem_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_modem_param.o: ../inc/config.h ../inc/courier/courier.h
set_modem_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_modem_param.o: ../inc/port/port.h
get_pri_cnt.o: ../inc/config.h ../libannex/api_if.h
get_pri_cnt.o: ../inc/courier/courier.h ../inc/erpc/netadmp.h netadm.h
get_pri_cnt.o: netadm_err.h
get_pri_param.o: ../inc/config.h ../inc/courier/courier.h
get_pri_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_pri_param.o: ../inc/config.h ../inc/courier/courier.h
set_pri_param.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
set_pri_param.o: ../inc/port/port.h
reset_pri.o: ../inc/config.h ../inc/courier/courier.h
reset_pri.o: ../inc/erpc/netadmp.h netadm.h netadm_err.h
get_b_cnt.o: ../inc/config.h ../libannex/api_if.h
get_b_cnt.o: ../inc/courier/courier.h ../inc/erpc/netadmp.h netadm.h
get_b_cnt.o: netadm_err.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
