#
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
#	Makes libannex library routines
#
# Original Author: Roger Parker	Created on: 1/5/87
#
# Revision Control Information:
#
# $Header: /annex/common/src/./libannex/RCS/Makefile,v 1.12 1994/08/26 16:55:47 carlson Exp $
#
# This file created by RCS from
# $Source: /annex/common/src/./libannex/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
#############################################################################
#
#  DATE:	$Date: 1994/08/26 16:55:47 $
#  REVISION:	$Revision: 1.12 $
#

LIBANX_OT = ${LIBANX_O} .

GFLG =

EFILES = libannex.a

all:
	$(MAKE) -f ../make.config -f Makefile ${EFILES}

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

cleanup:
	${RM} -f ${LIBANX_O} ${EFILES}

.c.o:
	${CC} ${CFLAGS} -DERPCD -c $<

${LIBANX_OT}:	../make.config

libannex.a:	${LIBANX_O}
	${AR} ${ARFLAGS} libannex.a ${LIBANX_O}
	${RANLIB} libannex.a

install:	all

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

bcopy.o: bcopy.c
dup2.o: dup2.c
erpc_subr.o: erpc_subr.c
srpc.o: srpc.c
hostname.o: hostname.c
in_cksum.o: in_cksum.c
inet.o: inet.c
ip_layer.o: ip_layer.c
sendrecv.o: sendrecv.c
slip_layer.o: slip_layer.c
socket_layer.o: socket_layer.c
udp_layer.o: udp_layer.c

bcopy.c: ../inc/config.h
dup2.c: ../inc/config.h
erpc_subr.c: ../inc/config.h ../inc/port/port.h \
	../inc/courier/courier.h ../inc/erpc/erpc.h
srpc.c: ../inc/config.h ../inc/port/port.h srpc.h \
	../inc/courier/courier.h
hostname.c: ../inc/config.h ../inc/port/port.h
in_cksum.c: ../inc/config.h ../inc/port/port.h ../inc/slip/slip_user.h
inet.c: ../inc/config.h ../inc/port/port.h
ip_layer.c: ../inc/config.h ../inc/port/port.h \
	../inc/slip/slip_user.h ../inc/slip/slip_system.h
sendrecv.c: ../inc/config.h
slip_layer.c: ../inc/config.h ../inc/port/port.h \
	../inc/slip/slip_user.h ../inc/slip/slip_system.h \
	../inc/slip/BSDslip.h
socket_layer.c: ../inc/config.h ../inc/slip/slip_user.h
udp_layer.c: ../inc/config.h ../inc/port/port.h \
	../inc/slip/slip_user.h ../inc/slip/slip_system.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
