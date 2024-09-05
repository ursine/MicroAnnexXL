##############################################################################
#
#        Copyright 1989, Xylogics, Inc.  ALL RIGHTS RESERVED.
#
# ALL RIGHTS RESERVED. Licensed Material - Property of Xylogics, Inc.
# This software is made available solely pursuant to the terms of a
# software license agreement which governs its use.
# Unauthorized duplication, distribution or sale are strictly prohibited.
#
# Makefile description:
#
#	Makefile for user-level SLIP daemon
#	(for use on netless XENIX systems only!)
#
# Original Author:  Jonathan Taylor	Created on: 84/07/08
# Revised 86/06/12: Dave Harris		Origin: Makefile.vax 1.1.1.2
#
# Revision Control Information:
#
# $Header: /annex/common/src/slipd/RCS/Makefile,v 1.7 1993/07/13 10:51:25 carlson Rel $
#
##############################################################################
#
# DATE:		$Date: 1993/07/13 10:51:25 $
# REVISION:	$Revision: 1.7 $
#

CFILES		= slipd.c stty.c
OFILES		= slipd.o stty.o

all:
	$(MAKE) -f ../make.config -f Makefile slipd

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

.c.o:
	${CC} ${CFLAGS} -DINSTALL_DIR=\"${INSTALL_DIR} -c $<

${OFILES}:	../make.config

slipd:		${OFILES} ../libannex/libannex.a
	${CC} ${CFLAGS} -o slipd ${OFILES} ../libannex/libannex.a

../libannex/libannex.a:	../make.config
	cd ../libannex; $(MAKE)

cleanup:
	${RM} -f slipd *.o

install:	all
	$(INSTALL) $(INSTALL_DIR) slipd
	$(INSTALL) readonly $(INSTALL_DIR) slipcfg

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

slipd.o: slipd.c ../inc/config.h ../inc/slip/slip_user.h
slipd.o: ../inc/slip/slip_system.h ../inc/slip/BSDslip.h
stty.o: stty.c ../inc/config.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
