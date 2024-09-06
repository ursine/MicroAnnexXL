#
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
#	Builds Internet trivial time server daemon
#
# Revision Control Information:
#
# $Header: /annex/common/src/timserver/RCS/Makefile,v 1.7 1993/12/30 14:19:13 carlson Exp $
#
# This file created by RCS from:
# $Source: /annex/common/src/timserver/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
##############################################################################
#
# DATE:		$Date: 1993/12/30 14:19:13 $
# REVISION:	$Revision: 1.7 $
#

OFILES = timserver.o

all:
	$(MAKE) -f ../make.config -f Makefile timserver

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

cleanup:
	${RM} -f ${OFILES} timserver

.c.o:
	${CC} ${CFLAGS} -c $<

timserver:	${OFILES} ../libannex/libannex.a
	${CC} ${CFLAGS} -o timserver ${OFILES} \
		../libannex/libannex.a ${LIBFLAG}

${OFILES}:	../make.config

../libannex/libannex.a:	../make.config
	cd ../libannex; $(MAKE)

install:	all
	$(INSTALL) $(INSTALL_DIR) timserver

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

timserver.o: timserver.c ../inc/config.h ../inc/port/port.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
