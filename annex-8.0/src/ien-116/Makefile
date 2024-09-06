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
#	Builds ien-116
#
# Revision Control Information:
#
# $Header: /annex/common/src/./ien-116/RCS/Makefile,v 1.11 1993/12/30 13:08:55 carlson Exp $
#
# This file created by RCS from:
# $Source: /annex/common/src/./ien-116/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
##############################################################################
#
# DATE:		$Date: 1993/12/30 13:08:55 $
# REVISION:	$Revision: 1.11 $
#

OFILES = ien116d.o
CFILES = ien116d.c

all:
	$(MAKE) -f ../make.config -f Makefile ien116d

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

cleanup:
	${RM} -f ${OFILES} ien116d

.c.o:
	${CC} ${CFLAGS} -c $<

${OFILES}:	../make.config

../libannex/libannex.a:	../make.config
	cd ../libannex; $(MAKE)

ien116d:	${OFILES} ../libannex/libannex.a
	${CC} ${CFLAGS} -o ien116d ${OFILES} \
		../libannex/libannex.a ${LIBFLAG}

install:	all
		$(INSTALL) $(INSTALL_DIR) ien116d

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

ien116d.o: ien116d.c ../inc/config.h ../inc/port/port.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
