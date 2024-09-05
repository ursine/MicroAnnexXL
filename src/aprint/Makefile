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
#	Builds aprint
#
# Revision Control Information:
#
# $Header: /annex/common/src/./aprint/RCS/Makefile,v 1.13 1993/12/30 12:50:26 carlson Exp $
#
# This file created by RCS from:
# $Source: /annex/common/src/./aprint/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
##############################################################################
#
# DATE:		$Date: 1993/12/30 12:50:26 $
# REVISION:	$Revision: 1.13 $
#

CFILES = aprint.c parsecap.c
OFILES = aprint.o parsecap.o

all:
	$(MAKE) -f ../make.config -f Makefile aprint

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

install:	all
	$(MAKE) -f ../make.config -f Makefile installit

remake:
	$(MAKE) clean
	$(MAKE) all

.c.o:
	${CC} ${CFLAGS} -c $<

cleanup:
	${RM} -f ${OFILES} aprint

aprint:		${OFILES} ../libannex/libannex.a
	${CC} ${CFLAGS} -o aprint ${OFILES} \
		../libannex/libannex.a ${LIBFLAG}

${OFILES}:	../make.config

../libannex/libannex.a:	../make.config
	cd ../libannex; $(MAKE)

installit:
	$(INSTALL) $(INSTALL_DIR) aprint

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

aprint.o: aprint.c ../inc/config.h ../inc/port/port.h aprint.h
parsecap.o: parsecap.c ../inc/config.h aprint.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
