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
#	Builds rtelnet
#
# Revision Control Information:
#
# $Header: /annex/common/src/./newrtelnet/RCS/Makefile,v 1.2 1993/07/13 10:37:30 carlson Rel $
#
# This file created by RCS from:
# $Source: /annex/common/src/./newrtelnet/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
##############################################################################
#
# DATE:		$Date: 1993/07/13 10:37:30 $
# REVISION:	$Revision: 1.2 $
#

# GFLG =	-g
GFLG =

OFILES = rtelnet.o machdep.o debugging.o
CFILES = rtelnet.c machdep.c debugging.c
EFILES = rtelnet

all:
	$(MAKE) -f ../make.config -f Makefile ${EFILES}

lint:
	lint -bh rtelnet.c machdep.c debugging.c

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

# These two are here just in case the links are missing.  These should
# NOT be used, since the installation should automatically create these
# links.
debugging.c:
	@echo "This is probably a configuration error!"
	ln -s debugging.vf debugging.c

machdep.c:
	@echo "This is probably a configuration error!"
	ln -s machdep.sun machdep.c

cleanup:
	${RM} -f ${OFILES} ${EFILES}

.c.o:
	${CC} ${GFLG} ${CFLAGS} -c $<

${OFILES}:	../make.config

rtelnet: ${OFILES} ${CFILES} ../netadm/netadm.a ../libannex/libannex.a
	${CC} ${GFLG} ${CFLAGS} -o rtelnet ${OFILES} \
		../netadm/netadm.a ../libannex/libannex.a ${LIBFLAG}

../libannex/libannex.a:	../make.config
	cd ../libannex; $(MAKE)

../netadm/netadm.a:	../make.config
	cd ../netadm; $(MAKE)

install:	all
	$(INSTALL) $(INSTALL_DIR) rtelnet

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

rtelnet.o: rtelnet.c rtelnet.h ../inc/config.h
machdep.o: machdep.c rtelnet.h ../inc/config.h
debugging.o: debugging.c rtelnet.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
