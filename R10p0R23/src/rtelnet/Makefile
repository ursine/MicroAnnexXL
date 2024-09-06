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
# $Header: /annex/common/src/rtelnet/RCS/Makefile,v 1.8 1993/07/13 10:40:52 carlson Rel $
#
# This file created by RCS from:
# $Source: /annex/common/src/rtelnet/RCS/Makefile,v $
#
# This file is currently under revision by:
# $Locker:  $
#
##############################################################################
#
# DATE:		$Date: 1993/07/13 10:40:52 $
# REVISION:	$Revision: 1.8 $
#

OFILES		= rtelnet.o
CFILES		= rtelnet.c

all:
	$(MAKE) -f ../make.config -f Makefile rtelnet 

remake:
	$(MAKE) clean
	$(MAKE) all

clean:
	$(MAKE) -f ../make.config -f Makefile cleanup

cleanup: 
	${RM} -f ${OFILES} rtelnet

.c.o:
	${CC} ${CFLAGS} -c $<

${OFILES}:	../make.config

rtelnet:	${OFILES} ${CFILES} ../netadm/netadm.a ../libannex/libannex.a
	${CC} ${CFLAGS} -o rtelnet ${OFILES} \
		../netadm/netadm.a ../libannex/libannex.a ${LIBFLAG}

../libannex/libannex.a:	../make.config
	cd ../libannex; $(MAKE)

../netadm/netadm.a:	../make.config
	cd ../netadm; $(MAKE)

install:	all
	$(INSTALL) $(INSTALL_DIR) rtelnet

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

rtelnet.o: rtelnet.c ../inc/config.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
