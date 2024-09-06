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
#
#	Makefile for Expedited Remote Procedure Call Daemon
#
# Original Author:  Jonathan Taylor	Created on: 84/07/08
#
# Revision Control Information:
#
# $Header: /u4/losso/annex/mckinley/src/erpcd/RCS/Makefile,v 2.37 1995/02/09 12:46:46 dfox Exp $
#
##############################################################################
#
# DATE:		$Date: 1995/02/09 12:46:46 $
# REVISION:	$Revision: 2.37 $
#

# Options which don't require the use of additional libraries or object
# files have been moved to acp_policy.h.
#
##############################################################################
#
# INSTRUCTIONS:
# 
# Caution: Do not use "make" to build or link anything (for example, do
# not do "make acp_policy.o"). The software should be built by just
# using the "make" or "make all" commands.  The use of the BUILD_CORRECTION
# definition will help enforce this.
# 
# The default build process creates 3 object libraries (if the src/make.config
# file was setup to do so).
# The objects built will stub out real security vendor code and erpcd will not
# validate any users for those regimes.  If, in a customized build, anyone
# wants to link in a library to use real security instead of using
# the stub libraries and they follow the instuctions here then the build
# will disable the use of the other security regimes but link in the one
# wanted.
# 
#


# The purpose of BUILD_CORRECTION is:
# If "make all" is called this will be redefined so that it will
# allow builds.  If something like "make erpcd" is called this will
# not be redefined and the build will fail. We want builds to fail
# in these circumstances because we must have definitions set in
# ../make.config

BUILD_CORRECTION = "Builds_should_be_done_with_make_all"


# Below are the stub files and related defines. They must be defined early.
# The CFG_ variables are defined in the ../make.config file.  That file
# is created at installation time. The values of the variables will depend
# on the system where the compiling is done and possibly by user responses
# to prompts at installation time.  If the CFG_ variables are not found then
# stub security libraries will not be built.

STUBCFILES =	${CFG_STUBCFILES}
STUBOFILES =	${CFG_STUBOFILES}
STUBLFILES =	${CFG_STUBLFILES}
STUBCOMPILING =	${CFG_STUBCOMPILING}
STUBLINKING =	${CFG_STUBLINKING}

STUB_HEADERS = ../stub/krb.h ../stub/sdi_athd.h ../stub/sdi_size.h \
		../stub/sdi_type.h ../stub/sdacmvls.h ../stub/sdconf.h \
		../stub/custpb.h ../stub/custfail.h



# If you will not be using the kerberos, securid and enigma security regimes 
# with erpcd then uncomment the following lines.  This will cause the building 
# of erpcd to be more easily accomplished but it will also build erpcd 
# without support for those security regimes.  Note though that the security 
# regimes can still be built into erpcd if you have the proper libraries 
# and header files. See below.
# 
# Uncomment the next 4 lines for building without use of other regimes.
# STUBOFILES =
# STUBLFILES =
# STUBCOMPILING =
# STUBLINKING =

# Uncomment the lines below to compile with the Security Dynamics
# SecurID (tm) user authentication routines.  This requires the sdclient.a
# library to be built and linked.

# Uncomment the next 6 lines for ACE/Server v1.1
# SECURIDFLAG = -DSECURID_CARD -DACE1_1 -I../sdclient -I../stub
# SECURIDFILES = ../sdclient/sdclient.a ../sdclient/sdconf.o
# STUBOFILES =
# STUBLFILES =
# STUBCOMPILING =
# STUBLINKING =

# Uncomment the next 6 lines for ACE/Server v1.2
# SECURIDFLAG = -DSECURID_CARD -DACE1_2 -I../sdclient -I../stub
# SECURIDFILES = ../sdclient/sdiclient.a
# Note the following two lines should be uncommented only if you are using
# a non-ANSI standard compiler.
# SECURIDCFILES = fflush.c
# SECURIDOFILES = fflush.o

# Uncomment the next 4 lines for ACE/Server v2.0 and v2.1
# SECURIDFLAG = -DSECURID_CARD -DACE2_0 -I../sdclient 
# SECURIDFILES = ../sdclient/sdiclient.a
# Note the following two lines should be uncommented only if you are using
# a non-ANSI standard compiler.
# SECURIDCFILES = fflush.c
# SECURIDOFILES = fflush.o
#STUBCFILES = 
#STUBOFILES =   
#STUBLFILES =
#STUBCOMPILING =
#STUBLINKING =

# The next line is for regular password security,
# comment it, and uncomment the previous 5 lines
# for ACE/Server v1.2 or v2.0 or v2.1 only.  If both are uncommented,
# both security types will be used. 
# Note: That in order to use the password security you also need to uncomment
# the appropriate lines in acp_policy.h.  The default password protocol used
# is ACP.  To use Unix native protocol you will need to uncomment NATIVEPASSWD.
# And if you use shadow files then you will need to uncomment USESHADOW for ACP
# and NATIVESHADOW for Unix native shadow files.
#	Also, note that this is only for use in conjunction with ACE versions
# for all other normal operations the acp_regime file should be used to define
# the security regime(see notes in the NA guide for acp_regime file).
#PASSFLAG = -DPASS_SEC


# Uncomment these lines to compile with the Enigma SafeWord
# Authentication server.  This requires the libidpb.a library to be built
# and linked.

# Uncomment the next 6 lines for Enigma SafeWord
# ENIGMAFLAG = -DENIGMA_SAFEWORD
# ENIGMAFILES = ../enigma/libidpb.a
# STUBOFILES =
# STUBLFILES =
# STUBCOMPILING =
# STUBLINKING =

# and, for the Network API of Enigma SafeWord, uncomment these 2:
# ENIGMAFLAG = -DENIGMA_SAFEWORD -DNET_ENIGMA_ACP
# ENIGMAFILES = ../enigma/swecapi.a
# ENIGMACFILES = acp_safeword.c
# ENIGMAOFILES = acp_safeword.o
# and, if when building the Network API Enigma SafeWord, the symbol
#  "__assert" comes up undefined, uncomment this line as well:
# ENIGMAFLAG = -DENIGMA_SAFEWORD -DNET_ENIGMA_ACP -DNEED_ENIGMA_ASSERT_PATCH

# For timeouts other than the default 1 minute during the Network API
#  password and challenge sequence, set the following in seconds:
# ENIGMATIMEOUTFLAG = -DDIALOG_TIMEOUT=180

# Uncomment these lines to compile with the trivial Kerberos 4
# authentication routines.  This requires that you have Kerberos 4 installed
# in your network and will link erpcd with the Kerberos libraries 
# obj/lib/krb/libkrb.a and obj/lib/des/libdes.a.
# Xylogics does not provide Kerberos sources.
# Note that you should modify the KERBEROSLIB and KERBINCLUDES defines to 
# point to the appropriate directories for your Kerberos installation.

# Uncomment the next 7 lines for Kerberos
# KERBEROSFLAG = -DKERBEROS
# KERBEROSLIB = /usr/kerberos/obj/lib/krb/libkrb.a /usr/kerberos/obj/lib/des/libdes.a
# KERBINCLUDES = -I/usr/kerberos/obj/include
# STUBOFILES =
# STUBLFILES =
# STUBCOMPILING =
# STUBLINKING =

# RADIUS options: by default RADIUS code is included but may not be enabled
RADIUSFLAG = -DRADIUS_ACCT


##############################################################################
#
# The rest of the file contains the Makefile's targets, dependencies and rules.
#
##############################################################################

.PRECIOUS: ../libannex/libannex.a ../netadm/netadm.a

EFILES = erpcd ch_passwd convert acp_dbm tms_dbm tms_convert spy acplint


all:
		$(MAKE) -f ../make.config -f Makefile ${EFILES} BUILD_CORRECTION=""

remake:
		$(MAKE) clean
		$(MAKE) all

clean:
		$(MAKE) -f ../make.config -f Makefile cleanup

lint:
		$(MAKE) -f ../make.config -f Makefile lintup

# depend:
#		$(MAKE) -f ../make.config -f Makefile dependencies

ERPCFILES = erpcd.c bfs.c acp.c acp_rpc.c acp_lib.c acp_policy.c \
 	 getacpdial.c acp_regime.c acp_group.c environment.c \
	 acp_tcp.c racp.c racp_asn1.c racp_lib.c acp_trap.c radius_config.c \
         md5.c radius_parser.c radius_acct.c tms.c tms_lib.c acp_radius.c \
         session_dbinf.c session_dbunx.c
ERPOFILES = erpcd.o bfs.o acp.o acp_rpc.o acp_lib.o acp_policy.o \
 	 getacpdial.o acp_regime.o acp_group.o environment.o \
	 acp_tcp.o racp.o racp_asn1.o racp_lib.o acp_trap.o radius_config.o \
         md5.o radius_parser.o radius_acct.o tms.o tms_lib.o acp_radius.o \
         session_dbinf.o session_dbunx.o

COMCFILES = getacppw.c getacpuser.c env_parser.c time_parser.c getacpstubs.c
COMOFILES = getacppw.o getacpuser.o env_parser.o time_parser.o getacpstubs.o

CDBCFILES = acp_dbm_lib.c
CDBOFILES = acp_dbm_lib.o

CFILES =	${ERPCFILES} ch_passwd.c convert.c ${COMCFILES} ${STUBCFILES}\
		${CDBCFILES} ${SECURIDCFILES} ${ENIGMACFILES} acp_dbm.c \
		tms_dbm.c tms_convert.c spy.c
OFILES =	${ERPOFILES} ch_passwd.o convert.o ${COMOFILES} ${STUBOFILES}\
		${STUBLFILES} ${CDBOFILES} ${SECURIDOFILES} ${ENIGMAOFILES} \
		acp_dbm.o tms_dbm.o tms_convert.o spy.o


ALLFLAGS =	${CFLAGS} ${USER_BFS} ${USER_INSTALL} ${BUILD_CORRECTION} \
		${ENIGMAFLAG} ${ENIGMATIMEOUTFLAG} ${SECURIDFLAG} ${PASSFLAG} \
		${KERBEROSFLAG} ${KERBINCLUDES} $(RADIUSFLAG)

cleanup:
		${RM} -f ${EFILES} ${OFILES}

# dependencies:
# 		mkdep ${ALLFLAGS} ${ERPCFILES} ${COMCFILES} \
# 			../libannex/libannex.a ../netadm/netadm.a ${LIBFLAG}

.c.o:
	${CC} ${ALLFLAGS} ${STUBCOMPILING} -c $<


${OFILES}:	../make.config Makefile

Builds_should_be_done_with_make_all:

libstubs.a: stub_sw.o stub_sid.o stub_krb.o
libstubs.a: stub_sw.o stub_sid.o stub_krb.o
	$(AR) crv libstubs.a stub_sw.o stub_sid.o stub_krb.o
	$(RANLIB) libstubs.a

erpcd:	${ERPOFILES} ${COMOFILES} ../libannex/libannex.a ../netadm/netadm.a \
	${ENIGMAFILES} ${SECURIDFILES} ${KERBEROSLIB} ${STUBLFILES}\
		${CDBOFILES} ${SECURIDOFILES} ${ENIGMAOFILES}
		@/bin/echo "*** Building erpcd utility ***" > /dev/tty
		${CC} ${BUILD_CORRECTION} ${CFLAGS} -o erpcd \
			${ERPOFILES} ${SECURIDOFILES} ${COMOFILES} \
			${ENIGMAOFILES} ${CDBOFILES}\
			../libannex/libannex.a ../netadm/netadm.a \
			${SECURIDFILES} ${KERBEROSLIB} ${ENIGMAFILES} \
			${STUBLINKING} ${LIBFLAG}
		@/bin/echo "*** Done building erpcd utility ***" > /dev/tty

ch_passwd:	ch_passwd.o ${COMOFILES} ${CDBOFILES} ../libannex/libannex.a 
		@/bin/echo "*** Building ch_passwd utility ***" > /dev/tty
		${CC} ${CFLAGS} -o ch_passwd ch_passwd.o ${COMOFILES} \
	        ${CDBOFILES} ../libannex/libannex.a ${LIBFLAG}
		@/bin/echo "*** Done building ch_passwd utility ***" > /dev/tty

convert:	convert.o ${COMOFILES} ../libannex/libannex.a
		@/bin/echo "*** Building convert utility ***" > /dev/tty
		${CC} ${CFLAGS} -o convert convert.o ${COMOFILES} \
			../libannex/libannex.a ${LIBFLAG}
		@/bin/echo "*** Done building convert utility ***" > /dev/tty

acp_dbm:        acp_dbm.o ${CDBOFILES} ../libannex/libannex.a
		@/bin/echo "*** Building acp_dbm utility ***" > /dev/tty
		${CC} ${CFLAGS} -o acp_dbm acp_dbm.o ${CDBOFILES} \
                        ../libannex/libannex.a ${LIBFLAG}
		@/bin/echo "*** Done building acp_dbm utility ***" > /dev/tty

tms_dbm:        tms_dbm.o tms_lib.o ../libannex/libannex.a ../netadm/netadm.a
		@/bin/echo "*** Building tms_dbm utility ***" > /dev/tty
		${CC} ${CFLAGS} -o tms_dbm tms_dbm.o tms_lib.o \
		../libannex/libannex.a  ../netadm/netadm.a ${LIBFLAG}
		@/bin/echo "*** Done building tms_dbm utility ***" > /dev/tty

tms_convert:    tms_convert.o tms_lib.o ../libannex/libannex.a \
		../netadm/netadm.a
		@/bin/echo "*** Building tms_convert utility ***" > /dev/tty
		${CC} ${CFLAGS} -o tms_convert tms_convert.o tms_lib.o \
		../libannex/libannex.a  ../netadm/netadm.a ${LIBFLAG}
		@/bin/echo "*** Done building tms_convert utility ***" > /dev/tty

spy:            spy.o ../libannex/erpc_subr.o ../libannex/libannex.a \
		../netadm/netadm.a
		@/bin/echo "*** Building spy utility ***" > /dev/tty
		${CC} ${CFLAGS} -o spy spy.o ../libannex/erpc_subr.o \
		../libannex/libannex.a  ../netadm/netadm.a ${LIBFLAG}
		@/bin/echo "*** Done building spy utility ***" > /dev/tty

acplint:	acplint.o getacpuser.o getacpstubs.o env_parser.o time_parser.o
		@/bin/echo "*** Building acplint utility ***" > /dev/tty
		${CC} ${CFLAGS} -g -o acplint acplint.o getacpuser.o getacpstubs.o \
			env_parser.o time_parser.o ../libannex/libannex.a ${LIBFLAG}
		@/bin/echo "*** Done building acplint utility ***" > /dev/tty
 
lintup:
		lint ${ALLFLAGS} ${ERPCFILES} ${COMCFILES} ${CDBCFILES}
		lint ${ALLFLAGS} ch_passwd.c ${COMCFILES} ${CDBCFILES}
		lint ${ALLFLAGS} convert.c ${COMCFILES}
		lint ${ALLFLAGS} acp_dbm.c ${COMCFILES}
		lint ${ALLFLAGS} tms_dbm.c tms_lib.c
		lint ${ALLFLAGS} tms_convert.c tms_lib.c
		lint ${ALLFLAGS} spy.c ../libannex/erpc_subr.c

../libannex/libannex.a:
		cd ../libannex; $(MAKE) -f ../make.config -f Makefile libannex.a

../netadm/netadm.a: 
		cd ../netadm/; $(MAKE) -f ../make.config -f Makefile netadm.a

install:	all ${INSTALL_INITD}
		$(INSTALL) execsuid $(INSTALL_DIR) ch_passwd
		$(INSTALL) $(INSTALL_DIR) erpcd
		$(INSTALL) $(INSTALL_DIR) acp_dbm
		$(INSTALL) $(INSTALL_DIR) tms_dbm
		$(INSTALL) $(INSTALL_DIR) tms_convert
		$(INSTALL) $(INSTALL_DIR) spy
		$(INSTALL) precious-data $(INSTALL_DIR) eservices
		$(INSTALL) readonly $(INSTALL_DIR) tms-dbm.hlp

INITD = /etc/init.d
ANNEXINIT = annex-initd
STARTPREFIX = /etc/rc2.d/S82
STOPPREFIX = /etc/rc0.d/K09

install-initd:
	@echo "*** Installing init.d start and stop script ***" > /dev/tty
	$(INSTALL) sysexec $(INITD) $(ANNEXINIT)
	$(RM) -f /etc/rc[20].d/[SK][0-9][0-9]$(ANNEXINIT)
	ln $(INITD)/$(ANNEXINIT) $(STARTPREFIX)$(ANNEXINIT)
	ln $(INITD)/$(ANNEXINIT) $(STOPPREFIX)$(ANNEXINIT)

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.
acp_dbm.o: acp_dbm.c acp_dbm_lib.h
acp_dbm_lib.o: acp_dbm_lib.c acp_dbm_lib.h acp_policy.h
tms_dbm.o: tms_dbm.c ../inc/erpc/acp_tms.h tms.h ../inc/config.h \
	../inc/port/port.h ../inc/port/install_dir.h ../inc/vers.h
tms_convert.o: tms_convert.c ../inc/erpc/acp_tms.h tms.h ../inc/config.h \
	../inc/port/port.h ../inc/port/install_dir.h ../inc/vers.h
spy.o: spy.c ../inc/port/port.h ../inc/erpc/erpc.h ../inc/erpc/bfs.h \
	../inc/courier/courier.h
tms_lib.o: tms_lib.c tms.h ../inc/config.h ../inc/port/port.h \
	../inc/port/install_dir.h
acp.o:	acp.c ../inc/config.h ../libannex/api_if.h \
	../inc/courier/courier.h ../inc/erpc/erpc.h acp.h \
	../libannex/srpc.h ../inc/port/port.h ../inc/erpc/netadmp.h
acp_lib.o: acp_lib.c ../inc/config.h ../libannex/api_if.h \
	../inc/port/install_dir.h acp.h ../libannex/srpc.h \
	acp_policy.h ../inc/port/port.h ../inc/erpc/netadmp.h
acp_policy.o:	acp_policy.c ../inc/config.h ../inc/ashadow.h \
	../inc/port/install_dir.h acp.h ../libannex/srpc.h \
	acp_policy.h ../inc/erpc/netadmp.h ../inc/port/port.h \
	../stub/krb.h ../stub/sdi_athd.h ../stub/sdi_size.h \
	../stub/sdi_type.h ../stub/sdacmvls.h ../stub/sdconf.h \
	../stub/custpb.h ../stub/custfail.h getacpuser.h acp_dbm_lib.h
acp_rpc.o:	acp_rpc.c ../inc/config.h ../inc/courier/courier.h \
	acp.h ../libannex/srpc.h ../inc/port/port.h acp_policy.h
acp_safeword.o: acp_safeword.c acp.h acp_policy.h ../enigma/swecapi.h
bfs.o:	bfs.c ../inc/config.h ../libannex/api_if.h \
	../inc/courier/courier.h ../inc/erpc/erpc.h ../inc/erpc/bfs.h \
	acp_policy.h ../inc/port/port.h
ch_passwd.o:	ch_passwd.c ../inc/config.h ../inc/port/install_dir.h \
	acp_policy.h acp_dbm_lib.h
convert.o:	convert.c ../inc/config.h ../inc/ashadow.h \
	../inc/port/install_dir.h acp_policy.h ../inc/port/port.h
erpcd.o:	erpcd.c ../inc/port/install_dir.h ../inc/config.h \
	acp_policy.h ../libannex/api_if.h ../inc/courier/courier.h \
	../inc/erpc/erpc.h ../inc/port/port.h acp_regime.h acp_group.h
getacpdial.o:	getacpdial.c ../inc/config.h ../inc/port/install_dir.h \
	acp_policy.h ../inc/port/port.h acp.h ../libannex/srpc.h
getacppw.o:	getacppw.c ../inc/config.h ../inc/ashadow.h \
	../inc/port/install_dir.h acp_policy.h ../inc/port/port.h
getacpuser.o:	getacpuser.c ../inc/port/port.h acp.h getacpuser.h acp_policy.h
getacpstubs.o:	getacpstubs.c ../inc/erpc/netadmp.h acp.h getacpuser.h
acp_regime.o:	acp_regime.c acp_regime.h acp_policy.h
acp_group.o:	acp_group.c acp_group.h acp_policy.h
environment.o: 	environment.c environment.h acp_policy.h time_parser.h acp_regime.h acp_group.h
fflush.o: fflush.c
time_parser.o:	time_parser.c time_parser.h
stub_sw.o: stub_sw.c ../stub/custpb.h ../stub/custfail.h
stub_sid.o: stub_sid.c ../stub/sdi_athd.h ../stub/sdi_size.h \
	../stub/sdi_type.h ../stub/sdacmvls.h ../stub/sdconf.h
stub_krb.o: stub_krb.c ../stub/krb.h
md5.o:	md5.c md5_defs.h
# IF YOU PUT ANYTHING HERE IT WILL GO AWAY

