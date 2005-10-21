# Makefile for pxdmcp


# Use this for Solaris
LIBS=-lnsl -lsocket
XAUTH=/usr/openwin/bin/xauth

# Use this for Linux
#LIBS=
#XAUTH=/usr/X11R6/bin/xauth


CC=gcc
CFLAGS=-O -Wall -DXAUTH='"$(XAUTH)"'


GZIP=gzip
CHMOD=chmod
TAR = tar
PGP = gpg
MD5SUM = md5sum -b
GZIP = gzip
SCP = scp

DEST = pen@ftp.lysator.liu.se:~ftp/pub/unix/pxdmcp


OBJS=xdmcp.o version.o

all: xdmcp

xdmcp:	$(OBJS)
	$(CC) -o xdmcp $(OBJS) $(LIBS)

version:
	(PACKNAME=`basename \`pwd\`` ; echo 'char version[] = "'`echo $$PACKNAME | cut -d- -f2`'";' >version.c)


clean distclean:
	rm -f *~ \#* core *.o xdmcp




dist:	version distclean
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(TAR) cf - $$PACKNAME | gzip -9 >$$PACKNAME.tar.gz)

sign:
	(PACKNAME=`basename \`pwd\`` ; cd .. ; rm -f $$PACKNAME.tar.gz.sig ; $(PGP) -ab -o $$PACKNAME.tar.gz.sig $$PACKNAME.tar.gz && chmod go+r $$PACKNAME.tar.gz.sig)

md5:
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(MD5SUM)  $$PACKNAME.tar.gz >$$PACKNAME.md5 && chmod go+r $$PACKNAME.md5)

upload:	dist md5 sign
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(SCP) $$PACKNAME.tar.gz $$PACKNAME.tar.gz.sig $$PACKNAME.md5 $(DEST))
