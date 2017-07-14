#
RANLIB=ranlib

SHELL = /bin/sh
srcdir = .

INSTALL = /usr/bin/install -c

TARG=libtacplus.a libtacplus.so

LIBS= $(USELIBS)

CFLAGS= -O
LDFLAGS=

CC = gcc
AR = ar
LD = ld


OBJS= tac_authen.o \
    tac_account.o \
    tac_author.o \
    tac_packet.o \
    tac_utils.o \
    tac_clnt.o \
    md5.o

all: $(TARG)

libtacplus.a: $(OBJS)
	@rm -f $@
	$(AR) rc $@ $(OBJS) $(LIBS)
	$(RANLIB) $@
#	${CC} -o $@ ${OBJS} ${LDFLAGS} ${LIBS}


libtacplus.so: $(OBJS)
	@rm -f $@
	$(LD) -shared -o $@.`cat VERSION` $(OBJS)
	ln -s $@.`cat VERSION` $@

.c.o:
	${CC} -c ${CFLAGS} $< -o $@

clean:
	rm -f *.o ${TARG}
