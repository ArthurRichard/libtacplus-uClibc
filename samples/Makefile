#
SHELL = /bin/sh
srcdir = .

INSTALL = /usr/bin/install -c

TARG1=tac_authen_c
TARG2=tac_authen_c2
TARG3=tac_author_c
TARG4=tac_account_c
TARG5=tac_client
TARG6=tac_server
TARG7=tacppd_client
TARG8=tac_perftest

USELIBS= -L../ -ltacplus
LIBS= $(USELIBS) -lnsl -lcrypto

CFLAGS=-O -DTACACS -I../
# add -DFBSD for freebsd
LDFLAGS=

CC = gcc

OBJS1= tac_authen_c.o
OBJS2= tac_authen_c2.o
OBJS3= tac_author_c.o
OBJS4= tac_account_c.o
OBJS5= tac_client.o
OBJS6= tac_server.o
OBJS7= tacppd_client.o
OBJS8= tac_perftest.o

all: $(TARG1) $(TARG2) $(TARG3) $(TARG4) $(TARG5) $(TARG6) $(TARG7) $(TARG8)

$(TARG1): $(OBJS1)
	${CC} -o $@ ${OBJS1} ${LDFLAGS} ${LIBS}
$(TARG2): $(OBJS2)
	${CC} -o $@ ${OBJS2} ${LDFLAGS} ${LIBS}
$(TARG3): $(OBJS3)
	${CC} -o $@ ${OBJS3} ${LDFLAGS} ${LIBS}
$(TARG4): $(OBJS4)
	${CC} -o $@ ${OBJS4} ${LDFLAGS} ${LIBS}
$(TARG5): $(OBJS5)
	${CC} -o $@ ${OBJS5} ${LDFLAGS} ${LIBS}
$(TARG6): $(OBJS6)
	${CC} -o $@ ${OBJS6} ${LDFLAGS} ${LIBS}
$(TARG7): $(OBJS7)
	${CC} -o $@ ${OBJS7} ${LDFLAGS} ${LIBS}
$(TARG8): $(OBJS8)
	${CC} -o $@ ${OBJS8} ${LDFLAGS} ${LIBS}
# add -lcompat for freebsd before ${LIBS}

.c.o:
	${CC} -c ${CFLAGS} $< -o $@

clean:
	rm -f *.o ${TARG1} ${TARG2} ${TARG3} ${TARG4} ${TARG5} ${TARG6} ${TARG7} \
	${TARG8}
