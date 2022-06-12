CC = gcc

CFLAGS = -pedantic -Wall -O2 -funroll-loops -g -mpopcnt 

LDLIBS = -lrt -L. -I. -Wl,-rpath=.

INCS=-I/usr/local/flint/include -I/usr/local/gmp/include -I/usr/local/mpfr/include

LIBS=-L/usr/local/flint/lib -L/usr/local/gmp/lib -L/usr/local/mpfr/lib -L/usr/local/ssl/lib64/ -lssl -lcrypto -lflint -lmpfr -lgmp -lm -lpthread

cock_IBE_object = cocks_IBE.c rand.c

all: cocks_IBE

cocks_IBE:
	$(CC) $(CFLAGS) $(INCS) $(cock_IBE_object) $(LDLIBS) -o cocks_IBE $(LIBS)
cocks_IBE.o: cocks_IBE.c rand.h standard.h

clean:
	$(RM) *.o cocks_IBE
