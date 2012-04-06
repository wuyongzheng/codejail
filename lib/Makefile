
MAXCALLBACKS = 200

.PHONY: all
all: libcodejail.so

dlmalloc.o: dlmalloc.c
	gcc -g -fPIC -DHAVE_MORECORE=1 -DMORECORE=cjsbrk -DUSE_LOCKS=1 -DNO_SEGMENT_TRAVERSAL=1 -DHAVE_MMAP=0 -DUSE_DL_PREFIX=1 -DONLY_MSPACES=1 -c -O3 -Wall dlmalloc.c

callback-stubs-32.S: gencbstub32.sh
	bash gencbstub32.sh $(MAXCALLBACKS) > callback-stubs-32.S

libcodejail.so: codejail.c cjmalloc.c refmon.c codejail-32.S callback-stubs-32.S dlmalloc.o codejail.h codejail-int.h
	gcc -g -O -shared -fPIC -Wall -Wl,-soname,libcodejail.so -o libcodejail.so -DMAXCALLBACKS=$(MAXCALLBACKS) codejail.c cjmalloc.c refmon.c codejail-32.S dlmalloc.o -lc -lrt -ldl

libregres.so: regres-lib.c libcodejail.so
	gcc -shared -fPIC -Wall -Wl,-soname,libregres.so -o libregres.so regres-lib.c -lc

regres-main: regres-main.c libregres.so libcodejail.so codejail.h
	gcc -g -o regres-main -Wall regres-main.c -lregres -lcodejail -L.

.PHONY: reg
reg: regres-main
	env LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH} CJJLIBS=libregres.so ./regres-main

.PHONY: clean
clean:
	rm libcodejail.so dlmalloc.o regres-main libregres.so
