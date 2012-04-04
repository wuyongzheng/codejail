
MAXCALLBACKS = 200

.PHONY: all
all: test-main hooked-main regres-main

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

libtest-lib.so: test-lib.c
	gcc -shared -fPIC -Wall -Wl,-soname,libtest-lib.so -o libtest-lib.so test-lib.c -lc

hooked-main: hooked-main.c libtest-lib.so libcodejail.so codejail.h
	gcc -g -o hooked-main -Wall hooked-main.c -ltest-lib -lcodejail -L.

test-main: test-main.c libtest-lib.so
	gcc -o test-main -Wall test-main.c -ltest-lib -L.

.PHONY: runr
runr: regres-main
	env LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH} CJJLIBS=libregres.so ./regres-main

.PHONY: runm
runm: test-main
	env LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH} ./test-main

.PHONY: runh
runh: hooked-main
	env LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH} CJJLIBS=libtest-lib.so ./hooked-main

.PHONY: clean
clean:
	rm test-main hooked-main libtest-lib.so libcodejail.so dlmalloc.o regres-main libregres.so
