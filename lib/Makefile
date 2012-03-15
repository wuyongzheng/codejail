.PHONY: all
all: test-main hooked-main

libtest-lib.so: test-lib.c
	gcc -shared -fPIC -Wall -Wl,-soname,libtest-lib.so -o libtest-lib.so test-lib.c -lc

test-main: test-main.c libtest-lib.so
	gcc -o test-main -Wall test-main.c -ltest-lib -L.

libcodejail.so: codejail.c cjmalloc.c codejail-32.S
	gcc -g -shared -fPIC -Wall -Wl,-soname,libcodejail.so -o libcodejail.so codejail.c cjmalloc.c codejail-32.S -lc -lrt -ldl

hooked-main: hooked-main.c libtest-lib.so libcodejail.so
	gcc -g -o hooked-main -Wall hooked-main.c -ltest-lib -lcodejail -L.

.PHONY: runm
runm:
	env LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH} ./test-main

.PHONY: runh
runh:
	env LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH} ./hooked-main
