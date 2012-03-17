#include "test-lib.h"
#include "codejail.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (void)
{
	const char const *jlibs[] = {"libtest-lib.so"};

	cj_create(0, 0, NULL, 1, jlibs);
	//cj_create(0, 0, NULL, 0, NULL);

	{
		char buff[100];
		strcpy(buff, "abc");
		cj_jail(strcpy, 2, buff, "def");
		printf("test 1: buff=%s\n", buff);
	}

	cj_jail(set_global, 1, 12345);
	printf("test 2: get_global() = %d\n", cj_jail(get_global, 0));
	printf("test 2: *get_globalref() = %d\n", *(int *)cj_jail(get_globalref, 0));

	{
		char buff[100];
		strcpy(buff, "Hello World!");
		cj_jail(strtoupper, 1, buff);
		printf("test 3: buff=%s\n", buff);
		cj_recv(buff, sizeof(buff));
		printf("test 3: after cj_recv(), buff=%s\n", buff);
	}

//	for (i = 0; i < 100000; i ++) {
//		cj_jail(set_global, 1, 12345);
//		cj_jail(get_global, 0);
//	}

	cj_destroy();

	return 0;
}
