#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "regres-lib.h"
#include "codejail.h"

static void presult (int n, int pass)
{
	printf("test %d: %s\n", n, pass ? "pass" : "fail");
}

static int callback1 (int a)
{
	return a + 1;
}

static int callback1_wrapper (int(*callback1)(int), int a)
{
	return callback1(a) + 10;
}

static int callback2 (int a)
{
	return cj_jail(call_callback, 2, cj_reg_callback(callback1, NULL, 1), a + 1) + 1;
}

int main (void)
{
	{
		char buff[100];
		strcpy(buff, "abc");
		cj_jail(strcpy, 2, buff, "def");
		presult(1, strcmp(buff, "abc") == 0);
	}

	{
		char buff[100];
		strcpy(buff, "abc");
		cj_jail(strcpy, 2, buff, "def");
		cj_recv(buff, sizeof(buff));
		presult(2, strcmp(buff, "def") == 0);
	}

	cj_jail(set_global, 1, 12345);
	presult(3, cj_jail(get_global, 0) == 12345);
	presult(4, *(int *)cj_jail(get_globalref, 0) == 12345);

	{
		char buff[100];
		strcpy(buff, "Hello World!");
		cj_jail(strtoupper, 1, buff);
		presult(5, strcmp(buff, "Hello World!") == 0);
		cj_recv(buff, sizeof(buff));
		presult(6, strcmp(buff, "HELLO WORLD!") == 0);
	}

	{
		char *buff = malloc(100);
		write_global("foo7");
		presult(7, strcmp(read_globalref(), "foo7") == 0);
		read_global(buff);
		presult(8, strcmp(buff, "foo7") == 0);
		strcpy(buff, "foo8");
		cj_jail(read_global, 1, buff);
		presult(9, strcmp(buff, "foo8") == 0);
		cj_recv(buff, 100);
		presult(10, strcmp(buff, "foo7") == 0);
	}

	{
		const int num = 1000;
		void *arr[num];
		int i;

		srand(1);
		for (i = 0; i < num; i ++) {
			arr[i] = malloc(rand() % 500 + 1);
			if (arr[i] == NULL)
				break;
			if (rand() % 2) {
				int j = rand() % (i + 1);
				free(arr[j]);
				arr[j] = malloc(rand() % 500 + 1);
				if (arr[j] == NULL)
					break;
			}
		}
		presult(11, i == num);
		for (i = 0; i < num; i ++)
			free(arr[i]);

		for (i = 0; i < num; i ++) {
			arr[i] = (void *)cj_jail(malloc, 1, rand() % 500 + 1);
			if (arr[i] == NULL)
				break;
			if (rand() % 2) {
				int j = rand() % (i + 1);
				if (rand() % 2)
					free(arr[j]);
				else
					cj_jail(free, 1, arr[j]);
				arr[j] = (void *)cj_jail(malloc, 1, rand() % 500 + 1);
				if (arr[j] == NULL)
					break;
			}
		}
		presult(12, i == num);
		for (i = 0; i < num; i ++)
			free(arr[i]);
	}

	presult(13, call_callback(callback1, 1) == 4);
	presult(14, cj_jail(call_callback, 2, cj_reg_callback(callback1, NULL, 1), 1) == 4);
	presult(15, cj_jail(call_callback, 2, cj_reg_callback(callback1, callback1_wrapper, 1), 1) == 14);
	presult(16, cj_jail(call_callback, 2, cj_reg_callback(callback2, NULL, 1), 1) == 8);

	return 0;
}
