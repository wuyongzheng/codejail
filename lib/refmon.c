#define _GNU_SOURCE
#include "codejail.h"
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static FILE *main_fp = NULL, *jail_fp = NULL;

FILE *cj_duplicate_file (FILE *fp)
{
	const char *mode;
	int fdm, fdj;

	if (cj_state != CJS_MAIN)
		return fp;
	if (main_fp != NULL) {
		fprintf(stderr, "only one shadow is supported. ignored.\n");
		return fp;
	}

	fdm = fileno(fp);
	if (fdm <= 2) {
		fprintf(stderr, "duplicate_file fd=%d. ignored.\n", fdm);
		return fp;
	}
	fdj = dup(fdm);

	assert((fp->_flags & 0xffff0000) == _IO_MAGIC);
	switch (fp->_flags & 0xc) {
		case 0: mode = "w+"; break;
		case _IO_NO_WRITES: mode = "r"; break;
		case _IO_NO_READS: mode = "w"; break;
		default: assert(0); // a file can be R, W or RW, but not none.
	}

	main_fp = fp;
	jail_fp = (FILE *)cj_jail(fdopen, 2, fdj, mode);
	fprintf(stderr, "duplicate fp=%p, fd=%d to fp=%p, fd=%d\n",
			main_fp, fdm, jail_fp, fdj);
	return jail_fp;
}

int fclose (FILE *fp)
{
	static int (*orig_fclose)(FILE *) = NULL;
	int retval;

	if (orig_fclose == NULL)
		orig_fclose = dlsym(RTLD_NEXT, "fclose");

	if (fp == main_fp) {
		assert(cj_state == CJS_MAIN);
		assert(jail_fp != NULL);
		fprintf(stderr, "closing duplicate: mfp=%p, jfp=%p\n", main_fp, jail_fp);
		retval = orig_fclose(fp);
		cj_jail(orig_fclose, 1, jail_fp);
		main_fp = jail_fp = NULL;
	} else if (fp == jail_fp) {
		assert(cj_state == CJS_JAIL);
		fprintf(stderr, "jail closing fp. we are screwed.\n");
	} else {
		retval = orig_fclose(fp);
	}
	return retval;
}

int refmon_init (void)
{
	return 0;
}
