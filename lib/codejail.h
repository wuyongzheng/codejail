#ifndef CODEJAIL_H
#define CODEJAIL_H

#include <stdint.h>
#include <stdio.h>

enum cj_state_enum {
	CJS_UNINIT,
	CJS_MAIN,
	CJS_JAIL
};

enum cj_memtype_enum {
	CJMT_ISOLATED,
	CJMT_PRIVATE,
	CJMT_SHARED
};

int cj_recv (void *data, size_t size);
int cj_send (void *data, size_t size);
uintptr_t cj_jail (void *func, int argc, ...);
FILE *cj_duplicate_file (FILE *fp);
enum cj_memtype_enum cj_memtype (void *addr);
extern enum cj_state_enum cj_state;
static inline enum cj_state_enum cj_get_state (void) {return cj_state;}

#endif
