#ifndef CODEJAIL_H
#define CODEJAIL_H

#include <stdint.h>
#include <stdio.h>

#define MSTACK_SIZE (64 * 1024)
#define JSTACK_SIZE (16 * 1024)
#define MHEAP_SIZE (1000 * 1024)
#define JHEAP_SIZE (1000 * 1024)
#define MAX_ARGS 16
#define MAX_MAP_SECTIONS 16

enum cj_message_type {
	CJ_MT_NULL,
	CJ_MT_SEND,
	CJ_MT_RECV,
	CJ_MT_JAIL,
	CJ_MT_RETURN,
	CJ_MT_EXIT
};

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

struct pusha_registers {
	uintptr_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
};

struct cj_message_header {
	enum cj_message_type type;
	union {
		struct {
			void *addr;
			size_t size;
		} sendrecv;
		struct {
			uintptr_t func;
			int argc;
			uintptr_t args[MAX_ARGS];
		} jail;
		struct {
			uintptr_t retval;
		} jreturn;
	};
};

//int cj_create (int nxjlib, int mlibn, const char **mlibs, int jlibn, const char **jlibs);
int cj_recv (void *data, size_t size);
int cj_send (void *data, size_t size);
uintptr_t cj_jail (void *func, int argc, ...);
//void cj_destroy (void);
FILE *cj_duplicate_file (FILE *fp);
enum cj_memtype_enum cj_memtype (void *addr);
extern enum cj_state_enum cj_state;
// use cj_get_state() instead of cj_state to prevent accidentally change cj_state
static inline enum cj_state_enum cj_get_state (void) {return cj_state;}

/* internal functions */
void cj_alloc_init (void);
//uintptr_t child_jail_entry (uintptr_t func, struct pusha_registers *pusha_addr);

#endif
