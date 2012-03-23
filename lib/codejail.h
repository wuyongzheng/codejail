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

extern enum cj_state_enum cj_state;
int cj_create (int nxjlib, int mlibn, const char **mlibs, int jlibn, const char **jlibs);
int cj_recv (void *data, size_t size);
int cj_send (void *data, size_t size);
uintptr_t cj_jail (void *func, int argc, ...);
int cj_destroy (void);
FILE *cj_duplicate_file (FILE *fp);

/* internal functions */
void cj_alloc_init (void);
//uintptr_t child_jail_entry (uintptr_t func, struct pusha_registers *pusha_addr);

#endif
