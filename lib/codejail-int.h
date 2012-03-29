#ifndef CODEJAIL_INT_H
#define CODEJAIL_INT_H

#include <stdint.h>
#include "codejail.h"

#define MSTACK_SIZE (64 * 1024)
#define JSTACK_SIZE (16 * 1024)
#define MHEAP_SIZE (1000 * 1024)
#define JHEAP_SIZE (1000 * 1024)
#define MAX_ARGS 16

enum cj_message_type {
	CJ_MT_NULL,
	CJ_MT_SEND,
	CJ_MT_RECV,
	CJ_MT_JAIL,
	CJ_MT_RETURN,
	CJ_MT_EXIT
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

void cj_alloc_init (void);
extern void jump_stack (unsigned long bos, unsigned long newbos);
extern void *call_varg_func (void *func, int argc, const void **argv);
void refmon_init (void);

#endif
