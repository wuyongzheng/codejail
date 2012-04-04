#ifndef CODEJAIL_INT_H
#define CODEJAIL_INT_H

#include <stdint.h>
#include "codejail.h"

#define MSTACK_SIZE (64 * 1024)
#define JSTACK_SIZE (16 * 1024)
#define MHEAP_SIZE (50000 * 1024)
#define JHEAP_SIZE (10000 * 1024)
#ifndef MAXCALLBACKS
# error "MAXCALLBACKS not defined."
#endif

enum cj_message_type {
	CJ_MT_NOTUSED,
	CJ_MT_SEND,
	CJ_MT_RECV,
	CJ_MT_JAIL,
	CJ_MT_RETURN,
	CJ_MT_CALLBACK,
	CJ_MT_CBRETURN,
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
			void *func;
			int argc;
			uintptr_t *argv;
		} jail;
		struct {
			int handle;
			uintptr_t *argv;
		} callback;
		struct {
			uintptr_t retval;
		} jreturn;
	};
};

void cj_alloc_init (void);
void jump_stack (unsigned long bos, unsigned long newbos);
uintptr_t call_varg_func (void *func, int argc, const uintptr_t *argv);
void refmon_init (void);
uintptr_t child_callback (int cbhandle, uintptr_t *argv);
void cj_callback_stub0 (void);
void cj_callback_stub1 (void);

#endif
