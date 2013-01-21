#ifndef CODEJAIL_INT_H
#define CODEJAIL_INT_H

#include <stdint.h>
#include "codejail.h"

#define MSTACK_SIZE (16000 * 1024)
#define JSTACK_SIZE (8000 * 1024)
#define MHEAP_SIZE (100000 * 1024)
#define JHEAP_SIZE (20000 * 1024)
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

extern int (*orig_munmap) (void *, size_t);
extern void *(*orig_mmap) (void *, size_t, int, int, int, off_t);

#endif
