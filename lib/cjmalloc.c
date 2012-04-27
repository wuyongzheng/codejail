#define _GNU_SOURCE
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <sys/mman.h>
#include "codejail-int.h"

#define ONLY_MSPACES 1
#define USE_DL_PREFIX 1
#include "dlmalloc.h"

extern void *heap_main, *heap_jail;
static struct cj_brk_info {
	void *base;
	void *curr;
	void *top;
	void *padding;
} *brk_main, *brk_jail, *brk_default;
static mspace dlms_main, dlms_jail, dlms_default;

void *cjsbrk (intptr_t increment)
{
	void *prev = brk_default->curr;
	brk_default->curr += increment;
	assert(brk_default->curr <= brk_default->top && brk_default->curr >= brk_default->base);
	return prev;
}

static void *cjm_malloc (size_t size)
{
	void *ptr;
	assert(brk_default != NULL && dlms_default != NULL);
	ptr = mspace_malloc(dlms_default, size);
	assert(ptr >= brk_default->base && ptr < brk_default->top);
	return ptr;
}

static void *cjm_calloc (size_t nmemb, size_t size)
{
	void *ptr;
	assert(brk_default != NULL && dlms_default != NULL);
	ptr = mspace_calloc(dlms_default, nmemb, size);
	assert(ptr >= brk_default->base && ptr < brk_default->top);
	return ptr;
}

static void *cjm_realloc (void *ptr, size_t size)
{
	void *newptr;

	assert(brk_default != NULL && dlms_default != NULL);
	if (ptr == NULL) {
		newptr = cjm_malloc(size);
	} else if (ptr >= heap_main && ptr < heap_main + MHEAP_SIZE) {
		assert(cj_state == CJS_MAIN); // I don't know what to do if jail realloc main's malloc
		newptr = mspace_realloc(dlms_main, ptr, size);
		assert(newptr >= brk_main->base && newptr < brk_main->top);
	} else if (ptr >= heap_jail && ptr < heap_jail + JHEAP_SIZE) {
		// main is allowed to realloc jail's malloc, but
		// I can't just call mspace_realloc directly, because
		// cjsbrk will allocate heap in main.
		assert(cj_state == CJS_JAIL);
		newptr = mspace_realloc(dlms_jail, ptr, size);
		assert(newptr >= brk_jail->base && newptr < brk_jail->top);
	} else { // allocated before us. we can't free it.
		newptr = cjm_malloc(size);
		memcpy(newptr, ptr, size); // may copy more if shrinking, shouldn't crash mostly.
	}
	return newptr;
}

static void *cjm_memalign (size_t alignment, size_t bytes)
{
	void *ptr;
	assert(brk_default != NULL && dlms_default != NULL);
	ptr = mspace_memalign(dlms_default, alignment, bytes);
	assert(ptr >= brk_default->base && ptr < brk_default->top);
	return ptr;
}

static void cjm_free (void *ptr)
{
	assert(brk_default != NULL && dlms_default != NULL);

	if (ptr >= heap_main && ptr < heap_main + MHEAP_SIZE) {
		if (cj_state == CJS_JAIL) {
			fprintf(stderr, "jail trying to free main heap %p, ignored and leaked\n", ptr);
			return;
		}
		mspace_free(dlms_main, ptr);
	} else if (ptr >= heap_jail && ptr < heap_jail + JHEAP_SIZE) {
		mspace_free(dlms_jail, ptr);
	}
}

pid_t fork(void) {return -1;}

void *mmap (void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *retaddr;
	static void *(*orig_mmap) (void *, size_t, int, int, int, off_t) = NULL;
	if (orig_mmap == NULL)
		orig_mmap = dlsym(RTLD_NEXT, "mmap");

	if (brk_default != NULL && addr == NULL && (flags & MAP_ANONYMOUS)) {
		retaddr = memalign(4096, length);
		memset(retaddr, 0, length);
		fprintf(stderr, "mmap anon %zd in %d -> %p\n", length, cj_state, retaddr);
	} else if (brk_default != NULL && addr == NULL && !(prot & PROT_WRITE) && (flags & MAP_PRIVATE)) {
		retaddr = orig_mmap(addr, length, prot, flags, fd, offset);
		assert((void *)cj_jail(orig_mmap, 6, retaddr, length, prot, flags, fd, offset) == retaddr);
		fprintf(stderr, "mmap ro %zd from %d in %d -> %p\n", length, fd, cj_state, retaddr);
	} else {
		retaddr = orig_mmap(addr, length, prot, flags, fd, offset);
	}

	return retaddr;
}

int munmap(void *addr, size_t length)
{
	int retval;
	static int (*orig_munmap) (void *, size_t) = NULL;
	if (orig_munmap == NULL)
		orig_munmap = dlsym(RTLD_NEXT, "munmap");

	if (brk_default != NULL && cj_memtype(addr) != CJMT_ISOLATED) {
		fprintf(stderr, "munmap %p+%zd ignored\n", addr, length);
		retval = 0;
	} else {
		retval = orig_munmap(addr, length);
	}

	return retval;
}

void cj_alloc_init (void)
{
	assert(cj_state != CJS_UNINIT);
	assert(heap_main != NULL && heap_jail != NULL);
	assert(brk_main == NULL && brk_jail == NULL);
	assert(dlms_main == NULL && dlms_jail == NULL);
	brk_main = heap_main;
	brk_jail = heap_jail;
	brk_default = cj_state == CJS_MAIN ? brk_main : brk_jail;
	brk_default->base = (void *)brk_default;
	brk_default->curr = (void *)brk_default + 4096;
	brk_default->top =  (void *)brk_default + MHEAP_SIZE;
	dlms_default = create_mspace_with_base(
			(void *)brk_default + sizeof(struct cj_brk_info),
			4096 - sizeof(struct cj_brk_info), 1);
	if (cj_state == CJS_MAIN) {
		dlms_main = dlms_default;
		dlms_jail = heap_jail + (dlms_main - heap_main); // assuming symmetry
	} else {
		dlms_jail = dlms_default;
		dlms_main = heap_main + (dlms_jail - heap_jail);
	}

	{
		const struct {
			void *func;
			const char *name;
		} hookfuncs[] = {
			{cjm_malloc, "malloc"},
			{cjm_calloc, "calloc"},
			{cjm_realloc, "realloc"},
			{cjm_memalign, "memalign"},
			{cjm_free, "free"}};
		int i;
		for (i = 0; i < sizeof(hookfuncs)/sizeof(hookfuncs[0]); i ++) {
			void *entry = dlsym(RTLD_DEFAULT, hookfuncs[i].name);
			void *entrynext = dlsym(RTLD_NEXT, hookfuncs[i].name);
			void *page;
			size_t size;
			unsigned char code[7];

			//printf("%s defa entry=%p\n", hookfuncs[i].name, entry);
			//printf("%s next entry=%p\n", hookfuncs[i].name, entrynext);

			// mov func, %eax
			code[0] = 0xb8;
			*(void **)(code+1) = hookfuncs[i].func;
			// jmp *%eax
			code[5] = 0xff;
			code[6] = 0xe0;

			assert(entry);
			page = (void *)((unsigned long)entry & 0xfffff000);
			size = entry - page > 4096 - 7 ? 8192 : 4096;
			assert(mprotect(page, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
			memcpy(entry, code, 7);
			assert(mprotect(page, size, PROT_READ | PROT_EXEC) == 0);

			if (entrynext != entry) {
				assert(entrynext);
				page = (void *)((unsigned long)entrynext & 0xfffff000);
				size = entrynext - page > 4096 - 7 ? 8192 : 4096;
				assert(mprotect(page, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
				memcpy(entrynext, code, 7);
				assert(mprotect(page, size, PROT_READ | PROT_EXEC) == 0);
			}
		}
	}
}
