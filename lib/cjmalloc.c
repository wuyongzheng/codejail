#define _GNU_SOURCE
#include "codejail.h"
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ONLY_MSPACES 1
#define USE_DL_PREFIX 1
#include "dlmalloc.h"

extern void *heap_main, *heap_jail;
struct cj_brk_info {
	void *base;
	void *curr;
	void *top;
	void *padding;
} *brk_main, *brk_jail, *brk_default;
mspace dlms_main, dlms_jail, dlms_default;

void *cjsbrk (intptr_t increment)
{
	void *prev = brk_default->curr;
	if (prev + increment > brk_default->top || prev + increment < brk_default->base)
		return (void *)(-1);
	brk_default->curr += increment;
	return prev;
}

void *malloc (size_t size)
{
	if (brk_default == NULL) {
		static void *(*orig_malloc)(size_t) = NULL;
		if (orig_malloc == NULL)
			orig_malloc = dlsym(RTLD_NEXT, "malloc");
		return orig_malloc(size);
	} else {
		return mspace_malloc(dlms_default, size);
	}
}

void *calloc (size_t nmemb, size_t size)
{
	if (brk_default == NULL) {
		static void *(*orig_calloc)(size_t, size_t) = NULL;
		if (nmemb == 1 && size == 20) // workaround for infinite recursion of dlsym+calloc
			return NULL;
		if (orig_calloc == NULL)
			orig_calloc = dlsym(RTLD_NEXT, "calloc");
		return orig_calloc(nmemb, size);
	} else {
		return mspace_calloc(dlms_default, nmemb, size);
	}
}

void *realloc (void *ptr, size_t size)
{
	if (brk_default == NULL) {
		static void *(*orig_realloc)(void *, size_t) = NULL;
		if (orig_realloc == NULL)
			orig_realloc = dlsym(RTLD_NEXT, "realloc");
		return orig_realloc(ptr, size);
	} else {
		return mspace_realloc(dlms_default, ptr, size);
	}
}

void *memalign (size_t alignment, size_t bytes)
{
	if (brk_default == NULL) {
		static void *(*orig_memalign)(size_t, size_t) = NULL;
		if (orig_memalign == NULL)
			orig_memalign = dlsym(RTLD_NEXT, "memalign");
		return orig_memalign(alignment, bytes);
	} else {
		return mspace_memalign(dlms_default, alignment, bytes);
	}
}

static void call_orig_free (void *ptr)
{
	static void (*orig_free)(void *) = NULL;
	if (orig_free == NULL)
		orig_free = dlsym(RTLD_NEXT, "free");
	orig_free(ptr);
}

void free (void *ptr)
{
	if (brk_default == NULL) { // before cj_alloc_init()
		call_orig_free(ptr);
		return;
	}

	if (ptr >= heap_main && ptr < heap_main + MHEAP_SIZE) {
		if (cj_state == CJS_JAIL) {
			fprintf(stderr, "jail trying to free main heap %p, ignored and leaked\n", ptr);
			return;
		}
		mspace_free(dlms_main, ptr);
	} else if (ptr >= heap_jail && ptr < heap_jail + JHEAP_SIZE) {
		mspace_free(dlms_jail, ptr);
	} else
		call_orig_free(ptr);
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
	brk_default->base = (void *)brk_default + 4096;
	brk_default->curr = (void *)brk_default + 4096;
	brk_default->top =  (void *)brk_default + MHEAP_SIZE;
	dlms_default = create_mspace_with_base(
			(void *)brk_default + sizeof(struct cj_brk_info),
			4096 - sizeof(struct cj_brk_info), 0);
	if (cj_state == CJS_MAIN) {
		dlms_main = dlms_default;
		dlms_jail = heap_jail + (dlms_main - heap_main); // assuming symmetry
	} else {
		dlms_jail = dlms_default;
		dlms_main = heap_main + (dlms_jail - heap_jail);
	}
}
