#define _GNU_SOURCE
#include "codejail.h"
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern void *heap_main, *heap_jail;
extern enum cj_state jailstate;
struct cj_malloc_struct {
	void *next;
	void *end;
};
static struct cj_malloc_struct *main_malloc_info = 0, *jail_malloc_info = 0;

static void *call_orig_malloc (size_t size)
{
	static void *(*orig_malloc)(size_t) = NULL;
	if (orig_malloc == NULL)
		orig_malloc = dlsym(RTLD_NEXT, "malloc");
	return orig_malloc(size);
}

void *malloc (size_t size)
{
	struct cj_malloc_struct *info = jailstate == CJS_JAIL ? jail_malloc_info : main_malloc_info;
	void *ptr;

	if (info == NULL)
		return call_orig_malloc(size);

	assert(size > 0);
	size = ((size - 1) / 8 + 1) * 8; // padd to mutiple of 8 bytes

	ptr = info->next;
	info->next += size;
	assert(info->next < info->end);
	return ptr;
}

static void *call_orig_calloc (size_t nmemb, size_t size)
{
	static void *(*orig_calloc)(size_t, size_t) = NULL;

	if (nmemb == 1 && size == 20) // workaround for infinite recursion of dlsym+calloc
		return NULL;

	if (orig_calloc == NULL)
		orig_calloc = dlsym(RTLD_NEXT, "calloc");
	return orig_calloc(nmemb, size);
}

void *calloc (size_t nmemb, size_t size)
{
	void *ptr;

	if (main_malloc_info == NULL)
		return call_orig_calloc(nmemb, size);

	ptr = malloc(nmemb * size);
	memset(ptr, nmemb * size, 0);
	return ptr;
}

static void *call_orig_realloc (void *ptr, size_t size)
{
	static void *(*orig_realloc)(void *, size_t) = NULL;

	if (orig_realloc == NULL)
		orig_realloc = dlsym(RTLD_NEXT, "realloc");
	return orig_realloc(ptr, size);
}

void *realloc (void *ptr, size_t size)
{
	struct cj_malloc_struct *info;
	void *newptr;

	if (ptr == NULL)
		return malloc(size);
	if (size == 0)
		return ptr;

	info = jailstate == CJS_JAIL ? jail_malloc_info : main_malloc_info;
	if (info == NULL)
		return call_orig_realloc(ptr, size);

	newptr = malloc(size);
	memmove(newptr, ptr, size);
	return newptr;
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
	if (ptr == NULL)
		return;

	if (main_malloc_info == NULL) { // before cj_alloc_init()
		call_orig_free(ptr);
		return;
	}

	if ((ptr < heap_main || ptr >= heap_main + MHEAP_SIZE) &&
			(ptr < heap_jail || ptr >= heap_jail + JHEAP_SIZE)) {
		call_orig_free(ptr);
		return;
	}
}

void cj_alloc_init (void)
{
	main_malloc_info = heap_main;
	jail_malloc_info = heap_jail;
	if (jailstate == CJS_JAIL) {
		jail_malloc_info->next = heap_jail + sizeof(*jail_malloc_info);
		jail_malloc_info->end = heap_jail + JHEAP_SIZE;
	} else {
		main_malloc_info->next = heap_main + sizeof(*main_malloc_info);
		main_malloc_info->end = heap_main + MHEAP_SIZE;
	}
}
