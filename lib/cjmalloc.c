#define _GNU_SOURCE
#include "codejail.h"
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern void *heap_main, *heap_jail;
extern int amijailed;
struct cj_malloc_struct {
	void *next;
	size_t last_alloc_size;
	void *end;
	void *_padd_unused;
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
	struct cj_malloc_struct *info = amijailed ? jail_malloc_info : main_malloc_info;
	void *ptr;

	if (info == NULL)
		return call_orig_malloc(size);

	assert(size > 0);
	size = ((size - 1) / 8 + 1) * 8; // padd to mutiple of 8 bytes

	ptr = info->next;
	info->next += size;
	info->last_alloc_size = size;
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

//void *realloc (void *ptr, size_t size)
//{
//}

static void call_orig_free (void *ptr)
{
	static void (*orig_free)(void *) = NULL;

	if (orig_free == NULL)
		orig_free = dlsym(RTLD_NEXT, "free");
	orig_free(ptr);
}

static void free_info (struct cj_malloc_struct *info, void *ptr)
{
	if (info->last_alloc_size > 0 && ptr == info->next - info->last_alloc_size) {
		info->next -= info->last_alloc_size;
		info->last_alloc_size = 0;
	}
}

void free (void *ptr)
{
	if (ptr == NULL)
		return;

	if (main_malloc_info == NULL) { // before cj_alloc_init()
		call_orig_free(ptr);
		return;
	}

	if (ptr >= heap_main && ptr < heap_main + MHEAP_SIZE) {
		if (amijailed) {
			fprintf(stderr, "jail free main. ignored. ptr=%p\n", ptr);
			return;
		} else
			free_info(main_malloc_info, ptr);
	} else if (ptr >= heap_jail && ptr < heap_jail + JHEAP_SIZE) {
		free_info(jail_malloc_info, ptr); // both main and jail can free jail.
	} else
		call_orig_free(ptr); // not in our heap? probably allocated before cj_alloc_init().
}

void cj_alloc_init (void)
{
	main_malloc_info = heap_main;
	jail_malloc_info = heap_jail;
	if (amijailed) {
		jail_malloc_info->next = heap_jail + sizeof(*jail_malloc_info);
		jail_malloc_info->last_alloc_size = 0;
		jail_malloc_info->end = heap_jail + JHEAP_SIZE;
	} else {
		main_malloc_info->next = heap_main + sizeof(*main_malloc_info);
		main_malloc_info->last_alloc_size = 0;
		main_malloc_info->end = heap_main + MHEAP_SIZE;
	}
}
