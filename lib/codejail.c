#define _GNU_SOURCE
#include "codejail.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

int socks[2]; // socks[0] for parent, socks[1] for child
int amijailed;
int shmfd;
void *stack_main, *stack_jail, *heap_main, *heap_jail;

void child_send (const struct cj_message_header *message)
{
}

void child_recv (const struct cj_message_header *message)
{
	send(socks[1], message->sendrecv.addr, message->sendrecv.size, 0);
}

void child_jail (const struct cj_message_header *message)
{
	uintptr_t (*func) (uintptr_t arg0, ...);
	struct cj_message_header retmsg;

	if (munmap(stack_main, MSTACK_SIZE)) {
		fprintf(stderr, "munmap(stack_main) failed\n");
		return;
	}
	if (mmap(stack_main, MSTACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, shmfd, 0) != stack_main) {
		fprintf(stderr, "failed to remap stack_main to same address.\n");
		return;
	}
	if (munmap(heap_main, MHEAP_SIZE)) {
		fprintf(stderr, "munmap(heap_main) failed\n");
		return;
	}
	if (mmap(heap_main, MHEAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, shmfd, MSTACK_SIZE + JSTACK_SIZE) != heap_main) {
		fprintf(stderr, "failed to remap heap_main to same address.\n");
		return;
	}

	func = (void *)message->jail.func;
	retmsg.jreturn.retval = (*func)(message->jail.args[0], message->jail.args[1], message->jail.args[2], message->jail.args[3], message->jail.args[4], message->jail.args[5], message->jail.args[6]); //TODO
	retmsg.type = CJ_MT_RETURN;
	send(socks[1], &retmsg, sizeof(retmsg), 0);
}

static unsigned long getbos (void)
{
	char buff[512], *ptr;
	int len, i;
	FILE *fp = fopen("/proc/self/stat", "r");
	len = fread(buff, 1, sizeof(buff) - 1, fp);
	assert(len > 0);
	fclose(fp);

	buff[len] = '\0';
	assert(strstr(buff, "  ") == NULL);
	ptr = strrchr(buff, ')');
	assert(ptr != NULL && ptr[1] == ' ');
	ptr += 2;
	for (i = 0; i < 25; i ++) {
		ptr = strchr(ptr, ' ');
		assert(ptr != NULL && ptr[1] != '\0');
		ptr ++;
	}
	return atoll(ptr);
}

void jump_stack (unsigned long bos, unsigned long newbos);

int do_child (void *arg)
{
	amijailed = 1;

	if (munmap(stack_main, MSTACK_SIZE)) {
		fprintf(stderr, "munmap(stack_main) failed\n");
		return 1;
	}
	if (mmap(stack_main, MSTACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, shmfd, 0) != stack_main) {
		fprintf(stderr, "failed to remap stack_main to same address.\n");
		return 1;
	}
	if (munmap(heap_main, MHEAP_SIZE)) {
		fprintf(stderr, "munmap(heap_main) failed\n");
		return 1;
	}
	if (mmap(heap_main, MHEAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, shmfd, MSTACK_SIZE + JSTACK_SIZE) != heap_main) {
		fprintf(stderr, "failed to remap heap_main to same address.\n");
		return 1;
	}
	cj_alloc_init();

	while (1) {
		struct cj_message_header message;
		size_t message_size;

		message_size = recv(socks[1], &message, sizeof(message), 0);
		assert(message_size == sizeof(message));
		switch (message.type) {
			case CJ_MT_SEND: child_send(&message); break;
			case CJ_MT_RECV: child_recv(&message); break;
			case CJ_MT_JAIL: child_jail(&message); break;
			case CJ_MT_EXIT: return 0;
			default: fprintf(stderr, "unknown message type %d\n", message.type); return 1;
		}
	}
}

int cj_create (void)
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) {
		fprintf(stderr, "socketpair() failed.\n");
		return 1;
	}

	shm_unlink("/cjshm");
	shmfd = shm_open("/cjshm", O_RDWR | O_CREAT, 0666);
	if (shmfd < 0) {
		fprintf(stderr, "shm_open(/cjshm) failed\n");
		return 1;
	}
	if (ftruncate(shmfd, SHM_SIZE)) {
		fprintf(stderr, "ftruncate failed\n");
		return 1;
	}
	stack_main = mmap(NULL, MSTACK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, 0);
	stack_jail = mmap(NULL, JSTACK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, MSTACK_SIZE);
	heap_main = mmap(NULL, MHEAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, MSTACK_SIZE + JSTACK_SIZE);
	heap_jail = mmap(NULL, JHEAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, MSTACK_SIZE + JSTACK_SIZE + MHEAP_SIZE);
	if (stack_main == NULL || stack_jail == NULL || heap_jail == NULL || heap_jail == NULL) {
		fprintf(stderr, "mmap failed\n");
		return 1;
	}

	if (clone(do_child, stack_jail + JSTACK_SIZE, CLONE_FILES|CLONE_FS, NULL) == -1) {
		fprintf(stderr, "clone() failed.\n");
		return 2;
	}

	// parent
	amijailed = 0;
	{
		unsigned long oldbos = getbos();
		oldbos = ((oldbos - 1) & 0xfffff000) + 4096; // round-up to page bound
		jump_stack(oldbos, (unsigned long)stack_main + MSTACK_SIZE);
	}
	cj_alloc_init();

	return 0;
}

int cj_recv (void *data, size_t size)
{
	struct cj_message_header message;

	if (amijailed) {
		fprintf(stderr, "callint cj_recv in jail.\n");
		return 1;
	}

	message.type = CJ_MT_RECV;
	message.sendrecv.addr = data;
	message.sendrecv.size = size;
	assert(send(socks[0], &message, sizeof(message), 0) == sizeof(message));
	assert(recv(socks[0], data, size, 0) == size);

	return 0;
}

int cj_send (void *data, size_t size)
{
	assert(0);
	return 0;
}

uintptr_t cj_jail (void *func, int argc, ...)
{
	struct cj_message_header message;
	va_list ap;
	int i;

	message.type = CJ_MT_JAIL;
	message.jail.func = (uintptr_t)func;
	message.jail.argc = argc;
	va_start(ap, argc);
	for (i = 0; i < argc && i < MAX_ARGS; i ++)
		message.jail.args[i] = va_arg(ap, uintptr_t);
	va_end(ap);
	send(socks[0], &message, sizeof(message), 0);
	recv(socks[0], &message, sizeof(message), 0);
	assert(message.type == CJ_MT_RETURN);
	return message.jreturn.retval;
}

int cj_destroy (void)
{
	struct cj_message_header message;
	message.type = CJ_MT_EXIT;
	send(socks[0], &message, sizeof(message), 0);
	return 0;
}
