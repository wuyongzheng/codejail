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
struct map_section_struct {
	void *ptr;
	size_t size;
	size_t offset;
	const char *path; // the library path as in /proc/pid/maps
	int isshared;
} map_sections[MAX_MAP_SECTIONS]; // [0] is main, [1] is jail, [2..] are libs.
int map_section_num;
void *stack_main, *stack_jail, *heap_main, *heap_jail;

static int shm_create (int mlibn, const char **mlibs, int jlibn, const char **jlibs)
{
	size_t shm_file_size = 0;

	/* the first two sections are main stack+heap and jail stack+heap */
	map_sections[0].offset = shm_file_size;
	shm_file_size += map_sections[0].size = MSTACK_SIZE + MHEAP_SIZE;
	map_sections[0].isshared = 0;
	map_sections[0].path = "main_stack_heap";
	map_sections[1].offset = shm_file_size;
	shm_file_size += map_sections[1].size = JSTACK_SIZE + JHEAP_SIZE;
	map_sections[1].isshared = 1;
	map_sections[1].path = "jail_stack_heap";
	map_section_num = 2;

	{
		FILE *fp = fopen("/proc/self/maps", "r");
		char line[512];
		char exe[256];
		int len;

		len = readlink("/proc/self/exe", exe, sizeof(exe));
		assert(len > 0 && len < sizeof(exe));
		exe[len] = '\0';

		while (fgets(line, sizeof(line), fp)) {
			unsigned long start, end;
			int i, isshared;

			if (strlen(line) > 0 && line[strlen(line) - 1] == '\n')
				line[strlen(line) - 1] = '\0';

			if (strstr(line, " rw-p ") == NULL)
				continue;

			/* 1. main exe is private. */
			if (strstr(line, exe)) {
				isshared = 0;
				goto hit;
			}
			/* 2. mlib is private. */
			for (i = 0; i < mlibn; i ++) {
				if (strstr(line, mlibs[i])) {
					isshared = 0;
					goto hit;
				}
			}
			/* 3. jlib is shared. */
			for (i = 0; i < jlibn; i ++) {
				if (strstr(line, jlibs[i])) {
					isshared = 1;
					goto hit;
				}
			}
			continue;
hit:
			assert(map_section_num < MAX_MAP_SECTIONS);
			sscanf(line, "%lx-%lx", &start, &end);
			map_sections[map_section_num].ptr = (void *)start;
			map_sections[map_section_num].size = end - start;
			map_sections[map_section_num].offset = shm_file_size;
			shm_file_size += map_sections[map_section_num].size;
			map_sections[map_section_num].path = strdup(strrchr(line, ' ') + 1);
			map_sections[map_section_num].isshared = isshared;
			map_section_num ++;
		}
		fclose(fp);
	}

	shm_unlink("/cjshm");
	shmfd = shm_open("/cjshm", O_RDWR | O_CREAT, 0666);
	if (shmfd < 0) {
		fprintf(stderr, "shm_open(/cjshm) failed\n");
		return 1;
	}
	if (ftruncate(shmfd, shm_file_size)) {
		fprintf(stderr, "ftruncate failed\n");
		return 1;
	}
	map_sections[0].ptr = mmap(NULL, map_sections[0].size,
			PROT_READ|PROT_WRITE, MAP_SHARED, shmfd,
			map_sections[0].offset);
	map_sections[1].ptr = mmap(NULL, map_sections[1].size,
			PROT_READ|PROT_WRITE, MAP_SHARED, shmfd,
			map_sections[1].offset);
	if (map_sections[0].ptr == NULL || map_sections[1].ptr == NULL) {
		fprintf(stderr, "mmap stack/heap failed\n");
		return 1;
	}
	stack_main = map_sections[0].ptr;
	heap_main = map_sections[0].ptr + MSTACK_SIZE;
	stack_jail = map_sections[1].ptr;
	heap_jail = map_sections[1].ptr + JSTACK_SIZE;

	{
		int i;
		void *tmpbuf = NULL;
		size_t tmpbuf_size = 0;
		for (i = 2; i < map_section_num; i ++) {
			fprintf(stderr, "remapping %p+0x%lx %s as %s\n",
					map_sections[i].ptr, (unsigned long)map_sections[i].size,
					map_sections[i].path,
					map_sections[i].isshared ? "shared" : "private");
			if (tmpbuf_size < map_sections[i].size) {
				tmpbuf_size = map_sections[i].size;
				if (tmpbuf)
					free(tmpbuf);
				tmpbuf = malloc(tmpbuf_size);
			}
			memcpy(tmpbuf, map_sections[i].ptr, map_sections[i].size);
			munmap(map_sections[i].ptr, map_sections[i].size);
			assert(mmap(map_sections[i].ptr, map_sections[i].size,
						PROT_READ|PROT_WRITE, MAP_SHARED, shmfd,
						map_sections[i].offset) == map_sections[i].ptr);
			memcpy(map_sections[i].ptr, tmpbuf, map_sections[i].size);
		}
		if (tmpbuf)
			free(tmpbuf);
	}

	return 0;
}

static int shm_remap (void)
{
	int i;
	for (i = 0; i < map_section_num; i ++) {
		if (map_sections[i].isshared)
			continue;
		munmap(map_sections[i].ptr, map_sections[i].size);
		assert(mmap(map_sections[i].ptr, map_sections[i].size,
					PROT_READ|PROT_WRITE, MAP_PRIVATE, shmfd,
					map_sections[i].offset) == map_sections[i].ptr);
	}
	return 0;
}

static void child_send (const struct cj_message_header *message)
{
}

static void child_recv (const struct cj_message_header *message)
{
	send(socks[1], message->sendrecv.addr, message->sendrecv.size, 0);
}

static void child_jail (const struct cj_message_header *message)
{
	uintptr_t (*func) (uintptr_t arg0, ...);
	struct cj_message_header retmsg;

	assert(shm_remap() == 0);

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

static int child_loop (void *arg)
{
	amijailed = 1;
	// close(socks[0]); // cannot close because of CLONE_FILES

	assert(shm_remap() == 0);

	cj_alloc_init();

	while (1) {
		struct cj_message_header message;
		ssize_t message_size;

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

static void drop_jlib_exec(int jlibn, const char **jlibs)
{
	FILE *fp = fopen("/proc/self/maps", "r");
	char line[512];

	while (fgets(line, sizeof(line), fp)) {
		int i;

		if (strlen(line) > 0 && line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		if (strstr(line, " r-xp ") == NULL)
			continue;

		for (i = 0; i < jlibn; i ++) {
			if (strstr(line, jlibs[i])) {
				unsigned long start, end;
				sscanf(line, "%lx-%lx", &start, &end);
				assert(mprotect((void *)start, end - start, PROT_READ) == 0); // if it fails, probably kernel is holding maps lock.
				break;
			}
		}
	}
	fclose(fp);
}


int cj_create (int nxjlib, int mlibn, const char **mlibs, int jlibn, const char **jlibs)
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) {
		fprintf(stderr, "socketpair() failed.\n");
		return 1;
	}

	if (shm_create(mlibn, mlibs, jlibn, jlibs))
		return 1;

	if (clone(child_loop, stack_jail + JSTACK_SIZE, CLONE_FILES|CLONE_FS, NULL) == -1) {
		fprintf(stderr, "clone() failed.\n");
		return 2;
	}

	// parent
	amijailed = 0;
	// close(socks[1]); // cannot close because CLONE_FILES
	if (nxjlib)
		drop_jlib_exec(jlibn, jlibs);
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

	assert(!amijailed);

	/* only stack_main and heap_main need to be received */
	if ((data < stack_main || data >= stack_main + MSTACK_SIZE) &&
			(data < heap_main || data >= heap_main + MHEAP_SIZE))
		return 0;

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

	/* when using wrapper library, if jailed library function calls another
	 * jailed library function, cj_jail will be used as well.
	 * We need to let it call directly */
	if (amijailed) {
		typedef uintptr_t (*func8) (uintptr_t, uintptr_t, uintptr_t, uintptr_t,
				uintptr_t, uintptr_t, uintptr_t, uintptr_t);
		return ((func8)func)((&argc)[1], (&argc)[2], (&argc)[3], (&argc)[4],
				(&argc)[5], (&argc)[6], (&argc)[7], (&argc)[8]);
	}

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

	assert(!amijailed);
	message.type = CJ_MT_EXIT;
	send(socks[0], &message, sizeof(message), 0);
	return 0;
}
