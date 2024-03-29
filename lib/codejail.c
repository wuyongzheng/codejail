#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include "codejail-int.h"

static int socks[2]; // socks[0] for parent, socks[1] for child
enum cj_state_enum cj_state;
static int shmfd;
#define MAX_MAP_SECTIONS 16
static struct map_section_struct {
	void *ptr;
	size_t size;
	size_t offset;
	const char *path; // the library path as in /proc/pid/maps
	int isshared;
} map_sections[MAX_MAP_SECTIONS]; // [0] is main, [1] is jail, [2..] are libs.
static int map_section_num;
static struct callback_struct {
	void *orig;
	void *wrapper;
	void *stub;
	int argc;
} *callbacks;
void *stack_main, *stack_jail, *heap_main, *heap_jail;
static pthread_mutex_t sock_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP; // mutex is only used in main
static int stats_jail = 0, stats_callback = 0,
		   stats_recv = 0, stats_recvb = 0,
		   stats_send = 0, stats_sendb = 0;
static int stats_jails[10] = {0};
static int stats_jail_level = 0;

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
	fprintf(stderr, "main stack=%p-%p, heap=%p-%p\n",
			stack_main, stack_main+MSTACK_SIZE,
			heap_main, heap_main+MHEAP_SIZE);
	fprintf(stderr, "jail stack=%p-%p, heap=%p-%p\n",
			stack_jail, stack_jail+JSTACK_SIZE,
			heap_jail, heap_jail+JHEAP_SIZE);

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
		//for (i = 0; i < map_section_num; i ++) printf("%p+%x %x %s\n", map_sections[i].ptr, map_sections[i].size, map_sections[i].offset, map_sections[i].path);
	}

	return 0;
}

static int shm_remap (void)
{
	int i;

	assert(orig_mmap != NULL && orig_munmap != NULL);
	for (i = 0; i < map_section_num; i ++) {
		if (map_sections[i].isshared)
			continue;
		orig_munmap(map_sections[i].ptr, map_sections[i].size);
		assert(orig_mmap(map_sections[i].ptr, map_sections[i].size,
					PROT_READ|PROT_WRITE, MAP_PRIVATE, shmfd,
					map_sections[i].offset) == map_sections[i].ptr);
	}
	return 0;
}

static void child_send (const struct cj_message_header *message)
{
	assert(recv(socks[1], message->sendrecv.addr, message->sendrecv.size, 0) == message->sendrecv.size);
}

static void child_recv (const struct cj_message_header *message)
{
	assert(send(socks[1], message->sendrecv.addr, message->sendrecv.size, 0) == message->sendrecv.size);
}

static void child_jail (const struct cj_message_header *message)
{
	struct cj_message_header retmsg;

	assert(shm_remap() == 0);

	retmsg.type = CJ_MT_RETURN;
	retmsg.jreturn.retval = call_varg_func(
			(void *)message->jail.func,
			message->jail.argc,
			message->jail.argv);
	assert(send(socks[1], &retmsg, sizeof(retmsg), 0) == sizeof(retmsg));
}

static uintptr_t child_service (void)
{
	assert(cj_state == CJS_JAIL);

	while (1) {
		struct cj_message_header message;
		ssize_t message_size;

		message_size = recv(socks[1], &message, sizeof(message), 0);
		assert(message_size == sizeof(message));
		switch (message.type) {
			case CJ_MT_SEND: child_send(&message); break;
			case CJ_MT_RECV: child_recv(&message); break;
			case CJ_MT_JAIL: child_jail(&message); break;
			case CJ_MT_CBRETURN: return message.jreturn.retval;
			case CJ_MT_EXIT: exit(0); return 0;
			default: fprintf(stderr, "unknown message type %d\n", message.type); return 1;
		}
	}
}

uintptr_t child_callback (int cbhandle, uintptr_t *argv)
{
	struct cj_message_header message;

	assert(cbhandle >= 0 && cbhandle < MAXCALLBACKS);
	assert(cj_state == CJS_JAIL);
	// if (cj_state == CJS_MAIN) {
	// 	return (uintptr_t)call_varg_func(callbacks[cbhandle].orig, callbacks[cbhandle].argc, (void **)argv);
	// }

	message.type = CJ_MT_CALLBACK;
	message.callback.handle = cbhandle;
	message.callback.argv = argv;
	assert(send(socks[1], &message, sizeof(message), 0) == sizeof(message));
	return child_service();
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

static int child_main (void *arg)
{
	cj_state = CJS_JAIL;
	// close(socks[0]); // cannot close because of CLONE_FILES

	assert(shm_remap() == 0);

	cj_alloc_init();

	while (1) {
		child_service();
	}
}

static void drop_jlib_exec (int jlibn, const char **jlibs)
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
				fprintf(stderr, "drop exec %s@%p-%p\n", jlibs[i], (void *)start, (void *)end);
				assert(mprotect((void *)start, end - start, PROT_READ) == 0); // if it fails, probably kernel is holding maps lock.
				break;
			}
		}
	}
	fclose(fp);
}

enum cj_memtype_enum cj_memtype (void *addr)
{
	int i;

	for (i = 0; i < map_section_num; i ++)
		if (addr >= map_sections[i].ptr && addr < map_sections[i].ptr + map_sections[i].size)
			return map_sections[i].isshared ? CJMT_SHARED : CJMT_PRIVATE;
	return CJMT_ISOLATED;
}

static int cj_create (int nxjlib, int mlibn, const char **mlibs, int jlibn, const char **jlibs)
{
	assert(cj_state == CJS_UNINIT);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) {
		fprintf(stderr, "socketpair() failed.\n");
		return 1;
	}

	if (shm_create(mlibn, mlibs, jlibn, jlibs))
		return 1;

	if (clone(child_main, stack_jail + JSTACK_SIZE, CLONE_FILES|CLONE_FS|SIGCHLD, NULL) == -1) {
		fprintf(stderr, "clone() failed.\n");
		return 2;
	}

	// parent
	cj_state = CJS_MAIN;
	// close(socks[1]); // cannot close because CLONE_FILES
	if (nxjlib)
		drop_jlib_exec(jlibn, jlibs);
	{
		unsigned long oldbos = getbos();
		oldbos = ((oldbos - 1) & 0xfffff000) + 4096; // round-up to page bound
		jump_stack(oldbos, (unsigned long)stack_main + MSTACK_SIZE);
	}
	cj_alloc_init();
	refmon_init();
	//pthread_mutex_init(&sock_mutex, PTHREAD_MUTEX_RECURSIVE);
	{
		int i, stub_size;
		callbacks = (struct callback_struct *)calloc(MAXCALLBACKS, sizeof(struct callback_struct));
		assert(cj_memtype(callbacks) == CJMT_PRIVATE);
		stub_size = (char *)cj_callback_stub1 - (char *)cj_callback_stub0;
		for (i = 0; i < MAXCALLBACKS; i ++)
			callbacks[i].stub = (void *)cj_callback_stub0 + i * stub_size;
	}

	return 0;
}

int cj_recv (void *data, size_t size)
{
	struct cj_message_header message;

	assert(size > 0);
	assert(cj_state != CJS_UNINIT);
	if (cj_state == CJS_JAIL)
		return 0;

	// don't recv shared type
	if (data == NULL || cj_memtype(data) == CJMT_SHARED)
		return 0;

	message.type = CJ_MT_RECV;
	message.sendrecv.addr = data;
	message.sendrecv.size = size;
	pthread_mutex_lock(&sock_mutex);
	assert(send(socks[0], &message, sizeof(message), 0) == sizeof(message));
	assert(recv(socks[0], data, size, 0) == size);
	pthread_mutex_unlock(&sock_mutex);
	stats_recv ++;
	stats_recvb += size;

	return 0;
}

int cj_send (void *data, size_t size)
{
	struct cj_message_header message;

	assert(size > 0);
	assert(cj_state != CJS_UNINIT);
	if (cj_state == CJS_JAIL)
		return 0;

	// don't send shared type
	if (data == NULL || cj_memtype(data) == CJMT_SHARED)
		return 0;

	message.type = CJ_MT_SEND;
	message.sendrecv.addr = data;
	message.sendrecv.size = size;
	pthread_mutex_lock(&sock_mutex);
	assert(send(socks[0], &message, sizeof(message), 0) == sizeof(message));
	assert(send(socks[0], data, size, 0) == size);
	pthread_mutex_unlock(&sock_mutex);
	stats_send ++;
	stats_sendb += size;

	return 0;
}

uintptr_t cj_jail (void *func, int argc, ...)
{
	struct cj_message_header message;

	assert(cj_state != CJS_UNINIT);
	/* when using wrapper library, if jailed library function calls another
	 * jailed library function, cj_jail will be used as well.
	 * We need to let it call directly */
	if (cj_state == CJS_JAIL) {
		return call_varg_func(func, argc, (uintptr_t *)(&argc)+1);
	}

	stats_jail_level ++;
	message.type = CJ_MT_JAIL;
	message.jail.func = func;
	message.jail.argc = argc;
	message.jail.argv = (uintptr_t *)(&argc) + 1;
	pthread_mutex_lock(&sock_mutex);
	assert(send(socks[0], &message, sizeof(message), 0) == sizeof(message));
	while (1) {
		int handle;
		uintptr_t retval;

		assert(recv(socks[0], &message, sizeof(message), 0) == sizeof(message));
		assert(message.type == CJ_MT_RETURN || message.type == CJ_MT_CALLBACK);
		if (message.type == CJ_MT_RETURN)
			break;

		handle = message.callback.handle;
		assert(handle >= 0 && handle < MAXCALLBACKS && callbacks[handle].orig);
		//TODO check if [argv,argv+argc] is valid memory
		if (callbacks[handle].wrapper) {
			uintptr_t argv[16];
			assert(callbacks[handle].argc <= 15);
			argv[0] = (uintptr_t)callbacks[handle].orig;
			memcpy(&argv[1], message.callback.argv, callbacks[handle].argc * sizeof(uintptr_t));
			retval = call_varg_func(
					callbacks[handle].wrapper,
					callbacks[handle].argc + 1,
					argv);
		} else {
			retval = call_varg_func(
					callbacks[handle].orig,
					callbacks[handle].argc,
					message.callback.argv);
		}
		message.type = CJ_MT_CBRETURN;
		message.jreturn.retval = retval;
		assert(send(socks[0], &message, sizeof(message), 0) == sizeof(message));
		stats_callback ++;
	}
	pthread_mutex_unlock(&sock_mutex);
	stats_jail ++;
	stats_jail_level --;
	assert(stats_jail_level < sizeof(stats_jails)/sizeof(stats_jails[0]));
	stats_jails[stats_jail_level] ++;
	return message.jreturn.retval;
}

void *cj_reg_callback (void *origfunc, void *wrapperfunc, int argc)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	int i;

	fprintf(stderr, "registering callback %p+%d as w=%p\n", origfunc, argc, wrapperfunc);

	assert(cj_state == CJS_MAIN);

	pthread_mutex_lock(&mutex);
	for (i = 0; i < MAXCALLBACKS; i ++) {
		if (callbacks[i].orig == NULL) {
			callbacks[i].orig = origfunc;
			callbacks[i].wrapper = wrapperfunc;
			callbacks[i].argc = argc;
			break;
		} else if (origfunc == callbacks[i].orig &&
				wrapperfunc == callbacks[i].wrapper) {
			assert(argc == callbacks[i].argc);
			break;
		}
	}
	assert(i < MAXCALLBACKS);
	pthread_mutex_unlock(&mutex);

	return callbacks[i].stub;
}

static void cj_destroy (void)
{
	struct cj_message_header message;

	assert(cj_state == CJS_MAIN);
	message.type = CJ_MT_EXIT;
	assert(send(socks[0], &message, sizeof(message), 0) == sizeof(message));
	if (wait(0) == -1)
		fprintf(stderr, "wait() failed.\n");
	fprintf(stderr, "stats: jail=%d, callback=%d, recv/send=%d/%d (%d/%d bytes)\n",
			stats_jail, stats_callback,
			stats_recv, stats_send,
			stats_recvb, stats_sendb);
	fprintf(stderr, "stats: jail0=%d, jail1=%d, jail2=%d\n",
			stats_jails[0], stats_jails[1], stats_jails[2]);
}

extern int (*origmain)(int, char **, char **);
int hookmain (int argc, char **argv, char **envp)
{
	char *mlibs[10], *jlibs[10], *env, *lib;
	int mlibn = 0, jlibn = 0, nx = 0, i;

	fprintf(stderr, "hookmain(%p, %d, %p, %p)\n", origmain, argc, argv, envp);

	if ((env = getenv("CJMLIBS")) != NULL) {
		env = strdup(env);
		for (lib = strtok(env, ","); lib != NULL; lib = strtok(NULL, ","))
			mlibs[mlibn ++] = strdup(lib);
		free(env);
	}
	if ((env = getenv("CJJLIBS")) != NULL) {
		env = strdup(env);
		for (lib = strtok(env, ","); lib != NULL; lib = strtok(NULL, ","))
			jlibs[jlibn ++] = strdup(lib);
		free(env);
	}
	if ((env = getenv("CJNX")) != NULL)
		nx = strcmp(env, "1") == 0;
	cj_create(nx, mlibn, (const char **)mlibs, jlibn, (const char **)jlibs);
	assert(cj_state == CJS_MAIN);
	for (i = 0; i < mlibn; i ++)
		free(mlibs[i]);
	for (i = 0; i < jlibn; i ++)
		free(jlibs[i]);

	atexit(cj_destroy);
	return origmain(argc, argv, envp);
}
