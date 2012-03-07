#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "pin.H"

#define PAGESIZE 4096
#define PAGESHIFT 12
#define TABLESIZE 1048576 // 2^20 or 4G/4K
#define STACKMIN 0xbf000000 // my brave assumption. check /proc/pid/maps to ensure

struct shadow_page {
	unsigned char data[PAGESIZE];
};

KNOB<string> KnobFuncs(KNOB_MODE_WRITEONCE, "pintool", "n", "x0x", "specify jail function names, sep by comma");
std::vector<std::string> funcs;
int injail = 0;
struct shadow_page *pagetable[TABLESIZE];

void OnWrite (ADDRINT addr)
{
	if (injail && pagetable[(unsigned long)addr >> PAGESHIFT] == NULL) {
		struct shadow_page *page = pagetable[(unsigned long)addr >> PAGESHIFT] = (struct shadow_page *)malloc(sizeof(struct shadow_page));
		memcpy(page->data, (void *)(addr - addr % PAGESIZE), PAGESIZE);
	}
}

VOID Instruction(INS ins, VOID *v)
{
	if (INS_IsMemoryWrite(ins)) {
		INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)OnWrite,
				IARG_MEMORYWRITE_EA,
				IARG_END);
	}
}

void OnRecv (ADDRINT addr, ADDRINT size)
{
	assert(injail == 0);
	printf("recv %p+%d\n", (void *)addr, size);
	for (unsigned int i = 0; i < size; i ++) {
		if (pagetable[(unsigned long)(addr + i) >> PAGESHIFT] != NULL)
			*(unsigned char *)(addr + i) = pagetable[(unsigned long)(addr + i) >> PAGESHIFT]->data[(unsigned long)(addr + i) % PAGESIZE];
	}
}

void pre_call (void)
{
	struct shadow_page *swap = (struct shadow_page *)malloc(sizeof(struct shadow_page));
	int i, count, count_stack;

	if (injail ++) {
		fprintf(stderr, "pre_call %d->%d\n, ignored.", injail-1, injail);
		return;
	}

	for (i = count = count_stack = 0; i < TABLESIZE; i ++) {
		struct shadow_page *page = pagetable[i];
		if (page) {
			if ((unsigned)i >= STACKMIN/PAGESIZE) {
				free(page);
				pagetable[i] = NULL;
				count_stack ++;
			} else {
				memcpy(swap->data, (char *)(i << PAGESHIFT), PAGESIZE);
				memcpy((char *)(i << PAGESHIFT), page->data, PAGESIZE);
				pagetable[i] = swap;
				swap = page;
				count ++;
			}
		}
	}
	free(swap);
	fprintf(stderr, "pre_call. %d page swapped, %d discarded\n", count, count_stack);
}

void post_call (void)
{
	struct shadow_page *swap = (struct shadow_page *)malloc(sizeof(struct shadow_page));
	int i, count, count_stack;

	if (-- injail) {
		fprintf(stderr, "post_call %d->%d\n, ignored.", injail+1, injail);
		return;
	}

	for (i = count = count_stack = 0; i < TABLESIZE; i ++) {
		struct shadow_page *page = pagetable[i];
		if (page) {
			memcpy(swap->data, (char *)(i << PAGESHIFT), PAGESIZE);
			memcpy((char *)(i << PAGESHIFT), page->data, PAGESIZE);
			pagetable[i] = swap;
			swap = page;
			count ++;
		}
	}
	free(swap);
	fprintf(stderr, "pos_call. %d page swapped\n", count);
}

VOID Routine(RTN rtn, VOID *v)
{
	for (vector<string>::const_iterator fun = funcs.begin(); fun != funcs.end(); fun ++) {
		//TODO check function specified by address
		if (RTN_Name(rtn).compare(*fun) == 0) {
			fprintf(stderr, "hooked to %s at %p\n", (*fun).c_str(), (void *)RTN_Address(rtn));
			RTN_Open(rtn);
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)pre_call, IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)post_call, IARG_END);
			RTN_Close(rtn);
		}
	}

	if (RTN_Name(rtn) == "cj_recv") {
		fprintf(stderr, "hooked to cj_recv at %p\n", (void *)RTN_Address(rtn));
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(OnRecv),
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);
		RTN_Close(rtn);
	}
}

VOID Usage ()
{
	fprintf(stderr, "usage...\n");
}

void add_funcs (void)
{
	const char *str = KnobFuncs.Value().c_str();
	const char *ptr1, *ptr2;

	ptr1 = str;
	ptr2 = strchr(ptr1, ',');
	while (ptr2 != NULL) {
		funcs.push_back(std::string(ptr1, ptr2 - ptr1));
		ptr1 = ptr2 + 1;
		ptr2 = strchr(ptr1, ',');
	}
	funcs.push_back(std::string(ptr1));
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();
	if (PIN_Init(argc, argv)) {
		Usage();
		return 1;
	}

	add_funcs();

	INS_AddInstrumentFunction(Instruction, 0);
	RTN_AddInstrumentFunction(Routine, 0);

	PIN_StartProgram();
	return 0;
}
