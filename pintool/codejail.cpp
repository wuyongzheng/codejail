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

KNOB<string> KnobFuncName(KNOB_MODE_WRITEONCE, "pintool", "n", "x0x", "specify jail function name");
KNOB<string> KnobFuncAddr(KNOB_MODE_WRITEONCE, "pintool", "a", "x0x", "specify jail function address");
char *func_name = NULL;
ADDRINT func_addr = 0;
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

void pre_call (void)
{
	struct shadow_page *swap = (struct shadow_page *)malloc(sizeof(struct shadow_page));
	int i, count;

	if (injail ++) {
		fprintf(stderr, "pre_call %d->%d\n, ignored.", injail-1, injail);
		return;
	}

	for (i = count = 0; i < TABLESIZE; i ++) {
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
	fprintf(stderr, "pre_call. %d page swapped\n", count);
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
			if ((unsigned)i >= STACKMIN/PAGESIZE) {
				memcpy((char *)(i << PAGESHIFT), page->data, PAGESIZE);
				free(page);
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

VOID Routine(RTN rtn, VOID *v)
{
	if (RTN_Address(rtn) == func_addr || (func_name != NULL && strcmp(func_name, RTN_Name(rtn).c_str()) == 0)) {
		fprintf(stderr, "hooked to %p\n", (void *)RTN_Address(rtn));
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)pre_call, IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)post_call, IARG_END);
		RTN_Close(rtn);
	}
}

VOID Usage ()
{
	fprintf(stderr, "usage...\n");
}

int main(int argc, char *argv[])
{
	if (PIN_Init(argc, argv)) {
		Usage();
		return 1;
	}

	if (KnobFuncName.Value().compare("x0x")) {
		func_name = strdup(KnobFuncName.Value().c_str());
	}
	if (KnobFuncAddr.Value().compare("x0x")) {
		sscanf(KnobFuncAddr.Value().c_str(), "%p", (void **)&func_addr);
	}

	PIN_InitSymbols();
	INS_AddInstrumentFunction(Instruction, 0);
	RTN_AddInstrumentFunction(Routine, 0);

	PIN_StartProgram();
	return 0;
}
