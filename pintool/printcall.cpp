#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "pin.H"

KNOB<string> KnobFuncs(KNOB_MODE_WRITEONCE, "pintool", "n", "x0x", "specify jail functions sep by comma");
std::vector<string> funcs;

VOID Arg1Before(CHAR * name, ADDRINT size)
{
	printf("calling %s %d(0x%x)\n", name, size, size);
}

VOID MallocAfter(ADDRINT ret)
{
	printf("returning 0x%x\n", ret);
}

void process_image (IMG img, VOID *v)
{
	printf("checking %s.\n", IMG_Name(img).c_str());

	/* both /lib/ld-linux.so.2 /lib/libc.so.6 has malloc. I only want to hook one */
	if (strcmp(IMG_Name(img).c_str(), "/lib/ld-linux.so.2") == 0)
		return;

	RTN mallocRtn = RTN_FindByName(img, "malloc");
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, "malloc", IARG_G_ARG0_CALLEE, IARG_END);
		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_G_RESULT0, IARG_END);
		RTN_Close(mallocRtn);
		printf("hooked to malloc at 0x%x.\n", RTN_Address(mallocRtn));
	}

	RTN freeRtn = RTN_FindByName(img, "free");
	if (RTN_Valid(freeRtn))
	{
		RTN_Open(freeRtn);
		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, "free", IARG_G_ARG0_CALLEE, IARG_END);
		RTN_Close(freeRtn);
		printf("hooked to free at 0x%x.\n", RTN_Address(freeRtn));
	}
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
		printf("check usage.\n");
		return 1;
	}

	add_funcs();

//	std::vector<std::string>::const_iterator fun;
//	for(fun=funcs.begin(); fun!=funcs.end(); fun++) {
//		printf("%s\n", (*fun).c_str());
//	}

	IMG_AddInstrumentFunction(process_image, 0);
	PIN_StartProgram();

	return 0;
}
