#include "test-lib.h"
#include <stdio.h>

int main (void)
{
	set_global(12345);
	printf("%d\n", get_global());
	return 0;
}
