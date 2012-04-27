#include <stdio.h>
#include <string.h>

static int global_int;
static unsigned char global_buffer[64];

void set_global (int val)
{
	global_int = val;
}

int get_global (void)
{
	return global_int;
}

int *get_globalref (void)
{
	return &global_int;
}

void write_global (const unsigned char *data)
{
	memcpy(global_buffer, data, 64);
}

void read_global (unsigned char *data)
{
	memcpy(data, global_buffer, 64);
}

void strtoupper (char *str)
{
	while (*str) {
		if (*str >= 'a' && *str <= 'z')
			*str -= 'a' - 'A';
		str ++;
	}
}
