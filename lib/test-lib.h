#ifndef TEST_LIB_H
#define TEST_LIB_H

void set_global (int val);

extern int global_int;
extern unsigned char global_buffer[64];

int get_global (void);
void write_global (const unsigned char *data);
void read_global (unsigned char *data);
void strtoupper (char *str);

#endif
