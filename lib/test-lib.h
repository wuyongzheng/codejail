#ifndef TEST_LIB_H
#define TEST_LIB_H

void set_global (int val);
int get_global (void);
int *get_globalref (void);
void write_global (const unsigned char *data);
void read_global (unsigned char *data);
void strtoupper (char *str);

#endif
