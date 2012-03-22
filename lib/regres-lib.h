#ifndef TEST_LIB_H
#define TEST_LIB_H

void set_global (int val);
int get_global (void);
int *get_globalref (void);
void write_global (const char *data);
char *read_globalref (void);
void read_global (char *data);
void strtoupper (char *str);

#endif
