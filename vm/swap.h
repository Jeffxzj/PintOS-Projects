#ifndef VM_SWAP
#define VM_SWAP

#include <stddef.h>

void swap_table_init (void);
size_t swap_out (void *);
void swap_in (void *, size_t);

#endif