#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

void swap_table_init (void);
size_t swap_out (void *);
void swap_in (void *, size_t);

#endif