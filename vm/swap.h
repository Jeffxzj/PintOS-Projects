#ifndef VM_SWAP
#define VM_SWAP

void swap_table_init (void);
size_t swap_out (void *);
void swap_in (void *, size_t index);

#endif