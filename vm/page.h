#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "frame.h"

#define STACK_LIMIT 8*(1 << 20)
enum spte_type 
{
  FILE,
  SWAP,
  MMAP
};

struct page_suppl_entry 
{
  struct file* file;
  enum spte_type type;

  uint8_t *upage;

  off_t ofs; 
  uint32_t read_bytes; 
  uint32_t zero_bytes; 
  bool writable;
  bool loaded;

  size_t swap_idx;

  struct hash_elem elem;  
};

struct page_suppl_entry*
page_create_spte (struct file *file,  off_t offset, uint8_t *upage, 
                  enum spte_type type, uint32_t read_bytes,
                  uint32_t zero_bytes, bool writable);


/* Returns a hash value for page p. */
unsigned
page_hash_func (const struct hash_elem *p_, void *aux);

/* Returns true if page a precedes page b. */
bool
page_hash_less_func (const struct hash_elem *a, 
                     const struct hash_elem *b,
                     void *aux);

bool
page_hash_insert (struct hash *table, struct page_suppl_entry *e);

struct page_suppl_entry *
page_hash_find (struct hash *table, uint8_t *upage);

bool page_load_file (struct page_suppl_entry *e);
bool page_load_swap (struct page_suppl_entry *e);
bool page_load_mmp (struct page_suppl_entry *e);

bool page_load (struct page_suppl_entry *e);

bool page_lazy_load (struct file *file, off_t ofs, uint8_t *upage, 
                     uint32_t read_bytes, uint32_t zero_bytes, bool writable);

bool stack_grow (void *fault_addr);

#endif