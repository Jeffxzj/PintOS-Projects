#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "frame.h"

#define STACK_LIMIT 8*1024*1024

enum spte_type 
{
  _FILE,
  _SWAP,
  _MMAP
};
struct page_suppl_entry 
	{
		struct file* file;       /* Store file pointer for loading */
		enum spte_type type;     /* Type of the file */

		uint8_t *upage;          /* User virtual address, unique identifier for a
															  page, key for hash table */
		off_t ofs; 
		uint32_t read_bytes;     /* Bytes at UPAGE must be read from file
          										  starting at OFS */
		uint32_t zero_bytes;     /* Bytes at UPAGE + READ_BYTES must be zeroed. */
		bool writable;           /* False if the page is read-only */
		bool loaded;             /* True if the page is loaded to physical addr */

		size_t swap_idx;         /* Index on swap bitmap returned by swap_out() */
  
    struct lock pte_lock;
    struct hash_elem elem;  /* Hash table element */
  };


/* Create a supplemental page table entry providing information */
struct page_suppl_entry *page_create_spte (struct file *file,  off_t offset, 
                                           uint8_t *upage, enum spte_type type, 
                                           uint32_t read_bytes, 
                                           uint32_t zero_bytes, bool writable);


/* Returns a hash value for page p. */
unsigned page_hash_func (const struct hash_elem *p, void *aux);
/* Returns true if page a precedes page b. */
bool page_hash_less_func (const struct hash_elem *a, 
                          const struct hash_elem *b,
                          void *aux);
bool page_hash_insert (struct hash *table, struct page_suppl_entry *e);
struct page_suppl_entry *page_hash_find (struct hash *table, uint8_t *upage);

void free_suppl_page_table (struct hash *spt);

/* Load functions */
bool page_load (struct page_suppl_entry *e);
bool page_load_file (struct page_suppl_entry *e);
bool page_load_swap (struct page_suppl_entry *e);

/* Used in process.c to for lazy load */
bool page_lazy_load (struct file *file, off_t ofs, uint8_t *upage, 
                     enum spte_type type, uint32_t read_bytes, 
                     uint32_t zero_bytes, bool writable);

bool stack_grow (void *fault_addr);

#endif