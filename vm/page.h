#include "filesys/file.h"
#include "lib/kernel/hash.h"

#define FILE 1
#define SWAP 2
#define MMAP 3

struct page_suppl_entry {
    struct file* file;
    int type;
    off_t ofs; 
    uint8_t *upage;
    uint32_t read_bytes; 
    uint32_t zero_bytes; 
    bool writable;
    bool loaded;
    struct hash_elem elem;  
};

struct page_suppl_entry*
page_create_spte (struct file *file,  off_t offset, uint8_t *upage, int type,
                    uint32_t read_bytes, uint32_t zero_bytes, bool writable);


/* Returns a hash value for page p. */
unsigned
page_hash_func (const struct hash_elem *p_, void *aux UNUSED);

/* Returns true if page a precedes page b. */
bool
page_hash_less_func (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED);

bool
page_hash_insert (struct hash *table, struct page_suppl_entry *e);

struct page_suppl_entry *
page_hash_find (struct hash *table, uint8_t *upage);

bool page_load_file (struct page_suppl_entry *e);
bool page_load_swap (struct page_suppl_entry *e);
bool page_load_mmp (struct page_suppl_entry *e);

bool page_load (struct page_suppl_entry *e);