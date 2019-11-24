#include <hash.h>
#include "filesys/file.h"


struct page_suppl_entry {
    struct file* file;
    int type;
    off_t ofs; 
    uint8_t *upage;
    uint32_t read_bytes; 
    uint32_t zero_bytes; 
    bool writable;
    struct hash_elem elem;  
};

struct page_suppl_entry*
page_create_spte (struct file *file,  off_t offset, uint8_t *upage,
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