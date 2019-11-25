#include <debug.h>
#include "page.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"


unsigned
page_hash_func (const struct hash_elem *p, void *aux UNUSED)
{
    const struct page_suppl_entry * e = hash_entry (p, struct page_suppl_entry,
                                                        elem);

    return hash_bytes (&e->upage, sizeof (e->upage));
}

bool
page_hash_less_func (const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED)
{
    const struct page_suppl_entry * e1;
    const struct page_suppl_entry * e2;
    e1 = hash_entry (a, struct page_suppl_entry,elem);
    e2 = hash_entry (b, struct page_suppl_entry,elem);

    return e1->upage < e2->upage;
}


struct page_suppl_entry *
page_create_spte ( struct file *file, off_t offset, uint8_t *upage, int type,
                   uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    struct page_suppl_entry *e;
    e = malloc(sizeof(struct page_suppl_entry));
    if (e == NULL)
        return NULL;

    e->type = type;
    e->file = file;
    e->ofs = offset;
    e->upage = upage;
    e->read_bytes = read_bytes;
    e->zero_bytes = zero_bytes;
    e->writable = writable;
    e->loaded = false;
    
    return e;
}

bool
page_hash_insert (struct hash *table, struct page_suppl_entry *e)
{
    if (table != NULL && e != NULL)
    {
        struct hash_elem* old = hash_insert (table, &e->elem);
        if (old != NULL)
            return false;
        return true;
    }

    return false;
}

struct page_suppl_entry *
page_hash_find (struct hash *table, uint8_t *upage)
{
    if (upage == NULL || table == NULL)
        return false;
    /* Generate a pseudo entry using for search */
    upage = pg_round_down (upage);
    struct page_suppl_entry search;
    search.upage = upage;

    /* Search the corresponding page */
    struct hash_elem *matched_elem = hash_find (table, &search.elem);
    if (matched_elem == NULL)
        return NULL;

    /* Transform elem to entry */
    struct page_suppl_entry *matched_page;
    matched_page = hash_entry (matched_elem, struct page_suppl_entry,elem);

    return matched_page;
}

/*
bool page_load (struct page_suppl_entry *e)
{
    switch (e->type) 
    {
        case MMAP:
            page_load_file (e);
        case SWAP:
            page_load_swap (e);
        case FILE:
            page_load_file (e);
    }
}
*/