#include "page.h"


unsigned
page_hash_func (const struct hash_elem *p, void *aux UNUSED)
{
    const struct page_suppl_entry * e = hash_entry (p, struct page_suppl_entry,
                                                        elem);

    return has_bytes (&e->upage, sizeof (e->upage));
}

bool
page_hash_less_func (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux)
{
    const struct page_suppl_entry * e1;
    const struct page_suppl_entry * e2;
    e1 = hash_entry (a, struct page_suppl_entry,elem);
    e2 = hash_entry (b, struct page_suppl_entry,elem);

    return e1->upage < e2->upage;
}

struct page_suppl_entry *
page_create_spte ( struct file *file, off_t offset, uint8_t *upage,
                    uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    struct page_suppl_entry *e;
    e = malloc(sizeof(struct page_suppl_entry));
    if (e == NULL)
        return NULL;
        
    e->file = file;
    e->ofs = offset;
    e->upage = upage;
    e->read_bytes = read_bytes;
    e->zero_bytes = zero_bytes;
    e->writable = writable;
    
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