#include "page.h"
#include "frame.h"
#include <debug.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "swap.h"

static void spte_destroy (struct hash_elem *e, void *aux);

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


struct page_suppl_entry*
page_create_spte (struct file *file,  off_t offset, uint8_t *upage, 
                  enum spte_type type, uint32_t read_bytes,
                  uint32_t zero_bytes, bool writable)
{
  struct page_suppl_entry *e;
  e = malloc (sizeof (struct page_suppl_entry));
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

/* Destroy the supplementary page table */
void
free_suppl_page_table (struct hash *spt)
{
  hash_destroy (spt, spte_destroy);
}

bool 
page_load_file (struct page_suppl_entry *e)
{
  /* Load the bytes in file into frame */
  void *frame = palloc_get_frame (PAL_USER, e);
  int flag = 0;
  if (frame == NULL)
    return false;
  /*
  if (thread_current() != fs_lock.holder){
    lock_acquire (&fs_lock);
    flag = 1;
  }
  */
  lock_acquire (&fs_lock);
  off_t actual_size = file_read_at (e->file, frame, e->read_bytes, e->ofs);
  lock_release (&fs_lock);
  /*
  if (flag == 1)
    lock_release (&fs_lock);
  */
  /* If reach the end of file, the actual read bytes 
      is not equal to the bytes it should read */
  if (actual_size != (off_t) e->read_bytes)
    {
      palloc_free_frame (frame);
      return false;
    }
  /* Memset the left bytes to 0 */
  if (e->zero_bytes > 0)
    {
      void *zero_start = frame + e->read_bytes;
      memset (zero_start, 0, e->zero_bytes);
    }
  /* Map the frame to the page table */
  if (!install_page (e->upage, frame, e->writable))
    {
      palloc_free_frame (frame);
      return false;
    }
  
  e->loaded = true;
  return true;
}

bool
page_load_swap (struct page_suppl_entry *e)
{
  void *frame = palloc_get_frame (PAL_USER, e);

  swap_in (frame, e->swap_idx);
  if (!install_page (e->upage, frame, e->writable))
  {
    palloc_free_frame (frame);
    return false;
  }
  e->loaded = true;
  return true;
  
}

bool 
page_load (struct page_suppl_entry *e)
{

  bool success = false;

  if (e->type == _FILE || e->type == _MMAP)
    success = page_load_file (e);
  else if (e->type == _SWAP)
    success = page_load_swap (e);

  return success;
}

/* Actually lazy load do not load anything to physical address, it just insert
   the needed supplementary page table entry to SPT of the current thread. */
bool
page_lazy_load (struct file *file, off_t ofs, uint8_t *upage,
                enum spte_type type, uint32_t read_bytes, 
                uint32_t zero_bytes, bool writable) 
{
  struct page_suppl_entry *spte;
  
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      spte = page_create_spte (file, ofs, upage, type, page_read_bytes, 
                               page_zero_bytes, writable);
      if (spte == NULL)
        return false;
      if (!page_hash_insert (&thread_current ()->suppl_page_table, spte))
        {
          free (spte);
          return false;
        }
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

bool 
stack_grow (void *fault_addr)
{
  if (fault_addr == NULL) 
    return false;
     
  struct page_suppl_entry *pte;
  struct thread *cur = thread_current ();
  pte = malloc (sizeof (struct page_suppl_entry));

  pte->loaded = true;
  pte->writable = true;
  pte->upage = pg_round_down (fault_addr);

  void *frame = palloc_get_frame (PAL_USER, pte);
  if (frame == NULL)
    {
      free (pte);
      return false;
    }

  if (!install_page (pte->upage, frame, pte->writable))
    {
      free (pte);
      palloc_free_frame (frame);
      return false;
    }

  if (!page_hash_insert (&cur->suppl_page_table, pte))
  {
    free (pte);
    palloc_free_frame (frame);
    return false;
  }

  return true;
}

/* Destructor for hash */
static void
spte_destroy (struct hash_elem *e, void *aux UNUSED)
{
  free (hash_entry (e, struct page_suppl_entry, elem));
}