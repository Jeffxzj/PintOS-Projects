#include <list.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "swap.h"
#include "frame.h"

void 
frame_table_init (void)
{
  list_init (&frame_table);
  lock_init (&frame_lock);
}

void *
palloc_get_frame (enum palloc_flags flags, struct page_suppl_entry *pte)
{
  if (!(flags & PAL_USER))
    return NULL;
  
  void *frame = palloc_get_page (flags);
  if (frame == NULL)
    return evict_frame (pte);

  struct ft_entry *ft_entry = malloc (sizeof (struct ft_entry));
  if (ft_entry == NULL)
    return NULL;
  
  ft_entry->pte = pte;
  ft_entry->frame = frame;
  ft_entry->owner = thread_current ();

  lock_acquire (&frame_lock);
  list_push_back (&frame_table, &ft_entry->elem);
  lock_release (&frame_lock);
  return frame;
}

void
palloc_free_frame (void *frame)
{
  if (frame == NULL)
    return;
  struct list_elem *e;
  lock_acquire (&frame_lock);
  for (e = list_begin (&frame_table); 
       e != list_end (&frame_table); 
       e = list_next (e))
    {
      struct ft_entry *ft_entry = list_entry (e, struct ft_entry, elem);
      if (ft_entry->frame == frame)
        {
          list_remove (e);
          free (ft_entry);
          palloc_free_page (frame);
          break;
        }
    }
  lock_release (&frame_lock);
}

void *
evict_frame (struct page_suppl_entry *e)
{

  struct thread *cur = thread_current ();
  while (true)
  {
    struct list_elem* search;
    for (search = list_begin (&frame_table);
         search != list_end (&frame_table); 
         search = list_next (search))
      {
        lock_acquire (&frame_lock);
        /* Lock it to make sure it won't be interrupted by 
          palloc_free_frame() or palloc_get_frame() */

        struct ft_entry* f_entry = list_entry (search, struct ft_entry, elem);

        /* If it hasn't accessed, make it unaccessed to avoid the situation
          that all page has been accessed so no page won't be found*/
        if (!pagedir_is_accessed (cur->pagedir, f_entry->pte->upage))
          pagedir_set_accessed (cur->pagedir, f_entry->pte->upage, false);

        /* Found! Swap out and update information. */
        else
          {
            /* For conveniece, get needed information */
            void *evi_frame = f_entry->frame;
            uint8_t *upage = f_entry->pte->upage;
            struct thread* owner = f_entry->owner;

            /* We will swap out the original upage, so set
               original pte type to SWAP */
            f_entry->pte->type = _SWAP;

            /* Set the originalupage in page table to not present */
            /* Swap and get index, record the index for reloading */
            pagedir_clear_page (owner->pagedir, upage);
            size_t idx = swap_out (evi_frame);
            f_entry->pte->swap_idx = idx;
        
            /* Now we get a evicted frame, set it all zero, so we can
              load other file later */
            memset (evi_frame, 0, PGSIZE);

            /* Remove the original fr_entry in frame table. 
               Murder people and his heart! */
            list_remove (&f_entry->elem);
            free (f_entry);

            /* Maintain a new ft_entry */
            struct ft_entry *new_ft = malloc (sizeof (struct ft_entry));
            new_ft->frame = evi_frame;
            new_ft->pte = e;
            new_ft->owner = thread_current ();
            list_push_back (&frame_table, &new_ft->elem);

            lock_release (&frame_lock);
            return evi_frame;
          }
        lock_release (&frame_lock);

      }
  }
}