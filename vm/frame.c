#include <list.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "swap.h"
#include "frame.h"
#include "userprog/syscall.h"

void 
frame_table_init (void)
{
  list_init (&frame_table);
  lock_init (&frame_lock);
}

void *
palloc_get_frame (enum palloc_flags flags, struct page_suppl_entry *spte)
{
  if (!(flags & PAL_USER))
    return NULL;
  /* Get a frame from memory */
  void *frame = palloc_get_page (flags);

  /* If there are no frame can be got, ready to evict a frame */
  if (frame == NULL)
    return evict_frame (spte);

  /* Maintain an ft_entry */
  struct ft_entry *ft_entry = malloc (sizeof (struct ft_entry));
  if (ft_entry == NULL)
    return NULL;
  
  ft_entry->pte = spte;
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

void
palloc_free_all_frame (struct thread *t)
{
  if (t == NULL)
    return;
  struct list_elem *e = list_begin (&frame_table);
  lock_acquire (&frame_lock);
  /* Traverse the list to free all ft_entry */ 
  while (e != list_end (&frame_table))
  {
    struct ft_entry *ft_entry = list_entry (e, struct ft_entry, elem);
    struct list_elem *next = list_next (e);
    if (ft_entry->owner == t)
      {
        /* Note that it need not call palloc_free_page() to free frame
           Since the frame will be freed in process_exit() in process.c
           using pagedir_destroy() */
        list_remove (e);
        free (ft_entry);
      }
    e = next;
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
        
        /* Lock it to make sure it won't be interrupted by 
          palloc_free_frame() or palloc_get_frame() */
        lock_acquire (&frame_lock);
        struct ft_entry* f_entry = list_entry (search, struct ft_entry, elem);

        /* If it has been accessed, make it unaccessed to avoid the situation
          that all page has been accessed so no page won't be found*/
        if (pagedir_is_accessed (cur->pagedir, f_entry->pte->upage))
          pagedir_set_accessed (cur->pagedir, f_entry->pte->upage, false);

        /* Found! Swap out and update information. */
        else
          {
            lock_acquire (&e->pte_lock);
            /* For conveniece, get needed information */
            void *evi_frame = f_entry->frame;
            struct page_suppl_entry *evi_pte = f_entry->pte;
            uint8_t *upage = f_entry->pte->upage;
            struct thread* owner = f_entry->owner;

            /* For a dirty page, write it back */
            if (pagedir_is_dirty (cur->pagedir, evi_pte->upage) && 
                (evi_pte ->type == _MMAP))
              {
                lock_acquire (&fs_lock);
                file_write_at (evi_pte->file,evi_pte->upage,
                               evi_pte->read_bytes,evi_pte->ofs);
                lock_release (&fs_lock);
              } 
            else
              {
                /* We will swap out the original upage, so set
                original pte type to SWAP */
                /* Swap and get index, record the index for reloading */
                f_entry->pte->type = _SWAP;
                size_t idx = swap_out (evi_frame);
                f_entry->pte->swap_idx = idx;
              }

            /* Set the original upage in page table to not present */
            pagedir_clear_page (owner->pagedir, upage);

            /* Now we get a evicted frame, set it all zero, so we can
              load other file later */
            memset (evi_frame, 0, PGSIZE);

            /* Remove the original fr_entry in frame table. */
            list_remove (&f_entry->elem);
            free (f_entry);

            /* Maintain a new ft_entry */
            struct ft_entry *new_ft = malloc (sizeof (struct ft_entry));
            new_ft->frame = evi_frame;
            new_ft->pte = e;
            new_ft->owner = thread_current ();
            list_push_back (&frame_table, &new_ft->elem);

            lock_release (&e->pte_lock);
            lock_release (&frame_lock);
            return evi_frame;
          }
        lock_release (&frame_lock);
      }
  }
}