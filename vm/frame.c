#include <list.h>
#include "threads/synch.h"
#include "threads/malloc.h"

#include "frame.h"


static struct lock frame_lock;

void 
frame_table_init (void)
{
  list_init (&frame_table);
  lock_init (&frame_lock);
}

void *
palloc_get_frame (enum palloc_flags flags)
{
  if (!(flags & PAL_USER))
    return NULL;
  void *frame = palloc_get_page (flags);
  struct ft_entry *ft_entry = malloc (sizeof (struct ft_entry));
  if (ft_entry == NULL)
    return NULL;
  
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
