#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"

struct list frame_table;
struct lock frame_lock;

struct ft_entry
  {
    void *frame;
    struct page_suppl_entry *pte;
    struct thread *owner;
    struct list_elem elem;
  };

void frame_table_init (void);
void *palloc_get_frame (enum palloc_flags, struct page_suppl_entry *pte);
void palloc_free_all_frame (struct thread *t);
void palloc_free_frame (void *frame);
void *evict_frame (struct page_suppl_entry *e);
#endif