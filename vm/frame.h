#ifndef VM_FRAME
#define VM_FRAME

#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"

struct list frame_table;

struct ft_entry
  {
    void *frame;
    struct thread *owner;
    struct list_elem elem;
  };

void frame_table_init (void);
void *palloc_get_frame (enum palloc_flags);
void palloc_free_frame (void *);


#endif