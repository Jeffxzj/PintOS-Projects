#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/thread.h"

void syscall_init (void);
void syscall_exit (int status);

void free_mmap_list (struct thread *t);

#endif /* userprog/syscall.h */
