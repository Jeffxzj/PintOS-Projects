#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/thread.h"

/* Lock to protect file system operations. */
struct lock fs_lock;  

void syscall_init (void);
void syscall_exit (int status);

#endif /* userprog/syscall.h */
