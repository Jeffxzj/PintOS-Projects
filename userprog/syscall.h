#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/file.c"

void syscall_init (void);

struct file_descriptor
  {
    int fd;
    struct file *file;
    struct list_elem elem;
  };

#endif /* userprog/syscall.h */
