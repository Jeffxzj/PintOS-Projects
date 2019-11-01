#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

void syscall_init (void);
void syscall_exit (int status);
struct file_descriptor
  {
    int fd;
    struct file *file;
    struct list_elem elem;
  };

#endif /* userprog/syscall.h */
