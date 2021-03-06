#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void try_sema_up (struct thread *parent, tid_t child_tid);
int try_sema_down (struct thread *parent, tid_t child_tid);

bool install_page (void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */
