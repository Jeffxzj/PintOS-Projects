#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "process.h"
#include "pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/user/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


static void syscall_handler (struct intr_frame *);

/* Syscall functions */
static void syscall_halt (void);
static void syscall_exit (int status);
static pid_t syscall_exec (const char *cmd_line);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_write (int fd, const void *buffer, unsigned size);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);

/* Helper functions */
static bool check_valid_pointer (const void *ptr);
static void BAD_POINTER_EXIT(const void *ptr);
static struct file *find_opened_file (struct thread *t, int fd);

static struct lock fs_lock;      /* Lock to protect file system syscalls */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{

  uint32_t *esp = f->esp;

  BAD_POINTER_EXIT (esp);

  int sys_code = *esp;
  switch (sys_code)
    {
    case SYS_HALT:
      {
        syscall_halt ();
        break;
      }
    case SYS_EXIT:
      {
        int status = *(esp + 1);
        syscall_exit (status);
        break;
      }
    case SYS_EXEC:
      {
        char *cmd_line = (char *)*(esp + 1);
        f->eax = syscall_exec (cmd_line);
        break;
      }
    case SYS_WAIT:
      {
        pid_t pid = *(esp + 1);
        f->eax = syscall_wait (pid);
        break;
      }
    case SYS_CREATE:
      {
        char *file = (char *)*(esp + 1);
        unsigned initial_size = *(esp + 2);
        f->eax = syscall_create (file, initial_size);
        break;
      }
    case SYS_REMOVE:
      {
        char *file = (char *)*(esp + 1);
        f->eax = syscall_remove (file);
        break;
      } 
    case SYS_OPEN:
      {
        char *file = (char *)*(esp + 1);
        f->eax = syscall_open (file);
        break;
      }
    case SYS_FILESIZE:
      {
        int fd = *(esp + 1);
        f->eax = syscall_filesize (fd);
        break;
      }
    case SYS_READ:
      {
        int fd = *(esp + 1);
        void *buffer = (void *)*(esp + 2);
        unsigned size = *(esp + 3);
        f->eax = syscall_read (fd, buffer, size);
        break;
      }
    case SYS_WRITE:
      {
        int fd = *(esp + 1);
        void *buffer = (void *)*(esp + 2);
        unsigned size = *(esp + 3);
        f->eax = syscall_write (fd, buffer, size);
        break;
      }
    case SYS_SEEK:
      {
        int fd = *(esp + 1);
        unsigned position = *(esp + 2);
        syscall_seek (fd, position);
        break;
      }
    case SYS_TELL:
      {
        int fd = *(esp + 1);
        f->eax = syscall_tell (fd);
        break;
      }
    case SYS_CLOSE:
      {
        int fd = *(esp + 1);
        syscall_close (fd);
        break;
      }
    default:
      break;
    }
}

void
syscall_halt (void)
{
  shutdown_power_off();
}

static void
syscall_exit (int status)
{      
  struct thread *cur = thread_current();
  struct thread * parent = get_thread_by_tid (cur->parent_tid);
  cur->exit_code = status;
  if (parent == NULL)
    return;
  if(list_empty(&parent->child_list) )
    return;
    
  struct list_elem* iter;
  for(iter = list_begin (&parent->child_list);
      iter != list_end (&parent->child_list);
      iter = list_next (iter)) 
    {
      struct child_info *child = list_entry(iter,struct child_info,child_ele);
      if (child->tid == cur->tid)
        {
          sema_up (&child->wait_sema);
          child->exited = true;
          child->exit_code = status;
          break;
        }  
    } 
  thread_exit ();
}

static pid_t
syscall_exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  return pid;
}

static int 
syscall_wait (pid_t pid)
{
  BAD_POINTER_EXIT (&pid);
  
  return process_wait (pid);
}

/* Creates a new file called file initially initial_size bytes in size. Returns 
   true if successful, false otherwise. Creating a new file does not open it: 
   opening is job of sys_open() */
static bool 
syscall_create (const char *file, unsigned initial_size)
{
  BAD_POINTER_EXIT (file);
  BAD_POINTER_EXIT (&initial_size);

  bool status = false;
  lock_acquire (&fs_lock);
  status = filesys_create (file, initial_size);
  lock_release (&fs_lock);
  return status;
}

/* Deletes the file called file. Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, and removing 
   an open file does not close it. */
static bool 
syscall_remove (const char *file)
{
  BAD_POINTER_EXIT (file);

  bool status = false;
  lock_acquire (&fs_lock);
  status = filesys_remove (file);
  lock_release (&fs_lock);
  return status;
}

/* Opens the file called file. Returns a nonnegative integer handle called a 
   "file descriptor" (fd), or -1 if the file could not be opened. */
static int 
syscall_open (const char *file)
{
  BAD_POINTER_EXIT (file);

  struct thread *cur = thread_current ();
  struct file_descriptor *fd_struct = NULL;
  int status = -1;
  lock_acquire (&fs_lock);
  struct file *f = filesys_open (file);
  if (f != NULL)
    {
      fd_struct = malloc (sizeof (struct file_descriptor));
      fd_struct->file = f;
      fd_struct->fd = ++cur->file_num;
      list_push_back (&cur->fd_list, &fd_struct->elem);
      status = fd_struct->fd;
    }
  lock_release (&fs_lock);
  return status;
}

/* Returns the size, in bytes, of the file open as fd. */
static int 
syscall_filesize (int fd)
{
  BAD_POINTER_EXIT (&fd);

  int size = -1;
  struct file *f = NULL;
  
  f = find_opened_file (thread_current(), fd);
  lock_acquire (&fs_lock);
  if (f != NULL)
    size = file_length (f);

  lock_release (&fs_lock);
  return size;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of 
   bytes actually read (0 at end of file), or -1 if the file could not be read 
   (due to a condition other than end of file). Fd 0 reads from the keyboard 
   using input_getc(). */
static int 
syscall_read (int fd, void *buffer, unsigned size)
{
  BAD_POINTER_EXIT (&fd);  
  BAD_POINTER_EXIT (buffer);
  BAD_POINTER_EXIT (&size);

  int size_read = -1;
  lock_acquire (&fs_lock);
  if (fd == 0)
    {
      uint8_t *buf = buffer;
      for (unsigned int i = 0; i < size; i++)
        buf[i] = input_getc ();
      size_read = size;
    }
  else
    {
      struct file *f = find_opened_file (thread_current(), fd);
      if (f != NULL)
        size_read = file_read (f, buffer, size);
    }
  lock_release (&fs_lock);
  return size_read;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
   bytes actually written, which may be less than size if some bytes could not 
   be written. */
static int 
syscall_write (int fd, const void *buffer, unsigned size)
{
   

  
  BAD_POINTER_EXIT (buffer);

  
  int size_write = -1;
  lock_acquire (&fs_lock);

  if (fd == 1)
    { 
      //for (unsigned int i = 0; i < size; i++){
        putbuf ((char *)buffer, (size_t)size);
      ///}
        
      size_write = size;
    }
  else
    {
      struct file *f = find_opened_file (thread_current(), fd);
      if (f != NULL)
        size_write = file_write (f, buffer, size);
    }
  lock_release (&fs_lock);
  return size_write;
}

static void 
syscall_seek (int fd, unsigned position)
{
  BAD_POINTER_EXIT (&fd);
  BAD_POINTER_EXIT (&position);
  lock_acquire (&fs_lock);
  struct file *f = find_opened_file (thread_current(), fd);
  if (f != NULL)
    file_seek (f,position);
  lock_release (&fs_lock);
  
}

static unsigned 
syscall_tell (int fd)
{
  lock_acquire (&fs_lock);
  unsigned pos;
  struct file *f = find_opened_file (thread_current(), fd);
  if (f != NULL)
    pos = (unsigned) file_tell (f);
  else
    pos = (unsigned) -1;
  
  lock_release (&fs_lock);
  return pos;  
}

static void 
syscall_close (int fd)
{
  lock_acquire (&fs_lock);
  struct file *f =find_opened_file (thread_current(), fd);
  if (f != NULL)
    file_close (f);
  lock_release (&fs_lock);

}

/* Helper functions */
static bool
check_valid_pointer (const void *ptr)
{
  struct thread *cur = thread_current ();
  /* Check if ptr is null and is a user virtual address */
  if (ptr != NULL && is_user_vaddr (ptr))
    {
      /* Check if ptr is allocated within the current thread's pages */
      bool is_addr_mapped = pagedir_get_page(cur->pagedir, ptr) != NULL;
      return is_addr_mapped; 
    }
  return false; 
}

static void 
BAD_POINTER_EXIT(const void *ptr)
{
  if (!check_valid_pointer (ptr))
    syscall_exit(-1);
}

static struct file *
find_opened_file (struct thread *t, int fd)
{
  struct list_elem *e = NULL;
  struct list *l = &t->fd_list;
  struct file_descriptor *fd_struct = NULL;
  for (e = list_begin (l); e != list_end (l); e = list_next (e))
    {
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->fd == fd)
        return fd_struct->file;
    }
  return NULL;
}