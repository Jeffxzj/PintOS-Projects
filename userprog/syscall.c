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
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);

/* Syscall functions */
static void syscall_halt (void);
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

/*Syscall functions for project 4. */
static bool syscall_chdir (const char *dir);
static bool syscall_mkdir (const char *dir);
static bool syscall_readdir (int fd, char *name);
static bool syscall_isdir (int fd);
static int syscall_inumber (int fd);

/* Helper functions */
static bool check_valid_pointer (void *ptr, uint8_t argc);
static bool check_valid_string (char *str);
static struct file_descriptor *find_opened_file (struct thread *t, int fd);

/* Lock to protect file system operations. */
static struct lock fs_lock;      

/* Constants to check bound of syscall code */
static const int SYSCODE_MIN = 0;
static const int SYSCODE_MAX = 19;

struct inode;
struct file;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{

  uint32_t *esp = f->esp;   /* convert f->esp to integer pointer */

  int sys_code = *esp;
  if (sys_code < SYSCODE_MIN || sys_code > SYSCODE_MAX || esp == NULL
      || !check_valid_pointer (f->esp, 4))
      syscall_exit (-1);

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
        if (!check_valid_string (cmd_line))
          syscall_exit (-1);
        f->eax = (uint32_t) syscall_exec (cmd_line);
        break;
      }
    case SYS_WAIT:
      {
        pid_t pid = *(esp + 1);
        f->eax = (uint32_t) syscall_wait (pid);
        break;
      }
    case SYS_CREATE:
      {
        char *file = (char *)*(esp + 1);
        unsigned initial_size = *(esp + 2);
        if (!check_valid_string (file))
          syscall_exit (-1);
        f->eax = (uint32_t) syscall_create (file, initial_size);
        break;
      }
    case SYS_REMOVE:
      {
        char *file = (char *)*(esp + 1);
        if (!check_valid_string (file))
          syscall_exit (-1);
        f->eax = (uint32_t) syscall_remove (file);
        break;
      } 
    case SYS_OPEN:
      {
        char *file = (char *)*(esp + 1);
        if (!check_valid_string (file))
          syscall_exit (-1);
        f->eax = (uint32_t) syscall_open (file);
        break;
      }
    case SYS_FILESIZE:
      {
        int fd = *(esp + 1);
        f->eax = (uint32_t) syscall_filesize (fd);
        break;
      }
    case SYS_READ:
      {
        int fd = *(esp + 1);
        void *buffer = (void *)*(esp + 2);
        unsigned size = *(esp + 3);
        if (!check_valid_pointer (buffer + size, 1))
          syscall_exit (-1);
        f->eax = (uint32_t) syscall_read (fd, buffer, size);
        break;
      }
    case SYS_WRITE:
      {
        int fd = *(esp + 1);
        void *buffer = (void *)*(esp + 2);
        unsigned size = *(esp + 3);
        if (!check_valid_pointer (buffer + size, 1))
          syscall_exit (-1);
        f->eax = (uint32_t) syscall_write (fd, buffer, size);
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
        f->eax = (uint32_t) syscall_tell (fd);
        break;
      }
    case SYS_CLOSE:
      {
        int fd = *(esp + 1);
        syscall_close (fd);
        break;
      }
    /* Syscalls for Project 4 */
    case SYS_CHDIR:
      {
        char *dir = (char *)*(esp + 1);
        f->eax = (uint32_t) syscall_chdir (dir);
        break;
      }
    case SYS_MKDIR:
      {
        char *dir = (char *)*(esp + 1);
        f->eax = (uint32_t) syscall_mkdir (dir);
        break;
      }
    case SYS_READDIR:
      {
        int fd = *(esp + 1);
        char *name = (char *)*(esp + 2);
        f->eax = (uint32_t) syscall_readdir (fd, name);
        break;
      }
    case SYS_ISDIR:
      {
        int fd = *(esp + 1);
        f->eax = (uint32_t) syscall_isdir (fd);
        break;
      }
    case SYS_INUMBER:
      {
        int fd = *(esp + 1);
        f->eax = (uint32_t) syscall_inumber (fd);
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

/* Terminates the current user program, returning status to the kernel. If the 
   process’s parent waits for it (see below), this is the status that will be 
   returned. Conventionally, a status of 0 indicates success and nonzero values 
   indicate errors.*/
void
syscall_exit (int status)
{      
  
  struct thread *cur = thread_current();
  struct thread *parent = get_thread_by_tid (cur->parent_tid);
  cur->exit_code = status;
  
  if (parent == NULL || list_empty (&parent->child_list))
    thread_exit ();
  
  struct list_elem* iter = NULL;
  struct child_info* child = NULL;
  for (iter = list_begin (&parent->child_list);
       iter != list_end (&parent->child_list);
       iter = list_next (iter)) 
    {
      child = list_entry (iter,struct child_info,child_ele);
      if (child->tid == cur->tid)
        {
          child->exit_code = status;
          break;
        }  
    } 
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing any given 
   arguments, and returns the new process’s program ID (pid). Must return pid 
   -1, which otherwise should not be a valid pid, if the program cannot load 
   or run for any reason. Thus, the parent process cannot return from the exec 
   until it knows whether the child process successfully loaded its executable. 
   You must use appropriate synchronization to ensure this. */
static pid_t
syscall_exec (const char *cmd_line)
{
  pid_t pid;
  
  if (cmd_line == NULL)
    return -1;
  
  lock_acquire (&fs_lock);
  pid = process_execute (cmd_line);
  lock_release (&fs_lock);
  /* Wait until the child thread load */
  sema_down (&thread_current()->load_sema);
  /* If load fails, return -1 */
  if (thread_current() -> child_load == -1)
    pid = -1;

  return pid;
}

/* Waits for a child process pid and retrieves the child’s exit status. */
static int 
syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

/* Creates a new file called file initially initial_size bytes in size. Returns 
   true if successful, false otherwise. Creating a new file does not open it: 
   opening is job of sys_open() */
static bool 
syscall_create (const char *file, unsigned initial_size)
{
  bool status = false;
  lock_acquire (&fs_lock);
  status = filesys_create (file, initial_size);
  lock_release (&fs_lock);
  return status;
}

/* Deletes the file called file. Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, and 
   removing an open file does not close it. */
static bool 
syscall_remove (const char *file)
{
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
  struct file_descriptor *fd_struct = NULL;
  struct thread *cur = thread_current ();
  
  lock_acquire (&fs_lock);
  struct file *f = filesys_open (file);
  lock_release (&fs_lock);
  
  if (f == NULL)
    return -1;
  
  fd_struct = malloc (sizeof (struct file_descriptor));
  fd_struct->file = f;
  fd_struct->fd = cur->file_num++;
  list_push_back (&cur->fd_list, &fd_struct->elem);
  return fd_struct->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int 
syscall_filesize (int fd)
{
  int size = -1;
  struct file_descriptor *fd_struct = NULL;
  fd_struct = find_opened_file (thread_current(), fd);
  if (fd_struct != NULL)
    {
      lock_acquire (&fs_lock);
      size = file_length (fd_struct->file);
      lock_release (&fs_lock);
    }
  return size;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of 
   bytes actually read (0 at end of file), or -1 if the file could not be read 
   (due to a condition other than end of file). Fd 0 reads from the keyboard 
   using input_getc(). */
static int 
syscall_read (int fd, void *buffer, unsigned size)
{
  int size_read = 0;
  struct file_descriptor *fd_struct = NULL;
  
  if (fd == 1)
    return -1;
  
  if (fd == 0)
    {
      uint8_t *buf = buffer;
      for (unsigned int i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }
  
  fd_struct = find_opened_file (thread_current(), fd);
  if (fd_struct == NULL || fd_struct->file == NULL)
    return -1;
  
  lock_acquire (&fs_lock);
  size_read = file_read (fd_struct->file, buffer, size);
  lock_release (&fs_lock);
  
  return size_read;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
   bytes actually written, which may be less than size if some bytes could not 
   be written. */
static int 
syscall_write (int fd, const void *buffer, unsigned size)
{  
  int size_write = 0 ;
  struct file_descriptor *fd_struct = NULL;
  
  if (fd == 0)
    return -1;
  
  if (fd == 1)
    { 
      putbuf ((char *)buffer, (size_t)size);
      return size;
    }
  
  fd_struct = find_opened_file (thread_current(), fd);
  if (fd_struct == NULL || fd_struct->file == NULL)
    return -1;
  
  lock_acquire (&fs_lock);
  size_write = file_write (fd_struct->file, buffer, size);
  lock_release (&fs_lock);
  
  return size_write;
}

/* Changes the next byte to be read or written in open file fd to position, 
   expressed in bytes from the beginning of the file. (Thus, a position of 0 
   is the file’s start.) */
static void 
syscall_seek (int fd, unsigned position)
{
  struct file_descriptor *fd_struct = find_opened_file (thread_current(), fd);
  lock_acquire (&fs_lock);
  if (fd_struct != NULL)
    file_seek (fd_struct->file, position);
  lock_release (&fs_lock);
}

/* Returns the position of the next byte to be read or written in open file fd, 
   expressed in bytes from the beginning of the file. */
static unsigned 
syscall_tell (int fd)
{
  unsigned pos = -1;
  struct file_descriptor *fd_struct = find_opened_file (thread_current(), fd);
  lock_acquire (&fs_lock);
  if (fd_struct != NULL)
    pos = (unsigned) file_tell (fd_struct->file);  
  lock_release (&fs_lock);
  return pos;  
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
   closes all its open file descriptors, as if by calling this function for 
   each one.*/
static void 
syscall_close (int fd)
{
  struct file_descriptor *fd_struct = find_opened_file (thread_current(), fd);
  lock_acquire (&fs_lock);
  if (fd_struct != NULL)
    {
      file_close (fd_struct->file);
      list_remove (&fd_struct->elem);
      free (fd_struct);    
    }
  lock_release (&fs_lock);
}

static bool 
syscall_chdir (const char *dir) 
{
  return false;
}

static bool syscall_mkdir (const char *dir)
{
  return false;
}

static bool syscall_readdir (int fd, char *name)
{
  return false;
}

static bool syscall_isdir (int fd)
{
  struct file_descriptor *fd_struct = find_opened_file (thread_current(), fd);
  if (fd_struct != NULL)
    return false;
  return inode_isdir (file_get_inode (fd_struct->file));
}

static int syscall_inumber (int fd)
{ 
  int inumber = -1;
  struct file_descriptor *fd_struct = find_opened_file (thread_current(), fd);
  lock_acquire (&fs_lock);
  if (fd_struct != NULL)
    inumber = inode_get_inumber (file_get_inode (fd_struct->file));
  lock_release (&fs_lock);
  return inumber;
}
/* Helper functions */
static bool
check_valid_pointer (void *ptr, uint8_t argc)
{
  struct thread *cur = thread_current ();
  uint32_t *iter = ptr;
  for (uint8_t i = 0; i < argc; i++, iter++)
    {
      /* Check if ptr is in user virtual address */
      if (!is_user_vaddr (iter))
        return false;
      /* Check if ptr is allocated within the current thread's pages */      
      if (pagedir_get_page (cur->pagedir, iter) == NULL)
        return false;        
    }
  return true;
}

/* Check validation of a string, ensure every char of string is in user addr */
static bool
check_valid_string (char *str)
{
  if (str == NULL)
    return false;
  
  for (char *s = str; ; s++)
    {
      if (!check_valid_pointer (s, 1))
        return false;
      if (*s == '\0')
        return true;
    }
  return false;
}

/* Search file in fd_list by fd number, return its file descriptor */
static struct file_descriptor*
find_opened_file (struct thread *t, int fd)
{
  struct list_elem *e = NULL;
  struct list *l = &t->fd_list;
  struct file_descriptor *fd_struct = NULL;
  for (e = list_begin (l); e != list_end (l); e = list_next (e))
    {
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->fd == fd)
        return fd_struct;
    }
  return NULL;
}