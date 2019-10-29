#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");

  uint32_t *esp = f->esp;

  BAD_POINTER_EXIT (esp);

  int sys_code = *esp;
  switch (sys_code)
    {
    case SYS_HALT:
      syscall_halt ();
      break;
    
    case SYS_EXIT:
      int status = *(esp + 1);
      syscall_exit (status);
      break;
    
    case SYS_EXEC:
      char *cmd_line = (char *)*(esp + 1);
      f->eax = syscall_exec (cmd_line);
      break;
    
    case SYS_WAIT:
      pid_t pid = *(esp + 1);
      f->eax = syscall_wait (pid);
      break;

    case SYS_CREATE:
      char *file = (char *)*(esp + 1);
      unsigned initial_size = *(esp + 2);
      f->eax = syscall_create (file, initial_size);
      break;
    
    case SYS_REMOVE:
      char *file = (char *)*(esp + 1);
      f->eax = syscall_remove (file);
      break;
    
    case SYS_OPEN:
      char *file = (char *)*(esp + 1);
      f->eax = syscall_open (file);
      break;
    
    case SYS_FILESIZE:
      int fd = *(esp + 1);
      f->eax = syscall_filesize (fd);
      break;
    
    case SYS_READ:
      int fd = *(esp + 1);
      void *buffer = (void *)*(esp + 2);
      unsigned size = *(esp + 3);
      f->eax = syscall_read (fd, buffer, size);
      break;
    
    case SYS_WRITE:
      int fd = *(esp + 1);
      void *buffer = (void *)*(esp + 2);
      unsigned size = *(esp + 3);
      f->eax = syscall_write (fd, buffer, size);
      break;

    case SYS_SEEK:
      int fd = *(esp + 1);
      unsigned position = *(esp + 2);
      syscall_seek (fd, position);
      break;

    case SYS_TELL:
      int fd = *(esp + 1);
      f->eax = syscall_tell (fd);
      break;

    case SYS_CLOSE:
      int fd = *(esp + 1);
      syscall_close (fd);
    
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
  
  thread_exit ();
}

static pid_t
syscall_exec (const char *cmd_line)
{

}

static bool 
syscall_remove (const char *file)
{

}

static int 
syscall_open (const char *file)
{

}

static int 
syscall_filesize (int fd)
{

}

static int 
syscall_read (int fd, void *buffer, unsigned size)
{

}

static int 
syscall_write (int fd, const void *buffer, unsigned size)
{

}

static void 
syscall_seek (int fd, unsigned position)
{

}

static unsigned 
syscall_tell (int fd)
{
  
}

static void 
syscall_close (int fd)
{

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
  if (!check_valid_pointer(ptr))
    syscall_exit(-1);
}