#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Helper functions for supporting sub-directories. */
static char *get_filename (const char *pathname);
static struct dir *get_directory (const char *pathname);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *pathname, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  //char *filename = get_filename (pathname);
  struct dir *dir = dir_open_root ();
  //struct dir *dir = get_directory (pathname);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, pathname, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *pathname)
{
  struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, pathname, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *pathname) 
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, pathname);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

static char *
get_filename (const char *pathname)
{
  size_t path_size = strlen (pathname) + 1;
  char s[path_size];                       /* String to tokenize */
  strlcpy (s, pathname, path_size);
  /* Standard usage of strtok(). 
     Save the last token which represents the filename. */    
  char *token, *save_ptr;
  char *file_token = NULL;
  for (token = strtok_r (s, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
    file_token = token;
  char *filename = malloc (strlen (file_token) + 1);
  strlcpy (filename, file_token, strlen (file_token) + 1);
  return filename;
}

/*
static struct dir *
get_directory (const char *pathname)
{
  size_t path_size = strlen (pathname) + 1;
  char s[path_size];
  strlcpy (s, pathname, path_size);
  struct dir *dir = NULL;
  bool is_absolute = s[0] == '/';
  if (is_absolute)
    dir = dir_reopen(thread_current()->cur_dir);

  char *token, *save_ptr;
  char *file_token = NULL;
  for (token = strtok_r (s, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
    {
      if (strcmp (token, "..") == 0)
        {
        }
    }
}
*/
