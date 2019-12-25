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
#include "cache.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Helper functions for supporting sub-directories. */
static char *get_filename (const char *pathname);
static struct dir *get_directory (const char *pathname);
struct dir;

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  cache_init ();
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
  flush_cache();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir)
{
  block_sector_t inode_sector = 0;
  char *filename = get_filename (name);
  struct dir *dir = get_directory (name);
  //printf("%s wocaonima\n",filename);
  //printf("%d", dir==NULL);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, filename, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  /* If creation type is a directory */
  if (is_dir && success)
    {
      struct dir *new_dir = dir_open (inode_open (inode_sector));
      block_sector_t parent_sector = inode_get_inumber (dir_get_inode (dir));
      dir_add(new_dir, ".", inode_sector);
      dir_add(new_dir, "..", parent_sector);
      dir_close (new_dir);
    }
  dir_close (dir);
  free (filename);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  if (strcmp (name,"/") == 0)
    return file_open(inode_open(ROOT_DIR_SECTOR));

  char *filename = get_filename (name);
  struct dir *dir = get_directory (name);
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, filename, &inode);
  dir_close (dir);
  free (filename);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char *filename = get_filename (name);
  struct dir *dir = get_directory (name);

  if (!strcmp(filename, ".") || !strcmp(filename, "..")) 
    {
      dir_close(dir);
      free (filename);
      return false;
    }

  bool success = dir != NULL && dir_remove (dir, filename);

  dir_close (dir); 
  free (filename);
  return success;
}

/* Change the current working directory of the process to dir, which may be 
   relative or absolute. Returns true if successful, false on failure. */
bool filesys_chdir (const char *name)
{
  struct thread *cur = thread_current ();

  if (strcmp (name, "/") == 0)
    {
      cur->cur_dir = dir_open_root ();
      return true;
    }
  
  char *dirname = get_filename (name);
  struct dir *dir = get_directory (name);
  
  struct inode *inode = NULL;
  bool success = (dir_lookup (dir, dirname, &inode)
                  && inode_isdir (inode));
  if (success){
    dir_close (cur->cur_dir);
    cur->cur_dir = dir_open (inode);
  }
  dir_close (dir);  
  free (dirname);
  return success;
}

bool 
filesys_readdir (char *name, struct file *file)
{
  bool success = false;
  struct inode *inode = file_get_inode (file);
  if (!inode_isdir (inode))
    return success;
  struct dir *dir = dir_open (inode);

  off_t pos = file_tell(file);
  dir_seek(dir, pos);
  success = dir_readdir (dir, name);
  file_seek(file, dir_tell(dir));
  
  //printf ("name:%d\n",success);
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
  struct dir *root = dir_open_root ();
  dir_add (root, ".", ROOT_DIR_SECTOR);
  dir_add (root, "..", ROOT_DIR_SECTOR);
  dir_close (root);
  free_map_close ();
  printf ("done.\n");
}

/*--------------------------- Parser functions ------------------------------*/
static char *
get_filename (const char *pathname)
{
  size_t path_size = strlen (pathname) + 1;
  char s[path_size];                       /* String to tokenize */
  strlcpy (s, pathname, path_size);
  /* Standard usage of strtok(). 
     Save the last token which represents the filename. */    
  char *token, *save_ptr;
  char *file_token = ""; /* Empty filename if nothing to tokenize */
  for (token = strtok_r (s, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
    file_token = token;
  char *filename = malloc (strlen (file_token) + 1); /* Remember to free it */
  if (filename == NULL)
    return NULL;
  strlcpy (filename, file_token, strlen (file_token) + 1);
  return filename;
}

static struct dir *
get_directory (const char *pathname)
{

  size_t path_size = strlen (pathname) + 1;
  char s[path_size];
  strlcpy (s, pathname, path_size);
  struct dir *dir = NULL;
  struct thread *cur = thread_current ();

  bool is_absolute = (s[0] == '/');
  if (is_absolute || !cur->cur_dir){
    //printf("root\n");
    dir = dir_open_root ();
    if (strcmp (s, "/") == 0)
      return dir;
    //printf("%d", dir==NULL); 
  }
  else
    dir = dir_open_cur ();
  char *token, *save_ptr;
  /* Extract the first token to ensure that file name will not be looked up
     if it is firstly created. */
  char *prev_token = strtok_r (s, "/", &save_ptr);
  for (token = strtok_r (NULL, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
    {
      struct inode *inode = NULL;
      if (dir_lookup (dir, prev_token, &inode) == false)
        {
          dir_close (dir);
          return NULL;
        }
      prev_token = token;
      /* Continue if inode is a file type */
      if (inode_isdir (inode) == false)
        continue;
      dir_close (dir);
      dir = dir_open (inode);
    }
  return dir;
}