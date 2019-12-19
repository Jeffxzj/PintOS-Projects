#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_NUM 123
#define INDIRECT_BLOCK_NUM 128
#define DB_INDIRECT_BLOCK_NUM 16384  // 128 * 128

#define MIN(x, y) ((x) < (y) ? (x) : (y))

static const char ZEROS[BLOCK_SECTOR_SIZE];

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. 
   1 indirect block and 1 double indirect block. */
struct inode_disk
  {
    //block_sector_t start;             /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    //uint32_t unused[125];               /* Not used. */
    
    bool is_dir;
    block_sector_t indirect_idx;
    block_sector_t db_indirect_idx;
    block_sector_t direct_blocks[DIRECT_BLOCK_NUM];
  };

static bool alloc_block_space (size_t sectors, struct inode_disk *disk_inode);
static bool extend_inode_level(size_t sectors, 
                               struct inode_disk *disk_inode, int level);
static void free_all_levels (const struct inode *inode);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */

    struct lock extend_lock;            /* Lock to protect inode extension */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    {
      block_sector_t indirect_blocks[INDIRECT_BLOCK_NUM];
      block_sector_t db_indirect_blocks[INDIRECT_BLOCK_NUM];

      const struct inode_disk *disk_inode = &(inode->data);
      block_sector_t sector_idx = pos / BLOCK_SECTOR_SIZE;
      if (sector_idx < DIRECT_BLOCK_NUM)
        return disk_inode->direct_blocks[sector_idx];
      
      sector_idx -= DIRECT_BLOCK_NUM;
      if (sector_idx < INDIRECT_BLOCK_NUM)
        {
          cache_read (disk_inode->indirect_idx, indirect_blocks);
          //block_read (fs_device, disk_inode->indirect_idx, indirect_blocks);
          return indirect_blocks[sector_idx];
        }
      
      sector_idx -= INDIRECT_BLOCK_NUM;
      if (sector_idx < DB_INDIRECT_BLOCK_NUM)
        {
          int l2 = sector_idx / INDIRECT_BLOCK_NUM;
          int l3 = sector_idx % INDIRECT_BLOCK_NUM;
          cache_read (disk_inode->db_indirect_idx, indirect_blocks);
          cache_read (indirect_blocks[l2], db_indirect_blocks);
          //block_read (fs_device, disk_inode->db_indirect_idx, indirect_blocks);
          //block_read (fs_device, indirect_blocks[l2], db_indirect_blocks);
          return db_indirect_blocks[l3];
        }
      sector_idx -= DB_INDIRECT_BLOCK_NUM;
      return -1;
    }
    //return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);
  
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return success;
  
  size_t sectors = bytes_to_sectors (length);
  disk_inode->length = length;
  disk_inode->magic = INODE_MAGIC;
  if (alloc_block_space (sectors, disk_inode))
  {
    //block_write (fs_device, sector, disk_inode);
    cache_write (sector, disk_inode);
    //disk_inode->length = length;
    success = true;
  }
  free (disk_inode);
  /*
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      if (free_map_allocate (sectors, &disk_inode->start)) 
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->start + i, zeros);
            }
          success = true; 
        } 
      free (disk_inode);
    }
  */
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (inode->sector, &inode->data);
  //block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          free_all_levels (inode);
          //free_inode (inode);
          /*
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); 
          */
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          //block_read (fs_device, sector_idx, buffer + bytes_read);
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          //block_read (fs_device, sector_idx, bounce);
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  struct inode_disk *disk_inode = &inode->data;

  if (inode->deny_write_cnt)
    return 0;
  
  /* EOF is reached, need file extension. */
  if (offset + size > disk_inode->length)
    {
      size_t sectors = bytes_to_sectors (offset + size);
      if (!alloc_block_space (sectors, disk_inode))
        return 0;
      disk_inode->length = offset + size;
      //block_write (fs_device, inode->sector, disk_inode);
      cache_write (inode->sector, disk_inode);
    }
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          //block_write (fs_device, sector_idx, buffer + bytes_written);
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            //block_read (fs_device, sector_idx, bounce);
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          //block_write (fs_device, sector_idx, bounce);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool
inode_isdir (const struct inode *inode)
{
  return inode->data.is_dir;
}

static bool 
alloc_block_space (size_t sectors, struct inode_disk *disk_inode)
{
  bool success = false;
  size_t total_sectors = sectors;   /* Total number of sectors to allocate */
  size_t level_sectors = MIN (total_sectors, DIRECT_BLOCK_NUM);
  success = extend_inode_level (level_sectors, disk_inode, 1);
  if (!success || total_sectors <= DIRECT_BLOCK_NUM)
    return success;

  /* First level is full, extend space to second level. */
  total_sectors -= DIRECT_BLOCK_NUM;
  level_sectors = MIN (total_sectors, INDIRECT_BLOCK_NUM);
  success = extend_inode_level (level_sectors, disk_inode, 2);
  if (!success || total_sectors <= INDIRECT_BLOCK_NUM)
    return success;

  /* Second level is full, extend space to the third level. */
  total_sectors -= INDIRECT_BLOCK_NUM;
  level_sectors = MIN (total_sectors, DB_INDIRECT_BLOCK_NUM);
  success = extend_inode_level (level_sectors, disk_inode, 3);
  if (!success || total_sectors <= DB_INDIRECT_BLOCK_NUM)
    return success;

  printf("block allocation failed, space requested too large\n");
  return success;
}

static bool
extend_inode_level (size_t sectors, struct inode_disk *disk_inode, int level)
{
  /* For all cases, break if total_sectors is 0, which means all sectors of
     the file have been allocated */
  size_t total_sectors = sectors; 
  switch (level)
    {
    case 1:
      {
        for (size_t i = 0; i < DIRECT_BLOCK_NUM; i++)
          {
            if (total_sectors == 0) 
              break;
            if (disk_inode->direct_blocks[i] != 0)
              continue;
            if (!free_map_allocate (1, &disk_inode->direct_blocks[i]))
              return false;
            //block_write (fs_device, disk_inode->direct_blocks[i], ZEROS);
            cache_write (disk_inode->direct_blocks[i], ZEROS);
            total_sectors--;
          }
        break;
      }
    case 2:
      {
        block_sector_t indirect_blocks[INDIRECT_BLOCK_NUM];
        /* If the it is the first time to extend level 2 block. */
        if (disk_inode->indirect_idx == 0)
          {
            if (!free_map_allocate (1, &disk_inode->indirect_idx))
              return false;
            //block_write (fs_device, disk_inode->indirect_idx, ZEROS);
            cache_write (disk_inode->indirect_idx, ZEROS);
          }
        //block_read (fs_device, disk_inode->indirect_idx, indirect_blocks);
        cache_read (disk_inode->indirect_idx, indirect_blocks);        
        
        for (size_t i = 0; i < INDIRECT_BLOCK_NUM; i++)
          {
            if (total_sectors == 0)
              break;
            if (indirect_blocks[i] != 0)
              continue;
            if (!free_map_allocate (1, &indirect_blocks[i]))
              return false;
            //block_write (fs_device, indirect_blocks[i], ZEROS);
            cache_write (indirect_blocks[i], ZEROS);
            total_sectors--;
          }
        //block_write (fs_device, disk_inode->indirect_idx, indirect_blocks);
        cache_write (disk_inode->indirect_idx, indirect_blocks);
        break;
      }
    case 3:
      {
        block_sector_t indirect_blocks[INDIRECT_BLOCK_NUM];
        block_sector_t db_indirect_blocks[INDIRECT_BLOCK_NUM];
        if (disk_inode->db_indirect_idx == 0)
          {
            if (!free_map_allocate (1, &disk_inode->db_indirect_idx))
              return false;
            //block_write (fs_device, disk_inode->db_indirect_idx, ZEROS);
            cache_write (disk_inode->db_indirect_idx, ZEROS);
          }
        //block_read (fs_device, disk_inode->db_indirect_idx, indirect_blocks);
        cache_read (disk_inode->db_indirect_idx, indirect_blocks);
        for (size_t i = 0; i < INDIRECT_BLOCK_NUM; i++)
          {
            if (total_sectors == 0)
              break;
            if (indirect_blocks[i] == 0)
              {
                if (!free_map_allocate (1, &indirect_blocks[i]))
                  return false;
                //block_write (fs_device, indirect_blocks[i], ZEROS);
                cache_write (indirect_blocks[i], ZEROS);
              }
            //block_read (fs_device, indirect_blocks[i], db_indirect_blocks);
            cache_read (indirect_blocks[i], db_indirect_blocks);
            for (size_t j = 0; j < INDIRECT_BLOCK_NUM; j++)
              {
                if (total_sectors == 0)
                  break;
                if (db_indirect_blocks[j] == 0)
                  {
                    if (!free_map_allocate (1, &db_indirect_blocks[i]))
                      return false;
                    //block_write (fs_device, db_indirect_blocks[i], ZEROS);
                    cache_write (db_indirect_blocks[i], ZEROS);
                    total_sectors--;
                  }
              }
            //block_write (fs_device, indirect_blocks[i], db_indirect_blocks);
            cache_write (indirect_blocks[i], db_indirect_blocks);
          }
        //block_write (fs_device, disk_inode->db_indirect_idx, indirect_blocks);
        cache_write (disk_inode->db_indirect_idx, indirect_blocks);
        break;
      }
    default:
      break;
    }
  return true;
}

static void
free_all_levels (const struct inode *inode)
{
  const struct inode_disk *disk_inode = &(inode->data);
  size_t total_sectors = (size_t) bytes_to_sectors(disk_inode->length);
  size_t level_sectors = MIN (total_sectors, DIRECT_BLOCK_NUM);
  for (size_t i = 0; i < level_sectors; i++) 
    free_map_release (disk_inode->direct_blocks[i], 1);
  if (total_sectors <= DIRECT_BLOCK_NUM)
    return;

  block_sector_t indirect_blocks[INDIRECT_BLOCK_NUM];
  total_sectors -= DIRECT_BLOCK_NUM;
  level_sectors = MIN (total_sectors, INDIRECT_BLOCK_NUM);
  //block_read (fs_device, disk_inode->indirect_idx, indirect_blocks);
  cache_read (disk_inode->indirect_idx, indirect_blocks);
  for (size_t i = 0; i < level_sectors; i++)
    free_map_release (indirect_blocks[i], 1);
  if (total_sectors <= INDIRECT_BLOCK_NUM)
    return;
  
  block_sector_t db_indirect_blocks[INDIRECT_BLOCK_NUM];
  total_sectors -= INDIRECT_BLOCK_NUM;
  level_sectors = MIN (total_sectors, DB_INDIRECT_BLOCK_NUM);
  //block_read (fs_device, disk_inode->db_indirect_idx, indirect_blocks);
  cache_read (disk_inode->db_indirect_idx, indirect_blocks);
  for (size_t i = 0; i < INDIRECT_BLOCK_NUM; i++)
    {
      if (indirect_blocks[i] == 0)
        break;
      //block_read (fs_device, indirect_blocks[i], db_indirect_blocks);
      cache_read (indirect_blocks[i], db_indirect_blocks);
      for (size_t j = 0; j < INDIRECT_BLOCK_NUM; j++)
        {
          if (db_indirect_blocks[j] == 0)
            break;
          free_map_release (db_indirect_blocks[j], 1);
        }
    }
  return;
}