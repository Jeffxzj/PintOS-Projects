#include "cache.h"
#include "filesys.h"
#include <string.h>
#include "../threads/malloc.h"
#include "../devices/timer.h"
#include "../threads/thread.h"

void read_ahead_func (void *next_sector);
static void write_behind_func (void *aux UNUSED);

static struct cache_ele* cache_evict (void);

/* Set every cache_entry's valid bit to false and init lock */
void cache_init(void)
{
  for (int i = 0; i < cache_size; i++)
    {
      cache_array[i].valid = false;
      lock_init(&cache_array[i].cache_lock);
    }
  thread_create ("write_behind", PRI_DEFAULT, write_behind_func, NULL);
}

/* Find correspond cache entry given sector index */
static struct cache_ele* cache_find (block_sector_t sector)
{
  for (int i = 0; i < cache_size; i++)
    {
      lock_acquire (&cache_array[i].cache_lock);

      if (cache_array[i].sector_idx == sector && cache_array[i].valid)
        {
          lock_release (&cache_array[i].cache_lock);
          return &cache_array[i];
        }

      lock_release (&cache_array[i].cache_lock);
    }
  /* Not found, return NULL */
  return NULL;
}

/* Get a cache entry */
static struct cache_ele* cache_get_entry (void)
{
  /* Iterate the array to find an unused entry */
  for (int i = 0; i < cache_size; i++)
  {
    lock_acquire (&cache_array[i].cache_lock);

    if (!cache_array[i].valid)
      {
        cache_array[i].valid = true;
        lock_release (&cache_array[i].cache_lock);
        return &cache_array[i];
      }

    lock_release (&cache_array[i].cache_lock);  
  }

  /* If all used, evict one */
  return cache_evict();
}

/* Evict a cache entry */
static struct cache_ele* cache_evict (void)
{
  int index = 0;
  /* Iterate */
  while (true)
    {
      struct cache_ele* cur = &cache_array[index];
      lock_acquire (&cur->cache_lock);
      /* If this entry has been visited recently, 
         set it to false in case that no entry will be evicted */
      if (cur->visited)
        cur->visited = false;
      
      /* If this entry has not been visited recently,
         evict it! */
      else
        {
          /* If it is dirty, write back */
          if (cur->dirty)
            {
              block_write (fs_device, cur->sector_idx, cur->data);
              cur->dirty = false;
            }
          cur -> valid = true;
          lock_release (&cur->cache_lock);
          return cur;
        }
      lock_release (&cur->cache_lock);

      index++;
      if (index == cache_size)
        index = 0;
    }
}

/* Read block data into buffer */ 
void cache_read (block_sector_t sector_idx, void *buffer)
{
  struct cache_ele* cur = cache_find (sector_idx);

  /* If found in cache, read data into buffer directly */
  if (cur != NULL)
    {
      lock_acquire (&cur->cache_lock);
      memcpy (buffer, cur->data, BLOCK_SECTOR_SIZE);
    }
  /* Not found, get an entry, read data from block into buffer and cache */
  else 
    {
      cur = cache_get_entry ();
      lock_acquire (&cur->cache_lock);
      block_read (fs_device, sector_idx, cur->data);
      memcpy (buffer, cur->data, BLOCK_SECTOR_SIZE);
    }

    cur->visited = true;
    cur->sector_idx = sector_idx; 
    lock_release (&cur->cache_lock); 
}

void cache_write (block_sector_t sector_idx, const void *buffer)
{
  struct cache_ele* cur = cache_find (sector_idx);
  /* If not found, get a new entry */
  if (cur == NULL)
    cur = cache_get_entry ();
  lock_acquire (&cur->cache_lock);
  /* Write data into cache instead of writing to block */
  memcpy (cur->data, buffer, BLOCK_SECTOR_SIZE);

  cur->sector_idx = sector_idx;
  cur->visited = true;
  cur->dirty = true;
  lock_release (&cur->cache_lock);
}

/* Used for flushing dirty cache into block periodically */
void flush_cache (void)
{
  for (int i = 0; i < cache_size; i++)
    {
      struct cache_ele* cur = &cache_array[i];
      lock_acquire (&cur->cache_lock);
      if (cur->valid && cur->dirty)
        {
          block_write (fs_device, cur->sector_idx, cur->data);
          cur->dirty = false;
        }
      lock_release (&cur->cache_lock);
    }
}

/* Flush cache periodically */
static void write_behind_func (void *aux UNUSED)
{
  while (true)
    {
      timer_sleep (FLUSH_FREQU);
      flush_cache ();
    }
}


void cache_read_ahead (block_sector_t sector_idx)
{
  block_sector_t *next_sector = malloc (sizeof (block_sector_t));
  *next_sector = sector_idx + 1;
  thread_create ("read_ahead", PRI_DEFAULT, read_ahead_func, next_sector);
}

void read_ahead_func (void *next_sector)
{
  block_sector_t sector_idx = *(block_sector_t *)next_sector;
  struct cache_ele* found = cache_find (sector_idx);
  if (!found)
    cache_read (sector_idx, NULL);
  
  free(next_sector);
}