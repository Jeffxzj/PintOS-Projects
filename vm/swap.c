#include "swap.h"
#include <debug.h>
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <stdio.h>


const size_t SECTOR_NUM = PGSIZE / BLOCK_SECTOR_SIZE;  /* Sectors per page. */

struct block *swap_block;  /* The block disk for swapping space */

struct bitmap *swap_map;   /* Bitmap to indicate a swap slot is used or not */
															
struct lock swap_lock;     /* Lock to protect the operations on swap_map */

void
swap_table_init (void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    PANIC ("block device cannot be initialized\n");
  
  swap_map = bitmap_create (block_size (swap_block) / SECTOR_NUM);
  if (swap_map == NULL)
    PANIC ("bitmap creation fails\n");
  
  bitmap_set_all (swap_map, false);
  lock_init (&swap_lock);
}

size_t
swap_out (void *frame)
{
  lock_acquire (&swap_lock);
  size_t empty_idx = bitmap_scan_and_flip (swap_map, 0, 1, false);
  lock_release (&swap_lock);
  for (size_t i = 0; i < SECTOR_NUM; i++)
    {
      block_write (swap_block, empty_idx * SECTOR_NUM + i,
                   frame + i * BLOCK_SECTOR_SIZE);
    }
  return empty_idx;
}

void 
swap_in (void *frame, size_t idx)
{
  for (size_t i = 0; i < SECTOR_NUM; i++)
  {
    block_read (swap_block, idx * SECTOR_NUM + i,
                frame + i * BLOCK_SECTOR_SIZE);
  }
  bitmap_flip (swap_map, idx);
}