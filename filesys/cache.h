#include "../devices/block.h"
#include <stdbool.h>
#include "../threads/synch.h"

#define cache_size 64
#define FLUSH_FREQU 2 * TIMER_FREQ

struct cache_ele
{
  block_sector_t sector_idx;
  bool dirty;
  bool valid;
  bool visited;
  struct lock cache_lock;
  uint8_t data[BLOCK_SECTOR_SIZE];
};

struct cache_ele cache_array[cache_size];

void cache_init(void);
void flush_cache(void);

void cache_write (block_sector_t sector_idx, const void *buffer);
void cache_read (block_sector_t sector_idx, void *buffer);
void cache_read_ahead (block_sector_t sector_idx);