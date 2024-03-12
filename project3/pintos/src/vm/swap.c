#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "devices/block.h"
#include "vm/swap.h"
void swap_init(){
    device = block_get_role(BLOCK_SWAP);
    bmap = bitmap_create(block_size(device)/8);
    bitmap_set_all(bmap, 1);
    lock_init (&swap_S);
}
