#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "devices/block.h"
struct block *device;
struct bitmap *bmap;
struct lock swap_S;
void swap_init();
