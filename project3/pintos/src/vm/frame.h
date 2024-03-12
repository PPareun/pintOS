#include "threads/thread.h"
#include "vm/page.h"
#include <list.h>
struct frame_table{
    struct list_elem frame_elem;
    bool LRU_num;
    uint8_t *kpage;
    struct page *page;
};
struct list frame_list;
