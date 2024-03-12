#include "threads/thread.h"
#include <hash.h>
#include "filesys/off_t.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


struct page{
    struct file *file;
    off_t ofs;
    uint8_t *upage;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
    struct hash_elem page_elem;
    int swap_index;
};
struct mmap_elem{
    struct file *file;
    uint8_t *upage;
};

size_t hash_func(struct hash_elem *e, void *aux);
bool hash_less(struct hash_elem *e, struct hash_elem *r, void *aux);
bool page_init(struct hash *h);



