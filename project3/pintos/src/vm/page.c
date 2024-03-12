#include "threads/thread.h"
#include <hash.h>
#include "filesys/off_t.h"
#include "vm/page.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

size_t hash_func(struct hash_elem *e, void *aux){ return hash_entry(e, struct page, page_elem)->upage;}
bool hash_less(struct hash_elem *e, struct hash_elem *r, void *aux) {return hash_entry(e, struct page, page_elem)->upage < hash_entry(r, struct page, page_elem)->upage;}
bool page_init(struct hash *h) {return hash_init(h, hash_func, hash_less, NULL);}


