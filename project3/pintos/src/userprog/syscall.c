#include "userprog/syscall.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <hash.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "pagedir.h"
#include "devices/input.h"
#include "vm/page.h"
void verify(const void *vaddr);
static void syscall_handler (struct intr_frame *);
void exit(int status);
int write (int fd, const void *buffer, unsigned size);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
void close (int fd);
int read (int fd, void *buffer, unsigned size);
int filesize (int fd);
tid_t exec (const char *cmd_line);
bool remove (const char *file);
void seek (int fd, unsigned position);
unsigned tell (int fd);
int wait (tid_t tid);
int mmap (int fd, uint8_t *addr);
void munmap (int mapping);
void
syscall_init (void)
{
  sema_init (&load_S, 1);
  lock_init (&syscall_S);
  good_child = true;
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  verify(f->esp);
    struct thread *cur = thread_current ();
    uint32_t *pd;
    pd = cur->pagedir;
  if(pagedir_get_page(pd, pg_round_down(f->esp)) == NULL) exit(-1);
  if ((int)*(uint32_t *)f->esp == SYS_HALT)
      shutdown_power_off();
  else if((int)*(uint32_t *)f->esp == SYS_EXIT) {
      verify(f->esp + 4);
      exit((int)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_WRITE) {
      verify(f->esp + 20);
      verify(f->esp + 24);
      verify(f->esp + 28);
      f->eax = write((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28));
  }
  else if((int)*(uint32_t *)f->esp == SYS_CREATE){
      verify(f->esp + 16);
      verify(f->esp + 20);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 16),(unsigned)*(uint32_t *)(f->esp + 20));
  }
  else if((int)*(uint32_t *)f->esp == SYS_OPEN) {
      verify(f->esp + 4);
      f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_CLOSE) {
      verify(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_READ) {
      verify(f->esp + 20);
      verify(f->esp + 24);
      verify(f->esp + 28);
      f->eax = read((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28));
  }
  else if((int)*(uint32_t *)f->esp == SYS_FILESIZE) {
      verify(f->esp + 4);
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_EXEC) {
      verify(f->esp + 4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_REMOVE) {
      verify(f->esp + 4);
      f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_SEEK){
      verify(f->esp + 16);
      verify(f->esp + 20);
      seek((int)*(uint32_t *)(f->esp + 16),(unsigned)*(uint32_t *)(f->esp + 20));
  }
  else if((int)*(uint32_t *)f->esp == SYS_TELL) {
      verify(f->esp + 4);
      f->eax = tell((int)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_WAIT) {
      verify(f->esp + 4);
      f->eax = wait((tid_t)*(uint32_t *)(f->esp + 4));
  }
  else if((int)*(uint32_t *)f->esp == SYS_MMAP){
      verify(f->esp + 16);
      f->eax = mmap((int)*(uint32_t *)(f->esp + 16),(uint8_t *)*(uint32_t *)(f->esp + 20));
  }
  else if((int)*(uint32_t *)f->esp == SYS_MUNMAP) {
      verify(f->esp + 4);
      munmap((int)*(uint32_t *)(f->esp + 4));
  }
  else exit(-1);
}
void verify(const void * vaddr){
    if(is_user_vaddr(vaddr) == 0){
        exit(-1);
    }
}
void exit(int status){
    struct thread *cur = thread_current ();
    int i;
    for(i=0;i<128;i++){
        if((cur->fd_list)[i]){
            struct file * file = (cur->fd_list)[i];
            if(file) file_close(file);
        }
    }
    char *save_ptr;
    printf ("%s: exit(%d)\n", strtok_r (cur->name, " ", &save_ptr), status);
    cur->exit_status = status;
    thread_exit ();
}
int write (int fd, const void *buffer, unsigned size){
    verify(buffer);
    if(fd == 1){
        putbuf(buffer, size);
        return size;
    }
    else if(fd < 2 || fd>128){
        return -1;
    }
    else{
        struct thread *cur = thread_current ();
        struct file * file = (cur->fd_list)[fd-2];
        if(file == 0) return -1;
        lock_acquire(&syscall_S);
        int ret = file_write(file, buffer, size);
        lock_release(&syscall_S);
        return ret;
    }
    return 0;
}
bool create (const char *file, unsigned initial_size){
    verify(file);
    if(file == NULL || strlen(file) == 0){
        exit(-1);
    }
    bool ret = filesys_create(file, initial_size);
    return ret;
}
int open (const char *file){
    verify(file);
    if(file == NULL){
        return -1;
    }
    lock_acquire(&syscall_S);
    struct file * opened_file = filesys_open(file);
    if(opened_file== NULL) { lock_release(&syscall_S); return -1;}
    struct thread *cur = thread_current ();
    int ret = 0;
    while((cur->fd_list)[ret] != 0){
        ret++;
        if (ret == 126){
            ret = -1;
            break;
        }
    }
    if(ret == -1){
        lock_release(&syscall_S);
        file_close(opened_file);
        return -1;
    }
    char *save_ptr;
    if(!strcmp(file, strtok_r (cur->name, " ", &save_ptr))) {
        file_deny_write(opened_file);}
    (cur->fd_list)[ret] = opened_file;
    lock_release(&syscall_S);
    return ret + 2;
}
void close (int fd){
    if(fd<2 || fd>128){
        exit(-1);
    }
    struct thread *cur = thread_current ();
    struct file * close_file = cur->fd_list[fd-2];
    if(close_file != NULL) {
        file_close(close_file);
        cur->fd_list[fd-2] = 0;
    }
}
int read (int fd, void *buffer, unsigned size){
    verify(buffer);
    if(fd == 0){
        return input_getc();
    }
    else if(fd < 2 || fd>128){
        return -1;
    }
    else{
        struct thread *cur = thread_current ();
        struct file * file = (cur->fd_list)[fd-2];
        if(file == 0) return -1;
        lock_acquire(&syscall_S);
        int ret = file_read(file, buffer, size);
        lock_release(&syscall_S);
        return ret;
    }
}
int filesize (int fd){
    struct thread *cur = thread_current ();
    struct file * file = (cur->fd_list)[fd-2];
    if(file == 0) return -1;
    return file_length(file);
}
tid_t exec (const char *cmd_line){
    verify(cmd_line);
    lock_acquire(&syscall_S);
    bool flag = false;
    char *save_ptr;
    char fn_copy[128];
    strlcpy (fn_copy, cmd_line, strlen(cmd_line) + 1);
    if(filesys_open(strtok_r (fn_copy, " ", &save_ptr)) == NULL) {lock_release(&syscall_S); return -1;}
    tid_t ret = process_execute(cmd_line);
    sema_down(&load_S);
    if(!good_child){
        good_child = true;
        flag = true;
    }
    sema_up(&load_S);
    lock_release(&syscall_S);
    if(flag) return -1;
    return ret;
}
bool remove (const char *file){
    verify(file);
    bool ret = filesys_remove(file);
    return ret;
}
void seek (int fd, unsigned position){
    struct thread *cur = thread_current ();
    struct file * file = (cur->fd_list)[fd-2];
    if(file == 0) exit(-1);
    file_seek(file, position);
}

unsigned tell (int fd){
    struct thread *cur = thread_current ();
    struct file * file = (cur->fd_list)[fd-2];
    if(file == 0) exit(-1);
    return file_tell(file);
}
int wait (tid_t tid){
    tid_t ret =  process_wait(tid);
    return ret;
}
int mmap (int fd, uint8_t *addr){
    struct thread *t = thread_current ();
     uint32_t *pd;
     pd = t->pagedir;
    struct file * file;
    struct page *page = malloc(sizeof(struct page));
    page->upage = addr;
    struct hash_elem *file_page_elem = hash_find(&(t->page_hash), &(page->page_elem));
    free(page);
    if(fd < 2 || fd>128||pg_round_down(addr)!=addr||addr==0||file_page_elem != NULL||is_user_vaddr(addr) == 0||pagedir_get_page(pd, addr)!=NULL){
        return -1;
    }
    if((t->fd_list)[fd-2]) file = file_reopen((t->fd_list)[fd-2]);
    if(file == NULL || file_length(file)==0) return -1;
    int ofs = 0;
    struct mmap_elem *mmap_E = malloc(sizeof(struct mmap_elem));
    mmap_E -> file = file;
    mmap_E -> upage = addr;
    int i;
    int ret;
    for(i=0;i<128;i++){
        if((t->mmap_list)[i]==0){
            ret = i;
            t->mmap_list[i] = mmap_E;
            break;
        }
    }
    int read_bytes = file_length(file);
    while (read_bytes > 0)
      {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
        struct page *page = malloc(sizeof(struct page));
          page->file = file;
          page->ofs = ofs;
          page->read_bytes = page_read_bytes;
          page->zero_bytes = page_zero_bytes;
          page->writable = 1;
          page->upage = addr;
          hash_insert(&(t->page_hash), &(page->page_elem));
        read_bytes -= page_read_bytes;
        addr += PGSIZE;
        ofs += page_read_bytes;
      }
    return ret;
}
void munmap (int mapping){
    struct thread *t = thread_current ();
    struct mmap_elem *mmap_E = t->mmap_list[mapping];
    if(!mmap_E) return;
    struct page *page = malloc(sizeof(struct page));
    page->upage = mmap_E->upage;
    while(1){
        struct hash_elem *file_page_elem = hash_find(&(t->page_hash), &(page->page_elem));
        if(file_page_elem == NULL) break;
        struct page *file_page = hash_entry(file_page_elem, struct page, page_elem);
        if(pagedir_is_dirty(t->pagedir, file_page->upage)){
            file_write_at(file_page->file, file_page->upage, file_page->read_bytes, file_page->ofs);
        }
        page->upage += PGSIZE;
    }
    file_close(mmap_E->file);
    free(t->mmap_list[mapping]);
    t->mmap_list[mapping] = 0;
    return ;
}
