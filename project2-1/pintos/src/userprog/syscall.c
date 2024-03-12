#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "pagedir.h"
void verify(const void *vaddr);
static void syscall_handler (struct intr_frame *);
void exit(int status);
int write (int fd, const void *buffer, unsigned size);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
void close (int fd);
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  verify(f->esp);
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
      write((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28));
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
  else exit(-1);
}
void verify(const void * vaddr){
    struct thread *cur = thread_current ();
    uint32_t *pd;
    pd = cur->pagedir;
    if(is_user_vaddr(vaddr) == 0 || pagedir_get_page(pd, vaddr) == NULL){
        exit(-1);
    }
}
void exit(int status){
    struct thread *cur = thread_current ();
    char *save_ptr;
    printf ("%s: exit(%d)\n", strtok_r (cur->name, " ", &save_ptr), status);
    thread_exit ();
}
int write (int fd, const void *buffer, unsigned size){
    if(fd == 1){
        putbuf(buffer, size);
        return size;
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
        exit(-1);
    }
    struct file * opened_file = filesys_open(file);
    if(opened_file== NULL) return -1;
    struct thread *cur = thread_current ();
    int ret = 0;
    while((cur->fd_list)[ret] != NULL){
        ret++;
    }
    (cur->fd_list)[ret] = opened_file;
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
        cur->fd_list[fd-2] = NULL;
    }
}
