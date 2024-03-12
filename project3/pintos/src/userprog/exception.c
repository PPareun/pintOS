#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include <hash.h>
#include <round.h>
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
    bool not_present;  /* True: not-present page, false: writing r/o page. */
    bool write;        /* True: access was write, false: access was read. */
    bool user;         /* True: access by user, false: access by kernel. */
    void *fault_addr;  /* Fault address. */
    /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
    asm ("movl %%cr2, %0" : "=r" (fault_addr));
    
    
    /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
    intr_enable ();
    
    /* Count page faults. */
    page_fault_cnt++;
    
    /* Determine cause. */
    not_present = (f->error_code & PF_P) == 0;
    write = (f->error_code & PF_W) != 0;
    user = (f->error_code & PF_U) != 0;
    struct thread *t = thread_current ();
    struct page *page = malloc(sizeof(struct page));
    void * new = pg_round_down(fault_addr);
    page->upage = new;
    struct hash_elem *file_page_elem = hash_find(&(t->page_hash), &(page->page_elem));
    free(page);
    if(file_page_elem == NULL) {
        if(fault_addr < f->esp-32 || !is_user_vaddr(new)) {exit(-1);}
        uint8_t *kpage;
        kpage = palloc_get_page (PAL_USER | PAL_ZERO);
        if (kpage != NULL)
        {
            struct thread *t = thread_current ();
            pagedir_set_page (t->pagedir, new, kpage, true);
            return;
        }
    }
    uint8_t *kpage = palloc_get_page (PAL_USER);
    
    if (kpage == NULL) {
        struct list_elem *e;
        e = list_begin (&frame_list);
        struct frame_table *victim = list_entry (e, struct frame_table, frame_elem);
        uint8_t *kpage = victim->kpage;
        int index = bitmap_scan(bmap, 0, 1, 1);
        victim->page->swap_index = index;
        int i;
        bitmap_set(bmap, index, 0);
        lock_acquire(&swap_S);
        for(i=0;i<8;i++){
            block_write(device, index*8 + i, (kpage) + 512*i);
        }
        lock_release(&swap_S);
        victim->page = hash_entry(file_page_elem, struct page, page_elem);
        struct page *file_page = hash_entry(file_page_elem, struct page, page_elem);
        if(file_page -> swap_index > -1){
            lock_acquire(&swap_S);
            int i;
            for(i=0;i<8;i++){
                block_read(device, (file_page->swap_index)*8 + i, kpage + 512*i);
            }
            lock_release(&swap_S);
            bitmap_set(bmap, file_page -> swap_index, 1);
            file_page -> swap_index = -1;
        }
        else{
            file_seek(file_page->file, file_page->ofs);
            if (file_read (file_page->file, kpage, file_page->read_bytes) != (int) file_page->read_bytes)
            {
                palloc_free_page (kpage);
                exit(-1);
            }
            memset (kpage + file_page->read_bytes, 0, file_page->zero_bytes);
        }
        if (!(pagedir_get_page (t->pagedir, file_page->upage) == NULL
                && pagedir_set_page (t->pagedir, file_page->upage, kpage, file_page->writable)))
              {
                  palloc_free_page (kpage);
                  exit(-1);
              }
        return;
    }
  struct page *file_page = hash_entry(file_page_elem, struct page, page_elem);
      file_seek(file_page->file, file_page->ofs);
      if (file_read (file_page->file, kpage, file_page->read_bytes) != (int) file_page->read_bytes)
      {
          palloc_free_page (kpage);
          exit(-1);
      }
      memset (kpage + file_page->read_bytes, 0, file_page->zero_bytes);
    if (!(pagedir_get_page (t->pagedir, file_page->upage) == NULL
          && pagedir_set_page (t->pagedir, file_page->upage, kpage, file_page->writable)))
        {
            palloc_free_page (kpage);
            exit(-1);
        }
    struct frame_table *frame = malloc(sizeof(struct frame_table));
    frame->kpage = kpage;
    frame->LRU_num = true;
    frame->page = file_page;
    list_push_back(&frame_list, &(frame->frame_elem));
 
}

