#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
bool good_child;
void syscall_init (void);
struct lock syscall_S;
struct semaphore load_S;
struct semaphore start_S;
#endif /* userprog/syscall.h */
