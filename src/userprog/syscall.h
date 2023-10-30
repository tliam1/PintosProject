#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"

void syscall_init (void);
void syscall_halt(void);
void syscall_exit(int);
int syscall_exec(const char *cmd_line);
int syscall_wait(int pid);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_open(char * file);
int syscall_filesize(int fd_num);
int syscall_read(int fd, void * buffer, unsigned size);
int syscall_write(int fd, void *buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);
void close_extra_files(int fd_num);
void close_thread_files(tid_t tid);
#endif /* userprog/syscall.h */
