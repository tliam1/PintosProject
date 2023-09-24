#include "userprog/syscall.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
//#include "devices/shutdown.h"
//#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
//#include "threads/palloc.h"
//#include "threads/malloc.h"
//#include "threads/interrupt.h"
//#include "threads/thread.h"
//#include "threads/vaddr.h"
//#include "threads/synch.h"
#include "threads/init.h"
//#include "threads/thread.h"
//#include "lib/kernel/list.h"
//#include "lib/user/syscall.h"
static void syscall_handler (struct intr_frame *);
bool is_ptr_valid(const void *user_ptr);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  uint32_t *esp;

  // The system call number is in the 32-bit word at the caller's stack pointer.
  esp = f->esp;

	if(!is_valid_ptr(esp)){
    sys_exit(-1);
  }

	switch(*esp){
		case SYS_HALT:
		{
			printf("SYSCALL: SYS_HALT \n");
			syscall_halt();
			break;
		}
		case SYS_EXIT:
		{
			printf("SYSCALL: SYS_EXIT \n");
      if(!is_valid_ptr((const void *)(esp + 1)))
        sys_exit(-1);
      sys_exit((int)*(esp+1));
      break;
		}
		case SYS_EXEC:
		{
			//break;
		}
		case SYS_WAIT:
		{
			//break;
		}
		case SYS_CREATE:
		{
			//break;
		}
		case SYS_REMOVE:
		{
			//break;
		}
		case SYS_OPEN:
		{
			//break;
		}
		case SYS_FILESIZE:
		{
			//break;
		}
		case SYS_READ:
		{
			//break;
		}
		case SYS_WRITE:
		{
			//break;
		}
		case SYS_SEEK:
		{
			//break;
		}
		case SYS_TELL:
		{
			//break;
		}
		case SYS_CLOSE:
		{
			//break;
		}
		default:
		{
			printf("SYSCALL NOT RECOGNIZED/NOT CREATED YET\n");
			sys_exit(-1);
    	break;
		}
	}
  //thread_exit (); reserved for exit sys calls only now?
}

/*Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h). This should be seldom used, because you lose some information about possible deadlock situations, etc.*/
void syscall_halt(){
	shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
void syscall_exit(int exit_num){
	 if(exit_num != 0){
	 	printf("SYS_EXIT: ERROR \n");
	 }
	 else{
	 	printf("SYS_EXIT: SUCCESS \n");
	 }
	 thread_exit ();
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.
*/
pid_t syscall_exec(const char *cmd_line){

}

/*Waits for a child process pid and retrieves the child's exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.

Longer description on the stanford site
*/ 

int syscall_wait(pid_t pid){

}

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. Creating a new file does not open it: opening the new file is a separate operation which would require a open system call. */

bool syscall_create(const char *file, unsigned initial_size){

}

/*Deletes the file called file. Returns true if successful, false otherwise. A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.*/
bool syscall_remove(const char *file){

}

/*Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.*/

int syscall_open(char * file){

}

/* Returns the size, in bytes, of the file open as fd. */
int syscall_filesize(int fd){

}

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). */ 
int syscall_read(int fd, void * buffer, unsigned size){

}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts. */
int syscall_write(int fd, void *buffer, unsigned size){

}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. A later write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) These semantics are implemented in the file system and do not require any special effort in system call implementation. */ 
void syscall_seek(int fd, unsigned position){

}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
unsigned syscall_tell(int fd){

}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */ 
void syscall_close(int fd){

}


// simple check to see if the pointer is safe to use
// probably needs more later, but good for now
bool is_ptr_valid(const void *user_ptr)
{
  if(user_ptr == NULL){
    printf("Pointer is INVALID\n");
		return false;
  }
  return true;
}
