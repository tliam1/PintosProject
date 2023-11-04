#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "lib/user/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
static void syscall_handler (struct intr_frame *);
bool is_valid_ptr(const void *user_ptr);
struct lock filesys_lock;
struct file_descriptor{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};
struct file_descriptor * retrieve_file(int fd);



void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");
  uint32_t *esp;

  // The system call number is in the 32-bit word at the caller's stack pointer.
  esp = f->esp;

	if(!is_valid_ptr(esp)){
    syscall_exit(-1);
  }

	switch(*esp){
		case SYS_HALT:
		{
			//printf("SYSCALL: SYS_HALT \n");
			syscall_halt();
			break;
		}
		case SYS_EXIT:
		{
			//printf("SYSCALL: SYS_EXIT \n");
      if(!is_valid_ptr((const void *)(esp + 1)))
        syscall_exit(-1);
      syscall_exit((int)*(esp+1));
      break;
		}
		case SYS_EXEC:
		{
			// Validate the pointer to the first argument on the stack
      if(!is_valid_ptr((void*)(esp + 1)))
      	syscall_exit(-1);
      	
       // Validate the buffer that the first argument is pointing to, this is a pointer to the command line args
      // that include the filename and additional arguments for process execute
      if(!is_valid_ptr((void *)*(esp + 1)))
        syscall_exit(-1);

      // pointers are valid, call sys_exec and save result to eax for the interrupt frame
      f->eax = (uint32_t)syscall_exec((const char *)*(esp + 1));
			break;
		}
		case SYS_WAIT:
		{
			if(is_valid_ptr((const void*) (esp+1))){
        f->eax = process_wait(*(esp + 1));
      }else{
        syscall_exit(-1);
      }
      break;
		}
		case SYS_CREATE:
		{
			if(!is_valid_ptr((const void*) (esp+5)))
        syscall_exit(-1);

      if(!is_valid_ptr((const void*) (esp+4)))
        syscall_exit(-1);

      if(!is_valid_ptr((const void*) *(esp+4)))
        syscall_exit(-1);

      //printf("SYSCALL: SYS_CREATE: filename: %s\n", *(esp+4));

      lock_acquire(&filesys_lock);
      f->eax = filesys_create((const char*)*(esp+4), (off_t)*(esp+5));
      lock_release(&filesys_lock);

      break;
		}
		case SYS_REMOVE:
		{
			if(!is_valid_ptr((const void*) (esp+4)))
        syscall_exit(-1);

      if(!is_valid_ptr((const void*) *(esp+4)))
        syscall_exit(-1);

      //printf("SYSCALL: SYS_REMOVE: filename: %s\n", *(esp+1));

      lock_acquire(&filesys_lock);
      f->eax = filesys_remove((const char *)*(esp+1));
      lock_release(&filesys_lock);
      break;
		}
		case SYS_OPEN:
		{
			// Validate the pointer to the first and only argument on the stack
      if(!is_valid_ptr((const void*)(esp + 1)))
        syscall_exit(-1);

      // Validate the dereferenced pointer to the buffer holding the filename
      if(!is_valid_ptr((const void*)*(esp + 1)))
        syscall_exit(-1);

      //printf("SYSCALL: SYS_OPEN: filename: %s\n", *(esp+1));

      // set return value of sys call to the file descriptor
      f->eax = (uint32_t)syscall_open((char *)*(esp + 1));
      break;
		}
		case SYS_FILESIZE:
		{
			if(!is_valid_ptr((const void *)(esp + 1)))
        syscall_exit(-1);

      //printf("SYSCALL: SYS_FILESIZE: fd_num: %d\n", *(esp+1));

      f->eax = syscall_filesize((int)(*(esp+1)));
      break;
		}
		case SYS_READ:
		{
			//printf("READ: starting syswrite with esp = %d\n", *esp);
      if(is_valid_ptr((const void*)(esp+5)) && is_valid_ptr( (const void*) (esp+6)) && is_valid_ptr((const void*)(esp+7)))
      {
        printf("WRITE: size = %d\n", *(esp+7));
        if(is_valid_ptr((const void*)(*(esp+6))) && is_valid_ptr((const void*)((*(esp+6)+*(esp+7)-1))))
          f->eax = (uint32_t) syscall_read((int) *(esp+5), (const void*) *(esp+6),
                                (unsigned) *(esp+7));
        else{
          //printf("READ: Pointer found as invalid 2\n");
          syscall_exit(-1);
        }
      }else{
        //printf("READ: Pointer found as invalid 1\n");
        syscall_exit(-1);
      }
      break;
		}
		case SYS_WRITE:
		{
			//printf("WRITE: starting syswrite with esp = %d\n", *esp);
      if(is_valid_ptr((const void*)(esp+5)) && is_valid_ptr( (const void*) (esp+6)) && is_valid_ptr((const void*)(esp+7)))
      {
        //printf("WRITE: size = %d\n", *(esp+7));
        if(is_valid_ptr((const void*)(*(esp+6))) && is_valid_ptr((const void*)((*(esp+6)+*(esp+7)-1))))
          f->eax = (uint32_t) syscall_write((int) *(esp+5), (const void*) *(esp+6), (unsigned) *(esp+7));
        else{
        	//printf("WRITE: Pointer found as invalid 1\n");
          syscall_exit(-1);
        }
      }else{
        //printf("WRITE: Pointer found as invalid 1\n");
        syscall_exit(-1);
      }
      break;
		}
		case SYS_SEEK:
		{
			if(!is_valid_ptr((const void *)(esp + 4)))
        syscall_exit(-1);

      if(!is_valid_ptr((const void *)(esp + 5)))
        syscall_exit(-1);

      syscall_seek((int)(*(esp+4)), (unsigned)(*(esp+5)));
      break;
		}
		case SYS_TELL:
		{
			if(!is_valid_ptr((const void *)(esp + 1)))
        syscall_exit(-1);

      f->eax = syscall_tell((int)(*(esp + 1)));
      break;
		}
		case SYS_CLOSE:
		{
			if(!is_valid_ptr((const void *)(esp + 1)))
    	  syscall_exit(-1);

    	syscall_close((int)(*(esp+1)));
    	break;
		}
		default:
		{
			//printf("SYSCALL NOT RECOGNIZED/NOT CREATED YET\n");
			syscall_exit(-1);
    	break;
		}
	}
  //thread_exit (); reserved for exit sys calls only now?
}


int syscall_filesize(int fd_num)
{
  struct file_descriptor * file_desc;
  int returnval = -1;

  //printf("sys_filesize: retrieving file descriptor: %d\n", fd_num);

  // using the file filesystem => acquire lock
  lock_acquire(&filesys_lock);

  file_desc = retrieve_file(fd_num);

  if (file_desc != NULL)
  {
    //printf("sys_filesize: retrieved file descriptor: %d\n", file_desc->fd_num);
    returnval = file_length(file_desc->file_struct);
  }
  lock_release(&filesys_lock);
  return returnval;
}


/*Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h). This should be seldom used, because you lose some information about possible deadlock situations, etc.*/
void syscall_halt(){
	shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
void syscall_exit(int exit_num){
	struct child_status *child_status;
  struct thread *curr = thread_current();
  struct thread *parent_thread = thread_get_by_id(curr->parent_tid);

  printf ("%s: exit(%d)\n", curr->name, exit_num);

  if (parent_thread != NULL)
   {
     // iterate through parent's child list to find current thread's entry
     // to update its status
     struct list_elem *elem = list_head(&parent_thread->children);

     //first check the head
     child_status = list_entry(elem, struct child_status, elem_child_status);
     if (child_status->child_tid == curr->tid)
     {
       lock_acquire(&parent_thread->child_lock);
       child_status->exited = true;
       child_status->child_exit_status = exit_num;
       lock_release(&parent_thread->child_lock);
     }

     //and check the whole list too
     while((elem = list_next(elem)) != list_tail(&parent_thread->children))
     {
       child_status = list_entry(elem, struct child_status, elem_child_status);
       if (child_status->child_tid == curr->tid)
       {
         lock_acquire(&parent_thread->child_lock);
         child_status->exited = true;
         child_status->child_exit_status = exit_num;
         lock_release(&parent_thread->child_lock);
       }
     }
   }

  thread_exit();
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.
*/
int syscall_exec(const char *cmdline){
	char * cmdline_cp;
  char * ptr;
  char * file_name;
  struct file * f;
  int thread_id;
  
  //parse file name
  cmdline_cp = malloc(strlen(cmdline)+1);
  strlcpy(cmdline_cp, cmdline, strlen(cmdline)+1);
  file_name = strtok_r(cmdline_cp, " ", &ptr);
  
  
  //run executable (create new process)
   lock_acquire(&filesys_lock);

  // try and open file name
  f = filesys_open(file_name);

  // f will be null if file not found in file system
  if (f == NULL){
    // nothing to do here exec fails, release lock and return -1
    //printf("SYSCALL: sys_exec: filesys_open failed\n");
    lock_release(&filesys_lock);
    return (pid_t)-1;
  } else {
    // file exists, we can close file and call our implemented process_execute() to run the executable
    file_close(f);
    lock_release(&filesys_lock);

    // wait for child process to load successfully, otherwise return -1
    thread_current()->child_load = 0;
    thread_id = process_execute(cmdline);
    lock_acquire(&thread_current()->child_lock);
    //printf("SYSCALL: sys_exec: waiting until child_load != 0\n");
    while(thread_current()->child_load == 0)
      cond_wait(&thread_current()->child_condition, &thread_current()->child_lock);
    //printf("SYSCALL: sys_exec: child_load != 0\n");
    if(thread_current()->child_load == -1) // load failed no process id to return
     {
       thread_id = -1;
       //printf("SYSCALL: sys_exec: child_load failed\n");
     }
    lock_release(&thread_current()->child_lock);
    return thread_id;
  }
}

/*Waits for a child process pid and retrieves the child's exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.

Longer description on the stanford site
*/ 

int syscall_wait(int pid){

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
  // obtain lock for filesystem since we are about to open the file
  lock_acquire(&filesys_lock);

  // open the file
  struct file * new_file_struct = filesys_open(file);

  // file will be null if file not found in file system
  if (new_file_struct==NULL){
    // nothing to do here open fails, return -1
    //printf("sys_open: file not found in filesystem \n");
    lock_release(&filesys_lock);
    return -1;
  }
  // else add file to current threads list of open files
  // from pintos notes section 3.3.4 System calls: when a single file is opened more than once, whether by a single
  // process or different processes each open returns a new file descriptor. Different file descriptors for a single
  // file are closed independently in seperate calls to close and they do not share a file position. We should make a
  // list of files so if a single file is opened more than once we can close it without conflicts.
  struct file_descriptor * new_thread_file = malloc(sizeof(struct file_descriptor));
  new_thread_file->file_struct = new_file_struct;
  new_thread_file->fd_num = thread_current()->next_fd;
  new_thread_file->owner = thread_current()->tid;
  thread_current()->next_fd++;
  list_push_back(&thread_current()->open_files, &new_thread_file->elem);
  //printf("sys_open: file found in filesystem. new file_descriptor number: %d \n", new_thread_file->fd_num);
  lock_release(&filesys_lock);
  return new_thread_file->fd_num;
}


/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). */ 
int syscall_read(int fd, void * buffer, unsigned size){
	struct file_descriptor *fd_struct;
  int bytes_written = 0;

  lock_acquire(&filesys_lock);

  if(fd == STDOUT_FILENO) {
    lock_release(&filesys_lock);
    return -1;
  }

  if(fd == STDIN_FILENO) {
    uint8_t c;
    unsigned counter = size;
    uint8_t *buf = buffer;
    while(counter > 1 && (c = input_getc()) != 0) {
      *buf = c;
      buffer++;
      counter--;
    }
    *buf = 0;
    lock_release(&filesys_lock);
    return (size - counter);
  }

  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL)
    bytes_written = file_read(fd_struct->file_struct, buffer, size);

  lock_release(&filesys_lock);
  return bytes_written;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts. */
int syscall_write(int fd, void *buffer, unsigned size){
  struct file_descriptor *fd_struct;
  int bytes_written = 0;

  lock_acquire(&filesys_lock);

  if(fd == STDIN_FILENO){
    lock_release(&filesys_lock);
    return -1;
  }
  if(fd == STDOUT_FILENO){
    putbuf (buffer, size);
    lock_release(&filesys_lock);
    return size;
  }

  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL){
    bytes_written = file_write(fd_struct->file_struct, buffer, size);
  }

  lock_release(&filesys_lock);
  return bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. A later write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) These semantics are implemented in the file system and do not require any special effort in system call implementation. */ 
void syscall_seek(int fd, unsigned position){
	struct file_descriptor *fd_struct;
  lock_acquire(&filesys_lock);
  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL)
    file_seek(fd_struct->file_struct, position);
  lock_release(&filesys_lock);
  return;
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
unsigned syscall_tell(int fd){
	struct file_descriptor *fd_struct;
  int bytes = 0;
  lock_acquire(&filesys_lock);
  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL)
    bytes = file_tell(fd_struct->file_struct);
  lock_release(&filesys_lock);
  return bytes;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */ 
void syscall_close(int fd){
	struct file_descriptor *fd_struct;
  lock_acquire(&filesys_lock);
  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL && fd_struct->owner == thread_current()->tid)
    close_extra_files(fd);
  lock_release(&filesys_lock);
}


// simple check to see if the pointer is safe to use
// probably needs more later, but good for now
bool is_valid_ptr(const void *user_ptr)
{
  struct thread *curr = thread_current();
  if(user_ptr != NULL && is_user_vaddr(user_ptr))
  {
    return (pagedir_get_page(curr->pagedir, user_ptr)) != NULL;
  }
  if(user_ptr == NULL){
    //printf("Pointer is NULL\n");
  }else{
    //printf("Pointer is not user address space\n");
  }
  return false;
}





struct file_descriptor * retrieve_file(int fd){
  struct list_elem *list_element;
  struct file_descriptor *fd_struct;
  for(list_element = list_head(&thread_current()->open_files); list_element != list_tail(&thread_current()->open_files);
  list_element = list_next(list_element)){
    fd_struct = list_entry (list_element, struct file_descriptor, elem);
    if (fd_struct->fd_num == fd)
      return fd_struct;
  }
  //This is done for the tail
  fd_struct = list_entry (list_element, struct file_descriptor, elem);
  if (fd_struct->fd_num == fd)
    return fd_struct;

  return NULL;
}

void close_extra_files(int fd_num)
{
  struct list_elem *elem;
  struct list_elem *temp;
  struct file_descriptor *file_desc;
  elem = list_head (&(thread_current()->open_files));
  while ((elem = list_next (elem)) != list_tail (&(thread_current()
      ->open_files)))
  {
    temp = list_prev(elem);
    file_desc = list_entry(elem, struct file_descriptor, elem);
    if (file_desc->fd_num == fd_num)
    {
      list_remove(elem);
      file_close(file_desc->file_struct);
      free(file_desc);
      return;
    }
    elem = temp;
  }
  return;
}

void close_thread_files(tid_t tid)
{
  struct list_elem *elem;
  struct list_elem *temp;
  struct file_descriptor *file_desc;

  elem = list_tail (&(thread_current()->open_files));
  while ((elem = list_prev (elem)) != list_head (&(thread_current()->open_files)))
  {
      temp = list_next(elem);
      file_desc = list_entry(elem, struct file_descriptor, elem);
      if (file_desc->owner == tid)
      {
        list_remove(elem);
        file_close(file_desc->file_struct);
        free(file_desc);
      }
      elem = temp;
  }
}

