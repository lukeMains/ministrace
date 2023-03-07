#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include "main.h"

int main(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program> [args]\n", argv[0]);
    exit(1);
  }

  pid_t cpid = fork();

  // Error checking
  if (-1 == cpid) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  
  if (0 == cpid) {
    // Child process:
    return run_tracee(argc - 1, &argv[1]); // Child process + args start as the second value of argv
  } else {
    // Parent process:
    return run_tracer(cpid);
  }
}

int run_tracee(int argc, char **argv)
{
  int retval;
  char *file;
  char *args [argc + 1]; // +1 to make space for NULL at the end
  memcpy(args, argv, argc * sizeof(char*));
  args[argc] = NULL;

  file = args[0];

  ptrace(PTRACE_TRACEME);
  kill(getpid(), SIGSTOP); // Child process stops itself so parent can attach
  retval = execvp(file, args);

  return retval;
}

int run_tracer(pid_t tracee_pid)
{
  int status, syscall, syscall_retval;

  waitpid(tracee_pid, &status, 0); // Initial wait for child process

  // TODO: Check value of status
  
  ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, PTRACE_O_TRACESYSGOOD);

  while(true) {
    if (0 != wait_for_syscall(tracee_pid)) break;

    syscall = ptrace(PTRACE_PEEKUSER, tracee_pid, sizeof(long) * ORIG_RAX);
    fprintf(stderr, "syscall(%d) = ", syscall);

    if (0 != wait_for_syscall(tracee_pid)) break;

    syscall_retval = ptrace(PTRACE_PEEKUSER, tracee_pid, sizeof(long) * RAX);
    fprintf(stderr, "%d\n", syscall_retval);
  }
  
  return EXIT_SUCCESS;
}

int wait_for_syscall(pid_t tracee_pid)
{
  int status;
  while(true) {
    ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0);
    waitpid(tracee_pid, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
      return 0;

    if (WIFEXITED(status))
      return 1;
  }
}
