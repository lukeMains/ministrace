#include <sys/types.h>

#ifndef MAIN_H
#define MAIN_H

/*
 * TODO
 */
int run_tracee(int argc, char **argv);

/*
 * TODO
 */
int run_tracer(pid_t tracee_pid);

/*
 * TODO
 */
int wait_for_syscall(pid_t tracee_pid);

#endif
