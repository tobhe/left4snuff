/*
 * Copyright (c) 2021 Tobias Heider <tobias.heider@stusta.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <dirent.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static void print_usage(void);
static void handle_child(pid_t, int);
static pid_t find_proc(void);

int procs = 1;

static void
print_usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-s2]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char	*args[3];
	pid_t	 p, child;
	long	 r;
	int	 status;

	bzero(args, sizeof(args));

	p = fork();
	switch (p) {
	case -1:
		fprintf(stderr, "error: fork\n");
		exit(1);
	case 0:
		printf("CHILD: %d\n", getpid());
#if 1
		args[0] = "steam";
		args[1] = "steam://rungameid/550";
		args[2] = NULL;

		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		execvp("steam", args);
#else
		args[0] = "ls";
		args[1] = "-la";
		args[2] = NULL;

		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		execvp("ls", args);
		break;
#endif
	default:
		printf("PARENT: %d\n", getpid());
		child = wait(NULL);
		procs = 0;
		ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACEEXEC);
		printf("The child %d was stopped\n", child);
		ptrace(PTRACE_CONT, p, NULL, NULL);

		find_proc();

		for(;;) {
			child = waitpid(-1, &status, 0);
			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				printf("child %d exited\n", child);
				if (--procs == 0)
					break;
			}
			handle_child(child, status >> 16);
		}
	}
	return (0);
}

static void
handle_child(pid_t pid, int status)
{
	long	newpid;
	pid_t	p = pid;

	if (status == PTRACE_EVENT_FORK ||
	    status == PTRACE_EVENT_VFORK ||
	    status == PTRACE_EVENT_CLONE) {
		ptrace(PTRACE_GETEVENTMSG, p, NULL, &newpid);
		p = newpid;
		procs++;
	}
	printf("child %d\n", p);
	ptrace(PTRACE_SETOPTIONS, p, NULL,
	    PTRACE_O_TRACEFORK |
	    PTRACE_O_TRACEVFORK |
	    PTRACE_O_TRACECLONE);
	ptrace(PTRACE_CONT, p, NULL, NULL);
}

static pid_t
find_proc(void)
{
	char		 path[32], buf[1024];
	const char	*err;
	DIR		*dir;
	struct dirent	*dirent;
	pid_t		 pid, ret = -1;
	ssize_t		 bytes;
	int		 fd;

	dir = opendir("/proc");
	if (dir == NULL)
		return (-1);

	bzero(buf, sizeof(buf));

	while ((dirent = readdir(dir))) {
		/* Read pid, check sanity */
		pid = atoi(dirent->d_name);
		if (pid < 1 || pid > INT_MAX)
			continue;

		if (snprintf(path, sizeof(path) - 1, "/proc/%d/comm", pid) < 0)
			continue;

		if ((fd = open(path, O_RDONLY)) == -1) {
			continue;
		}

		if ((bytes = read(fd, buf, sizeof(buf) - 1)) == -1)
			continue;

		/* Remove trailing newline */
		buf[bytes - 1] = '\0';

		if (strncmp("hl2_linux", buf, sizeof(buf) -1) == 0)
			ret = pid;
	}

	return (pid);
}
