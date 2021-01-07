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
	int	 i, status;
	pid_t	 pid = -1;

	bzero(args, sizeof(args));

	p = fork();
	switch (p) {
	case -1:
		fprintf(stderr, "error: fork\n");
		exit(1);
	case 0:
		/* Run game */
		args[0] = "steam";
		args[1] = "steam://rungameid/550";
		args[2] = NULL;
		execvp("steam", args);
	default:
		/* Wait up to 10s to find process */
		for (i = 0; i < 10; i++) {
			if ((pid = find_proc()) != -1)
				break;
			sleep(1);
		}
		if (pid == -1)
			errx(1, "error: process not found\n");

		printf("Found PID: %d\n",pid);

		/* */
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
			errx(1, "error: failed to attach to process\n");
		while ((child = wait(NULL))) {
			printf("The child %d was stopped\n", child);
			if (child == pid) {
				/* XXX: Magic here */
				ptrace(PTRACE_CONT, child, NULL, NULL);
				break;
			}
			ptrace(PTRACE_CONT, child, NULL, NULL);
		}
	}
	return (0);
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

	while ((dirent = readdir(dir))) {
		/* Read pid, check sanity */
		pid = atoi(dirent->d_name);
		if (pid < 1 || pid > INT_MAX)
			continue;

		/* XXX: use cmdline instead of comm */
		if (snprintf(path, sizeof(path) - 1, "/proc/%d/comm", pid) < 0)
			continue;

		if ((fd = open(path, O_RDONLY)) == -1)
			continue;

		if ((bytes = read(fd, buf, sizeof(buf) - 1)) == -1)
			continue;

		/* Remove trailing newline */
		buf[bytes - 1] = '\0';

		if (strncmp("hl2_linux", buf, sizeof(buf) -1) == 0) {
			printf("Found %s at %s\n", buf, path);
			ret = pid;
			break;
		}
	}
	return (ret);
}
