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
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static int find_mapping(pid_t, size_t *, size_t *);
static pid_t find_proc(void);
static int find_replace_check(pid_t, size_t, size_t);

const uint64_t snip = 0x05c60d75db841175;
const uint64_t patch = 0x05c60d75db8404eb;

int
main()
{
	char	*args[3], *errstr = NULL;
	int	 i;
	pid_t	 pid = -1, p, child;
	size_t	 offset, size;

	/* XXX: getopt? */

	bzero(args, sizeof(args));

	p = fork();
	switch (p) {
	case -1:
		errx(1, "error: fork\n");
	case 0:
		/* Run game */
		args[0] = "steam";
		args[1] = "steam://rungameid/550";
		args[2] = NULL;
		execvp("steam", args);
		break;
	default:
		/* Wait up to 20s to find process */
		for (i = 0; i < 20; i++) {
			if ((pid = find_proc()) != -1)
				break;
			sleep(1);
		}
		if (pid == -1)
			errx(1, "error: process not found\n");

		printf("found PID: %d\n",pid);

		/* Attach and patch */
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
			errx(1, "error: failed to attach to process\n");
		while ((child = wait(NULL))) {
			printf("The child %d was stopped\n", child);
			if (child != pid) {
				ptrace(PTRACE_CONT, child, NULL, NULL);
				continue;
			}

			if (find_mapping(pid, &offset, &size) == -1) {
				errstr = "error: failed to find "
				    "engine.so\n";
				break;
			}

			if (find_replace_check(pid, offset, size) == -1)
				errstr = "error: failed to patch "
				    "engine.so\n";
			break;
		}
		ptrace(PTRACE_CONT, child, NULL, NULL);

		if (errstr)
			errx(1, errstr);
	}
	return (0);
}

static int
find_replace_check(pid_t pid, size_t offset, size_t size)
{
	char	 path[PATH_MAX], *buf = NULL, *p;
	int	 fd, ret = -1;
	size_t	 addr;

	if (snprintf(path, sizeof(path) - 1, "/proc/%d/mem", pid) < 0)
		return (-1);

	if ((fd = open(path, O_RDONLY)) == -1) {
		printf("%s: error: open failed\n", __func__);
		return (-1);
	}

	if (lseek(fd, offset, SEEK_SET) == -1)
		goto done;

	if ((buf = calloc(size, sizeof(*buf))) == NULL)
		goto done;

	if (read(fd, buf, size) == -1)
		goto done;

	if ((p = memmem(buf, size, &snip, sizeof(snip))) == NULL)
		goto done;

	addr = offset + (p - buf);
	
	if (ptrace(PTRACE_POKETEXT, pid, addr, (void *)patch) == -1) {
		printf("error: ptrace failed\n");
		goto done;
	}
	ret = 0;
 done:
	close(fd);
	free(buf);
	return (ret);
}

static int
find_mapping(pid_t pid, size_t *offset, size_t *size)
{
	char		 path[PATH_MAX], *line = NULL, *found;
	FILE		*f;
	int		 ret = -1;
	size_t		 len = 0;
	unsigned int	 start, end;

	if (snprintf(path, sizeof(path) - 1, "/proc/%d/maps", pid) < 0)
		return (-1);
	if ((f = fopen(path, "r")) == NULL)
		return (-1);

	while (getline(&line, &len, f) != -1) {
		found = strstr(line, "engine.so");
		if (found == NULL)
			continue;
		if (sscanf(line ,"%x-%x", &start, &end) == -1)
			errx(1, "error: scanf\n");
		printf("start: %x -> end: %x\n", start, end);
		*offset = start;
		*size = end - start;
		ret = 0;
		break;
	}

	free(line);
	fclose(f);
	return (ret);
}

static pid_t
find_proc(void)
{
	char		 path[PATH_MAX], buf[1024];
	DIR		*dir;
	int		 fd;
	pid_t		 pid, ret = -1;
	ssize_t		 bytes;
	struct dirent	*dirent;

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

		if ((bytes = read(fd, buf, sizeof(buf) - 1)) == -1) {
			close(fd);
			continue;
		}

		/* Remove trailing newline */
		buf[bytes - 1] = '\0';

		if (strncmp("hl2_linux", buf, sizeof(buf) -1) == 0) {
			printf("Found %s at %s\n", buf, path);
			close(fd);
			ret = pid;
			break;
		}
		close(fd);
	}

	closedir(dir);
	return (ret);
}
