/*
 * this file is part of tty8.
 *
 * Copyright (c) 2015 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <pty.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <paths.h>

#define REDRAW_TTY(tty) ((1 == write(tty, "\f", 1)) ? 0 : -1)
#define CLEAR_TTY(tty) ((4 == write(tty, "\033[2J", 4)) ? 0 : -1)
#define RESET_TTY(tty) ((2 == write(tty, "\033c", 2)) ? 0 : -1)

enum keys {
	KEY_NEXT = '\v',
	KEY_PREV = '\n',
	KEY_QUIT = '\0'
};

struct vtty {
	pid_t pid;
	int master;
};

static int enable_aio(const int fd, const int sig, const pid_t pid)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (-1 == flags)
		return -1;

	if (-1 == fcntl(fd, F_SETSIG, sig))
		return -1;

	if (-1 == fcntl(fd, F_SETFL, O_ASYNC | O_NONBLOCK | flags))
		return -1;

	if (-1 == fcntl(fd, F_SETOWN, pid))
		return -1;

	return 0;
}

static int resize_tty(const int tty, const struct winsize *size)
{
	if (-1 == ioctl(tty, TIOCSWINSZ, size))
		return -1;

	if (-1 == REDRAW_TTY(tty))
		return -1;

	return 0;
}

static int start_child(struct vtty *vtty,
                       const struct termios *term,
                       const struct winsize *size,
                       const sigset_t *mask,
                       char *const argv[],
                       const int sig,
                       const pid_t self)
{
	/* we spawn the child processes under pseudo-terminals, with the same
	 * attributes as the output terminal */
	vtty->pid = forkpty(&vtty->master, NULL, term, NULL);
	switch (vtty->pid) {
		case 0:
			if (0 == sigprocmask(SIG_SETMASK, mask, NULL))
				(void) execvp(argv[0], argv);
			exit(EXIT_FAILURE);

			case (-1):
				return -1;
	}

	/* resize the pseudo-terminal, to match the output terminal size */
	if (-1 == resize_tty(vtty->master, size))
		return -1;

	/* enable I/O signals for output */
	if (-1 == enable_aio(vtty->master, sig, self))
		return -1;

	return 0;
}

static int set_active(struct vtty *vtty,
                      const struct termios *term,
                      const struct winsize *size,
                      const sigset_t *mask,
                      char *const argv[],
                      const int sig,
                      const pid_t self)
{
	if (-1 == CLEAR_TTY(STDOUT_FILENO))
		return -1;

	if (-1 == vtty->pid) {
		if (-1 == start_child(vtty, term, size, mask, argv, sig, self))
			return -1;
	}

	if (-1 == REDRAW_TTY(vtty->master))
		return -1;

	return 0;
}

static int next_child(int *active,
                      struct vtty vttys[NTTYS],
                      const struct termios *term,
                      const struct winsize *size,
                      const sigset_t *mask,
                      char *const argv[],
                      const int sig,
                      const pid_t self)
{
	if (NTTYS - 1 > *active)
		++*active;
	else
		*active = 0;

	if (-1 == set_active(&vttys[*active],
	                     term,
	                     size,
	                     mask,
	                     argv,
	                     sig,
	                     self))
		return -1;

	return 0;
}

static int prev_child(int *active,
                      struct vtty vttys[NTTYS],
                      const struct termios *term,
                      const struct winsize *size,
                      const sigset_t *mask,
                      char *const argv[],
                      const int sig,
                      const pid_t self)
{
	if (0 < *active)
		--*active;
	else
		*active = NTTYS - 1;

	if (-1 == set_active(&vttys[*active],
	                     term,
	                     size,
	                     mask,
	                     argv,
	                     sig,
	                     self))
		return -1;

	return 0;
}

static void destroy_vtty(struct vtty *vtty)
{
	(void) close(vtty->master);
	vtty->master = -1;
	vtty->pid = -1;
}

int main(int argc, char *argv[])
{
	unsigned char buf[BUFSIZ];
	siginfo_t sig;
	struct termios rawterm;
	struct termios oldterm;
	struct winsize size;
	sigset_t mask;
	sigset_t oldmask;
	struct vtty vttys[NTTYS];
	pid_t self;
	char *sh[2];
	char *const *cmd;
	size_t len;
	int ret = EXIT_FAILURE;
	int insig;
	int outsig;
	int i;
	int active;

	if (1 == argc) {
		/* get the shell path */
		sh[0] = getenv("SHELL");
		if (NULL == sh[0])
			sh[0] = _PATH_BSHELL;
		sh[1] = NULL;
		cmd = sh;
	}
	else {
		if (0 != strlen(argv[1]))
			cmd = &argv[1];
		else {
			(void) fprintf(stderr, "Usage: %s [CMD]\n", argv[0]);
			goto end;
		}
	}

	/* get the output terminal size */
	if (-1 == ioctl(STDOUT_FILENO, TIOCGWINSZ, &size))
		goto end;

	/* get the output terminal attributes, so we can reset them later */
	if (-1 == tcgetattr(STDOUT_FILENO, &oldterm))
		goto end;

	/* block SIGCHLD, SIGINT, SIGTERM, SIGWINCH and two real-time signals used
	 * to detect I/O */
	if (-1 == sigemptyset(&mask))
		goto end;
	if (-1 == sigaddset(&mask, SIGCHLD))
		goto end;
	if (-1 == sigaddset(&mask, SIGINT))
		goto end;
	if (-1 == sigaddset(&mask, SIGTERM))
		goto end;
	if (-1 == sigaddset(&mask, SIGWINCH))
		goto end;
	insig = SIGRTMIN;
	if (-1 == sigaddset(&mask, insig))
		goto end;
	outsig = 1 + insig;
	if (-1 == sigaddset(&mask, outsig))
		goto end;
	if (-1 == sigprocmask(SIG_BLOCK, &mask, &oldmask))
		goto end;

	/* enable I/O signals for input */
	self = getpid();
	if (-1 == enable_aio(STDIN_FILENO, insig, self))
		goto end;

	/* spawn one child process */
	if (-1 == start_child(&vttys[0],
	                      &oldterm,
	                      &size,
	                      &oldmask,
	                      cmd,
	                      outsig,
	                      self))
		goto end;

	/* initialize the other children IDs with -1, so we can spawn them
	 * on-demand */
	for (i = 1; NTTYS > i; ++i)
		vttys[i].pid = -1;

	/* clear the terminal, to force redraw */
	if (-1 == CLEAR_TTY(STDOUT_FILENO))
		goto reap;

	/* make the output terminal raw, so child process output can be passed to it
	 * as-is */
	(void) memcpy(&rawterm, &oldterm, sizeof(rawterm));
	cfmakeraw(&rawterm);
	if (-1 == tcsetattr(STDIN_FILENO, TCSADRAIN, &rawterm))
		goto reap;

	/* make the first child the active one */
	active = 0;

	do {
		/* wait for a signal */
		if (-1 == sigwaitinfo(&mask, &sig))
			goto reset;

		switch (sig.si_signo) {
			/* if a child process has terminated, reap it */
			case SIGCHLD:
				if (sig.si_pid != waitpid(sig.si_pid, NULL, WNOHANG))
					goto reset;

				/* replace the PID with -1 and switch to the next child */
				for (i = 0; NTTYS > i; ++i) {
					if (sig.si_pid == vttys[i].pid) {
						destroy_vtty(&vttys[i]);
						if (-1 == next_child(&active,
						                     vttys,
						                     &oldterm,
						                     &size,
						                     &oldmask,
						                     cmd,
						                     outsig,
						                     self))
							goto reset;
						break;
					}
				}
				continue;

			/* pass SIGINT to the child */
			case SIGINT:
				if (-1 == kill(vttys[active].pid, SIGINT))
					goto reset;
				continue;

			/* terminate upon SIGTERM */
			case SIGTERM:
				for (i = NTTYS - 1; 0 <= i; --i) {
					if (-1 != vttys[i].pid)
						(void) kill(vttys[i].pid, SIGTERM);
				}
				ret = EXIT_SUCCESS;
				goto reset;

			/* if the output terminal size has changed, adjust the size of all
			 * psuedo-terminals - the kernel will take care of sending
			 * SIGWINCH to the processes inside them */
			case SIGWINCH:
				if (-1 == ioctl(STDOUT_FILENO, TIOCGWINSZ, &size))
					goto reset;

				for (i = 0; NTTYS > i; ++i) {
					if (-1 != vttys[i].pid) {
						if (-1 == resize_tty(vttys[i].master, &size))
							goto reset;
					}
				}
				continue;
		}

		if (outsig == sig.si_signo) {
			/* if the output signal was received, ignore signals emitted by
			 * psuedo-terminals other than the active one */
			if (vttys[active].master != sig.si_fd)
				continue;

			do {
				/* read the active process output and pass it to the output
				 * terminal */
				len = read(vttys[active].master, (void *) buf, sizeof(buf));
				if (0 == len)
					break;
				if (-1 != len) {
					if (len != write(STDOUT_FILENO, buf, (size_t) len))
						goto reset;
					break;
				}

				if (EAGAIN == errno)
					break;

				/* if the pseudo-terminal is gone, switch to the next child */
				if (EIO == errno) {
					destroy_vtty(&vttys[active]);
					if (-1 == next_child(&active,
					                     vttys,
					                     &oldterm,
					                     &size,
					                     &oldmask,
					                     cmd,
					                     outsig,
					                     self))
						goto reset;
					break;
				}

				goto reset;
			} while (1);
		}
		else if (insig == sig.si_signo) {
			/* otherwise, if it's the input signal - read from standard input
			 * and pass everything to the active psuedo-terminal */
			do {
				len = read(STDIN_FILENO, (void *) buf, sizeof(buf));
				if (0 == len)
					break;
				if (-1 == len) {
					if (EAGAIN == errno)
						break;
					goto reset;
				}

				/* if the input consists of special control characters, act
				 * accordingly */
				if (1 == len) {
					switch (buf[0]) {
						case KEY_NEXT:
							if (-1 == next_child(&active,
							                     vttys,
							                     &oldterm,
							                     &size,
							                     &oldmask,
							                     cmd,
							                     outsig,
							                     self))
								goto reset;
							continue;

						case KEY_PREV:
							if (-1 == prev_child(&active,
							                     vttys,
							                     &oldterm,
							                     &size,
							                     &oldmask,
							                     cmd,
							                     outsig,
							                     self))
								goto reset;
							continue;

						case KEY_QUIT:
							if (-1 == raise(SIGTERM))
								goto reset;
					}
				}

				if (len != write(vttys[active].master, buf, (size_t) len))
					goto reset;
			} while (1);
		}
		else
			goto reset;
	} while (1);

reset:
	/* reset the output terminal settings */
	(void) tcsetattr(STDOUT_FILENO, TCSADRAIN, &oldterm);
	(void) CLEAR_TTY(STDOUT_FILENO);
	(void) RESET_TTY(STDOUT_FILENO);

reap:
	/* reap all children */
	for (i = NTTYS - 1; 0 <= i; --i) {
		if (-1 != vttys[i].pid) {
			(void) close(vttys[i].master);
			(void) waitpid(vttys[i].pid, NULL, WNOHANG);
		}
	}

end:
	return ret;
}
