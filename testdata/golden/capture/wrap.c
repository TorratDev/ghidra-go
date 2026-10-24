// Byte-for-byte relay between parent and the real decompile; logs both streams.
// Real binary and log dir are compiled in (-DREAL_PATH/-DLOG_DIR). Logs <pid>.in / <pid>.out.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child;
static void fwd(int s) { if (child > 0) kill(child, s); }

static int pump(int from, int to, int log) {
	char buf[65536];
	ssize_t n = read(from, buf, sizeof buf);
	if (n < 0) return errno == EINTR ? 1 : 0;
	if (n == 0) return 0;
	for (ssize_t o = 0; o < n;) {
		ssize_t w = write(to, buf + o, n - o);
		if (w < 0) { if (errno == EINTR) continue; return 0; }
		o += w;
	}
	for (ssize_t o = 0; o < n;) {
		ssize_t w = write(log, buf + o, n - o);
		if (w < 0) { if (errno == EINTR) continue; break; }
		o += w;
	}
	return 1;
}

int main(void) {
	const char *real = REAL_PATH, *dir = LOG_DIR;
	if (!real || !dir) { fputs("unconfigured\n", stderr); return 127; }
	char p[4096];
	snprintf(p, sizeof p, "%s/%d.in", dir, getpid());
	int lin = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	snprintf(p, sizeof p, "%s/%d.out", dir, getpid());
	int lout = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (lin < 0 || lout < 0) { perror("log"); return 127; }
	int ci[2], co[2];
	if (pipe(ci) || pipe(co)) { perror("pipe"); return 127; }
	child = fork();
	if (child < 0) { perror("fork"); return 127; }
	if (!child) {
		dup2(ci[0], 0); dup2(co[1], 1);
		close(ci[0]); close(ci[1]); close(co[0]); close(co[1]);
		execl(real, real, (char *)NULL);
		perror("exec"); _exit(127);
	}
	close(ci[0]); close(co[1]);
	struct sigaction sa = {.sa_handler = fwd};
	sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
	struct pollfd f[2] = {{0, POLLIN, 0}, {co[0], POLLIN, 0}};
	int in_open = 1, out_open = 1;
	while (out_open) {
		f[0].fd = in_open ? 0 : -1;
		if (poll(f, 2, -1) < 0 && errno != EINTR) break;
		if (in_open && (f[0].revents & (POLLIN | POLLHUP)) && !pump(0, ci[1], lin)) { close(ci[1]); in_open = 0; }
		if (f[1].revents & (POLLIN | POLLHUP)) { if (!pump(co[0], 1, lout)) out_open = 0; }
	}
	int st = 0;
	while (waitpid(child, &st, 0) < 0 && errno == EINTR);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
