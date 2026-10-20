/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * slowfs.so: LD_PRELOAD model of a filesystem share whose requests are served
 * one at a time (Apple's virtiofs device of Docker Desktop: one serial dispatch
 * queue), with a cold directory read that costs SLOWFS_ENTRY_US per entry.
 * See README.md.
 *
 * - "The queue" is a FIFO ticket lock. Every file request below takes it.
 * - readdir: every SLOWFS_BATCH-th entry of a thread is one getdents request,
 *   which holds the queue for SLOWFS_BATCH * SLOWFS_ENTRY_US (READDIRPLUS: one
 *   host lookup per entry). fstatat/stat/lstat hold it for SLOWFS_STAT_US.
 * - open/openat, pwrite, write to a regular file, fsync, fdatasync pass through
 *   the queue without a cost of their own: they wait while a batch is served.
 * - SLOWFS_LOG=FILE: a line "time tid thread-name entries" per 2,000 directory
 *   entries a thread read (which thread walks, and when).
 * Sockets and pipes are not touched. Not tied to macOS: it runs on any Linux.
 *
 * Build (Linux, the glibc of the image): gcc -O2 -shared -fPIC -o slowfs.so slowfs.c -ldl -lpthread
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_ulong next_ticket, now_serving;
static long entry_us = 500, stat_us = 20, batch = 128;
static __thread long entries;
static int log_fd = -1;  /* SLOWFS_LOG: a line per 2,000 directory entries of a thread */

__attribute__((constructor)) static void init(void)
{
	const char *v;
	if( (v = getenv("SLOWFS_ENTRY_US")) != NULL ) entry_us = atol(v);
	if( (v = getenv("SLOWFS_STAT_US")) != NULL ) stat_us = atol(v);
	if( (v = getenv("SLOWFS_BATCH")) != NULL ) batch = atol(v);
	if( batch < 1 ) batch = 1;
	if( (v = getenv("SLOWFS_LOG")) != NULL )
		log_fd = syscall(SYS_openat, AT_FDCWD, v, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
}

static void log_entries(void)
{
	if( log_fd < 0 )
		return;
	char name[17] = { 0 };
	prctl(PR_GET_NAME, name);
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	char line[128];
	int n = snprintf(line, sizeof(line), "%ld.%03ld %ld %s %ld\n", (long)ts.tv_sec, ts.tv_nsec / 1000000,
					 (long)syscall(SYS_gettid), name, entries);
	syscall(SYS_write, log_fd, line, n);
}

static void sleep_us(long us)
{
	if( us <= 0 )
		return;
	struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };
	while( nanosleep(&ts, &ts) == -1 && errno == EINTR )
		;
}

static void q_enter(void)
{
	unsigned long me = atomic_fetch_add(&next_ticket, 1);
	while( atomic_load(&now_serving) != me )
		sleep_us(50);
}

static void q_leave(void)
{
	atomic_fetch_add(&now_serving, 1);
}

static void q_cost(long us)
{
	int e = errno;
	q_enter();
	sleep_us(us);
	q_leave();
	errno = e;
}

#define REAL(name, ret, ...) \
	static ret (*real_##name)(__VA_ARGS__); \
	if( real_##name == NULL ) real_##name = dlsym(RTLD_NEXT, #name)

static int regular(int fd)
{
	struct stat st;
	/* the raw syscall: no request of its own through the queue */
	return syscall(SYS_fstat, fd, &st) == 0 && S_ISREG(st.st_mode);
}

static void dir_entry(void)
{
	if( ++entries % batch == 1 || batch == 1 )
		q_cost(batch * entry_us);
	if( entries % 2000 == 0 )
		log_entries();
}

struct dirent *readdir(DIR *dir)
{
	REAL(readdir, struct dirent *, DIR *);
	dir_entry();
	return real_readdir(dir);
}

struct dirent64 *readdir64(DIR *dir)
{
	REAL(readdir64, struct dirent64 *, DIR *);
	dir_entry();
	return real_readdir64(dir);
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
	REAL(fstatat, int, int, const char *, struct stat *, int);
	q_cost(stat_us);
	return real_fstatat(dirfd, path, st, flags);
}

int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags)
{
	REAL(fstatat64, int, int, const char *, struct stat64 *, int);
	q_cost(stat_us);
	return real_fstatat64(dirfd, path, st, flags);
}

int stat(const char *path, struct stat *st)
{
	REAL(stat, int, const char *, struct stat *);
	q_cost(stat_us);
	return real_stat(path, st);
}

int lstat(const char *path, struct stat *st)
{
	REAL(lstat, int, const char *, struct stat *);
	q_cost(stat_us);
	return real_lstat(path, st);
}

int open(const char *path, int flags, ...)
{
	REAL(open, int, const char *, int, ...);
	mode_t mode = 0;
	if( flags & (O_CREAT | O_TMPFILE) )
	{
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	q_cost(0);
	return real_open(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
	REAL(open64, int, const char *, int, ...);
	mode_t mode = 0;
	if( flags & (O_CREAT | O_TMPFILE) )
	{
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	q_cost(0);
	return real_open64(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
	REAL(openat, int, int, const char *, int, ...);
	mode_t mode = 0;
	if( flags & (O_CREAT | O_TMPFILE) )
	{
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	q_cost(0);
	return real_openat(dirfd, path, flags, mode);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
{
	REAL(pwrite, ssize_t, int, const void *, size_t, off_t);
	q_cost(0);
	return real_pwrite(fd, buf, n, off);
}

ssize_t pwrite64(int fd, const void *buf, size_t n, off_t off)
{
	REAL(pwrite64, ssize_t, int, const void *, size_t, off_t);
	q_cost(0);
	return real_pwrite64(fd, buf, n, off);
}

ssize_t write(int fd, const void *buf, size_t n)
{
	REAL(write, ssize_t, int, const void *, size_t);
	if( regular(fd) )
		q_cost(0);
	return real_write(fd, buf, n);
}

int fsync(int fd)
{
	REAL(fsync, int, int);
	q_cost(0);
	return real_fsync(fd);
}

int fdatasync(int fd)
{
	REAL(fdatasync, int, int);
	q_cost(0);
	return real_fdatasync(fd);
}
