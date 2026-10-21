/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_UTIL_H
#define HAVE_UTIL_H

#include <stdbool.h>
#include <stdint.h>

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

void *ADDROFFSET(const void *x);
unsigned int ADDRSIZE(const void *x);
void *PORTOFFSET(const void *x);

bool sockaddr_storage_from(struct sockaddr_storage *ss, int family, void *host, uint16_t port);
bool parse_addr(char const * const addr, char const * const iface, uint16_t const port, struct sockaddr_storage * const sa, int * const socket_domain, socklen_t * const sizeof_sa);

int ipv6_addr_linklocal(struct in6_addr const * const a);
int ipv6_addr_v4mapped(struct in6_addr const * const a);

struct tempfile
{
	int fd;
	FILE *fh;
	char *path;
};

/*
 * A temporary file that can not be made (no descriptor, a full disk, its folder gone): an info
 * line, and an event of util_tempfile_summary (one warning a minute, log_summary.h).
 */
struct log_summary;
extern struct log_summary util_tempfile_summary;
struct tempfile *tempfile_new(char *path, char *prefix);
struct tempfile *tempdownload_new(char *prefix);

/*
 * The temporary files of samples are in <download.dir>/.incoming, not in
 * download.dir itself: the same filesystem (the store links a sample from there
 * as <download.dir>/<md5>), but a file made and removed there does not change
 * the mtime of download.dir, which the size cap of the store (store.py,
 * DirQuota) watches to read the folder again. modules/python/dionaea/upload.py
 * (incoming_file) is the same for the services in Python.
 */
#define INCOMING_DIR ".incoming"
/* <download_dir>/.incoming, newly allocated */
char *incoming_path(const char *download_dir);
/*
 * At the start of dionaea, as its user: makes the folder (0700), sets its mode
 * to 0700, and removes what an earlier run left in it (a run that
 * ended without its cleanup). Reads only that folder, never download.dir. NULL: nothing.
 */
void incoming_prepare(const char *download_dir);
/*
 * A temporary file for a sample in <download_dir>/.incoming, the folder made
 * again (0700) if it is gone; NULL download_dir: in the folder of the system for
 * temporary files. NULL and a warning if it can not be made.
 */
struct tempfile *tempincoming_new(const char *download_dir, char *prefix);
void tempfile_close(struct tempfile *tf);
void tempfile_unlink(struct tempfile *tf);
void tempfile_free(struct tempfile *tf);

#endif
