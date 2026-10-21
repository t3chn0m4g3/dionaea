/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <glib.h>


#include "config.h"
#include "dionaea.h"
#include "util.h"
#include "log.h"
#include "log_summary.h"

#define D_LOG_DOMAIN "util"

struct log_summary util_tempfile_summary = LOG_SUMMARY_INIT("temporary files not made", "file(s)");

/* a temporary file of a dump, a download or an upload that is not made: info, one warning a minute */
static void tempfile_failed(const char *path, int error)
{
	g_info("could not open path %s (%s)", path, strerror(error));
	log_summary_addf(&util_tempfile_summary, "%s (%s)", path, strerror(error));
}

void *ADDROFFSET(const void *x)
{
	if( x == NULL )
		return NULL;

	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in, sin_addr));
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in6, sin6_addr));
	}

	return NULL;
}

unsigned int ADDRSIZE(const void *x)
{
	if( x == NULL )
		return 0;
	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return sizeof(struct sockaddr_in);
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return sizeof(struct sockaddr_in6);
	}
	return 0;
}

void *PORTOFFSET(const void *x)
{
	if( x == NULL )
		return NULL;

	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in, sin_port));
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in6, sin6_port));
	}

	return NULL;
}

int ipv6_addr_any(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] | a->s6_addr32[1] |
			a->s6_addr32[2] | a->s6_addr32[3] ) == 0);
}

int ipv6_addr_loopback(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] | a->s6_addr32[1] |
			a->s6_addr32[2] | (a->s6_addr32[3] ^ htonl(1))) == 0);
}

int ipv6_addr_linklocal(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] & htonl(0xFFC00000)) == htonl(0xFE800000));
}

int ipv6_addr_v4mapped(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] | a->s6_addr32[1]) == 0 &&
		   a->s6_addr32[2] == htonl(0x0000ffff));
}

void ipv6_v6_map_v4(struct sockaddr_in6 *from, struct sockaddr_in *to)
{
	to->sin_family = PF_INET;
	to->sin_port = from->sin6_port;
	to->sin_addr.s_addr = from->sin6_addr.s6_addr32[3];
}

void ipv6_v4_map_v6(struct sockaddr_in *from, struct sockaddr_in6 *to)
{
	to->sin6_family = PF_INET6;
	to->sin6_port = from->sin_port;
	to->sin6_addr.s6_addr32[3] = from->sin_addr.s_addr;
	to->sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
	to->sin6_addr.s6_addr32[1] = 0;
	to->sin6_addr.s6_addr32[0] = 0;
}

bool sockaddr_storage_from(struct sockaddr_storage *ss, int family, void *host, uint16_t port)
{
	ss->ss_family = family;
	if( family == PF_INET )
	{
		struct sockaddr_in *in4 = (void *)ss;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, host, sizeof(struct in_addr));
		return true;
	}else
	if( family == PF_INET6 )
	{
		struct sockaddr_in6 *in6 = (void *)ss;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, host, sizeof(struct in6_addr));
		return true;
	}
	return false;
}

bool parse_addr(char const * const addr, char const * const iface, uint16_t const port, struct sockaddr_storage * const sa, int * const socket_domain, socklen_t * const sizeof_sa)
{
	struct sockaddr_in6 *si6;
	struct sockaddr_in *si;
	struct sockaddr_un *su;

	GError *error = NULL;
	gboolean use_ipv4_mapped_ipv6;

	si6 = (struct sockaddr_in6 *)sa;
	si  = (struct sockaddr_in  *)sa;
	su  = (struct sockaddr_un  *)sa;


	int validaddr = inet_pton(PF_INET6, addr, &si6->sin6_addr);

	if( validaddr > 0 )
	{
		si6->sin6_family = PF_INET6;
		si6->sin6_port = htons(port);
		*sizeof_sa = sizeof(struct sockaddr_in6);
		*socket_domain = PF_INET6;
		if( ipv6_addr_linklocal(&si6->sin6_addr) )
		{
			if( iface == NULL || strlen(iface) == 0 || if_nametoindex(iface) == 0 )
			{
				g_warning("Link Local address %s without valid scope id?", addr);
				return false;
			}
			si6->sin6_scope_id = if_nametoindex(iface);
		}
		return true;
	}

	validaddr = inet_pton(PF_INET, addr, &si->sin_addr);
	if( validaddr > 0 )
	{
		si->sin_family = PF_INET;
		si->sin_port = htons(port);

		use_ipv4_mapped_ipv6 = g_key_file_get_boolean(g_dionaea->config, "dionaea", "listen.use_ipv4_mapped_ipv6", &error);
		// ToDo: handler error
		if (error != NULL) {
			g_debug("%s", error->message);
		}
		g_clear_error(&error);
		if (use_ipv4_mapped_ipv6 == TRUE) {
#ifdef CAN_BIND_IPV4_MAPPED_IPV6
            ipv6_v4_map_v6(si, si6);
            *sizeof_sa = sizeof(struct sockaddr_in6);
            *socket_domain = PF_INET6;
		} else {
#else
			g_warning("IPv4 mapped IPv6 enabled but not available");
		}
#endif
		*sizeof_sa = sizeof(struct sockaddr_in);
		*socket_domain = PF_INET;
#ifdef CAN_BIND_IPV4_MAPPED_IPV6
		}
#endif
		return true;
	}

	static const char *un_prefix = "un://";
	if( strncmp(addr, un_prefix,  strlen(un_prefix)) == 0 )
	{
		const char *p = addr + strlen(un_prefix);
		if( strlen(p) > sizeof(struct sockaddr_storage) - sizeof(unsigned short) )
		{
			g_warning("unix path would not fit into buffer\n");
			return false;
		}
		su->sun_family = PF_UNIX;
		strncpy(su->sun_path, p, 107);
		*sizeof_sa = sizeof(su->sun_family) + strlen(su->sun_path);
		*socket_domain = PF_UNIX;
		return true;
	}

	return false;
}

/* a temporary file in path; NULL with errno set, and no warning when mkstemp() failed (*made false) */
static struct tempfile *tempfile_open(const char *path, const char *prefix, bool *made)
{
	struct tempfile *tf = g_malloc0(sizeof(struct tempfile));

	*made = false;
	if( prefix )
		tf->path = g_strdup_printf("%s/%sXXXXXX", path, prefix);
	else
		tf->path = g_strdup_printf("%s/XXXXXX", path);
	tf->fd = mkstemp(tf->path);
	if( tf->fd == -1 )
	{
		int error = errno;
		g_free(tf->path);
		g_free(tf);
		errno = error;
		return NULL;
	}

	*made = true;
	tf->fh = fdopen(tf->fd, "w+");
	if( tf->fh == NULL )
	{
		int error = errno;
		tempfile_failed(tf->path, error);
		unlink(tf->path);
		close(tf->fd);
		g_free(tf->path);
		g_free(tf);
		errno = error;
		return NULL;
	}
	return tf;
}

struct tempfile *tempfile_new(char *path, char *prefix)
{
	bool made;
	struct tempfile *tf = tempfile_open(path, prefix, &made);
	if( tf == NULL && !made )
	{
		int error = errno;
		tempfile_failed(path, error);
		errno = error;
	}
	return tf;
}

char *incoming_path(const char *download_dir)
{
	return g_build_filename(download_dir, INCOMING_DIR, NULL);
}

void incoming_prepare(const char *download_dir)
{
	if( download_dir == NULL )
		return;
	char *path = incoming_path(download_dir);
	struct stat st;
	if( lstat(path, &st) == 0 && !S_ISDIR(st.st_mode) )
	{
		/* a file or a link of that name: the temporary files are never put elsewhere */
		g_warning("%s is no folder, it is replaced by one", path);
		if( unlink(path) != 0 )
			g_warning("Could not remove %s (%s)", path, strerror(errno));
	}
	if( mkdir(path, S_IRWXU) != 0 && errno != EEXIST )
	{
		g_warning("Could not create %s, the temporary files of the samples are made there (%s)",
				  path, strerror(errno));
		g_free(path);
		return;
	}
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	DIR *dir = NULL;
	if( fd == -1 || (dir = fdopendir(fd)) == NULL )
	{
		g_warning("Could not read %s (%s)", path, strerror(errno));
		if( fd != -1 )
			close(fd);
		g_free(path);
		return;
	}
	if( fstat(fd, &st) == 0 && (st.st_mode & 07777) != S_IRWXU && fchmod(fd, S_IRWXU) != 0 )
		g_warning("Could not set the mode of %s to 0700 (%s)", path, strerror(errno));
	guint removed = 0;
	struct dirent *entry;
	while( (entry = readdir(dir)) != NULL )
	{
		if( strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 )
			continue;
		/* only files of an earlier run: nothing here makes folders */
		if( fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || S_ISDIR(st.st_mode) )
			continue;
		if( unlinkat(fd, entry->d_name, 0) == 0 )
			removed++;
		else
			g_warning("Could not remove %s/%s (%s)", path, entry->d_name, strerror(errno));
	}
	closedir(dir);
	if( removed > 0 )
		g_info("Removed %u temporary file(s) of an earlier run from %s", removed, path);
	g_free(path);
}

struct tempfile *tempincoming_new(const char *download_dir, char *prefix)
{
	if( download_dir == NULL )
		return tempfile_new((char *)g_get_tmp_dir(), prefix);
	char *path = incoming_path(download_dir);
	bool made;
	struct tempfile *tf = tempfile_open(path, prefix, &made);
	if( tf == NULL && !made && errno == ENOENT )
	{
		/* made at the start of dionaea, gone meanwhile (not download.dir itself: ENOENT again) */
		if( mkdir(path, S_IRWXU) == 0 || errno == EEXIST )
			tf = tempfile_open(path, prefix, &made);
	}
	if( tf == NULL && !made )
	{
		int error = errno;
		tempfile_failed(path, error);
		errno = error;
	}
	g_free(path);
	return tf;
}

struct tempfile *tempdownload_new(char *prefix)
{
	/* ToDo: replace
  struct lcfgx_tree_node *node;
	if( lcfgx_get_string(g_dionaea->config.root, &node, "downloads.dir") != LCFGX_PATH_FOUND_TYPE_OK )
	{
		g_warning("missing downloads.dir in dionaea.conf");
		return NULL;
	}
	return tempfile_new((char *)node->value.string.data, prefix);
  */
	return tempfile_new((char *)"/tmp", prefix);
}

/*
 * The stream owns the descriptor once fdopen() succeeded: fclose() closes it.
 * A close() of tf->fd after that closes the number a second time, and by then
 * another thread or connection may have opened a file under it.
 */
void tempfile_close(struct tempfile *tf)
{
	if( tf->fh != NULL )
		fclose(tf->fh);
	else if( tf->fd != -1 )
		close(tf->fd);

	tf->fd = -1;
	tf->fh = NULL;
}

void tempfile_unlink(struct tempfile *tf)
{
	unlink(tf->path);
}


void tempfile_free(struct tempfile *tf)
{
	if( tf->path )
		g_free(tf->path);
	g_free(tf);
}
