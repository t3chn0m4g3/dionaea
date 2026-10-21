/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */

/*
 * connection_listen() of a TCP connection: when listen() fails the socket is
 * closed and forgotten (con->socket = -1).
 *
 * The accept loops of TCP and TLS: an error of one pending connection
 * (ECONNABORTED, ...) is retried at most CONNECTION_ACCEPT_TRANSIENT_MAX times
 * in a row, then the loop goes back to the event loop with the watcher still
 * active. A TLS listener that the protocol closes for the connection it just
 * accepted (origin hook, incident handlers) is not accepted on again.
 *
 * A download connection (download_guard) whose every address the download target
 * filter refused gets ECONFILTERED; one with an address the filter allowed gets
 * ECONUNREACH when no address could be connected.
 *
 * The lines of every connection that the core writes when a limit or the system refuses
 * it (accepts that fail in a row, a connection closed for running out of fds, no socket,
 * a read of TCP or UDP or a UDP reply that fails, the address of an accepted connection) are
 * info; one warning a minute of each
 * sums them up (log_summary.h, the clock of the test).
 *
 * Built from the sources of dionaea without dionaea.c (g_dionaea is here);
 * listen(), close(), accept(), socket(), recv(), recvmsg(), sendmsg(), getpeername() and the
 * bind of the privileged child are wrapped (-Wl,--wrap=...).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ev.h>
#include <glib.h>

#include "dionaea.h"
#include "connection.h"
#include "incident.h"
#include "log_summary.h"

struct dionaea *g_dionaea = NULL;
static struct dionaea d;
static struct ihandlers ih;

static gint closes_of_closed_fds;
static int listen_fails_with;

int __real_close(int fd);
int __wrap_close(int fd)
{
	if( fcntl(fd, F_GETFD) == -1 && errno == EBADF )
		g_atomic_int_inc(&closes_of_closed_fds);
	return __real_close(fd);
}

int __real_listen(int fd, int backlog);
int __wrap_listen(int fd, int backlog)
{
	if( listen_fails_with != 0 )
	{
		errno = listen_fails_with;
		return -1;
	}
	return __real_listen(fd, backlog);
}

/* accept(): calls, calls on a closed socket (-1), and the first accept_fails calls fail with ECONNABORTED */
static gint accept_calls;
static gint accepts_on_closed;
static gint accept_fails;
/* the errno of those failures (0: ECONNABORTED) */
static int accept_fails_with;
int __real_accept(int fd, struct sockaddr *addr, socklen_t *len);
int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *len)
{
	g_atomic_int_inc(&accept_calls);
	if( fd == -1 )
		g_atomic_int_inc(&accepts_on_closed);
	if( g_atomic_int_get(&accept_fails) > 0 )
	{
		g_atomic_int_add(&accept_fails, -1);
		errno = accept_fails_with != 0 ? accept_fails_with : ECONNABORTED;
		return -1;
	}
	return __real_accept(fd, addr, len);
}

/* socket(), recv(), recvmsg() and sendmsg() fail with *_fails_with while it is not 0 */
static int socket_fails_with;
static int recv_fails_with;
static int recvmsg_fails_with;
static int sendmsg_fails_with;
static int getpeername_fails_with;

int __real_getpeername(int fd, struct sockaddr *addr, socklen_t *len);
int __wrap_getpeername(int fd, struct sockaddr *addr, socklen_t *len)
{
	if( getpeername_fails_with != 0 )
	{
		errno = getpeername_fails_with;
		return -1;
	}
	return __real_getpeername(fd, addr, len);
}

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
	if( socket_fails_with != 0 )
	{
		errno = socket_fails_with;
		return -1;
	}
	return __real_socket(domain, type, protocol);
}

ssize_t __real_recv(int fd, void *buf, size_t len, int flags);
ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags)
{
	if( recv_fails_with != 0 )
	{
		errno = recv_fails_with;
		return -1;
	}
	return __real_recv(fd, buf, len, flags);
}

/* with _FORTIFY_SOURCE (an optimised build, e.g. the ThreadSanitizer stage) recv() is __recv_chk() */
ssize_t __real___recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags);
ssize_t __wrap___recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags)
{
	if( recv_fails_with != 0 )
	{
		errno = recv_fails_with;
		return -1;
	}
	return __real___recv_chk(fd, buf, len, buflen, flags);
}

ssize_t __real_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags)
{
	if( recvmsg_fails_with != 0 )
	{
		errno = recvmsg_fails_with;
		return -1;
	}
	return __real_recvmsg(fd, msg, flags);
}

ssize_t __real_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t __wrap_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	if( sendmsg_fails_with != 0 )
	{
		errno = sendmsg_fails_with;
		return -1;
	}
	return __real_sendmsg(fd, msg, flags);
}

/* no privileged child in the test: bind directly */
int __wrap_pchild_sent_bind(int sx, struct sockaddr *s, socklen_t size)
{
	return bind(sx, s, size);
}

static void listen_failure_forgets_the_socket(void)
{
	g_atomic_int_set(&closes_of_closed_fds, 0);
	struct connection *con = connection_new(connection_transport_tcp);
	g_assert_true(connection_bind(con, "127.0.0.1", 0, NULL));
	/* for TCP the socket is made in listen */
	g_assert_cmpint(con->socket, ==, -1);

	listen_fails_with = EADDRINUSE;
	g_assert_false(connection_listen(con, 1));
	g_assert_cmpint(con->socket, ==, -1);
	g_assert_cmpint(g_atomic_int_get(&closes_of_closed_fds), ==, 0);

	/* the next listen makes a new socket, nothing is closed twice */
	listen_fails_with = 0;
	g_assert_true(connection_listen(con, 1));
	g_assert_cmpint(con->socket, >=, 0);
	g_assert_cmpint(fcntl(con->socket, F_GETFD), !=, -1);
	g_assert_cmpint(g_atomic_int_get(&closes_of_closed_fds), ==, 0);

	ev_io_stop(d.loop, &con->events.io_in);
	close(con->socket);
	con->socket = -1;
	/* as the accept of connection_tcp.c frees a connection it does not report */
	connection_free_cb(d.loop, &con->events.free, 0, false);
}

static void *no_ctx(struct connection *con)
{
	(void)con;
	return NULL;
}

/* a listening connection of trans on 127.0.0.1, a free port; its port in *port */
static struct connection *listener(enum connection_transport trans, int *port)
{
	struct connection *con = connection_new(trans);
	con->protocol.ctx_new = no_ctx;
	g_assert_true(connection_bind(con, "127.0.0.1", 0, NULL));
	g_assert_true(connection_listen(con, 8));
	struct sockaddr_in sa;
	socklen_t size = sizeof(sa);
	g_assert_cmpint(getsockname(con->socket, (struct sockaddr *)&sa, &size), ==, 0);
	*port = ntohs(sa.sin_port);
	return con;
}

/* a connection to port of 127.0.0.1 that the listener has pending */
static int client(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	g_assert_cmpint(connect(fd, (struct sockaddr *)&sa, sizeof(sa)), ==, 0);
	return fd;
}

/* runs the loop until the connections the test closed are freed (their free timers) */
static void run_frees(void)
{
	gint64 end = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
	while( g_get_monotonic_time() < end )
	{
		ev_run(d.loop, EVRUN_NOWAIT);
		g_usleep(10000);
	}
}

static void free_listener(struct connection *con)
{
	ev_io_stop(d.loop, &con->events.io_in);
	ev_timer_stop(d.loop, &con->events.accept_retry_timeout);
	close(con->socket);
	con->socket = -1;
	connection_free_cb(d.loop, &con->events.free, 0, false);
}

/* transient errors of accept(): at most CONNECTION_ACCEPT_TRANSIENT_MAX calls in a row, then the event loop */
static void accept_retries_are_capped(gconstpointer data)
{
	enum connection_transport trans = GPOINTER_TO_INT(data);
	int port;
	struct connection *con = listener(trans, &port);
	g_atomic_int_set(&accept_calls, 0);
	g_atomic_int_set(&accept_fails, 4 * CONNECTION_ACCEPT_TRANSIENT_MAX);
	if( trans == connection_transport_tcp )
		connection_tcp_accept_cb(d.loop, &con->events.io_in, EV_READ);
	else
		connection_tls_accept_cb(d.loop, &con->events.io_in, EV_READ);
	g_assert_cmpint(g_atomic_int_get(&accept_calls), ==, CONNECTION_ACCEPT_TRANSIENT_MAX);
	/* back in the event loop, still listening */
	g_assert_true(ev_is_active(&con->events.io_in));
	g_assert_cmpint(con->socket, >=, 0);
	g_atomic_int_set(&accept_fails, 0);
	free_listener(con);
}

/* the origin hook closes the TLS listener: the loop accepts nothing more on it */
static struct connection *closing_listener;
static struct connection *accepted_by_hook;
static gint origins;
static void close_the_listener(struct connection *con, struct connection *origin)
{
	g_atomic_int_inc(&origins);
	accepted_by_hook = con;
	g_assert_true(origin == closing_listener);
	connection_close(origin);
}

static void tls_listener_closed_in_the_origin_hook(void)
{
	int port;
	struct connection *con = listener(connection_transport_tls, &port);
	closing_listener = con;
	con->protocol.origin = close_the_listener;
	/* two connections pending: the loop would take the second one after the first */
	int clients[2] = { client(port), client(port) };
	g_atomic_int_set(&accept_calls, 0);
	g_atomic_int_set(&accepts_on_closed, 0);
	g_atomic_int_set(&origins, 0);
	connection_tls_accept_cb(d.loop, &con->events.io_in, EV_READ);
	g_assert_cmpint(g_atomic_int_get(&origins), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&accepts_on_closed), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&accept_calls), ==, 1);
	g_assert_cmpint(con->socket, ==, -1);
	/* the accepted connection waits for its handshake: closed, then both are freed by the loop */
	connection_close(accepted_by_hook);
	close(clients[0]);
	close(clients[1]);
	run_frees();
}

/* ---- the download target filter of the core ---- */

static gboolean error_called;
static int last_error = -1;

static bool record_error(struct connection *con, enum connection_error error)
{
	(void)con;
	error_called = TRUE;
	last_error = error;
	return false;
}

/* the download policy of the test: 127.0.0.1 only */
static void allow_loopback(struct incident *i, void *ctx)
{
	(void)ctx;
	GString *address;
	if( incident_value_string_get(i, "address", &address) && strcmp(address->str, "127.0.0.1") == 0 )
		incident_value_int_set(i, "allow", 1);
}

/* a port of 127.0.0.1 that nobody listens on */
static int closed_port(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	g_assert_cmpint(bind(fd, (struct sockaddr *)&sa, sizeof(sa)), ==, 0);
	socklen_t size = sizeof(sa);
	g_assert_cmpint(getsockname(fd, (struct sockaddr *)&sa, &size), ==, 0);
	close(fd);
	return ntohs(sa.sin_port);
}

static void download_connect(const char *first, const char *second)
{
	error_called = FALSE;
	last_error = -1;
	struct connection *con = connection_new(connection_transport_tcp);
	con->protocol.ctx_new = no_ctx;
	con->protocol.error = record_error;
	con->download_guard = true;
	con->remote.port = htons(closed_port());
	connection_set_type(con, connection_type_connect);
	node_info_add_addr(&con->remote, first);
	node_info_add_addr(&con->remote, second);
	connection_connect_next_addr(con);
	gint64 end = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while( !error_called && g_get_monotonic_time() < end )
	{
		ev_run(d.loop, EVRUN_NOWAIT);
		g_usleep(10000);
	}
	g_assert_true(error_called);
	run_frees();
}

static void every_address_refused_is_econfiltered(void)
{
	download_connect("10.0.0.1", "192.0.2.1");
	g_assert_cmpint(last_error, ==, ECONFILTERED);
}

static void a_refused_and_an_attempted_address_is_econunreach(void)
{
	download_connect("10.0.0.1", "127.0.0.1");
	g_assert_cmpint(last_error, ==, ECONUNREACH);
	download_connect("127.0.0.1", "10.0.0.1");
	g_assert_cmpint(last_error, ==, ECONUNREACH);
}

static void the_errors_have_their_text(void)
{
	g_assert_cmpstr(connection_strerror(ECONUNREACH), ==, "could not connect host(s)");
	g_assert_cmpstr(connection_strerror(ECONMANY), ==, "too many connections");
	g_assert_cmpstr(connection_strerror(ECONFILTERED), ==, "download target refused by the filter");
	g_assert_null(connection_strerror((enum connection_error)3));
	g_assert_null(connection_strerror((enum connection_error)(ECONFILTERED + 1)));
}

/* ---- the lines of every connection: info, one warning a minute ---- */

static GPtrArray *infos;
static GPtrArray *warnings;

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	if( infos != NULL && (level & G_LOG_LEVEL_INFO) )
		g_ptr_array_add(infos, g_strdup(message));
	else if( warnings != NULL && (level & G_LOG_LEVEL_WARNING) )
		g_ptr_array_add(warnings, g_strdup(message));
	else if( level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING) )
		g_log_default_handler(domain, level, message, data);
}

static gint64 summary_now;
static GHashTable *summary_timers;  /* summary -> the time its timer fires (gint64 *) */

static gint64 summary_clock(void)
{
	return summary_now;
}

static bool summary_schedule(struct log_summary *s, double after)
{
	gint64 *at = g_new(gint64, 1);
	*at = summary_now + (gint64)(after * G_USEC_PER_SEC);
	g_hash_table_replace(summary_timers, s, at);
	return true;
}

static const struct log_summary_hooks summary_hooks = { summary_clock, summary_schedule };

static struct log_summary *const summaries[] = {
	&connection_accept_failed_summary, &connection_out_of_fds_summary, &connection_no_socket_summary,
	&connection_tcp_read_failed_summary, &connection_udp_read_failed_summary, &connection_udp_not_sent_summary,
	&connection_no_address_summary, &connection_accept_backoff_summary,
};

static void lines_start(void)
{
	infos = g_ptr_array_new_with_free_func(g_free);
	warnings = g_ptr_array_new_with_free_func(g_free);
	summary_now = 1000 * G_USEC_PER_SEC;
	summary_timers = g_hash_table_new_full(NULL, NULL, NULL, g_free);
	for( size_t i = 0; i < G_N_ELEMENTS(summaries); i++ )
	{
		log_summary_set_hooks(summaries[i], &summary_hooks);
		log_summary_reset(summaries[i]);
	}
}

/* the clock goes on by seconds, the timers on the way fire */
static void lines_advance(int seconds)
{
	summary_now += (gint64)seconds * G_USEC_PER_SEC;
	GHashTableIter it;
	gpointer key, value;
	GPtrArray *due = g_ptr_array_new();
	g_hash_table_iter_init(&it, summary_timers);
	while( g_hash_table_iter_next(&it, &key, &value) )
		if( *(gint64 *)value <= summary_now )
			g_ptr_array_add(due, key);
	for( guint i = 0; i < due->len; i++ )
	{
		g_hash_table_remove(summary_timers, due->pdata[i]);
		log_summary_due(due->pdata[i]);
	}
	g_ptr_array_free(due, TRUE);
}

static void lines_end(void)
{
	for( size_t i = 0; i < G_N_ELEMENTS(summaries); i++ )
	{
		log_summary_reset(summaries[i]);
		log_summary_set_hooks(summaries[i], NULL);
	}
	g_hash_table_destroy(summary_timers);
	g_ptr_array_free(infos, TRUE);
	g_ptr_array_free(warnings, TRUE);
	infos = NULL;
	warnings = NULL;
}

static guint lines_with(GPtrArray *lines, const char *prefix)
{
	guint n = 0;
	for( guint i = 0; i < lines->len; i++ )
		if( g_str_has_prefix(lines->pdata[i], prefix) )
			n++;
	return n;
}

static const char *last_line(GPtrArray *lines)
{
	g_assert_cmpuint(lines->len, >, 0);
	return lines->pdata[lines->len - 1];
}

/* the accept loops of TCP and TLS, three times: one info line each, one warning at once, one when its minute ends */
static void accept_retries_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	for( int i = 0; i < 3; i++ )
	{
		int port;
		enum connection_transport trans = i % 2 == 0 ? connection_transport_tcp : connection_transport_tls;
		struct connection *con = listener(trans, &port);
		g_atomic_int_set(&accept_fails, CONNECTION_ACCEPT_TRANSIENT_MAX);
		if( trans == connection_transport_tcp )
			connection_tcp_accept_cb(d.loop, &con->events.io_in, EV_READ);
		else
			connection_tls_accept_cb(d.loop, &con->events.io_in, EV_READ);
		g_atomic_int_set(&accept_fails, 0);
		free_listener(con);
		lines_advance(1);
	}
	g_assert_cmpuint(lines_with(infos, "accept() failed 16 times in a row on 127.0.0.1:"), ==, 3);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(g_str_has_prefix(warnings->pdata[0], "accepts failed in a row: 1 time(s) in the last minute, "
														"the last: 127.0.0.1:"));
	g_assert_true(g_str_has_suffix(warnings->pdata[0], " (Software caused connection abort)"));
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_true(g_str_has_prefix(last_line(warnings), "accepts failed in a row: 2 time(s) in the last minute, "));
	lines_end();
}

/* accept() fails with EMFILE: the listener pauses with an info line, one warning a minute for all listeners */
static void accept_backoffs_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	accept_fails_with = EMFILE;
	for( int i = 0; i < 4; i++ )
	{
		int port;
		struct connection *con = listener(i % 2 == 0 ? connection_transport_tcp : connection_transport_tls, &port);
		g_atomic_int_set(&accept_fails, 1);
		if( i % 2 == 0 )
			connection_tcp_accept_cb(d.loop, &con->events.io_in, EV_READ);
		else
			connection_tls_accept_cb(d.loop, &con->events.io_in, EV_READ);
		/* paused: no watcher, the retry timer runs */
		g_assert_false(ev_is_active(&con->events.io_in));
		g_assert_true(ev_is_active(&con->events.accept_retry_timeout));
		free_listener(con);
		lines_advance(1);
	}
	accept_fails_with = 0;
	g_atomic_int_set(&accept_fails, 0);
	g_assert_cmpuint(lines_with(infos, "accept() failed on 127.0.0.1:"), ==, 4);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(g_str_has_prefix(warnings->pdata[0], "listeners paused after accept() failed: 1 time(s) in the last "
														"minute, the last: 127.0.0.1:"));
	g_assert_true(g_str_has_suffix(warnings->pdata[0], " (Too many open files)"));
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_true(g_str_has_prefix(last_line(warnings), "listeners paused after accept() failed: 3 time(s) "));
	lines_end();
}

/* above 70 % of the fds the accepted connections are closed: one info line each, one warning a minute */
static void connections_closed_for_fds_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	int limit = d.limits.fds;
	d.limits.fds = 4;
	int port;
	struct connection *con = listener(connection_transport_tcp, &port);
	int clients[3] = { client(port), client(port), client(port) };
	connection_tcp_accept_cb(d.loop, &con->events.io_in, EV_READ);
	free_listener(con);
	struct connection *tls = listener(connection_transport_tls, &port);
	int tls_client = client(port);
	connection_tls_accept_cb(d.loop, &tls->events.io_in, EV_READ);
	free_listener(tls);
	d.limits.fds = limit;
	g_assert_cmpuint(lines_with(infos, "Running out of fds, closing connection (fd "), ==, 4);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(g_str_has_prefix(warnings->pdata[0], "connections closed for running out of fds: "
														"1 connection(s) in the last minute, the last: fd "));
	g_assert_true(g_str_has_suffix(warnings->pdata[0], ", limit 4, applied limit 2"));
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_true(g_str_has_prefix(last_line(warnings), "connections closed for running out of fds: 3 connection(s) "));
	for( int i = 0; i < 3; i++ )
		close(clients[i]);
	close(tls_client);
	run_frees();
	lines_end();
}

/* no socket for a connection (EMFILE): one info line each, one warning a minute */
static void connections_without_a_socket_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	socket_fails_with = EMFILE;
	for( int i = 0; i < 5; i++ )
	{
		error_called = FALSE;
		struct connection *con = connection_new(connection_transport_udp);
		con->protocol.error = record_error;
		g_assert_false(connection_bind(con, "127.0.0.1", 0, NULL));
		g_assert_true(error_called);
		lines_advance(1);
	}
	socket_fails_with = 0;
	g_assert_cmpuint(lines_with(infos, "socket() failed for con "), ==, 5);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(warnings->pdata[0], ==, "connections without a socket: 1 connection(s) in the last minute, "
											"the last: Too many open files");
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(last_line(warnings), ==, "connections without a socket: 4 connection(s) in the last minute, "
											 "the last: Too many open files");
	run_frees();
	lines_end();
}

/* an accepted connection whose address can not be read (not a client that is gone): info, one warning a minute */
static void connections_without_their_address_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	int port;
	struct connection *con = listener(connection_transport_tcp, &port);
	int clients[3] = { client(port), client(port), client(port) };
	getpeername_fails_with = ENOBUFS;
	connection_tcp_accept_cb(d.loop, &con->events.io_in, EV_READ);
	getpeername_fails_with = 0;
	free_listener(con);
	g_assert_cmpuint(lines_with(infos, "getpeername failed (No buffer space available)"), ==, 3);
	g_assert_cmpuint(lines_with(infos, "accepting connection failed, closing connection"), ==, 3);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(warnings->pdata[0], ==, "connections without their address: 1 connection(s) in the last minute, "
											"the last: getpeername, No buffer space available");
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(last_line(warnings), ==, "connections without their address: 2 connection(s) in the last minute, "
											 "the last: getpeername, No buffer space available");
	for( int i = 0; i < 3; i++ )
		close(clients[i]);
	run_frees();
	lines_end();
}

/* a TCP read that fails (not a reset of the client): an info line, one warning a minute */
static struct connection *accepted_tcp;
static void keep_accepted(struct connection *con, struct connection *origin)
{
	(void)origin;
	accepted_tcp = con;
}

static void no_established(struct connection *con)
{
	(void)con;
}

static void tcp_reads_that_fail_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	int port;
	struct connection *con = listener(connection_transport_tcp, &port);
	con->protocol.origin = keep_accepted;
	con->protocol.established = no_established;
	int clients[3];
	for( int i = 0; i < 3; i++ )
	{
		clients[i] = client(port);
		accepted_tcp = NULL;
		connection_tcp_accept_cb(d.loop, &con->events.io_in, EV_READ);
		g_assert_nonnull(accepted_tcp);
		recv_fails_with = EIO;
		connection_tcp_io_in_cb(d.loop, &accepted_tcp->events.io_in, EV_READ);
		recv_fails_with = 0;
		lines_advance(1);
	}
	free_listener(con);
	g_assert_cmpuint(lines_with(infos, "recv failed size -1 recv_size "), ==, 3);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(g_str_has_prefix(warnings->pdata[0], "TCP reads failed: 1 connection(s) in the last minute, "
														"the last: Input/output error, connection 127.0.0.1:"));
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_true(g_str_has_prefix(last_line(warnings), "TCP reads failed: 2 connection(s) in the last minute, "));
	for( int i = 0; i < 3; i++ )
		close(clients[i]);
	run_frees();
	lines_end();
}

/* a UDP read or reply that fails: an info line, one warning a minute */
static void udp_reads_and_replies_that_fail_are_info_and_one_warning_a_minute(void)
{
	lines_start();
	struct connection *con = connection_new(connection_transport_udp);
	con->protocol.ctx_new = no_ctx;
	g_assert_true(connection_bind(con, "127.0.0.1", 0, NULL));
	/* the client of the session */
	g_strlcpy(con->remote.node_string, "198.51.100.4:6969", sizeof(con->remote.node_string));
	recvmsg_fails_with = ECONNREFUSED;
	for( int i = 0; i < 4; i++ )
	{
		connection_udp_io_in_cb(d.loop, &con->events.io_in, EV_READ);
		lines_advance(1);
	}
	recvmsg_fails_with = 0;
	sendmsg_fails_with = EINVAL;
	for( int i = 0; i < 4; i++ )
	{
		struct udp_packet *packet = g_malloc0(sizeof(struct udp_packet));
		struct sockaddr_in *to = (struct sockaddr_in *)&packet->to;
		to->sin_family = AF_INET;
		to->sin_port = htons(9);
		to->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		memcpy(&packet->from, &con->local.addr, sizeof(packet->from));
		packet->data = g_string_new("reply");
		GList *packets = g_list_append(NULL, packet);
		_connection_send_packets(con, con->socket, &packets);
		g_assert_null(packets);
		lines_advance(1);
	}
	sendmsg_fails_with = 0;
	g_assert_cmpuint(lines_with(infos, "connection error -1 Connection refused (198.51.100.4:6969)"), ==, 4);
	g_assert_cmpuint(lines_with(infos, "sendtofrom failed Invalid argument (198.51.100.4:6969)"), ==, 4);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(warnings->pdata[0], ==, "UDP reads failed: 1 read(s) in the last minute, the last: "
											"Connection refused (198.51.100.4:6969)");
	g_assert_cmpstr(warnings->pdata[1], ==, "UDP replies not sent: 1 packet(s) in the last minute, the last: "
											"Invalid argument (198.51.100.4:6969)");
	lines_advance(60);
	g_assert_cmpuint(warnings->len, ==, 4);
	ev_io_stop(d.loop, &con->events.io_in);
	close(con->socket);
	con->socket = -1;
	connection_free_cb(d.loop, &con->events.free, 0, false);
	lines_end();
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
	d.loop = ev_loop_new(0);
	d.ihandlers = &ih;
	d.config = g_key_file_new();
	/* the accept loops close connections above 70 % of it */
	d.limits.fds = 1024;
	g_dionaea = &d;
	ihandler_new("dionaea.download.resolve", allow_loopback, NULL);
	g_test_add_func("/connection/listen-failure-forgets-the-socket", listen_failure_forgets_the_socket);
	g_test_add_data_func("/connection/accept-retries-are-capped/tcp", GINT_TO_POINTER(connection_transport_tcp),
						 accept_retries_are_capped);
	g_test_add_data_func("/connection/accept-retries-are-capped/tls", GINT_TO_POINTER(connection_transport_tls),
						 accept_retries_are_capped);
	g_test_add_func("/connection/tls-listener-closed-in-the-origin-hook", tls_listener_closed_in_the_origin_hook);
	g_test_add_func("/connection/download/every-address-refused", every_address_refused_is_econfiltered);
	g_test_add_func("/connection/download/refused-and-attempted", a_refused_and_an_attempted_address_is_econunreach);
	g_test_add_func("/connection/strerror", the_errors_have_their_text);
	g_test_add_func("/connection/lines/accept-retries", accept_retries_are_info_and_one_warning_a_minute);
	g_test_add_func("/connection/lines/accept-backoff", accept_backoffs_are_info_and_one_warning_a_minute);
	g_test_add_func("/connection/lines/out-of-fds", connections_closed_for_fds_are_info_and_one_warning_a_minute);
	g_test_add_func("/connection/lines/no-socket", connections_without_a_socket_are_info_and_one_warning_a_minute);
	g_test_add_func("/connection/lines/tcp-read", tcp_reads_that_fail_are_info_and_one_warning_a_minute);
	g_test_add_func("/connection/lines/no-address", connections_without_their_address_are_info_and_one_warning_a_minute);
	g_test_add_func("/connection/lines/udp", udp_reads_and_replies_that_fail_are_info_and_one_warning_a_minute);
	int result = g_test_run();
	ev_loop_destroy(d.loop);
	g_key_file_free(d.config);
	return result;
}
