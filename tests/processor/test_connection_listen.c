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
 * Built from the sources of dionaea without dionaea.c (g_dionaea is here);
 * listen(), close(), accept() and the bind of the privileged child are wrapped
 * (-Wl,--wrap=listen,--wrap=close,--wrap=accept,--wrap=pchild_sent_bind).
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
int __real_accept(int fd, struct sockaddr *addr, socklen_t *len);
int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *len)
{
	g_atomic_int_inc(&accept_calls);
	if( fd == -1 )
		g_atomic_int_inc(&accepts_on_closed);
	if( g_atomic_int_get(&accept_fails) > 0 )
	{
		g_atomic_int_add(&accept_fails, -1);
		errno = ECONNABORTED;
		return -1;
	}
	return __real_accept(fd, addr, len);
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

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
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
	int result = g_test_run();
	ev_loop_destroy(d.loop);
	g_key_file_free(d.config);
	return result;
}
