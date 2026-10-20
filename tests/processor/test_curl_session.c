/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The sessions of the curl module (modules/curl/module.c, included here for
 * its static functions) when no temp file can be made (no descriptor left, a
 * full disk): the download or the upload is dropped with one warning.
 *
 * The end of a download that does not complete: a target the download target
 * filter refused (the open-socket callback) is download_refused(), any other
 * failure download_failed() with its reason (src/download_log.c makes the log
 * lines); curl's text of a refused socket is not used. A refusal is only a
 * refusal when the filter refused every address of the last hop (no address of
 * it was attempted); a response of a server (a redirect) starts a new hop.
 */
#include "../../modules/curl/module.c"

struct dionaea *g_dionaea;

/* ---- the temp files: none ---- */

static gint tempfiles_asked;

struct tempfile *tempincoming_new(const char *download_dir, char *prefix)
{
	(void)download_dir;
	(void)prefix;
	g_atomic_int_inc(&tempfiles_asked);
	return NULL;
}

#define NOT_REACHED(ret, name, ...) ret name(__VA_ARGS__) { g_assert_not_reached(); }
NOT_REACHED(void, tempfile_close, struct tempfile *tf)
NOT_REACHED(void, tempfile_free, struct tempfile *tf)
NOT_REACHED(void, tempfile_unlink, struct tempfile *tf)
NOT_REACHED(struct ihandler *, ihandler_new, char *pattern, ihandler_cb cb, void *ctx)
NOT_REACHED(struct incident *, incident_new, const char *origin)
NOT_REACHED(void, incident_free, struct incident *e)
NOT_REACHED(void, incident_report, struct incident *i)
NOT_REACHED(bool, incident_value_con_set, struct incident *e, const char *name, struct connection *val)
NOT_REACHED(bool, incident_value_string_set, struct incident *e, const char *name, GString *str)

/* ---- the download target filter and the log lines of failed downloads ---- */

static gboolean allow_targets;
static GPtrArray *filter_asked;
static GPtrArray *refused_urls;
static GPtrArray *failed;   /* "<url> (<reason>)" */

bool download_destination_allowed(const char *address)
{
	g_ptr_array_add(filter_asked, g_strdup(address));
	return allow_targets;
}

void download_refused(const char *url)
{
	g_ptr_array_add(refused_urls, g_strdup(url));
}

void download_failed(const char *url, const char *reason)
{
	g_ptr_array_add(failed, g_strdup_printf("%s (%s)", url, reason));
}

/* ---- the connection of the incident ---- */

static gint refs;
static struct connection *the_con;

int connection_ref(struct connection *con)
{
	g_assert_true(con == the_con);
	return ++refs;
}

int connection_unref(struct connection *con)
{
	g_assert_true(con == the_con);
	g_assert_cmpint(refs, >, 0);
	return --refs;
}

/* ---- incidents: a table of name -> struct opaque_data ---- */

static struct incident *test_incident(void)
{
	struct incident *i = g_malloc0(sizeof(*i));
	i->origin = g_strdup("test");
	i->data = g_hash_table_new(g_str_hash, g_str_equal);
	return i;
}

static void test_incident_string(struct incident *i, const char *name, const char *value)
{
	struct opaque_data *d = g_malloc0(sizeof(*d));
	d->type = opaque_type_string;
	d->name = g_strdup(name);
	d->opaque.string = g_string_new(value);
	g_hash_table_insert(i->data, d->name, d);
}

static void test_incident_free(struct incident *i)
{
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, i->data);
	while( g_hash_table_iter_next(&iter, &key, &value) )
	{
		struct opaque_data *d = value;
		g_string_free(d->opaque.string, TRUE);
		g_free(d->name);
		g_free(d);
	}
	g_hash_table_destroy(i->data);
	g_free(i->origin);
	g_free(i);
}

static bool value_get(struct incident *e, const char *name, enum opaque_data_type type, GString **str)
{
	struct opaque_data *d = g_hash_table_lookup(e->data, name);
	if( d == NULL || d->type != type )
		return false;
	*str = d->opaque.string;
	return true;
}

bool incident_value_string_get(struct incident *e, const char *name, GString **str)
{
	return value_get(e, name, opaque_type_string, str);
}

bool incident_value_bytes_get(struct incident *e, const char *name, GString **str)
{
	return value_get(e, name, opaque_type_bytes, str);
}

bool incident_value_con_get(struct incident *e, const char *name, struct connection **con)
{
	(void)e;
	if( strcmp(name, "con") != 0 || the_con == NULL )
		return false;
	*con = the_con;
	return true;
}

/* ---- the tests ---- */

static GPtrArray *warnings;

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	if( level & (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE) )
		return;
	if( level & G_LOG_LEVEL_WARNING )
	{
		g_ptr_array_add(warnings, g_strdup(message));
		return;
	}
	g_log_default_handler(domain, level, message, data);
}

static void download_without_tempfile(void)
{
	struct connection con;
	memset(&con, 0, sizeof(con));
	g_strlcpy(con.local.ip_string, "10.0.0.1", sizeof(con.local.ip_string));
	the_con = &con;
	g_ptr_array_set_size(warnings, 0);
	g_atomic_int_set(&tempfiles_asked, 0);

	struct incident *i = test_incident();
	session_download_new(i, "http://192.0.2.1/x.exe");
	g_assert_cmpint(g_atomic_int_get(&tempfiles_asked), ==, 1);
	/* nothing queued, the connection given back */
	g_assert_cmpint(curl_runtime.queued, ==, 0);
	g_assert_cmpint(refs, ==, 0);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_nonnull(strstr(g_ptr_array_index(warnings, 0), "Could not create the file of the download"));

	test_incident_free(i);
	the_con = NULL;
}

static void upload_without_tempfile(void)
{
	g_ptr_array_set_size(warnings, 0);
	g_atomic_int_set(&tempfiles_asked, 0);

	struct incident *i = test_incident();
	test_incident_string(i, "_url", "http://192.0.2.1/submit");
	test_incident_string(i, "_callback", "dionaea.modules.python.test.result");
	test_incident_string(i, "_userdata", "x");
	test_incident_string(i, "file", "/tmp/sample");
	session_upload_new(i);
	g_assert_cmpint(g_atomic_int_get(&tempfiles_asked), ==, 1);
	/* nothing queued: its end would have closed the file that is not there */
	g_assert_cmpint(curl_runtime.queued, ==, 0);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_nonnull(strstr(g_ptr_array_index(warnings, 0), "Could not create the file of the upload"));

	test_incident_free(i);
}

static void reset_downloads(void)
{
	g_ptr_array_set_size(warnings, 0);
	g_ptr_array_set_size(filter_asked, 0);
	g_ptr_array_set_size(refused_urls, 0);
	g_ptr_array_set_size(failed, 0);
}

static struct curl_sockaddr ipv4(const char *address)
{
	struct curl_sockaddr a;
	memset(&a, 0, sizeof(a));
	a.family = AF_INET;
	a.socktype = SOCK_STREAM;
	a.protocol = IPPROTO_TCP;
	a.addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *in = (struct sockaddr_in *)&a.addr;
	in->sin_family = AF_INET;
	in->sin_port = htons(80);
	g_assert_cmpint(inet_pton(AF_INET, address, &in->sin_addr), ==, 1);
	return a;
}

static struct session *download_session(void)
{
	struct session *session = g_malloc0(sizeof(*session));
	session->type = session_type_download;
	session->url = g_strdup("http://192.0.2.1/x.exe");
	return session;
}

/* a refused target: no socket, download_refused() with the url curl was at, no warning */
static void a_refused_target_is_reported_as_refused(void)
{
	reset_downloads();
	allow_targets = FALSE;
	struct session *session = download_session();
	struct curl_sockaddr a = ipv4("127.0.0.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &a), ==, CURL_SOCKET_BAD);
	g_assert_cmpuint(filter_asked->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(filter_asked, 0), ==, "127.0.0.1");
	g_strlcpy(session->error, "failed to open socket: Success", sizeof(session->error));
	download_done(session, CURLE_COULDNT_CONNECT, "http://127.0.0.1/redirected");
	g_assert_cmpuint(refused_urls->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(refused_urls, 0), ==, "http://127.0.0.1/redirected");
	g_assert_cmpuint(failed->len, ==, 0);
	g_assert_cmpuint(warnings->len, ==, 0);
	session_free(session);
}

/* an allowed target that does not answer: download_failed() with curl's text */
static void a_failure_is_reported_with_its_reason(void)
{
	reset_downloads();
	allow_targets = TRUE;
	struct session *session = download_session();
	struct curl_sockaddr a = ipv4("192.0.2.1");
	curl_socket_t fd = download_open_socket(session, CURLSOCKTYPE_IPCXN, &a);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	g_strlcpy(session->error, "Failed to connect to 192.0.2.1 port 80: Connection refused", sizeof(session->error));
	download_done(session, CURLE_COULDNT_CONNECT, "http://192.0.2.1/x.exe");
	g_assert_cmpuint(refused_urls->len, ==, 0);
	g_assert_cmpuint(failed->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(failed, 0), ==,
					"http://192.0.2.1/x.exe (Failed to connect to 192.0.2.1 port 80: Connection refused)");
	g_assert_cmpuint(warnings->len, ==, 0);
	session_free(session);
}

/* a refused address, then an allowed one that fails: a failure, curl gave up at the allowed one */
static void an_allowed_address_after_a_refused_one_is_a_failure(void)
{
	reset_downloads();
	struct session *session = download_session();
	allow_targets = FALSE;
	struct curl_sockaddr a = ipv4("10.0.0.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &a), ==, CURL_SOCKET_BAD);
	allow_targets = TRUE;
	struct curl_sockaddr b = ipv4("192.0.2.1");
	curl_socket_t fd = download_open_socket(session, CURLSOCKTYPE_IPCXN, &b);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	download_done(session, CURLE_COULDNT_CONNECT, "http://192.0.2.1/x.exe");
	g_assert_cmpuint(refused_urls->len, ==, 0);
	g_assert_cmpuint(failed->len, ==, 1);
	session_free(session);
}

/* a refusal and another error of curl (a timeout): a failure; without curl's text the text of the code */
static void another_error_after_a_refusal_is_a_failure(void)
{
	reset_downloads();
	allow_targets = FALSE;
	struct session *session = download_session();
	struct curl_sockaddr a = ipv4("10.0.0.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &a), ==, CURL_SOCKET_BAD);
	download_done(session, CURLE_OPERATION_TIMEDOUT, "http://192.0.2.1/x.exe");
	g_assert_cmpuint(refused_urls->len, ==, 0);
	g_assert_cmpuint(failed->len, ==, 1);
	char *expected = g_strdup_printf("http://192.0.2.1/x.exe (%s)", curl_easy_strerror(CURLE_OPERATION_TIMEDOUT));
	g_assert_cmpstr(g_ptr_array_index(failed, 0), ==, expected);
	g_free(expected);
	session_free(session);
}

/* an allowed address that fails, then a refused one: a failure, the real failure is not hidden */
static void a_refused_address_after_an_allowed_one_is_a_failure(void)
{
	reset_downloads();
	struct session *session = download_session();
	allow_targets = TRUE;
	struct curl_sockaddr a = ipv4("192.0.2.1");
	curl_socket_t fd = download_open_socket(session, CURLSOCKTYPE_IPCXN, &a);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	allow_targets = FALSE;
	struct curl_sockaddr b = ipv4("10.0.0.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &b), ==, CURL_SOCKET_BAD);
	download_done(session, CURLE_COULDNT_CONNECT, "http://192.0.2.1/x.exe");
	g_assert_cmpuint(refused_urls->len, ==, 0);
	g_assert_cmpuint(failed->len, ==, 1);
	session_free(session);
}

/* a redirect (a response of the first server) to a refused target: a refusal of the new url */
static void a_refused_redirect_is_a_refusal(void)
{
	reset_downloads();
	struct session *session = download_session();
	allow_targets = TRUE;
	struct curl_sockaddr a = ipv4("192.0.2.1");
	curl_socket_t fd = download_open_socket(session, CURLSOCKTYPE_IPCXN, &a);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	char status[] = "HTTP/1.1 302 Found\r\n";
	char location[] = "Location: http://127.0.0.1/next\r\n";
	g_assert_cmpuint(download_header_cb(status, 1, strlen(status), session), ==, strlen(status));
	g_assert_cmpuint(download_header_cb(location, 1, strlen(location), session), ==, strlen(location));
	allow_targets = FALSE;
	struct curl_sockaddr b = ipv4("127.0.0.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &b), ==, CURL_SOCKET_BAD);
	download_done(session, CURLE_COULDNT_CONNECT, "http://127.0.0.1/next");
	g_assert_cmpuint(refused_urls->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(refused_urls, 0), ==, "http://127.0.0.1/next");
	g_assert_cmpuint(failed->len, ==, 0);
	session_free(session);
}

/* sockets of another purpose and addresses of another family are not the filter's */
static void other_sockets_are_no_refusal(void)
{
	reset_downloads();
	allow_targets = TRUE;
	struct session *session = download_session();
	struct curl_sockaddr a = ipv4("192.0.2.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_ACCEPT, &a), ==, CURL_SOCKET_BAD);
	a.family = AF_UNIX;
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &a), ==, CURL_SOCKET_BAD);
	g_assert_cmpuint(filter_asked->len, ==, 0);
	/* an address of another family counts as attempted: a refusal after it is no refusal */
	allow_targets = FALSE;
	struct curl_sockaddr b = ipv4("10.0.0.1");
	g_assert_cmpint(download_open_socket(session, CURLSOCKTYPE_IPCXN, &b), ==, CURL_SOCKET_BAD);
	download_done(session, CURLE_COULDNT_CONNECT, "http://192.0.2.1/x.exe");
	g_assert_cmpuint(refused_urls->len, ==, 0);
	g_assert_cmpuint(failed->len, ==, 1);
	session_free(session);
}

/* the warnings of the module name the url of the client as printable text, at most 256 characters */
static void the_warnings_hold_the_url_as_plain_text(void)
{
	g_ptr_array_set_size(warnings, 0);
	struct incident *i = test_incident();
	session_download_new(i, "http://192.0.2.1/a\nb \x1b[31m");
	test_incident_free(i);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==, "Could not create the file of the download of "
					"http://192.0.2.1/a?b ?[31m, the download is dropped");

	g_ptr_array_set_size(warnings, 0);
	i = test_incident();
	char *long_url = g_strdup_printf("http://192.0.2.1/%0400d", 0);
	test_incident_string(i, "_url", long_url);
	test_incident_string(i, "_callback", "dionaea.modules.python.test.result");
	session_upload_new(i);
	test_incident_free(i);
	g_assert_cmpuint(warnings->len, ==, 1);
	char *expected = g_strdup_printf("Could not create the file of the upload to %.256s..., the upload is dropped", long_url);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==, expected);
	g_free(expected);

	/* the end of an upload that failed */
	g_ptr_array_set_size(warnings, 0);
	struct session *session = g_malloc0(sizeof(*session));
	session->type = session_type_upload;
	session->url = g_strdup("http://192.0.2.1/submit");
	g_strlcpy(session->error, "Failed\r\nb \x1b]0;t\x07", sizeof(session->error));
	upload_done(session, CURLE_COULDNT_CONNECT, "http://192.0.2.1/next\n");
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==,
					"UPLOAD FAIL: http://192.0.2.1/next? => (7) Failed??b ?]0;t?");
	session_free(session);
	g_free(long_url);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	warnings = g_ptr_array_new_with_free_func(g_free);
	filter_asked = g_ptr_array_new_with_free_func(g_free);
	refused_urls = g_ptr_array_new_with_free_func(g_free);
	failed = g_ptr_array_new_with_free_func(g_free);
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
	g_assert_cmpint(curl_global_init(CURL_GLOBAL_ALL), ==, 0);
	curl_runtime.multi = curl_multi_init();
	curl_runtime.download_dir = g_strdup("/nonexistent");
	g_test_add_func("/curl/download/no-tempfile", download_without_tempfile);
	g_test_add_func("/curl/upload/no-tempfile", upload_without_tempfile);
	g_test_add_func("/curl/download/refused", a_refused_target_is_reported_as_refused);
	g_test_add_func("/curl/download/failed", a_failure_is_reported_with_its_reason);
	g_test_add_func("/curl/download/refused-then-failed", an_allowed_address_after_a_refused_one_is_a_failure);
	g_test_add_func("/curl/download/refused-then-timeout", another_error_after_a_refusal_is_a_failure);
	g_test_add_func("/curl/download/other-sockets", other_sockets_are_no_refusal);
	g_test_add_func("/curl/download/allowed-then-refused", a_refused_address_after_an_allowed_one_is_a_failure);
	g_test_add_func("/curl/download/refused-redirect", a_refused_redirect_is_a_refusal);
	g_test_add_func("/curl/warnings-plain-text", the_warnings_hold_the_url_as_plain_text);
	int result = g_test_run();
	curl_multi_cleanup(curl_runtime.multi);
	g_free(curl_runtime.download_dir);
	curl_global_cleanup();
	g_ptr_array_free(warnings, TRUE);
	g_ptr_array_free(filter_asked, TRUE);
	g_ptr_array_free(refused_urls, TRUE);
	g_ptr_array_free(failed, TRUE);
	return result;
}
