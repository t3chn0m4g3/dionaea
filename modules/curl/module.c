/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdio.h>

#include <curl/curl.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "module.h"
#include "incident.h"
#include "download_log.h"
#include "log_text.h"
#include "log.h"
#include "util.h"

#define D_LOG_DOMAIN "curl"

/* the downloads and uploads of every connection that are dropped or fail: an info line each, one
 * warning a minute of each summary (log_summary.h) */
static struct log_summary download_no_file = LOG_SUMMARY_INIT("downloads dropped, no file could be made", "download(s)");
static struct log_summary upload_no_file = LOG_SUMMARY_INIT("uploads dropped, no file could be made", "upload(s)");
static struct log_summary upload_failed = LOG_SUMMARY_INIT("uploads failed", "upload(s)");

static struct
{
	struct ev_timer timer_event;
	CURLM *multi;
	struct ihandler *download_ihandler;
	struct ihandler *upload_ihandler;
	int queued;
	int active;
	char *download_dir;
} curl_runtime;

enum session_type
{
	session_type_download,
	session_type_upload
};

struct session
{
	CURL *easy;
	char *url;
	char *laddr;
	char error[CURL_ERROR_SIZE];

	enum session_type type;
	union
	{
		struct
		{
			struct tempfile *file;
			struct connection *ctxcon;
			/* the addresses of this hop (a response of a server starts a new one): the
			 * download target filter refused one, one was attempted */
			bool refused_seen;
			bool allowed_seen;
		}download;

		struct
		{
			struct curl_httppost    *formpost;
			struct curl_httppost    *last;
			struct curl_slist       *headers;
			char 					*username;
			char 					*password;


			char 					*callback;
			char					*userdata;
			struct tempfile 		*file;
		}upload;
	}action;
};

struct session_socket
{
	curl_socket_t sockfd;
	struct session *session;
	int action;
	struct ev_io io;
};

static struct session *session_new(void)
{
	struct session *session;
	session = g_malloc0(sizeof(struct session));
	session->error[0]='\0';
	session->easy = curl_easy_init();
	return session;
}

static void session_free(struct session *session)
{
	g_free(session->url);
	if( session->laddr )
		g_free(session->laddr);
	switch( session->type )
	{
	case session_type_download:
		if( session->action.download.file )
		{
			tempfile_unlink(session->action.download.file);
			tempfile_free(session->action.download.file);
			session->action.download.file = NULL;
		}
		if( session->action.download.ctxcon != NULL )
			connection_unref(session->action.download.ctxcon);
		break;

	case session_type_upload:
		curl_formfree(session->action.upload.formpost);
		curl_slist_free_all(session->action.upload.headers);
		if( session->action.upload.username != NULL )
			g_free(session->action.upload.username);
		if( session->action.upload.password != NULL )
			g_free(session->action.upload.password);
		if( session->action.upload.callback != NULL )
			g_free(session->action.upload.callback);
		if( session->action.upload.userdata != NULL )
			g_free(session->action.upload.userdata);
		if( session->action.upload.file != NULL )
			tempfile_free(session->action.upload.file);
		break;
	}


	g_free(session);

}

static void timer_cb(struct ev_loop *loop,  struct ev_timer *w, int revents);

/*
 * The end of a download. One that does not complete is logged by download_log.c: a
 * target the download target filter refused (curl could not connect, and the filter
 * refused every address of the last hop, none was attempted; curl's text "failed to
 * open socket" is not used) as refused, any other end as a failure with its reason.
 * This is the rule of the core for the other download clients (ECONFILTERED).
 */
static void download_done(struct session *session, CURLcode result, const char *eff_url)
{
	const char *url = eff_url != NULL ? eff_url : session->url;
	if( result == CURLE_OK )
	{
		g_info("DOWNLOAD DONE: %s => (%d) %s", url, result, session->error);
		tempfile_close(session->action.download.file);

		struct incident *i = incident_new("dionaea.download.complete");
		incident_value_string_set(i, "path", g_string_new(session->action.download.file->path));
		incident_value_string_set(i, "url", g_string_new(session->url));
		if( session->action.download.ctxcon )
			incident_value_con_set(i, "con", session->action.download.ctxcon);

		incident_report(i);
		incident_free(i);
		return;
	}

	if( result == CURLE_COULDNT_CONNECT && session->action.download.refused_seen &&
		!session->action.download.allowed_seen )
		download_refused(url);
	else
		download_failed(url, session->error[0] != '\0' ? session->error : curl_easy_strerror(result));
	if( session->action.download.file != NULL )
		tempfile_close(session->action.download.file);
}

/* An upload that failed: an info line and the summary, the url and curl's text as printable text (log_text.h) */
static void upload_done(struct session *session, CURLcode result, const char *eff_url)
{
	char *url = log_text_new(eff_url != NULL ? eff_url : session->url, "(no url)");
	char *error = log_text_new(session->error, "");
	g_info("UPLOAD FAIL: %s => (%d) %s", url, result, error);
	log_summary_addf(&upload_failed, "%s => (%d) %s", url, result, error);
	g_free(error);
	g_free(url);

	if( session->action.upload.callback == NULL )
		return;

	tempfile_close(session->action.upload.file);
	tempfile_unlink(session->action.upload.file);
}

/* Update the event timer after curl_multi library calls */
static int multi_timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
	g_debug("%s %li", __PRETTY_FUNCTION__,  timeout_ms);
	ev_timer_stop(g_dionaea->loop, &curl_runtime.timer_event);
	/* -1: libcurl wants no timer.
	 * 0: libcurl wants a call of curl_multi_socket_action() right away. This
	 * callback runs inside of libcurl (e.g. from curl_multi_add_handle()), where
	 * libcurl refuses a call of its API (CURLM_RECURSIVE_API_CALL), so it is
	 * done by the next iteration of the event loop. */
	if( timeout_ms >= 0 )
	{
		double  t = (double) timeout_ms / 1000.0;
		ev_timer_init(&curl_runtime.timer_event, timer_cb, t, 0.);
		ev_timer_start(g_dionaea->loop, &curl_runtime.timer_event);
	}
	return 0;
}

/* Check for completed transfers, and remove their easy handles */
static void check_run_count(void)
{
	g_debug("%s queued %i active %i", __PRETTY_FUNCTION__, curl_runtime.queued, curl_runtime.active);
	if( curl_runtime.queued > curl_runtime.active )
	{
		char *eff_url=NULL;
		CURLMsg *msg;
		int msgs_left;
		struct session *session=NULL;
		CURL*easy;

		g_debug("REMAINING: %d", curl_runtime.queued);
		easy=NULL;
		while( (msg = curl_multi_info_read(curl_runtime.multi, &msgs_left)) )
		{
			if( msg->msg == CURLMSG_DONE )
			{
				curl_runtime.queued--;

				easy=msg->easy_handle;
				curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&session );
				curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);

				switch( session->type )
				{
				case session_type_download:
					download_done(session, msg->data.result, eff_url);
					break;

				case session_type_upload:
					if( msg->data.result == CURLE_OK )
					{
						g_info("UPLOAD DONE: %s => (%d) %s", eff_url, msg->data.result, session->error);

						if( session->action.upload.callback == NULL )
							break;

						tempfile_close(session->action.upload.file);
						// if we have a callback, call the callback
						struct incident *i = incident_new(session->action.upload.callback);
						incident_value_string_set(i, "path", g_string_new(session->action.upload.file->path));
						if( session->action.upload.userdata != NULL )
							incident_value_string_set(i, "_userdata", g_string_new(session->action.upload.userdata));
						incident_report(i);
						incident_free(i);
						tempfile_unlink(session->action.upload.file);
					} else
					{
						upload_done(session, msg->data.result, eff_url);
					}
					break;
				}

				curl_multi_remove_handle(curl_runtime.multi, easy);
				curl_easy_cleanup(easy);
				session_free(session);
			}
		}
	}
}

static void event_cb(struct ev_loop *loop,  struct ev_io *w, int revents)
{
	g_debug("%s  w %p revents %i", __PRETTY_FUNCTION__, w, revents);
	CURLMcode rc;

	int action = (revents&EV_READ?CURL_POLL_IN:0)|(revents&EV_WRITE?CURL_POLL_OUT:0);
	do
	{
		rc = curl_multi_socket_action(curl_runtime.multi, w->fd, action, &curl_runtime.active);
	} while( rc == CURLM_CALL_MULTI_PERFORM );

	check_run_count();

	if( curl_runtime.queued <= 0 )
	{
		g_debug("last transfer done, kill timeout");
		ev_timer_stop(g_dionaea->loop, &curl_runtime.timer_event);
	}
}



static void timer_cb(struct ev_loop *loop,  struct ev_timer *w, int revents)
{
	g_debug("%s  w %p revents %i", __PRETTY_FUNCTION__, w, revents);
	CURLMcode rc;
	do
	{
		rc = curl_multi_socket_action(curl_runtime.multi, CURL_SOCKET_TIMEOUT, 0, &curl_runtime.active);
	} while( rc == CURLM_CALL_MULTI_PERFORM );
	check_run_count();
}

static void session_info_free(struct session_socket *info)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	if( info )
	{
		if( ev_is_active(&info->io) )
			ev_io_stop(g_dionaea->loop, &info->io);
		g_free(info);
	}
}

static void session_set_socket(struct session *session, struct session_socket *info, curl_socket_t s, int action)
{
	g_debug("%s", __PRETTY_FUNCTION__);

	int kind = (action&CURL_POLL_IN?EV_READ:0)|(action&CURL_POLL_OUT?EV_WRITE:0);

	info->sockfd = s;
	info->action = action;
	info->session = session;
	if( ev_is_active(&info->io) )
		ev_io_stop(g_dionaea->loop, &info->io);
	ev_io_init(&info->io, event_cb, info->sockfd, kind);
	if( kind != 0 )
		ev_io_start(g_dionaea->loop, &info->io);
}

/* CURLMOPT_SOCKETFUNCTION */
static int curl_socketfunction_cb(CURL *easy, curl_socket_t s, int action, void *cbp, void *sockp)
{
	g_debug("%s e %p s %i what %i cbp %p sockp %p", __PRETTY_FUNCTION__, easy, s, action, cbp, sockp);

	struct session_socket *info = (struct session_socket*) sockp;
	struct session *session;
	curl_easy_getinfo(easy, CURLOPT_PRIVATE, &session);

#ifdef DEBUG
	const char *action_str[]={ "none", "IN", "OUT", "INOUT", "REMOVE"};
#endif

	g_debug("socket callback: s=%d e=%p what=%s ", s, easy, action_str[action]);

	if( action == CURL_POLL_REMOVE )
	{
		session_info_free(info);
	} else
	{
		if( !info )
		{
			g_debug("Adding data: %s", action_str[action]);
			info = g_malloc0(sizeof(struct session_socket));
			session_set_socket(session, info, s, action);
			curl_multi_assign(curl_runtime.multi, s, info);
		} else
		{
			g_debug("Changing action from %s to %s", action_str[info->action], action_str[action]);
			session_set_socket(session, info, s, action);
		}
	}
	return 0;
}



/* CURLOPT_WRITEFUNCTION */
static size_t curl_writefunction_cb(void *ptr, size_t size, size_t nmemb, void *data)
{

	struct session *session = (struct session *) data;
	if( session->type == session_type_download )
	{
		g_debug("session %p file %i", session, session->action.download.file->fd);
		if( write(session->action.download.file->fd, ptr, size*nmemb) != size*nmemb)
			return -1;
	}else
	if( session->type == session_type_upload )
	{
		if( session->action.upload.file == NULL )
			return size*nmemb;

		g_debug("session %p file %i", session, session->action.upload.file->fd);
		if( write(session->action.upload.file->fd, ptr, size*nmemb) != size*nmemb)
			return -1;
	}

	return size * nmemb;
}

/* CURLOPT_PROGRESSFUNCTION */
static int curl_progressfunction_cb (void *p, double dltotal, double dlnow, double ult, double uln)
{
#ifdef DEBUG
	struct session *session = (struct session *)p;
	g_debug("Progress: %s (down:%g/%g up:%g/%g)", session->url, dlnow, dltotal, uln, ult);
#endif
	return 0;
}

/* CURLOPT_DEBUGFUNCTION */
static int curl_debugfunction_cb(CURL *easy, curl_infotype type, char *data, size_t size, void *userp)
{

	struct session *session = NULL;
	curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&session);
	switch( type )
	{
	case CURLINFO_TEXT:
		{
			char *text = g_strdup(data);
			int len = strlen(text);
			if( text[len-1] == '\n' )
				text[len-1] = '\0';
			g_debug("%s: %s", session->url, text);
			g_free(text);
		}
		break;

	case CURLINFO_HEADER_OUT:
	case CURLINFO_DATA_OUT:
	case CURLINFO_SSL_DATA_OUT:
	case CURLINFO_HEADER_IN:
	case CURLINFO_DATA_IN:
	case CURLINFO_SSL_DATA_IN:
	default:
		break;
	}

	return 0;
}

void session_upload_new(struct incident *i)
{
	GHashTableIter iter;
	gpointer key, value;
	GString *gstemp;
	struct session *session = NULL;
	char *url = NULL;


	if (incident_value_string_get(i, "_url", &gstemp) == false )
	{
		g_debug("dionaea.upload.request got no _url in incident!");
		return;
	}

	session = session_new();

	session->type = session_type_upload;

	url = gstemp->str;
	session->url = g_strdup(url);

	g_hash_table_iter_init (&iter, i->data);

	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		char *name = key;
		struct opaque_data *d = value;
		char name_and_param[1024];
		if( d->type == opaque_type_int )
		{
			g_warning("incident key %s has integer value. all post fields must be string values.", name);
		} else
		if( d->type == opaque_type_string)
		{
			/* ignore help field values */
			if( strstr(name, "_ct") != NULL ||
				strcmp(name, "_url") == 0)
				continue;

			if( strcmp(name, "_callback") == 0 )
			{ /* incident callback */
				session->action.upload.callback = g_strdup(d->opaque.string->str);
				session->action.upload.file = tempincoming_new(curl_runtime.download_dir, "httpupload-");
			}else
			if( strcmp(name, "_userdata") == 0 )
			{ /* incident callback userdata */
				session->action.upload.userdata = g_strdup(d->opaque.string->str);
			}else
			if( strcmp(name, "user") == 0 )
			{ /* http auth user */
				session->action.upload.username = g_strdup(d->opaque.string->str);
				curl_easy_setopt(session->easy, CURLOPT_USERNAME, session->action.upload.username);
			}else
			if( strcmp(name, "pass") == 0 )
			{ /* http auth password */
				session->action.upload.password = g_strdup(d->opaque.string->str);
				curl_easy_setopt(session->easy, CURLOPT_PASSWORD, session->action.upload.password);
			}else
			if( strncmp(name, "file://", 7) == 0 )
			{ /* we upload this file */
				curl_formadd(&session->action.upload.formpost,
							 &session->action.upload.last,
							 CURLFORM_COPYNAME, name + 7,
							 CURLFORM_FILE, d->opaque.string->str,
							 CURLFORM_END);
			}else
			{ /* all other values */
				snprintf(name_and_param, 1024, "%s_ct", name);
				if ( incident_value_string_get(i, name_and_param, &gstemp) == true)
				{ /* with content type */
					curl_formadd(&session->action.upload.formpost,
								 &session->action.upload.last,
								 CURLFORM_COPYNAME, name,
								 CURLFORM_CONTENTTYPE, gstemp->str,
								 CURLFORM_COPYCONTENTS, d->opaque.string->str,
								 CURLFORM_END);
				} else
				{ /* without content type */
					curl_formadd(&session->action.upload.formpost,
								 &session->action.upload.last,
								 CURLFORM_COPYNAME, name,
								 CURLFORM_COPYCONTENTS, d->opaque.string->str,
								 CURLFORM_END);
				}
			}
		}
	}

	if( session->action.upload.callback != NULL && session->action.upload.file == NULL )
	{
		/* the answer for the callback has no file (no descriptor left, a full disk) */
		char *text = log_text_new(session->url, "(no url)");
		g_info("Could not create the file of the upload to %s, the upload is dropped", text);
		log_summary_add(&upload_no_file, text);
		g_free(text);
		curl_easy_cleanup(session->easy);
		session_free(session);
		return;
	}

	char buf[] = "Expect:";
	session->action.upload.headers = curl_slist_append(session->action.upload.headers, buf);


	curl_easy_setopt(session->easy, CURLOPT_URL, session->url);
	curl_easy_setopt(session->easy, CURLOPT_HTTPPOST, session->action.upload.formpost);
	curl_easy_setopt(session->easy, CURLOPT_HTTPHEADER, session->action.upload.headers);
	curl_easy_setopt(session->easy, CURLOPT_WRITEFUNCTION, curl_writefunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_WRITEDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_DEBUGFUNCTION, curl_debugfunction_cb);
//	curl_easy_setopt(session->easy, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(session->easy, CURLOPT_ERRORBUFFER, session->error);
	curl_easy_setopt(session->easy, CURLOPT_PRIVATE, session);
	curl_easy_setopt(session->easy, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(session->easy, CURLOPT_PROGRESSFUNCTION, curl_progressfunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_PROGRESSDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_LOW_SPEED_TIME, 3L);
	curl_easy_setopt(session->easy, CURLOPT_LOW_SPEED_LIMIT, 10L);
	curl_easy_setopt(session->easy, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)");
	curl_easy_setopt(session->easy, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(session->easy, CURLOPT_SSL_VERIFYHOST, 0);

	g_debug("Adding easy %p to multi %p (%s)", session->easy, curl_runtime.multi, url);
	curl_multi_add_handle(curl_runtime.multi, session->easy);
	curl_runtime.queued++;
	check_run_count();
}

/* CURLOPT_OPENSOCKETFUNCTION of a download, context: the session */
static curl_socket_t download_open_socket(void *context, curlsocktype purpose,
                                         struct curl_sockaddr *address)
{
    struct session *session = context;
    char text[INET6_ADDRSTRLEN];
    const void *ip;
    if (purpose != CURLSOCKTYPE_IPCXN)
        return CURL_SOCKET_BAD;
    if (address->family == AF_INET)
        ip = &((struct sockaddr_in *)&address->addr)->sin_addr;
    else if (address->family == AF_INET6)
        ip = &((struct sockaddr_in6 *)&address->addr)->sin6_addr;
    else
    {
        /* no address the filter can judge: attempted, not refused */
        session->action.download.allowed_seen = true;
        return CURL_SOCKET_BAD;
    }
    if (!inet_ntop(address->family, ip, text, sizeof(text)))
    {
        session->action.download.allowed_seen = true;
        return CURL_SOCKET_BAD;
    }
    if (!download_destination_allowed(text))
    {
        g_debug("download target %s refused by the filter", text);
        session->action.download.refused_seen = true;
        return CURL_SOCKET_BAD;
    }
    session->action.download.allowed_seen = true;
    return socket(address->family, address->socktype, address->protocol);
}

/* CURLOPT_HEADERFUNCTION of a download: a status line is a response of a server, the
 * addresses of the next hop (a redirect) are judged anew */
static size_t download_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    struct session *session = userdata;
    size_t len = size * nitems;
    if (len >= 5 && strncmp(buffer, "HTTP/", 5) == 0)
    {
        session->action.download.refused_seen = false;
        session->action.download.allowed_seen = false;
    }
    return len;
}

static void session_download_new(struct incident *i, char *url)
{
	g_debug("%s incident %p", __PRETTY_FUNCTION__, i);

	struct session *session = session_new();
	session->type = session_type_download;


	session->url = g_strdup(url);


	struct connection *con = NULL;
	if( incident_value_con_get(i, "con", &con) )
	{
		session->laddr = g_strdup(con->local.ip_string);
		curl_easy_setopt(session->easy, CURLOPT_INTERFACE, session->laddr);
		connection_ref(con);
	}

	curl_easy_setopt(session->easy, CURLOPT_URL, session->url);
	curl_easy_setopt(session->easy, CURLOPT_WRITEFUNCTION, curl_writefunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_WRITEDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_DEBUGFUNCTION, curl_debugfunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(session->easy, CURLOPT_ERRORBUFFER, session->error);
	curl_easy_setopt(session->easy, CURLOPT_PRIVATE, session);
	curl_easy_setopt(session->easy, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(session->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(session->easy, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(session->easy, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(session->easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    /* Apply the same resolved-address check to every redirect; no shared upload
     * sockets and no environment proxies: every connection goes to the checked address. */
    curl_easy_setopt(session->easy, CURLOPT_PROXY, "");
    curl_easy_setopt(session->easy, CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(session->easy, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(session->easy, CURLOPT_OPENSOCKETFUNCTION, download_open_socket);
    curl_easy_setopt(session->easy, CURLOPT_OPENSOCKETDATA, session);
    curl_easy_setopt(session->easy, CURLOPT_HEADERFUNCTION, download_header_cb);
    curl_easy_setopt(session->easy, CURLOPT_HEADERDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_PROGRESSFUNCTION, curl_progressfunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_PROGRESSDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_LOW_SPEED_TIME, 3L);
	curl_easy_setopt(session->easy, CURLOPT_LOW_SPEED_LIMIT, 10L);
	curl_easy_setopt(session->easy, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)");

	session->action.download.file = tempincoming_new(curl_runtime.download_dir, "http-");
	session->action.download.ctxcon = con;
	if( session->action.download.file == NULL )
	{
		/* no descriptor left or a full disk: no download, the connection is given back */
		char *text = log_text_new(session->url, "(no url)");
		g_info("Could not create the file of the download of %s, the download is dropped", text);
		log_summary_add(&download_no_file, text);
		g_free(text);
		curl_easy_cleanup(session->easy);
		session_free(session);
		return;
	}

	g_debug("session %p file %i path %s", session, session->action.download.file->fd, session->action.download.file->path);

	g_debug("Adding easy %p to multi %p (%s)", session->easy, curl_runtime.multi, url);
	curl_multi_add_handle(curl_runtime.multi, session->easy);
	curl_runtime.queued++;
	check_run_count();
}

static void curl_ihandler_cb(struct incident *i, void *ctx)
{
	g_debug("%s i %p ctx %p", __PRETTY_FUNCTION__, i, ctx);
	GString *url;
	if( strcmp(i->origin, "dionaea.download.offer") == 0 )
	{
		if( incident_value_bytes_get(i, "url", &url) || incident_value_string_get(i, "url", &url) ) {
			if( strncasecmp(url->str,  "http", 4) != 0 )
				return;
			session_download_new(i, url->str);
		} else {
			g_critical("download without url?");
		}
	} else
		if( strcmp(i->origin, "dionaea.upload.request") == 0 )
	{
		session_upload_new(i);
	}
}

static bool curl_config(void)
{
  GError *error = NULL;

  g_debug("%s", __PRETTY_FUNCTION__);

  curl_runtime.download_dir = g_key_file_get_string(g_dionaea->config, "dionaea", "download.dir", &error);

  return true;
}

static bool curl_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);

	if( curl_global_init(CURL_GLOBAL_ALL) != 0 )
		return false;

	curl_version_info_data *curlinfo;
	curlinfo = curl_version_info(CURLVERSION_NOW);

	GString *features = g_string_new("");
	GString *protocols = g_string_new("");
	if( curlinfo->features )
	{

		struct curl_feature
		{
			const char *name;
			int bitmask;
		};
		static const struct curl_feature feats[] = {
			{"c-ares", CURL_VERSION_ASYNCHDNS},
			{"debug", CURL_VERSION_DEBUG},
#ifdef CURL_VERSION_CURLDEBUG
			{"debugmemory", CURL_VERSION_CURLDEBUG},
#endif
			{"gss", CURL_VERSION_GSSNEGOTIATE},
			{"idn", CURL_VERSION_IDN},
			{"ipv6", CURL_VERSION_IPV6},
			{"largefile", CURL_VERSION_LARGEFILE},
			{"ntlm", CURL_VERSION_NTLM},
			{"spnego", CURL_VERSION_SPNEGO},
			{"ssl",  CURL_VERSION_SSL},
			{"sspi",  CURL_VERSION_SSPI},
			{"krb4", CURL_VERSION_KERBEROS4},
			{"libz", CURL_VERSION_LIBZ},
			{"charconv", CURL_VERSION_CONV}
		};
		for( unsigned int i=0; i<sizeof(feats)/sizeof(feats[0]); i++ )
			if( curlinfo->features & feats[i].bitmask )
				g_string_append_printf(features, ",%s", feats[i].name);

	}
	if( curlinfo->protocols )
		for( const char * const *proto=curlinfo->protocols; *proto; ++proto )
			g_string_append_printf(protocols, ",%s", *proto);

	g_info("curl version %s features:%s protocols:%s ", curlinfo->version, features->str+1, protocols->str+1);
	g_string_free(features, TRUE);
	g_string_free(protocols, TRUE);

	curl_runtime.multi = curl_multi_init();
	ev_timer_init(&curl_runtime.timer_event, timer_cb, 0., 0.);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_SOCKETFUNCTION, curl_socketfunction_cb);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_SOCKETDATA, NULL);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_TIMERDATA, NULL);
	CURLMcode rc;
	do
	{
		rc = curl_multi_socket_all(curl_runtime.multi, &curl_runtime.active);
	} while( CURLM_CALL_MULTI_PERFORM == rc );

	curl_runtime.download_ihandler = ihandler_new("dionaea.download.offer", curl_ihandler_cb, NULL);
	curl_runtime.upload_ihandler = ihandler_new("dionaea.upload.request", curl_ihandler_cb, NULL);
	return true;
}

static bool curl_freex(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	curl_global_cleanup();
	return true;
}

static bool curl_hup(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api curl_api =
	{
		.config = &curl_config,
		.start = NULL,
		.new = &curl_new,
		.free = &curl_freex,
		.hup = &curl_hup
	};

    return &curl_api;
}
