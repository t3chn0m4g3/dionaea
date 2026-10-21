/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <Python.h>
#include <errcode.h> // E_EOF, not part of Python.h
#include <glib.h>
#include <stdio.h>
#include <ev.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h> // sigaction
#include <dirent.h>
#include <stddef.h>

// set terminal to char mode
#include <termios.h>


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h> // qsort
#include <ifaddrs.h> // getifaddrs
#include <stddef.h> // offsetof
#include <net/if.h> // if_nametoindex

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h> // af_packet
#endif

#include "connection.h"
#include "dionaea.h"
#include "modules.h"

#include "log.h"

#include "connection.h"
#include "protocol.h"
#include "incident.h"
#include "processor.h"
#include "util.h"
#include "module.h"

#define D_LOG_DOMAIN "python"
PyObject *PyInit_core(void);

struct protocol *trace_proto;


void python_processor_bistream_create(struct connection *con);
bool python_processor_bistream_accept(struct connection *con, void *config);
void python_processor_bistream_io_in(struct connection *con, struct processor_data *pd, void *data, int size);
void python_processor_bistream_io_out(struct connection *con, struct processor_data *pd, void *data, int size);
void python_processor_bistream_free(void *data);

struct processor proc_python_bistream =
{
	.name = "python",
	.process = python_processor_bistream_accept,
	.free = python_processor_bistream_free,
	.io_in = python_processor_bistream_io_in,
	.io_out = python_processor_bistream_io_out,
};

static struct python_runtime
{
	struct ev_io python_cli_io_in;
	FILE *stdIN;
	GHashTable *imports;
	struct termios read_termios;
	struct termios poll_termios;
	struct ihandler *mkshell_ihandler;

	struct
	{
		struct protocol proto;
		struct ihandler pyhandler;
		struct processor processor;
	} traceables;
	GString *sys_path;
} runtime;





struct import
{
	char *name;
	PyObject *module;
};



static bool config(void)
{
	// ToDo: Try to reload config
	return true;
}

/*
 * Interactive Python shell on a terminal on stdin (docker run -t -i).
 * The event loop runs without the GIL (start() releases it), so take it.
 * On EOF (^D) or a terminal that went away (EIO, hangup) stdin stays
 * readable for ever: stop the watcher, else this callback would spin.
 */
void python_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
	PyCompilerFlags cf;
	cf.cf_flags = 0;

	PyGILState_STATE gil_state = PyGILState_Ensure();
	tcsetattr(STDIN_FILENO, TCSANOW, &runtime.read_termios);
	int ret = PyRun_InteractiveOneFlags(runtime.stdIN, "<stdin>", &cf);
	traceback();
	bool closed = ret == E_EOF || feof(runtime.stdIN) || ferror(runtime.stdIN);
	PyGILState_Release(gil_state);

	if( closed )
	{
		g_info("stdin closed, stopping the interactive Python shell");
		ev_io_stop(EV_A_ w);
		clearerr(runtime.stdIN);
		return;
	}
	tcsetattr(STDIN_FILENO, TCSANOW, &runtime.poll_termios);
}

static void python_mkshell_ihandler_cb(struct incident *i, void *ctx)
{
	g_debug("%s i %p ctx %p", __PRETTY_FUNCTION__, i, ctx);
	struct connection *con;
	if( incident_value_con_get(i, "con", &con) )
	{
		g_debug("mkshell for %p", con);
		const char *name = "cmd";
		PyObject *module = PyImport_ImportModule(name);
		if( module == NULL )
		{
			PyErr_Print();
			g_error("Import failed %s", name);
		}
		Py_DECREF(module);
		PyObject *func = PyObject_GetAttrString(module, "remoteshell");
		PyObject *arglist = Py_BuildValue("()");
		PyObject *r = PyObject_CallObject(func, arglist);
		Py_DECREF(arglist);
		g_debug("r %p", r);
		struct head
		{
			PyObject_HEAD
		};
		struct connection **pp = (struct connection **)((char *)r + sizeof(struct head));
		g_debug("p %p %p", pp, *pp);
		struct connection *p = *pp;
		con->protocol.ctx = p->protocol.ctx;
		con->protocol.ctx = p->protocol.ctx_new(con);
		con->protocol.io_in = p->protocol.io_in;
		con->protocol.idle_timeout = p->protocol.idle_timeout;
		con->protocol.sustain_timeout = p->protocol.sustain_timeout;
		con->protocol.established = p->protocol.established;
		ev_io_start(g_dionaea->loop, &con->events.io_in);
//		ev_io_start(g_dionaea->loop, &con->events.io_out);
		con->protocol.established(con);
	} else
		g_critical("mkshell fail");

}

static bool hupy(void)
{
	g_debug("%s node",  __PRETTY_FUNCTION__);
	gchar **module_names;
	GError *error = NULL;
	gsize num;
	gchar **module_name;

	module_names = g_key_file_get_string_list(g_dionaea->config, "module.python", "imports", &num, &error);

	// ToDo: check error
	for (module_name = module_names; *module_name; module_name++) {
		struct import *i;
		if( (i = g_hash_table_lookup(runtime.imports, module_name)) != NULL ) {
			g_message("Import %s exists, reloading", *module_name);

			PyObject *func = PyObject_GetAttrString(i->module, "stop");
			if ( func != NULL ) {
				PyObject *arglist = Py_BuildValue("()");
				PyObject *r = PyObject_CallObject(func, arglist);
				traceback();
				// PyErr_Print();
				Py_DECREF(arglist);
				Py_XDECREF(r);
				Py_DECREF(func);
			} else {
				traceback();
			}

			PyObject *module = PyImport_ReloadModule(i->module);
			if( module == NULL ) {
				PyErr_Print();
				g_critical("Reloading module %s failed", i->name);
				module = i->module;
			} else {
				Py_DECREF(module);
				i->module = module;
			}
			func = PyObject_GetAttrString(module, "new");
			if( func != NULL ) {
				PyObject *arglist = Py_BuildValue("()");
				PyObject *r = PyObject_CallObject(func, arglist);
				traceback();
				Py_DECREF(arglist);
				Py_XDECREF(r);
				Py_DECREF(func);
			} else {
				traceback();
			}
			func = PyObject_GetAttrString(module, "start");
			if( func != NULL ) {
				PyObject *arglist = Py_BuildValue("()");
				PyObject *r = PyObject_CallObject(func, arglist);
				traceback();
				Py_DECREF(arglist);
				Py_XDECREF(r);
				Py_DECREF(func);
			} else {
				traceback();
			}
		} else {
			g_message("New Import %s", *module_name);
			PyObject *module = PyImport_ImportModule(*module_name);
			if( module == NULL ) {
				g_critical("Could not import module %s", *module_name);
				//free(module_name);
				continue;
			}
			Py_DECREF(module);
			i = g_malloc0(sizeof(struct import));
			i->name = g_strdup(*module_name);
			i->module = module;
			g_hash_table_insert(runtime.imports, i->name, i);

			PyObject *func = PyObject_GetAttrString(module, "new");
			if( func != NULL ) {
				PyObject *arglist = Py_BuildValue("()");
				PyObject *r = PyObject_CallObject(func, arglist);
				Py_DECREF(arglist);
				Py_XDECREF(r);
				Py_DECREF(func);
			} else {
				PyErr_Clear();
			}

		}
		//free(name);
	}
	return true;
}

/*
 * The event loop ended, dionaea waits for the threadpool next: the imports
 * with a flush() (dionaea.ihandlers: the commits of log_sqlite) write what
 * they buffer, so a stop timeout during that wait loses nothing of it.
 * stop() in freepy() follows as before.
 */
static bool flushpy(void)
{
	g_debug("%s %s", __PRETTY_FUNCTION__, __FILE__);
	PyGILState_STATE gil_state = PyGILState_Ensure();

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, runtime.imports);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		struct import *imp = value;
		PyObject *func = PyObject_GetAttrString(imp->module, "flush");
		if( func != NULL )
		{
			g_info("flush %s", (char *)key);
			PyObject *arglist = Py_BuildValue("()");
			PyObject *r = PyObject_CallObject(func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(r);
			Py_DECREF(func);
		} else
			PyErr_Clear();
		traceback();
	}

	PyGILState_Release(gil_state);
	return true;
}

static bool freepy(void)
{
	g_debug("%s %s", __PRETTY_FUNCTION__, __FILE__);
	if( runtime.stdIN != NULL )
	{
		ev_io_stop(g_dionaea->loop, &runtime.python_cli_io_in);
		tcsetattr(STDIN_FILENO, TCSADRAIN, &runtime.read_termios);
	}

	/*
	 * The event loop ran without the GIL (start() released it): take it
	 * back before calling into Python, a Python thread of a module may
	 * still run. Py_Finalize() wants it held and ends it, so it is not
	 * released.
	 */
	PyGILState_Ensure();

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, runtime.imports);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		struct import *imp = value;
		PyObject *module = imp->module;
		g_info("stop %s %p %p", (char *)key, imp, imp->module);

		PyObject *func = PyObject_GetAttrString(module, "stop");
		if( func != NULL )
		{
			PyObject *arglist = Py_BuildValue("()");
			PyObject *r = PyObject_CallObject(func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(r);
			Py_DECREF(func);
		} else
			PyErr_Clear();
		traceback();
	}

	Py_Finalize();
	g_hash_table_destroy(runtime.imports);
	return true;
}


static bool start(void)
{
	g_info("%s %s", __PRETTY_FUNCTION__, __FILE__);
	PyGILState_STATE gil_state = PyGILState_Ensure();

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, runtime.imports);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		struct import *imp = value;
		PyObject *module = imp->module;
		g_info("start %s %p %p", (char *)key, imp, imp->module);

		PyObject *func = PyObject_GetAttrString(module, "start");
		if( func != NULL )
		{
			PyObject *arglist = Py_BuildValue("()");
			PyObject *r = PyObject_CallObject(func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(r);
			Py_DECREF(func);
		} else
			PyErr_Clear();
		traceback();
	}
	PyGILState_Release(gil_state);
	PyEval_SaveThread();
	return true;
}

static bool new(struct dionaea *dionaea)
{
	g_debug("%s %s %p", __PRETTY_FUNCTION__, __FILE__, g_dionaea);
//	int v = PyImport_AppendInittab("dionaea.core", &PyInit_core);
//	g_warning("PyImport_AppendInittab %i", v);

	g_debug("Python Interpreter %s", PYTHON_PATH);

	/*
	 * Py_SetProgramName and PyEval_InitThreads are deprecated (removal
	 * planned for Python 3.15); the GIL exists from the start since 3.7.
	 * Keep what Py_Initialize() did: no C locale coercion and no UTF-8
	 * mode, the PyConfig defaults would turn on both in the C locale of
	 * the container (process wide LC_CTYPE=C.UTF-8).
	 */
	/* Python installs its own handler of SIGINT (KeyboardInterrupt); the one dionaea had
	 * before (its event loop, installed before the modules) is put back below */
	struct sigaction sigint_before;
	sigaction(SIGINT, NULL, &sigint_before);

	PyStatus status;
	PyPreConfig preconfig;
	PyPreConfig_InitPythonConfig(&preconfig);
	preconfig.coerce_c_locale = 0;
	preconfig.utf8_mode = 0;
	status = Py_PreInitialize(&preconfig);
	if( PyStatus_Exception(status) )
		g_error("Could not pre-initialize Python: %s", status.err_msg ? status.err_msg : "unknown error");

	PyConfig pyconfig;
	PyConfig_InitPythonConfig(&pyconfig);
	// as the compat config of Py_Initialize(): leave the C stdio streams
	// alone, do not parse a command line
	pyconfig.configure_c_stdio = 0;
	pyconfig.parse_argv = 0;
	status = PyConfig_SetBytesString(&pyconfig, &pyconfig.program_name, PYTHON_PATH);
	if( !PyStatus_Exception(status) )
		status = Py_InitializeFromConfig(&pyconfig);
	PyConfig_Clear(&pyconfig);
	if( PyStatus_Exception(status) )
		g_error("Could not initialize Python: %s", status.err_msg ? status.err_msg : "unknown error");

	PyGILState_STATE gil_state = PyGILState_Ensure();

	runtime.sys_path = g_string_new(DIONAEA_PYTHON_SITELIBDIR);

	PyRun_SimpleString("import sys");
	char relpath[1024];
	int i=0;
	gchar **sys_paths;
	GError *error = NULL;
	gsize num;
	gchar **sys_path;
	sys_paths = g_key_file_get_string_list(g_dionaea->config, "module.python", "sys_paths", &num, &error);

	for (sys_path = sys_paths; *sys_path; sys_path++) {
		if( strcmp(*sys_path, "default") == 0 ) {
			sprintf(relpath, "sys.path.insert(%i, '%s')", i, DIONAEA_PYTHON_SITELIBDIR);
		} else {
			// ToDO
		/*	if( *sys_path == '/' )
				sprintf(relpath, "sys.path.insert(%i, '%s')", i, name);
			else
				sprintf(relpath, "sys.path.insert(%i, '%s/%s')", i, PREFIX, name);
				*/
		}
		g_debug("running %s %s", relpath, *sys_path);
		PyRun_SimpleString(relpath);
		i++;
	}
	PyRun_SimpleString("from dionaea.core import init_traceables");
	PyRun_SimpleString("init_traceables()");

	runtime.imports = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	gchar **module_names;
	gchar **module_name;
	module_names = g_key_file_get_string_list(g_dionaea->config, "module.python", "imports", &num, &error);
	for (module_name = module_names; *module_name; module_name++) {
		PyObject *module = PyImport_ImportModule(*module_name);
		if( module == NULL ) {
			PyErr_Print();
			g_error("Import failed %s", *module_name);
		}
		Py_DECREF(module);
		struct import *i = g_malloc0(sizeof(struct import));
		i->name = g_strdup(*module_name);
		i->module = module;
		g_hash_table_insert(runtime.imports, i->name, i);
		PyObject *func = PyObject_GetAttrString(module, "new");
		if( func != NULL ) {
			PyObject *arglist = Py_BuildValue("()");
			PyObject *r = PyObject_CallObject(func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(r);
			Py_DECREF(func);
		} else {
			PyErr_Clear();
		}
		traceback();
		//free(name);
	}

	sigaction(SIGINT, &sigint_before, NULL);

	if( isatty(STDIN_FILENO) )
	{
		g_debug("Interactive Python shell");
		runtime.stdIN = fdopen(STDIN_FILENO, "r");
		ev_io_init(&runtime.python_cli_io_in, python_io_in_cb, STDIN_FILENO, EV_READ);
		ev_io_start(g_dionaea->loop, &runtime.python_cli_io_in);

		PyObject *v;
		v = PySys_GetObject("ps1");
		if( v == NULL )
		{
			PySys_SetObject("ps1", v = PyUnicode_FromString(">>> "));
			Py_XDECREF(v);
		}
		v = PySys_GetObject("ps2");
		if( v == NULL )
		{
			PySys_SetObject("ps2", v = PyUnicode_FromString("... "));
			Py_XDECREF(v);
		}

		v = PyImport_ImportModule("readline");
		if( v == NULL )
			PyErr_Clear();
		else
			Py_DECREF(v);

		tcgetattr(0, &runtime.read_termios);
		memcpy(&runtime.poll_termios, &runtime.read_termios, sizeof(struct termios));
		runtime.read_termios.c_lflag |= (ICANON|ECHOCTL|ECHO);
		runtime.poll_termios.c_lflag &= ~(ICANON|ECHOCTL|ECHO);
		tcsetattr(0, TCSANOW, &runtime.poll_termios);
	}

	runtime.mkshell_ihandler = ihandler_new("dionaea.*.mkshell", python_mkshell_ihandler_cb, NULL);

	g_hash_table_insert(g_dionaea->processors->names, (void *)proc_python_bistream.name, &proc_python_bistream);
	PyGILState_Release(gil_state);
	// save = PyEval_SaveThread();
	return true;
}

void log_wrap(char *name, int number, char *file, int line, char *msg)
{
#ifdef PERFORMANCE
	return;
#else
	char *log_domain;
	GLogLevelFlags log_level = G_LOG_LEVEL_DEBUG;
	int x = 0;

#ifdef DEBUG
	if ( strncmp(file, runtime.sys_path->str, runtime.sys_path->len) == 0 )
		file += runtime.sys_path->len;

	x = asprintf(&log_domain, "%s %s:%i", name, file, line);
#else
	x = asprintf(&log_domain, "%s", name);
#endif
	if( x == -1 )
		return;

	if( number == 0 || number == 10 ) {
		log_level = G_LOG_LEVEL_DEBUG;
	} else if( number == 20 ) {
		log_level = G_LOG_LEVEL_INFO;
	} else if( number == 30 ) {
		log_level = G_LOG_LEVEL_WARNING;
	} else if( number == 40 ) {
		// in glib2 critical is a critical warning
		log_level = G_LOG_LEVEL_CRITICAL;
	} else if( number == 50 ) {
		// in glib2 an error is critical and calls the abort function to
		// terminate the program immediately
		log_level = G_LOG_LEVEL_ERROR;
	}
	g_log(log_domain, log_level, "%s", msg);
	free(log_domain);

#endif
}


static int cmp_ifaddrs_by_ifa_name(const void *p1, const void *p2)
{
	return strcmp((*(struct ifaddrs **)p1)->ifa_name, (*(struct ifaddrs **)p2)->ifa_name);
}

PyObject *pyversion(PyObject *self, PyObject *args)
{
#define DICT_SET_ITEM(d, k, v) \
	{\
	PyObject *x = PyUnicode_FromString( (char *)g_dionaea->version->k.v); \
	PyDict_SetItemString(d, #v, x); \
	Py_DECREF(x); }\



	PyObject *result = PyDict_New();
	PyObject *dionaea = PyDict_New();
	DICT_SET_ITEM(dionaea, dionaea, version);

	PyObject *compiler = PyDict_New();

	DICT_SET_ITEM(compiler, compiler, os);
	DICT_SET_ITEM(compiler, compiler, arch);
	DICT_SET_ITEM(compiler, compiler, date);
	DICT_SET_ITEM(compiler, compiler, time);
	DICT_SET_ITEM(compiler, compiler, name);
	DICT_SET_ITEM(compiler, compiler, version);

	PyObject *info = PyDict_New();
	DICT_SET_ITEM(info, info, node);
	DICT_SET_ITEM(info, info, sys);
	DICT_SET_ITEM(info, info, machine);
	DICT_SET_ITEM(info, info, release);

#undef DICT_SET_ITEM

	PyDict_SetItemString(result, "dionaea", dionaea);
	Py_DECREF(dionaea);
	PyDict_SetItemString(result, "compiler", compiler);
	Py_DECREF(compiler);
	PyDict_SetItemString(result, "info", info);
	Py_DECREF(info);
	return result;
}

PyObject *pygetifaddrs(PyObject *self, PyObject *args)
{
	struct ifaddrs *iface, *head;
	PyObject *result;

	result = PyDict_New();

	if( getifaddrs(&head) < 0 )
	{
		g_warning("getifaddrs failed (%s)",  strerror(errno));
		return result;
	}

	PyObject *pyiface, *pyaddr, *pynetmask, *pybroadcast, *pypointtopoint, *pyaf, *pyafdict, *pyaflist, *pyafdetails, *pyscopeid;
	pynetmask = NULL;

	int count=0;
	for( iface=head; iface != NULL; iface=iface->ifa_next )
		count++;

	struct ifaddrs *ifaces[count];
	memset(ifaces, 0, count*sizeof(struct ifaces *));

	for( count=0,iface=head; iface != NULL; iface=iface->ifa_next )
		ifaces[count++] = iface;

	qsort(ifaces, count, sizeof(struct ifaddrs *), cmp_ifaddrs_by_ifa_name);

	int i=0;

	char *old_ifa_name = "";
	pyafdict = NULL;
	for(i = 0; i < count; i++) {
		iface = ifaces[i];
		if( iface->ifa_addr == NULL )
			continue;

		if( iface->ifa_addr->sa_family != AF_INET && iface->ifa_addr->sa_family != AF_INET6
#ifdef AF_PACKET
			&& iface->ifa_addr->sa_family != AF_PACKET
#endif
			)
			continue;

		if( !(iface->ifa_flags & IFF_UP) )
			continue;

		if( strcmp(old_ifa_name, iface->ifa_name) != 0 )
		{
			old_ifa_name = iface->ifa_name;
			pyiface = PyUnicode_FromString(iface->ifa_name);
			pyafdict = PyDict_New();
			PyDict_SetItemString (result, iface->ifa_name, pyafdict);
			Py_DECREF(pyiface);
		}

		pyaf = PyLong_FromLong(iface->ifa_addr->sa_family);
		if( ! PyDict_Contains(pyafdict, pyaf) )
		{
			pyaflist = PyList_New(0);
			PyDict_SetItem(pyafdict, pyaf, pyaflist);
		} else
		{
			pyaflist = PyDict_GetItem(pyafdict, pyaf);
		}
		Py_DECREF(pyaf);

		pyafdetails = PyDict_New();

		pyaddr = NULL;
		char ip_string[INET6_ADDRSTRLEN+1] = "";
		void *offset = ADDROFFSET(iface->ifa_addr);
		if( offset )
		{
			inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
			pyaddr = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "addr", pyaddr);
			Py_DECREF(pyaddr);

		}
#ifdef AF_PACKET
		else
		if( iface->ifa_addr->sa_family == AF_PACKET && PyList_Size(pyaflist) == 0 )
		{
			struct sockaddr_ll *lladdr = (struct sockaddr_ll *)iface->ifa_addr;

			int len = lladdr->sll_halen;
			char *data = (char *)lladdr->sll_addr;
			char *ptr = ip_string;
			int j;
			for( j = 0; j < len; j++ )
			{
				sprintf (ptr, "%02x:", data[j] & 0xff);
				ptr += 3;
			}
			*--ptr = '\0';
			pyaddr = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "addr", pyaddr);
			Py_DECREF(pyaddr);
		}
#endif
		if( pyaddr )
			PyList_Append(pyaflist, pyafdetails);
		Py_DECREF(pyafdetails);


		offset = ADDROFFSET(iface->ifa_netmask);
#ifdef AF_PACKET
		if( offset && iface->ifa_addr->sa_family != AF_PACKET )
		{
			inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
			pynetmask = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "netmask", pynetmask);
			Py_DECREF(pynetmask);
		}
#endif
		if( iface->ifa_addr->sa_family == AF_INET6 )
		{
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)iface->ifa_addr;

			if( ipv6_addr_linklocal(&sa6->sin6_addr) )
			{	// local scope address
				pyscopeid = PyLong_FromLong(if_nametoindex(iface->ifa_name));
				PyDict_SetItemString(pyafdetails, "scope", pyscopeid);
				Py_DECREF(pyscopeid);
			}
		}
		if( iface->ifa_flags & IFF_BROADCAST )
		{
			offset = ADDROFFSET(iface->ifa_broadaddr);
			if( offset )
			{
				inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
				pybroadcast = PyUnicode_FromString(ip_string);
				PyDict_SetItemString(pyafdetails, "broadcast", pybroadcast);
				Py_DECREF(pybroadcast);
			}
		}

		if( iface->ifa_flags & IFF_POINTOPOINT )
		{
			offset = ADDROFFSET(iface->ifa_dstaddr);
			if( offset )
			{
				inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
				pypointtopoint = PyUnicode_FromString(ip_string);
				PyDict_SetItemString(pyafdetails, "pointtopoint", pypointtopoint);
				Py_DECREF(pypointtopoint);
			}
		}
	}
	freeifaddrs(head);
	return result;
}


/*
PyObject *pylcfgx_tree(struct lcfgx_tree_node *node)
{
	if( node->type == lcfgx_map )
	{
		obj = PyDict_New();
		struct lcfgx_tree_node *it;
		for( it = node->value.elements; it != NULL; it = it->next )
		{
			PyObject *val = pylcfgx_tree(it);
			PyDict_SetItemString(obj, it->key, val);
			Py_DECREF(val);
		}
	} else
		if( node->type == lcfgx_list )
	{
		obj = PyList_New(0);
		struct lcfgx_tree_node *it;
		for( it = node->value.elements; it != NULL; it = it->next )
		{
			PyObject *val = pylcfgx_tree(it);
			PyList_Append(obj, val);
			Py_DECREF(val);
		}
	} else
		if( node->type == lcfgx_string )
	{
		obj = PyUnicode_FromStringAndSize(node->value.string.data, node->value.string.len);
	}
	return obj;
}
*/

/*
 * The values of g_dionaea->config as Python objects. Each returns a new
 * reference (None for a missing key) and frees what GLib returned.
 */
PyObject *py_config_string(gchar *group, gchar *key)
{
	gchar *value;
	GError *error = NULL;
	PyObject *obj_value;

	value = g_key_file_get_string(g_dionaea->config, group, key, &error);
	g_clear_error(&error);
	if (value == NULL) {
		Py_RETURN_NONE;
	}
	obj_value = PyUnicode_FromString(value);
	g_free(value);
	if (obj_value == NULL) {
		PyErr_Clear();
		Py_RETURN_NONE;
	}
	return obj_value;
}

PyObject *py_config_string_list(gchar *group, gchar *key)
{
	gchar **values, **value;
	GError *error = NULL;
	gsize num;
	PyObject *obj_values, *obj_value;

	values = g_key_file_get_string_list(g_dionaea->config, group, key, &num, &error);
	g_clear_error(&error);
	if (values == NULL) {
		Py_RETURN_NONE;
	}
	obj_values = PyList_New(0);
	if (obj_values == NULL) {
		g_strfreev(values);
		PyErr_Clear();
		Py_RETURN_NONE;
	}

	for(value = values; *value; value++) {
		obj_value = PyUnicode_FromString(*value);
		if (obj_value == NULL) {
			PyErr_Clear();
			continue;
		}
		PyList_Append(obj_values, obj_value);
		Py_DECREF(obj_value);
	}
	g_strfreev(values);
	return obj_values;
}

/* dict[key] = value, and the reference of value is given up (SetItem takes its own) */
static void py_dict_set_new(PyObject *dict, const char *key, PyObject *value)
{
	PyDict_SetItemString(dict, key, value);
	Py_DECREF(value);
}

/*
 * g_dionaea.config(): called for every upload, download and many requests.
 * PyDict_SetItemString does not steal the reference, so each value is released here.
 */
PyObject *py_config(PyObject *self, PyObject *args)
{
	PyObject *obj, *obj2;

	obj = PyDict_New();
	obj2 = PyDict_New();
	py_dict_set_new(obj2, "listen.mode", py_config_string("dionaea", "listen.mode"));
	py_dict_set_new(obj2, "listen.interfaces", py_config_string_list("dionaea", "listen.interfaces"));
	py_dict_set_new(obj2, "listen.addresses", py_config_string_list("dionaea", "listen.addresses"));
	py_dict_set_new(obj2, "download.dir", py_config_string("dionaea", "download.dir"));
	py_dict_set_new(obj, "dionaea", obj2);

	obj2 = PyDict_New();
	py_dict_set_new(obj2, "ihandler_configs", py_config_string_list("module.python", "ihandler_configs"));
	py_dict_set_new(obj2, "service_configs", py_config_string_list("module.python", "service_configs"));
	py_dict_set_new(obj, "module", obj2);

	return obj;
}

/*
 * Timers of the event loop for Python (dionaea.core.timer).
 *
 * The callable runs in the thread of the loop with the GIL, so it may use what
 * the callbacks of the connections use (sqlite handles, connections). The timer
 * holds a reference of the callable; py_timer_free() gives it up. A timer that
 * ran out (no repeat) gives it up itself, so its Python object can go. The
 * callable may stop its own timer: it is freed when the callable returns.
 */
struct py_timer
{
	struct ev_timer timer;
	PyObject *callback;
	bool running;
	bool freed;
};

static void py_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct py_timer *t = (struct py_timer *)w;
	PyGILState_STATE gil_state = PyGILState_Ensure();

	t->running = true;
	if( t->callback != NULL )
	{
		PyObject *r = PyObject_CallNoArgs(t->callback);
		if( r == NULL )
			traceback();
		Py_XDECREF(r);
	}
	t->running = false;

	if( t->freed )
	{
		Py_CLEAR(t->callback);
		g_free(t);
	} else
	if( !ev_is_active(&t->timer) && t->callback != NULL )
	{
		/* last thing done with t: the release may free the timer */
		PyObject *callback = t->callback;
		t->callback = NULL;
		Py_DECREF(callback);
	}
	PyGILState_Release(gil_state);
}

struct py_timer *py_timer_new(PyObject *callback, double after, double repeat)
{
	struct py_timer *t = g_malloc0(sizeof(struct py_timer));
	Py_INCREF(callback);
	t->callback = callback;
	ev_timer_init(&t->timer, py_timer_cb, after < 0. ? 0. : after, repeat < 0. ? 0. : repeat);
	ev_timer_start(g_dionaea->loop, &t->timer);
	return t;
}

void py_timer_free(struct py_timer *t)
{
	if( t == NULL )
		return;
	if( g_dionaea != NULL && g_dionaea->loop != NULL )
		ev_timer_stop(g_dionaea->loop, &t->timer);
	if( t->running )
	{
		t->freed = true;
		return;
	}
	Py_CLEAR(t->callback);
	g_free(t);
}

/**
 * traceback requirements
 * cython is rather special for exceptions
 * you can create try/catch blocks, but you do not get access to the
 * exception/traceback
 * therefore we proxy all calls to cython code, and ask cython to preserve
 * the exception flags, so we can take care in our proxy
 *
 */


void set_ihandler(struct ihandler *ih)
{
	memcpy(&runtime.traceables.pyhandler, ih, sizeof(struct ihandler));
}

void traceable_ihandler_cb (struct incident *i, void *ctx)
{
	g_debug("%s incident %p ctx %p",__PRETTY_FUNCTION__, i, ctx);
	runtime.traceables.pyhandler.cb(i, ctx);
	traceback();
}

/**
 * called from cython code,
 * exports pointers to the cython protocol functions
 *
 * @param p      the cython protocol
 */
void set_protocol(struct protocol *p)
{
	memcpy(&runtime.traceables.proto, p,  sizeof(struct protocol));
}


void *traceable_ctx_new_cb(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	void *ctx = runtime.traceables.proto.ctx_new(con);
	traceback();
	return ctx;
}

void traceable_ctx_free_cb(void *ctx)
{
	g_debug("%s ctx %p", __PRETTY_FUNCTION__, ctx);
	runtime.traceables.proto.ctx_free(ctx);
	traceback();
}

void traceable_origin_cb(struct connection *con, struct connection *origin)
{
	g_debug("%s origin %p con %p", __PRETTY_FUNCTION__, origin, con);
	runtime.traceables.proto.origin(con, origin);
	traceback();
}

void traceable_established_cb(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	runtime.traceables.proto.established(con);
	traceback();
}


uint32_t traceable_io_in_cb(struct connection *con, void *context, unsigned char *data, uint32_t size)
{
	g_debug("%s con %p ctx %p data %p size %i",__PRETTY_FUNCTION__, con, context, data, size);
	uint32_t s = runtime.traceables.proto.io_in(con, context, data, size);
	traceback();
	return s;
}

void traceable_io_out_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, context);
	runtime.traceables.proto.io_out(con, context);
	traceback();
}

bool traceable_error_cb(struct connection *con, enum connection_error error)
{
	g_debug("%s con %p error %i",__PRETTY_FUNCTION__, con, error);
	bool ret = runtime.traceables.proto.error(con, error);
	traceback();
	return ret;
}

bool traceable_disconnect_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.disconnect(con, context);
	traceback();
	return ret;
}

bool traceable_idle_timeout_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.idle_timeout(con, context);
	traceback();
	return ret;
}

bool traceable_listen_timeout_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.listen_timeout(con, context);
	traceback();
	return ret;
}

bool traceable_sustain_timeout_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.sustain_timeout(con, context);
	traceback();
	return ret;
}

/**
 * python bistreams are special
 * we want to allow python to access the bistream dump as part
 * of the connection object, therefore we create a dummy stream
 * processor, which is only attached to python connections
 *
 *
 */

void set_processor(struct processor *p)
{
	memcpy(&runtime.traceables.processor, p, sizeof(struct processor));
}

struct processor_data proc_python_bistream_processor_data =
{
	.processor = &proc_python_bistream,
};

bool python_processor_bistream_accept(struct connection *con, void *config)
{
	g_debug("%s con %p config %p",  __PRETTY_FUNCTION__, con, config);
	if( con->protocol.ctx_new == traceable_ctx_new_cb )
	{
		runtime.traceables.processor.process(con, NULL);
		return true;
	}

	g_warning("the python bistream only works for python protocols, check your bistream filters");

	return false;
}


void python_processor_bistream_io_in(struct connection *con, struct processor_data *pd, void *data, int size)
{
	runtime.traceables.processor.io_in(con, NULL, data, size);
}

void python_processor_bistream_io_out(struct connection *con, struct processor_data *pd, void *data, int size)
{
	runtime.traceables.processor.io_out(con, NULL, data, size);
}

void python_processor_bistream_free(void *data)
{
}

/*
 * An exception the Python code left behind (a callback of the binding, new(), start(), stop(),
 * a module of the configuration) goes to dionaea.logtext.log_exception: with a handler of
 * logging it is logged there at warning with its traceback (exc_info), so the formatter of the
 * log handler of dionaea (dionaea/log.py, dionaea/logtext.py) writes it as printable lines of
 * at most 256 characters, at most 40 of them. Without a handler (before dionaea.log new(),
 * after its stop()) log_exception returns that text and it goes to g_warning here, never raw
 * to stderr. The exception is cleared.
 */
void traceback(void)
{
	PyGILState_STATE gil_state = PyGILState_Ensure();
	if( !PyErr_Occurred() )
	{
		PyGILState_Release(gil_state);
		return;
	}

#if PY_VERSION_HEX >= 0x030C0000
	PyObject *exc = PyErr_GetRaisedException();
#else
	PyObject *type = NULL;
	PyObject *exc = NULL;
	PyObject *tb = NULL;
	PyErr_Fetch(&type, &exc, &tb);
	PyErr_NormalizeException(&type, &exc, &tb);
	if( exc != NULL && tb != NULL )
		PyException_SetTraceback(exc, tb);
	Py_XDECREF(type);
	Py_XDECREF(tb);
#endif

	bool written = false;
	PyObject *logtext = exc != NULL ? PyImport_ImportModule("dionaea.logtext") : NULL;
	PyObject *text = logtext != NULL ? PyObject_CallMethod(logtext, "log_exception", "O", exc) : NULL;
	if( text != NULL && !PyErr_Occurred() )
	{
		if( text == Py_None )
			written = true;
		else if( PyUnicode_Check(text) )
		{
			const char *utf8 = PyUnicode_AsUTF8(text);
			if( utf8 != NULL )
			{
				/* printable ASCII and line breaks only (log_traceback) */
				g_warning("%s", utf8);
				written = true;
			}
		}
	}
	Py_XDECREF(text);
	Py_XDECREF(logtext);
	if( PyErr_Occurred() )
		PyErr_Clear();
	if( !written )
		g_warning("There was an error in the Python code, it could not be written");

	Py_XDECREF(exc);
	PyGILState_Release(gil_state);
}

struct module_api *module_init(struct dionaea *dionaea)
{
	g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, dionaea);
	static struct module_api python_api =
	{
		.config = &config,
		.start = &start,
		.new = &new,
		.free = &freepy,
		.hup = &hupy,
		.flush = &flushpy
	};
	return &python_api;
}
