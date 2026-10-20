/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <Python.h>
#include <stdbool.h>
#include "connection.h"

/*
 * Cython 3.1 no longer exports __pyx_empty_tuple. Use an empty tuple of our own
 * that is created once and kept for the life of the process. The result is a
 * borrowed reference, so there is nothing to release at the call sites.
 */
#ifndef DIONAEA_EMPTY_TUPLE_DEFINED
#define DIONAEA_EMPTY_TUPLE_DEFINED
/* binding.pyx includes this header more than once */
static inline PyObject *dionaea_empty_tuple(void)
{
	static PyObject *empty_tuple = NULL;
	if( empty_tuple == NULL )
		empty_tuple = PyTuple_New(0);
	return empty_tuple;
}
#endif

#define PY_CLONE(T)  (T)->ob_type->tp_new((T)->ob_type, dionaea_empty_tuple(), NULL)
#define PY_NEW(T) (((PyTypeObject*)(T))->tp_new( (PyTypeObject*)(T), dionaea_empty_tuple(), NULL))
#define PY_INIT(P, O) (P)->ob_type->tp_init((O), dionaea_empty_tuple(), NULL)
#define REFCOUNT(T) printf("obj refcount %i\n", (int)(T)->ob_refcnt)

#define REMOTE(C) (C)->remote
#define LOCAL(C) (C)->local

struct connection;

unsigned int python_handle_io_in_cb(struct connection *con, void *context, unsigned char *data, uint32_t size);

void log_wrap(char *name, int number, char *file, int line, char *msg);
void traceback(void);
PyObject *pygetifaddrs(PyObject *self, PyObject *args);
PyObject *py_config(PyObject *self, PyObject *args);
PyObject *pyversion(PyObject *self, PyObject *args);

/*
 * A timer of the event loop for Python (dionaea.core.timer): the callable runs
 * in the thread of the loop, as the callbacks of the connections do.
 */
struct py_timer;
struct py_timer *py_timer_new(PyObject *callback, double after, double repeat);
void py_timer_free(struct py_timer *t);


struct ihandler;
struct incident;
void set_ihandler(struct ihandler *ih);
void traceable_ihandler_cb(struct incident *i, void *ctx);


struct protocol;
void set_protocol(struct protocol *p);
void *traceable_ctx_new_cb(struct connection *con);
void traceable_ctx_free_cb(void *ctx);
void traceable_origin_cb(struct connection *origin, struct connection *con);
void traceable_established_cb(struct connection *con);
uint32_t traceable_io_in_cb(struct connection *con, void *context, unsigned char *data, uint32_t size);
void traceable_io_out_cb(struct connection *con, void *context);
bool traceable_error_cb(struct connection *con, enum connection_error error);
bool traceable_disconnect_cb(struct connection *con, void *context);
bool traceable_idle_timeout_cb(struct connection *con, void *context);
bool traceable_listen_timeout_cb(struct connection *con, void *context);
bool traceable_sustain_timeout_cb(struct connection *con, void *context);

struct processor;
void set_processor(struct processor *);
void python_processor_bistream_create(struct connection *con);
