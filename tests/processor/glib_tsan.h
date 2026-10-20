/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * Included first into every source of the ThreadSanitizer build of the
 * processor tests (-include glib_tsan.h), nowhere else.
 *
 * GLib orders its GMutex, GCond, GAsyncQueue and GThreadPool with futexes and
 * atomics inside its own uninstrumented library. ThreadSanitizer sees none of
 * that ordering: it reports every access under a GMutex as a race, and every
 * list node GLib allocates in one thread and frees in another. In these
 * sources the calls go to pthread based versions instead (glib_tsan.c), whose
 * ordering ThreadSanitizer sees; GLib keeps its own implementation for itself.
 * The code under test calls the same functions as with GLib.
 */
#ifndef PROCESSOR_TEST_GLIB_TSAN_H
#define PROCESSOR_TEST_GLIB_TSAN_H

#include <glib.h>

#define PROCESSOR_TEST_TSAN 1

void tsan_g_mutex_init(GMutex *mutex);
void tsan_g_mutex_clear(GMutex *mutex);
void tsan_g_mutex_lock(GMutex *mutex);
gboolean tsan_g_mutex_trylock(GMutex *mutex);
void tsan_g_mutex_unlock(GMutex *mutex);
void tsan_g_cond_init(GCond *cond);
void tsan_g_cond_clear(GCond *cond);
void tsan_g_cond_wait(GCond *cond, GMutex *mutex);
gboolean tsan_g_cond_wait_until(GCond *cond, GMutex *mutex, gint64 end_time);
void tsan_g_cond_signal(GCond *cond);
void tsan_g_cond_broadcast(GCond *cond);

GAsyncQueue *tsan_g_async_queue_new(void);
GAsyncQueue *tsan_g_async_queue_ref(GAsyncQueue *queue);
void tsan_g_async_queue_unref(GAsyncQueue *queue);
void tsan_g_async_queue_push(GAsyncQueue *queue, gpointer data);
gpointer tsan_g_async_queue_try_pop(GAsyncQueue *queue);
gint tsan_g_async_queue_length(GAsyncQueue *queue);

GThreadPool *tsan_g_thread_pool_new(GFunc func, gpointer user_data, gint max_threads, gboolean exclusive, GError **error);
gboolean tsan_g_thread_pool_push(GThreadPool *pool, gpointer data, GError **error);
void tsan_g_thread_pool_free(GThreadPool *pool, gboolean immediate, gboolean wait);
gint tsan_g_thread_pool_get_max_threads(GThreadPool *pool);
/* a test can refuse pushes (as its --wrap=g_thread_pool_push does without TSan) */
extern gboolean (*tsan_g_thread_pool_refuse)(GError **error);

#define g_mutex_init tsan_g_mutex_init
#define g_mutex_clear tsan_g_mutex_clear
#define g_mutex_lock tsan_g_mutex_lock
#define g_mutex_trylock tsan_g_mutex_trylock
#define g_mutex_unlock tsan_g_mutex_unlock
#define g_cond_init tsan_g_cond_init
#define g_cond_clear tsan_g_cond_clear
#define g_cond_wait tsan_g_cond_wait
#define g_cond_wait_until tsan_g_cond_wait_until
#define g_cond_signal tsan_g_cond_signal
#define g_cond_broadcast tsan_g_cond_broadcast
#define g_async_queue_new tsan_g_async_queue_new
#define g_async_queue_ref tsan_g_async_queue_ref
#define g_async_queue_unref tsan_g_async_queue_unref
#define g_async_queue_push tsan_g_async_queue_push
#define g_async_queue_try_pop tsan_g_async_queue_try_pop
#define g_async_queue_length tsan_g_async_queue_length
#define g_thread_pool_new tsan_g_thread_pool_new
#define g_thread_pool_push tsan_g_thread_pool_push
#define g_thread_pool_free tsan_g_thread_pool_free
#define g_thread_pool_get_max_threads tsan_g_thread_pool_get_max_threads

#endif
