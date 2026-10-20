/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The pthread based GMutex, GCond, GAsyncQueue and GThreadPool of the
 * ThreadSanitizer build of the processor tests, see glib_tsan.h.
 *
 * As in GLib's own fallback, the pthread mutex of a GMutex is allocated on
 * first use, so a zeroed (static) GMutex works without g_mutex_init().
 *
 * The pthread_cond_*wait interceptors of ThreadSanitizer crash on aarch64 with
 * pointer authentication (SIGILL in __sigsetjmp), so nothing here waits on a
 * pthread condition: a wait is a short sleep with the mutex released, a
 * spurious wakeup GCond allows (its callers check their condition in a loop);
 * the mutex orders the accesses.
 */
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "glib_tsan.h"

static pthread_mutex_t *mutex_impl(GMutex *mutex)
{
	pthread_mutex_t **slot = (pthread_mutex_t **)&mutex->p;
	pthread_mutex_t *impl = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
	if( impl == NULL )
	{
		pthread_mutex_t *fresh = malloc(sizeof(*fresh));
		g_assert_nonnull(fresh);
		pthread_mutex_init(fresh, NULL);
		if( __atomic_compare_exchange_n(slot, &impl, fresh, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) )
			impl = fresh;
		else
		{
			pthread_mutex_destroy(fresh);
			free(fresh);
		}
	}
	return impl;
}

void tsan_g_mutex_init(GMutex *mutex)
{
	mutex->p = NULL;
	(void)mutex_impl(mutex);
}

void tsan_g_mutex_clear(GMutex *mutex)
{
	pthread_mutex_t *impl = mutex->p;
	if( impl != NULL )
	{
		pthread_mutex_destroy(impl);
		free(impl);
	}
	mutex->p = NULL;
}

void tsan_g_mutex_lock(GMutex *mutex)
{
	g_assert_cmpint(pthread_mutex_lock(mutex_impl(mutex)), ==, 0);
}

gboolean tsan_g_mutex_trylock(GMutex *mutex)
{
	return pthread_mutex_trylock(mutex_impl(mutex)) == 0;
}

void tsan_g_mutex_unlock(GMutex *mutex)
{
	g_assert_cmpint(pthread_mutex_unlock(mutex_impl(mutex)), ==, 0);
}

void tsan_g_cond_init(GCond *cond)
{
	cond->p = NULL;
}

void tsan_g_cond_clear(GCond *cond)
{
	(void)cond;
}

void tsan_g_cond_wait(GCond *cond, GMutex *mutex)
{
	(void)cond;
	tsan_g_mutex_unlock(mutex);
	g_usleep(100);
	tsan_g_mutex_lock(mutex);
}

gboolean tsan_g_cond_wait_until(GCond *cond, GMutex *mutex, gint64 end_time)
{
	tsan_g_cond_wait(cond, mutex);
	return g_get_monotonic_time() < end_time;
}

void tsan_g_cond_signal(GCond *cond)
{
	(void)cond;
}

void tsan_g_cond_broadcast(GCond *cond)
{
	(void)cond;
}


struct tsan_async_queue
{
	GMutex mutex;
	GQueue items;
	gint refs;
};

GAsyncQueue *tsan_g_async_queue_new(void)
{
	struct tsan_async_queue *queue = g_new0(struct tsan_async_queue, 1);
	tsan_g_mutex_init(&queue->mutex);
	g_queue_init(&queue->items);
	queue->refs = 1;
	return (GAsyncQueue *)queue;
}

GAsyncQueue *tsan_g_async_queue_ref(GAsyncQueue *q)
{
	struct tsan_async_queue *queue = (struct tsan_async_queue *)q;
	g_atomic_int_inc(&queue->refs);
	return q;
}

void tsan_g_async_queue_unref(GAsyncQueue *q)
{
	struct tsan_async_queue *queue = (struct tsan_async_queue *)q;
	if( !g_atomic_int_dec_and_test(&queue->refs) )
		return;
	g_queue_clear(&queue->items);
	tsan_g_mutex_clear(&queue->mutex);
	g_free(queue);
}

void tsan_g_async_queue_push(GAsyncQueue *q, gpointer data)
{
	struct tsan_async_queue *queue = (struct tsan_async_queue *)q;
	tsan_g_mutex_lock(&queue->mutex);
	g_queue_push_tail(&queue->items, data);
	tsan_g_mutex_unlock(&queue->mutex);
}

gpointer tsan_g_async_queue_try_pop(GAsyncQueue *q)
{
	struct tsan_async_queue *queue = (struct tsan_async_queue *)q;
	tsan_g_mutex_lock(&queue->mutex);
	gpointer data = g_queue_pop_head(&queue->items);
	tsan_g_mutex_unlock(&queue->mutex);
	return data;
}

gint tsan_g_async_queue_length(GAsyncQueue *q)
{
	struct tsan_async_queue *queue = (struct tsan_async_queue *)q;
	tsan_g_mutex_lock(&queue->mutex);
	gint length = (gint)g_queue_get_length(&queue->items);
	tsan_g_mutex_unlock(&queue->mutex);
	return length;
}


/* a fixed number of workers that take the jobs in order */
struct tsan_pool
{
	GFunc func;
	gpointer user_data;
	gint max_threads;
	GMutex mutex;
	GQueue jobs;
	bool stop;
	pthread_t *threads;
};

gboolean (*tsan_g_thread_pool_refuse)(GError **error);

static void *tsan_pool_worker(void *data)
{
	struct tsan_pool *pool = data;
	tsan_g_mutex_lock(&pool->mutex);
	for( ;; )
	{
		gpointer job = g_queue_pop_head(&pool->jobs);
		if( job != NULL )
		{
			tsan_g_mutex_unlock(&pool->mutex);
			pool->func(job, pool->user_data);
			tsan_g_mutex_lock(&pool->mutex);
			continue;
		}
		if( pool->stop )
			break;
		tsan_g_mutex_unlock(&pool->mutex);
		g_usleep(100);
		tsan_g_mutex_lock(&pool->mutex);
	}
	tsan_g_mutex_unlock(&pool->mutex);
	return NULL;
}

GThreadPool *tsan_g_thread_pool_new(GFunc func, gpointer user_data, gint max_threads, gboolean exclusive, GError **error)
{
	(void)exclusive;
	(void)error;
	g_assert_cmpint(max_threads, >, 0);
	struct tsan_pool *pool = g_new0(struct tsan_pool, 1);
	pool->func = func;
	pool->user_data = user_data;
	pool->max_threads = max_threads;
	tsan_g_mutex_init(&pool->mutex);
	g_queue_init(&pool->jobs);
	pool->threads = g_new0(pthread_t, max_threads);
	for( gint i = 0; i < max_threads; i++ )
		g_assert_cmpint(pthread_create(&pool->threads[i], NULL, tsan_pool_worker, pool), ==, 0);
	return (GThreadPool *)pool;
}

gboolean tsan_g_thread_pool_push(GThreadPool *p, gpointer data, GError **error)
{
	struct tsan_pool *pool = (struct tsan_pool *)p;
	if( tsan_g_thread_pool_refuse != NULL && tsan_g_thread_pool_refuse(error) )
		return FALSE;
	tsan_g_mutex_lock(&pool->mutex);
	g_queue_push_tail(&pool->jobs, data);
	tsan_g_mutex_unlock(&pool->mutex);
	return TRUE;
}

void tsan_g_thread_pool_free(GThreadPool *p, gboolean immediate, gboolean wait)
{
	struct tsan_pool *pool = (struct tsan_pool *)p;
	g_assert_false(immediate);
	g_assert_true(wait);
	tsan_g_mutex_lock(&pool->mutex);
	pool->stop = true;
	tsan_g_mutex_unlock(&pool->mutex);
	for( gint i = 0; i < pool->max_threads; i++ )
		g_assert_cmpint(pthread_join(pool->threads[i], NULL), ==, 0);
	g_free(pool->threads);
	tsan_g_mutex_clear(&pool->mutex);
	g_free(pool);
}

gint tsan_g_thread_pool_get_max_threads(GThreadPool *p)
{
	return ((struct tsan_pool *)p)->max_threads;
}
