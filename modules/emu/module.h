/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct connection;
struct processor_data;
struct emu;
struct emu_env;

struct emu_ctx
{
	struct emu_config *config;
	uint64_t offset;	/* absolute stream offset: the data before it was scanned */
};

struct emu_config
{
	struct
	{
		int files;
		int filesize;
		int sockets;
		double sustain;
		double idle;
		double listen;
		int steps;
		double cpu;
	}limits;
};

void *proc_emu_ctx_new(void *cfg);
void proc_emu_ctx_free(void *ctx);
void *proc_emu_ctx_cfg_new(gchar *);
void proc_emu_on_io_in(struct connection *con, struct processor_data *pd);
void proc_emu_on_io_out(struct connection *con, struct processor_data *pd);

int run(struct emu *e, struct emu_env *env);
void profile(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset);


/* trim.c: the free memory of the arenas back to the system after a scan that built libemu's
 * instruction graph, at most once per EMU_TRIM_INTERVAL_US in the process (glibc only); a trim the
 * limit skipped is made once the interval is over, by the next scan that ends or, when the emu is
 * idle, by a thread of trim.c */
#define EMU_TRIM_INTERVAL_US (5 * (int64_t)1000000)
/* true when emu_shellcode_test() on e built the graph (the window had a GetPC candidate) */
bool emu_scan_built_graph(struct emu *e);
/* true for the one caller that may trim at the monotonic time now (microseconds) */
bool emu_trim_claim(int64_t now);
/* around a scan of a window; graph: emu_scan_built_graph() of it, its memory is freed */
void emu_trim_scan_begin(void);
void emu_trim_scan_end(bool graph);
/* stops the thread of the trailing trim (module free) */
void emu_trim_stop(void);
/* nothing pending, the thread stopped, the next claim succeeds at once, a failed thread warned about again (tests) */
void emu_trim_reset(void);
/* the trims made (deferred: by the trailing trim) and their time, for a probe (tests/load) */
struct emu_trim_stats
{
	_Atomic uint64_t count;
	_Atomic uint64_t total_us;
	_Atomic uint64_t max_us;
	_Atomic uint64_t deferred;
};
extern struct emu_trim_stats emu_trim_stats;

void emulate_ctx_free(void *ctx);
void emulate_thread(gpointer data, gpointer user_data);
void emulate(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset);

/* hooks.c */
struct emu_env;
struct emu_env_hook;

enum emu_state
{
	running, waiting, failed
};

struct emu_emulate_ctx
{
	struct emu_config *config;

	struct connection *ctxcon;

	GMutex mutex;
	struct emu *emu;
	struct emu_env *env;

	/**
	 * mapping 'virtual' fd to struct connection *
	 */
	GHashTable *sockets;
	/**
	 * mapping struct connection * to int32_t processhandle
	 */
	GHashTable *processes;
	GHashTable *files;
	unsigned long steps;
	uint32_t esp;
	enum emu_state state;
	GTimer *time;

	int serial;
};

struct emu_file
{
	FILE *fh;
	char *path;
};

void user_hook_accept_cb(EV_P_ struct ev_io *w, int revents);
uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
void user_hook_connect_cb(EV_P_ struct ev_io *w, int revents);
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_close(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
void user_hook_WaitForSingleObject_cb(EV_P_ struct ev_child *w,  int revents);
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...);


uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...);

int32_t ll_win_hook_recv(struct emu_env *env, struct emu_env_hook *hook);
int32_t ll_win_hook_accept(struct emu_env *env, struct emu_env_hook *hook);


uint32_t user_hook__lcreat(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lwrite(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lclose(struct emu_env *env, struct emu_env_hook *hook, ...);

extern struct processor proc_emu;
