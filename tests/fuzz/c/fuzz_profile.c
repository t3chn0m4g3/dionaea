/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * libFuzzer target of the JSON of an emu profile (modules/emu/profile.c,
 * json_profile_debug with json_escape_str and json_escape_bytea) and of
 * emu_profile_argument_add_bytea (third_party/libemu). The input builds a
 * profile of the shapes the hooks of libemu record: calls with ints, shorts,
 * strings and byte buffers from the emulated memory (any bytes, strings end
 * at a NUL), addresses, ports, pointers to values or structs, arrays.
 *
 * The JSON goes to the Python ihandlers as a str (strict UTF-8) and through
 * json.loads (emu.py, logsql.py), so it must be valid UTF-8 and valid JSON.
 * Every string of it (keys and values, in order) must decode to what the
 * profile holds: the bytes of a string argument that is valid UTF-8, the
 * escaped text of a byte argument (a printable ASCII byte but " and \ as it
 * is, every other one as \xNN).
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <emu/emu.h>
#include <emu/environment/emu_profile.h>

#include "dionaea.h"
#include "connection.h"
#include "incident.h"
#include "threads.h"
#include "module.h"
#include "fuzz_input.h"

void json_profile_debug(struct emu_profile *profile, GString *str);

/* ---- what profile() uses besides the JSON, never called here ---- */

struct dionaea *g_dionaea;

int run(struct emu *e, struct emu_env *env)
{
	(void)e;
	(void)env;
	abort();
}

void emulate(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset)
{
	(void)conf;
	(void)con;
	(void)data;
	(void)size;
	(void)offset;
	abort();
}

struct incident *incident_new(const char *origin)
{
	(void)origin;
	abort();
}

bool incident_value_string_set(struct incident *e, const char *name, GString *str)
{
	(void)e;
	(void)name;
	(void)str;
	abort();
}

bool incident_value_con_set(struct incident *e, const char *name, struct connection *val)
{
	(void)e;
	(void)name;
	(void)val;
	abort();
}

int connection_ref(struct connection *con)
{
	(void)con;
	abort();
}

struct async_cmd *async_cmd_new(async_cmd_cb function, void *data)
{
	(void)function;
	(void)data;
	abort();
}

void async_incident_report(void *data)
{
	(void)data;
	abort();
}

/* ---- a strict JSON reader: valid UTF-8, no lone surrogate, every string decoded ---- */

struct reader
{
	const unsigned char *p, *end;
	GPtrArray *strings; /* GByteArray: the decoded strings in order */
	int depth;
};

static void ws(struct reader *r)
{
	while( r->p < r->end && (*r->p == ' ' || *r->p == '\t' || *r->p == '\n' || *r->p == '\r') )
		r->p++;
}

static bool hex4(struct reader *r, unsigned *v)
{
	if( r->end - r->p < 4 )
		return false;
	*v = 0;
	for( int i = 0; i < 4; i++ )
	{
		unsigned char c = r->p[i];
		*v <<= 4;
		if( c >= '0' && c <= '9' ) *v |= c - '0';
		else if( c >= 'a' && c <= 'f' ) *v |= c - 'a' + 10;
		else if( c >= 'A' && c <= 'F' ) *v |= c - 'A' + 10;
		else return false;
	}
	r->p += 4;
	return true;
}

static bool string(struct reader *r)
{
	if( r->p >= r->end || *r->p != '"' )
		return false;
	r->p++;
	const unsigned char *start = r->p;
	while( r->p < r->end && *r->p != '"' )
	{
		if( *r->p == '\\' )
			r->p += 2;
		else
			r->p++;
	}
	if( r->p >= r->end )
		return false;
	const unsigned char *close = r->p;
	if( !g_utf8_validate((const char *)start, close - start, NULL) )
		return false;

	GByteArray *out = g_byte_array_new();
	for( const unsigned char *q = start; q < close; )
	{
		if( *q < 0x20 )
			goto bad;
		if( *q != '\\' )
		{
			g_byte_array_append(out, q, 1);
			q++;
			continue;
		}
		q++;
		guint8 c;
		switch( *q )
		{
		case '"': c = '"'; break;
		case '\\': c = '\\'; break;
		case '/': c = '/'; break;
		case 'b': c = '\b'; break;
		case 'f': c = '\f'; break;
		case 'n': c = '\n'; break;
		case 'r': c = '\r'; break;
		case 't': c = '\t'; break;
		case 'u':
			{
				struct reader h = { q + 1, close, NULL, 0 };
				unsigned v;
				if( !hex4(&h, &v) )
					goto bad;
				q = h.p;
				if( v >= 0xd800 && v <= 0xdbff )
				{
					unsigned low;
					if( close - q < 6 || q[0] != '\\' || q[1] != 'u' )
						goto bad;
					h.p = q + 2;
					if( !hex4(&h, &low) || low < 0xdc00 || low > 0xdfff )
						goto bad;
					q = h.p;
					v = 0x10000 + ((v - 0xd800) << 10) + (low - 0xdc00);
				} else if( v >= 0xdc00 && v <= 0xdfff )
					goto bad;
				gchar utf8[6];
				gint n = g_unichar_to_utf8(v, utf8);
				g_byte_array_append(out, (guint8 *)utf8, n);
				continue;
			}
		default:
			goto bad;
		}
		g_byte_array_append(out, &c, 1);
		q++;
	}
	r->p = close + 1;
	g_ptr_array_add(r->strings, out);
	return true;
bad:
	g_byte_array_free(out, TRUE);
	return false;
}

static bool value(struct reader *r);

static bool members(struct reader *r, char open, char close, bool keys)
{
	if( r->p >= r->end || *r->p != open || ++r->depth > 64 )
		return false;
	r->p++;
	ws(r);
	if( r->p < r->end && *r->p == close )
	{
		r->p++;
		r->depth--;
		return true;
	}
	for( ;; )
	{
		ws(r);
		if( keys )
		{
			if( !string(r) )
				return false;
			ws(r);
			if( r->p >= r->end || *r->p != ':' )
				return false;
			r->p++;
			ws(r);
		}
		if( !value(r) )
			return false;
		ws(r);
		if( r->p < r->end && *r->p == ',' )
		{
			r->p++;
			continue;
		}
		if( r->p < r->end && *r->p == close )
		{
			r->p++;
			r->depth--;
			return true;
		}
		return false;
	}
}

static bool value(struct reader *r)
{
	ws(r);
	if( r->p >= r->end )
		return false;
	switch( *r->p )
	{
	case '{': return members(r, '{', '}', true);
	case '[': return members(r, '[', ']', false);
	case '"': return string(r);
	default: return false; /* the profile has strings only */
	}
}

/* ---- the profile from the input, and the strings its JSON must hold ---- */

static const char *const FUNCTIONS[] = {
	"LoadLibraryA", "URLDownloadToFile", "WinExec", "CreateProcess", "socket", "connect",
	"bind", "listen", "accept", "recv", "send", "fwrite", "WriteFile", "execve", "",
};
static const char *const NAMES[] = { "", "lpFileName", "sin_port", "addr", "s_addr", "cb", "buf" };

struct builder
{
	struct emu_profile *profile;
	struct fuzz_input *in;
	GPtrArray *want;   /* GByteArray: the strings of the JSON, in order */
	int budget;        /* arguments left */
};

static void bytes_free(gpointer data)
{
	if( data != NULL )
		g_byte_array_unref(data);
}

static void want_text(struct builder *b, const void *text, size_t size)
{
	GByteArray *s = g_byte_array_sized_new((guint)size);
	g_byte_array_append(s, text, (guint)size);
	g_ptr_array_add(b->want, s);
}

static void want_str(struct builder *b, const char *text)
{
	want_text(b, text, strlen(text));
}

/* a string of the emulated memory: any bytes up to a NUL */
static char *memory_string(struct fuzz_input *in)
{
	size_t len = fuzz_u8(in);
	char *s = g_malloc(len + 1);
	size_t got = fuzz_bytes(in, s, len);
	s[got] = '\0';
	return s;
}

static void add_value(struct builder *b, int depth, bool named);

static void add_struct_members(struct builder *b, int depth)
{
	int n = fuzz_u8(b->in) % 5;
	for( int i = 0; i < n && b->budget > 0; i++ )
		add_value(b, depth + 1, true);
}

/* one argument; named: a member of a struct (the hooks put no pointer there) */
static void add_value(struct builder *b, int depth, bool named)
{
	b->budget--;
	uint8_t kind = fuzz_u8(b->in) % (named ? 7 : 10);
	char *name = (char *)NAMES[fuzz_u8(b->in) % G_N_ELEMENTS(NAMES)];
	if( depth > 6 && kind >= 5 )
		kind = 0;
	if( named )
		want_str(b, name);
	char text[32];
	switch( kind )
	{
	case 0:
		{
			int32_t v = (int32_t)fuzz_u32(b->in);
			emu_profile_argument_add_int(b->profile, "int", name, v);
			g_snprintf(text, sizeof(text), "%i", v);
			want_str(b, text);
		}
		break;
	case 1:
		{
			int16_t v = (int16_t)fuzz_u16(b->in);
			emu_profile_argument_add_short(b->profile, "short", name, v);
			g_snprintf(text, sizeof(text), "%i", v);
			want_str(b, text);
		}
		break;
	case 2:
		{
			char *s = memory_string(b->in);
			emu_profile_argument_add_string(b->profile, "char *", name, s);
			if( g_utf8_validate(s, -1, NULL) )
				want_str(b, s);
			else
				g_ptr_array_add(b->want, NULL); /* any valid string */
			g_free(s);
		}
		break;
	case 3:
		{
			uint32_t v = fuzz_u32(b->in);
			emu_profile_argument_add_ip(b->profile, "in_addr_t", name, v);
			struct in_addr a = { .s_addr = v };
			want_str(b, inet_ntoa(a));
		}
		break;
	case 4:
		{
			uint32_t v = fuzz_u16(b->in);
			emu_profile_argument_add_port(b->profile, "u_short", name, v);
			g_snprintf(text, sizeof(text), "%i", ntohs((uint16_t)v));
			want_str(b, text);
		}
		break;
	case 5:
		if( named )
		{
			emu_profile_argument_struct_start(b->profile, "", name);
			add_struct_members(b, depth);
			emu_profile_argument_struct_end(b->profile);
			break;
		}
		emu_profile_argument_add_none(b->profile);
		want_str(b, "");
		break;
	case 6:
		{
			/* a buffer of a hook (fwrite, WriteFile, send, recv): up to 64 KiB */
			uint32_t size = fuzz_u16(b->in);
			size_t got;
			const uint8_t *data = fuzz_span(b->in, size, &got);
			bool null_data = got == 0 && (fuzz_u8(b->in) & 1);
			emu_profile_argument_add_bytea(b->profile, "", name, null_data ? NULL : (unsigned char *)data,
			                               (uint32_t)got);
			GString *escaped = g_string_new(NULL);
			for( size_t i = 0; i < got; i++ )
			{
				unsigned char c = data[i];
				if( c >= 0x20 && c <= 0x7e && c != '"' && c != '\\' )
					g_string_append_c(escaped, (char)c);
				else
					g_string_append_printf(escaped, "\\x%02x", c);
			}
			want_text(b, escaped->str, escaped->len);
			g_string_free(escaped, TRUE);
		}
		break;
	case 7:
		/* a pointer, followed by what it points to */
		emu_profile_argument_add_ptr(b->profile, "void *", name, fuzz_u32(b->in));
		add_value(b, depth + 1, false);
		break;
	case 8:
		/* a pointer to a struct (sockaddr, STARTUPINFO) */
		emu_profile_argument_add_ptr(b->profile, "void *", name, fuzz_u32(b->in));
		emu_profile_argument_struct_start(b->profile, "", "");
		add_struct_members(b, depth);
		emu_profile_argument_struct_end(b->profile);
		break;
	default:
		{
			/* an array (argv[] of execve) */
			emu_profile_argument_array_start(b->profile, "const char *", name);
			int n = fuzz_u8(b->in) % 5;
			for( int i = 0; i < n && b->budget > 0; i++ )
				add_value(b, depth + 1, false);
			emu_profile_argument_array_end(b->profile);
		}
		break;
	}
}

static void quiet(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	(void)domain;
	(void)message;
	(void)data;
	if( level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL) )
		abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	g_log_set_default_handler(quiet, NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in = { data, size };
	struct builder b = { emu_profile_new(), &in, g_ptr_array_new_with_free_func(bytes_free), 256 };

	int functions = 0;
	while( fuzz_left(&in) > 0 && functions < 32 && b.budget > 0 )
	{
		const char *name = FUNCTIONS[fuzz_u8(&in) % G_N_ELEMENTS(FUNCTIONS)];
		emu_profile_function_add(b.profile, (char *)name);
		functions++;
		want_str(&b, "call");
		want_str(&b, name);
		want_str(&b, "args");
		int args = fuzz_u8(&in) % 6;
		for( int i = 0; i < args && b.budget > 0; i++ )
			add_value(&b, 0, false);
		want_str(&b, "return");
		uint8_t ret = fuzz_u8(&in) % 3;
		char text[32];
		if( ret == 1 )
		{
			int32_t v = (int32_t)fuzz_u32(&in);
			emu_profile_function_returnvalue_int_set(b.profile, "int", v);
			g_snprintf(text, sizeof(text), "%i", v);
		} else
			/* the default of a call: an int of -1 */
			g_snprintf(text, sizeof(text), "%i", -1);
		want_str(&b, text);
	}

	GString *json = g_string_new(NULL);
	json_profile_debug(b.profile, json);
	emu_profile_free(b.profile);

	struct reader r = { (const unsigned char *)json->str, (const unsigned char *)json->str + json->len,
	                    g_ptr_array_new_with_free_func(bytes_free), 0 };
	bool parsed = value(&r);
	ws(&r);
	if( !parsed || r.p != r.end || !g_utf8_validate(json->str, json->len, NULL) )
	{
		fprintf(stderr, "the JSON of the profile is not valid (at byte %td of %zu)\n",
		        (const char *)r.p - json->str, json->len);
		gchar *shown = g_strescape(json->str, NULL);
		fprintf(stderr, "%s\n", shown);
		g_free(shown);
		abort();
	}
	g_assert_cmpuint(r.strings->len, ==, b.want->len);
	for( guint i = 0; i < b.want->len; i++ )
	{
		GByteArray *want = g_ptr_array_index(b.want, i);
		GByteArray *got = g_ptr_array_index(r.strings, i);
		if( want != NULL )
			g_assert_cmpmem(got->data, got->len, want->data, want->len);
	}

	g_ptr_array_free(r.strings, TRUE);
	g_ptr_array_free(b.want, TRUE);
	g_string_free(json, TRUE);
	return 0;
}
