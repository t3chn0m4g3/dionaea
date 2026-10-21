/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The JSON of a profile (modules/emu/profile.c, json_profile_debug) for the
 * byte arguments the hooks of libemu record, e.g. the buffer of fwrite,
 * WriteFile or send. A byte argument is one JSON string: a printable ASCII
 * byte other than " and \ as it is, every other byte as \\x and two hex
 * digits. The string holds exactly the bytes of the argument: none for an
 * empty one, all of them for a long one. The rule does not depend on the
 * locale: Python sets LC_CTYPE of the process from the environment, and in a
 * locale of one byte per character isprint() takes bytes above 0x7e as well
 * (the processor-test stage of the Dockerfile makes en_US.ISO-8859-1).
 *
 * A string argument (a file name, a URL, a command line of the emulated
 * program) goes to the Python ihandlers as well, which read the JSON as
 * UTF-8: a string that is valid UTF-8 stays as it is (with the escapes of
 * JSON), every byte that is not part of a valid UTF-8 sequence is \u00NN,
 * the character of the same number.
 *
 * The rest of dionaea that profile.c calls (the emulation, the incidents,
 * the threads) is not used here and stubbed out.
 */
#include <ctype.h>
#include <locale.h>
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

void json_profile_debug(struct emu_profile *profile, GString *str);

/* ---- what profile() uses besides the JSON, never called here ---- */

struct dionaea *g_dionaea;

int run(struct emu *e, struct emu_env *env)
{
	(void)e;
	(void)env;
	g_assert_not_reached();
	return 0;
}

void emulate(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset)
{
	(void)conf;
	(void)con;
	(void)data;
	(void)size;
	(void)offset;
	g_assert_not_reached();
}

struct incident *incident_new(const char *origin)
{
	(void)origin;
	g_assert_not_reached();
	return NULL;
}

bool incident_value_string_set(struct incident *e, const char *name, GString *str)
{
	(void)e;
	(void)name;
	(void)str;
	g_assert_not_reached();
	return false;
}

bool incident_value_con_set(struct incident *e, const char *name, struct connection *val)
{
	(void)e;
	(void)name;
	(void)val;
	g_assert_not_reached();
	return false;
}

int connection_ref(struct connection *con)
{
	(void)con;
	g_assert_not_reached();
	return 0;
}

struct async_cmd *async_cmd_new(async_cmd_cb function, void *data)
{
	(void)function;
	(void)data;
	g_assert_not_reached();
	return NULL;
}

void async_incident_report(void *data)
{
	(void)data;
	g_assert_not_reached();
}

/* ---- the JSON string of one byte argument ---- */

/* the profile of one call "f" with a byte argument; returns the JSON string
 * of the argument without its quotes */
static char *json_of_bytes(const unsigned char *data, uint32_t size)
{
	struct emu_profile *profile = emu_profile_new();
	emu_profile_function_add(profile, "f");
	emu_profile_argument_add_bytea(profile, "", "", (unsigned char *)data, size);
	emu_profile_function_returnvalue_int_set(profile, "int", 0);

	GString *json = g_string_new(NULL);
	json_profile_debug(profile, json);
	emu_profile_free(profile);

	const char *args = strstr(json->str, "\"args\" : [ \n");
	g_assert_nonnull(args);
	const char *open = strchr(args + strlen("\"args\" : [ \n"), '"');
	g_assert_nonnull(open);
	const char *close = strchr(open + 1, '"');
	g_assert_nonnull(close);
	g_assert_cmpint(close[1], ==, '\n');
	char *value = g_strndup(open + 1, close - open - 1);
	g_string_free(json, TRUE);
	return value;
}

/* the rule of the header comment, independent of profile.c */
static char *expected(const unsigned char *data, size_t size)
{
	GString *s = g_string_sized_new(size * 5 + 1);
	for( size_t i = 0; i < size; i++ )
	{
		unsigned char c = data[i];
		if( c >= 0x20 && c <= 0x7e && c != '"' && c != '\\' )
			g_string_append_c(s, (char)c);
		else
			g_string_append_printf(s, "\\\\x%02x", c);
	}
	return g_string_free(s, FALSE);
}

static void check_bytes(const unsigned char *data, uint32_t size)
{
	char *got = json_of_bytes(data, size);
	char *want = expected(data, size);
	g_assert_cmpuint(strlen(got), ==, strlen(want));
	g_assert_cmpstr(got, ==, want);
	g_free(got);
	g_free(want);
}

static void test_empty(void)
{
	/* the hooks hand an empty buffer with a valid pointer (fwrite, WriteFile
	 * over 1 MiB) or with none (_lwrite) */
	static const unsigned char data[] = "AB";
	char *got = json_of_bytes(data, 0);
	g_assert_cmpstr(got, ==, "");
	g_free(got);

	got = json_of_bytes(NULL, 0);
	g_assert_cmpstr(got, ==, "");
	g_free(got);

	static const unsigned char newline[] = "\n";
	got = json_of_bytes(newline, 0);
	g_assert_cmpstr(got, ==, "");
	g_free(got);
}

static void test_one_byte(void)
{
	static const unsigned char a[] = "a";
	char *got = json_of_bytes(a, 1);
	g_assert_cmpstr(got, ==, "a");
	g_free(got);

	static const unsigned char nl[] = "\n";
	got = json_of_bytes(nl, 1);
	g_assert_cmpstr(got, ==, "\\\\x0a");
	g_free(got);
}

static void test_escapes(void)
{
	static const unsigned char data[] = {
		0x00, 0x01, 'a', '"', '\\', 0x7f, 0x80, 0xff, ' ', '~', 'b', 'c', '/', 0x1f, 0x09, 'z'
	};
	char *got = json_of_bytes(data, sizeof(data));
	g_assert_cmpstr(got, ==,
	                "\\\\x00\\\\x01a\\\\x22\\\\x5c\\\\x7f\\\\x80\\\\xff ~bc/\\\\x1f\\\\x09z");
	g_free(got);
	check_bytes(data, sizeof(data));

	/* every byte value once */
	unsigned char all[256];
	for( int i = 0; i < 256; i++ )
		all[i] = (unsigned char)i;
	check_bytes(all, sizeof(all));
}

static void test_long(void)
{
	/* 3 MiB and a byte: more than any hook copies, printable runs and escapes
	 * mixed, ending in a printable run */
	const uint32_t size = 3 * 1024 * 1024 + 1;
	unsigned char *data = g_malloc(size);
	for( uint32_t i = 0; i < size; i++ )
		data[i] = (i % 7 == 0) ? (unsigned char)(i & 0xff) : (unsigned char)('a' + i % 26);
	check_bytes(data, size);

	/* all printable: the whole input is one run */
	memset(data, 'x', size);
	char *got = json_of_bytes(data, size);
	g_assert_cmpuint(strlen(got), ==, size);
	g_free(got);

	/* nothing printable: five characters for every byte */
	memset(data, 0x01, size);
	got = json_of_bytes(data, size);
	g_assert_cmpuint(strlen(got), ==, (gsize)size * 5);
	g_free(got);
	g_free(data);
}

static void test_locale(void)
{
	if( setlocale(LC_CTYPE, "en_US.ISO-8859-1") == NULL )
	{
		g_test_skip("no locale en_US.ISO-8859-1");
		return;
	}
	g_assert_true(isprint(0xe4));
	unsigned char all[256];
	for( int i = 0; i < 256; i++ )
		all[i] = (unsigned char)i;
	check_bytes(all, sizeof(all));
	char *got = json_of_bytes((const unsigned char *)"\xe4\xa0", 2);
	g_assert_cmpstr(got, ==, "\\\\xe4\\\\xa0");
	g_free(got);
	setlocale(LC_CTYPE, "C");
}

/* the profile of one call "f" with a string argument; returns the whole JSON */
static char *json_of_string(const char *value)
{
	struct emu_profile *profile = emu_profile_new();
	emu_profile_function_add(profile, "f");
	emu_profile_argument_add_string(profile, "char *", "", (char *)value);
	emu_profile_function_returnvalue_int_set(profile, "int", 0);
	GString *json = g_string_new(NULL);
	json_profile_debug(profile, json);
	emu_profile_free(profile);
	return g_string_free(json, FALSE);
}

static void check_string(const char *value, const char *want)
{
	char *json = json_of_string(value);
	g_assert_true(g_utf8_validate(json, -1, NULL));
	char *quoted = g_strdup_printf("\"%s\"\n", want);
	g_assert_nonnull(strstr(json, quoted));
	g_free(quoted);
	g_free(json);
}

static void test_string_utf8(void)
{
	check_string("http://192.0.2.1/x.exe", "http:\\/\\/192.0.2.1\\/x.exe");
	check_string("a\"b\\c\n\x01", "a\\\"b\\\\c\\n\\u0001");
	/* valid UTF-8 as it is: two, three and four bytes */
	check_string("\xc3\xa4 \xe2\x82\xac \xf0\x9f\x98\x80", "\xc3\xa4 \xe2\x82\xac \xf0\x9f\x98\x80");
	/* the bytes of no valid sequence: alone, cut off, overlong, a surrogate, past U+10FFFF */
	check_string("\xff\xfe", "\\u00ff\\u00fe");
	check_string("a\xc3", "a\\u00c3");
	check_string("\xe2\x82x", "\\u00e2\\u0082x");
	check_string("\xc0\xaf", "\\u00c0\\u00af");
	check_string("\xed\xa0\x80", "\\u00ed\\u00a0\\u0080");
	check_string("\xf4\x90\x80\x80", "\\u00f4\\u0090\\u0080\\u0080");
	check_string("\x80\xc3\xa4\x80", "\\u0080\xc3\xa4\\u0080");
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/profile/bytea/empty", test_empty);
	g_test_add_func("/profile/bytea/one_byte", test_one_byte);
	g_test_add_func("/profile/bytea/escapes", test_escapes);
	g_test_add_func("/profile/bytea/long", test_long);
	g_test_add_func("/profile/bytea/locale", test_locale);
	g_test_add_func("/profile/string/utf8", test_string_utf8);
	return g_test_run();
}
