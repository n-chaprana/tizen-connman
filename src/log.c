/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include <signal.h>

#include "connman.h"

static const char *program_exec;
static const char *program_path;

#if defined TIZEN_EXT
#include <sys/stat.h>
#include <sys/time.h>

#define LOG_FILE_PATH "/opt/usr/data/network/connman.log"
#define MAX_LOG_SIZE	1 * 1024 * 1024
#define MAX_LOG_COUNT	15

#define openlog __connman_log_open
#define closelog __connman_log_close
#define vsyslog __connman_log
#define syslog __connman_log_s

static FILE *log_file = NULL;

void __connman_log_open(const char *ident, int option, int facility)
{
	if (!log_file)
		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");
}

void __connman_log_close(void)
{
	fclose(log_file);
	log_file = NULL;
}

static void __connman_log_update_file_revision(int rev)
{
	int next_log_rev = 0;
	char *log_file = NULL;
	char *next_log_file = NULL;

	next_log_rev = rev + 1;

	log_file = g_strdup_printf("%s.%d", LOG_FILE_PATH, rev);
	next_log_file = g_strdup_printf("%s.%d", LOG_FILE_PATH, next_log_rev);

	if (next_log_rev >= MAX_LOG_COUNT)
		if (remove(next_log_file) != 0)
			goto error;

	if (access(next_log_file, F_OK) == 0)
		__connman_log_update_file_revision(next_log_rev);

	if (rename(log_file, next_log_file) != 0)
		remove(log_file);

error:
	g_free(log_file);
	g_free(next_log_file);
}

static int __connman_log_make_backup(void)
{
	const int rev = 0;
	char *backup = NULL;
	int ret = 0;

	backup = g_strdup_printf("%s.%d", LOG_FILE_PATH, rev);

	if (access(backup, F_OK) == 0)
		__connman_log_update_file_revision(rev);

	if (rename(LOG_FILE_PATH, backup) != 0)
		if (remove(LOG_FILE_PATH) != 0)
			ret = -1;

	g_free(backup);
	return ret;
}

static void __connman_log_get_local_time(char *strtime, const int size)
{
	struct timeval tv;
	struct tm *local_ptm;
	char buf[32];

	gettimeofday(&tv, NULL);
	local_ptm = localtime(&tv.tv_sec);

	strftime(buf, sizeof(buf), "%m/%d %H:%M:%S", local_ptm);
	snprintf(strtime, size, "%s.%03ld", buf, tv.tv_usec / 1000);
}

void __connman_log(const int log_priority, const char *format, va_list ap)
{
	int log_size = 0;
	struct stat buf;
	char str[256];
	char strtime[40];

	if (!log_file)
		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");

	if (!log_file)
		return;

	if (fstat(fileno(log_file), &buf) < 0) {
		fclose(log_file);
		log_file = NULL;
		return;
	}

	log_size = buf.st_size;

	if (log_size >= MAX_LOG_SIZE) {
		fclose(log_file);
		log_file = NULL;

		if (__connman_log_make_backup() != 0)
			return;

		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");

		if (!log_file)
			return;
	}

	__connman_log_get_local_time(strtime, sizeof(strtime));

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		fprintf(log_file, "%s %s\n", strtime, str);
}

void __connman_log_s(int log_priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}
#endif

/* This makes sure we always have a __debug section. */
CONNMAN_DEBUG_DEFINE(dummy);

/**
 * connman_info:
 * @format: format string
 * @Varargs: list of arguments
 *
 * Output general information
 */
void connman_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_INFO, format, ap);

	va_end(ap);
}

/**
 * connman_warn:
 * @format: format string
 * @Varargs: list of arguments
 *
 * Output warning messages
 */
void connman_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_WARNING, format, ap);

	va_end(ap);
}

/**
 * connman_error:
 * @format: format string
 * @varargs: list of arguments
 *
 * Output error messages
 */
void connman_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_ERR, format, ap);

	va_end(ap);
}

/**
 * connman_debug:
 * @format: format string
 * @varargs: list of arguments
 *
 * Output debug message
 */
void connman_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}

static void signal_handler(int signo)
{
	connman_error("Aborting (signal %d) [%s]", signo, program_exec);

	print_backtrace(program_path, program_exec, 2);

	exit(EXIT_FAILURE);
}

static void signal_setup(sighandler_t handler)
{
	struct sigaction sa;
	sigset_t mask;

	sigemptyset(&mask);
	sa.sa_handler = handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
}

extern struct connman_debug_desc __start___debug[];
extern struct connman_debug_desc __stop___debug[];

static gchar **enabled = NULL;

static bool is_enabled(struct connman_debug_desc *desc)
{
	int i;

	if (!enabled)
		return false;

	for (i = 0; enabled[i]; i++) {
		if (desc->name && g_pattern_match_simple(enabled[i],
							desc->name))
			return true;
		if (desc->file && g_pattern_match_simple(enabled[i],
							desc->file))
			return true;
	}

	return false;
}

void __connman_log_enable(struct connman_debug_desc *start,
					struct connman_debug_desc *stop)
{
	struct connman_debug_desc *desc;
	const char *name = NULL, *file = NULL;

	if (!start || !stop)
		return;

	for (desc = start; desc < stop; desc++) {
		if (desc->flags & CONNMAN_DEBUG_FLAG_ALIAS) {
			file = desc->file;
			name = desc->name;
			continue;
		}

		if (file || name) {
			if (g_strcmp0(desc->file, file) == 0) {
				if (!desc->name)
					desc->name = name;
			} else
				file = NULL;
		}

		if (is_enabled(desc))
			desc->flags |= CONNMAN_DEBUG_FLAG_PRINT;
	}
}

int __connman_log_init(const char *program, const char *debug,
		gboolean detach, gboolean backtrace,
		const char *program_name, const char *program_version)
{
	static char path[PATH_MAX];
	int option = LOG_NDELAY | LOG_PID;

	program_exec = program;
	program_path = getcwd(path, sizeof(path));

	if (debug)
		enabled = g_strsplit_set(debug, ":, ", 0);

	__connman_log_enable(__start___debug, __stop___debug);

	if (!detach)
		option |= LOG_PERROR;

	if (backtrace)
		signal_setup(signal_handler);

	openlog(basename(program), option, LOG_DAEMON);

	syslog(LOG_INFO, "%s version %s", program_name, program_version);

	return 0;
}

void __connman_log_cleanup(gboolean backtrace)
{
	syslog(LOG_INFO, "Exit");

	closelog();

	if (backtrace)
		signal_setup(SIG_DFL);

	g_strfreev(enabled);
}
