/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifndef SYS_SOLARIS9
#include <stdint.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include "debug.h"
#include "util.h"

static char *debug_ident = NULL;
static uint8_t debug_level = DBG_INFO;
static char *debug_filepath = NULL;
static FILE *debug_file = NULL;
static int debug_syslogfacility = 0;
#if defined(WANT_FTICKS)
static int fticks_syslogfacility = 0;
#endif
static uint8_t debug_timestamp = 0;

void debug_init(char *ident) {
    debug_file = stderr;
    setvbuf(debug_file, NULL, _IONBF, 0);
    debug_ident = ident;
}

void debug_set_level(uint8_t level) {
    switch (level) {
    case 1:
	debug_level = DBG_ERR;
	return;
    case 2:
	debug_level = DBG_WARN;
	return;
    case 3:
	debug_level = DBG_NOTICE;
	return;
    case 4:
	debug_level = DBG_INFO;
	return;
    case 5:
	debug_level = DBG_DBG;
	return;
    }
}

void debug_timestamp_on() {
    debug_timestamp = 1;
}

uint8_t debug_get_level() {
    return debug_level;
}

int debug_set_destination(char *dest, int log_type) {
    static const char *facstrings[] = {
        "LOG_DAEMON", "LOG_MAIL", "LOG_USER", "LOG_LOCAL0",
	"LOG_LOCAL1", "LOG_LOCAL2", "LOG_LOCAL3", "LOG_LOCAL4",
	"LOG_LOCAL5", "LOG_LOCAL6", "LOG_LOCAL7", NULL };
    static const int facvals[] = {
        LOG_DAEMON, LOG_MAIL, LOG_USER, LOG_LOCAL0,
	LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4,
	LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7 };
    extern int errno;
    int i;

    if (!strncasecmp(dest, "file:///", 8)) {
	if (log_type != LOG_TYPE_FTICKS) {
	    debug_filepath = stringcopy(dest + 7, 0);
	    debug_file = fopen(debug_filepath, "a");
	    if (!debug_file) {
	        debug_file = stderr;
	        debugx(1, DBG_ERR, "Failed to open logfile %s\n%s",
                       debug_filepath, strerror(errno));
	    }
	    setvbuf(debug_file, NULL, _IONBF, 0);
	} else {
	    debug(DBG_WARN, "FTicksSyslogFacility starting with file:/// not "
                  "permitted, assuming default F-Ticks destination");
	}
	return 1;
    }
    if (!strncasecmp(dest, "x-syslog://", 11) || log_type == LOG_TYPE_FTICKS) {
	if (!strncasecmp(dest, "x-syslog://", 11)) {
            dest += 11;
            if (*dest == '/')
                dest++;
	}
	if (*dest) {
	    for (i = 0; facstrings[i]; i++)
		if (!strcasecmp(dest, facstrings[i]))
		    break;
	    if (!facstrings[i])
		debugx(1, DBG_ERR, "Unknown syslog facility %s", dest);
	    if (log_type != LOG_TYPE_FTICKS)
		debug_syslogfacility = facvals[i];
#if defined(WANT_FTICKS)
            else if (log_type == LOG_TYPE_FTICKS)
		fticks_syslogfacility = facvals[i];
#endif
	} else {
            if (log_type != LOG_TYPE_FTICKS)
                debug_syslogfacility = LOG_DAEMON;
#if defined(WANT_FTICKS)
            else if (log_type == LOG_TYPE_FTICKS)
                fticks_syslogfacility = 0;
#endif
    	}
	openlog(debug_ident, LOG_PID, debug_syslogfacility);
	return 1;
    }
    debug(DBG_ERR, "Unknown log destination, exiting %s", dest);
    exit(1);
}

void debug_reopen_log() {
    extern int errno;

    /* not a file, noop, return success */
    if (!debug_filepath) {
	debug(DBG_ERR, "skipping reopen");
	return;
    }

    if (debug_file != stderr)
	fclose(debug_file);

    debug_file = fopen(debug_filepath, "a");
    if (debug_file)
	debug(DBG_ERR, "Reopened logfile %s", debug_filepath);
    else {
	debug_file = stderr;
	debug(DBG_ERR, "Failed to open logfile %s, using stderr\n%s",
	      debug_filepath, strerror(errno));
    }
    setvbuf(debug_file, NULL, _IONBF, 0);
}

void debug_logit(uint8_t level, const char *format, va_list ap) {
    struct timeval now;
    char *timebuf;
    int priority;

    if (debug_syslogfacility) {
	switch (level) {
	case DBG_DBG:
	    priority = LOG_DEBUG;
	    break;
	case DBG_INFO:
	    priority = LOG_INFO;
	    break;
	case DBG_NOTICE:
	    priority = LOG_NOTICE;
	    break;
	case DBG_WARN:
	    priority = LOG_WARNING;
	    break;
	case DBG_ERR:
	    priority = LOG_ERR;
	    break;
	default:
	    priority = LOG_DEBUG;
	}
	vsyslog(priority, format, ap);
    } else {
	if (debug_timestamp && (timebuf = malloc(256))) {
	    gettimeofday(&now, NULL);
	    ctime_r(&now.tv_sec, timebuf);
	    timebuf[strlen(timebuf) - 1] = '\0';
	    fprintf(debug_file, "%s: ", timebuf + 4);
	    free(timebuf);
	}
	vfprintf(debug_file, format, ap);
	fprintf(debug_file, "\n");
    }
}

void debug(uint8_t level, char *format, ...) {
    va_list ap;
    if (level < debug_level)
	return;
    va_start(ap, format);
    debug_logit(level, format, ap);
    va_end(ap);
}

void debugx(int status, uint8_t level, char *format, ...) {
    if (level >= debug_level) {
	va_list ap;
	va_start(ap, format);
	debug_logit(level, format, ap);
	va_end(ap);
    }
    exit(status);
}

void debugerrno(int err, uint8_t level, char *format, ...) {
    if (level >= debug_level) {
	va_list ap;
	size_t len = strlen(format);
	char *tmp = malloc(len + 1024 + 2);
	assert(tmp);
	strcpy(tmp, format);
	tmp[len++] = ':';
	tmp[len++] = ' ';
	if (strerror_r(err, tmp + len, 1024))
	    tmp = format;
	va_start(ap, format);
	debug_logit(level, tmp, ap);
	va_end(ap);
    }
}

void debugerrnox(int err, uint8_t level, char *format, ...) {
    if (level >= debug_level) {
	va_list ap;
	va_start(ap, format);
	debugerrno(err, level, format, ap);
	va_end(ap);
    }
    exit(err);
}

#if defined(WANT_FTICKS)
void fticks_debug(const char *format, ...) {
    int priority;
    va_list ap;
    va_start(ap, format);
    if (!debug_syslogfacility && !fticks_syslogfacility)
    	debug_logit(0xff, format, ap);
    else {
    	priority = LOG_DEBUG | fticks_syslogfacility;
    	vsyslog(priority, format, ap);
    	va_end(ap);
    }
}
#endif
/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
