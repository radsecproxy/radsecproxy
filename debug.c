/*
 * Copyright (C) 2007 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include <errno.h>
#include "debug.h"

static char *debug_ident = NULL;
static uint8_t debug_level = DBG_INFO;
static FILE *debug_file = NULL;
static int debug_syslogfacility = 0;

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
	debug_level = DBG_INFO;
	return;
    case 4:
	debug_level = DBG_DBG;
	return;
    }
}

uint8_t debug_get_level() {
    return debug_level;
}

int debug_set_destination(char *dest) {
    static const char *facstrings[] = { "LOG_DAEMON", "LOG_MAIL", "LOG_USER", "LOG_LOCAL0",
					"LOG_LOCAL1", "LOG_LOCAL2", "LOG_LOCAL3", "LOG_LOCAL4",
					"LOG_LOCAL5", "LOG_LOCAL6", "LOG_LOCAL7", NULL };
    static const int facvals[] = { LOG_DAEMON, LOG_MAIL, LOG_USER, LOG_LOCAL0,
				   LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4,
				   LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7 };
    extern int errno;
    int i;
    
    if (!strncasecmp(dest, "file:///", 8)) {
	debug_file = fopen(dest + 7, "a");
	if (!debug_file)
	    debugx(1, DBG_ERR, "Failed to open logfile %s\n%s",
		   dest + 7, strerror(errno));
	setvbuf(debug_file, NULL, _IONBF, 0);
	return 1;
    }
    if (!strncasecmp(dest, "x-syslog://", 11)) {
	dest += 11;
	if (*dest == '/')
	    dest++;
	if (*dest) {
	    for (i = 0; facstrings[i]; i++)
		if (!strcasecmp(dest, facstrings[i]))
		    break;
	    if (!facstrings[i])
		debugx(1, DBG_ERR, "Unknown syslog facility %s", dest);
	    debug_syslogfacility = facvals[i];
	} else
	    debug_syslogfacility = LOG_DAEMON;
	openlog(debug_ident, LOG_PID, debug_syslogfacility);
	return 1;
    }
    debug(DBG_ERR, "Unknown log destination, exiting %s", dest);
    exit(1);
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
	timebuf = malloc(256);
	if (timebuf) {
	    gettimeofday(&now, NULL);
	    ctime_r(&now.tv_sec, timebuf);
	    timebuf[strlen(timebuf) - 1] = '\0';
	    fprintf(debug_file, "%s: ", timebuf);
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
