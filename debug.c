/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2011, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifdef __linux__
#include <sys/syscall.h>
#include <unistd.h>
#endif
#include "debug.h"
#include "util.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>

static char *debug_ident = NULL;
static uint8_t debug_level = DBG_INFO;
static char *debug_filepath = NULL;
static FILE *debug_file = NULL;
static int debug_syslogfacility = 0;
static int fticks_syslogfacility = 0;
static int active_syslogfacility = 0;
static uint8_t debug_timestamp = 0;
static uint8_t debug_tid = 0;

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

void debug_timestamp_on(void) {
    debug_timestamp = 1;
}

void debug_tid_on(void) {
    debug_tid = 1;
}

uint8_t debug_get_level(void) {
    return debug_level;
}

int debug_set_destination(char *dest, int log_type) {
    static const char *facstrings[] = {
        "LOG_DAEMON", "LOG_MAIL", "LOG_USER", "LOG_LOCAL0",
        "LOG_LOCAL1", "LOG_LOCAL2", "LOG_LOCAL3", "LOG_LOCAL4",
        "LOG_LOCAL5", "LOG_LOCAL6", "LOG_LOCAL7", NULL};
    static const int facvals[] = {
        LOG_DAEMON, LOG_MAIL, LOG_USER, LOG_LOCAL0,
        LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4,
        LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7};
    int i;

    if (!strncasecmp(dest, "file:///", 8)) {
        if (log_type != LOG_TYPE_FTICKS) {
#ifdef __CYGWIN__
            debug_filepath = stringcopy(dest + 8, 0);
#else
            debug_filepath = stringcopy(dest + 7, 0);
#endif
            debug_file = fopen(debug_filepath, "a");
            if (!debug_file)
                debugx(1, DBG_ERR, "Failed to open logfile %s\n%s",
                       debug_filepath, strerror(errno));
            fclose(debug_file);
            debug_file = stderr;
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
            else if (log_type == LOG_TYPE_FTICKS)
                fticks_syslogfacility = facvals[i];
        } else {
            if (log_type != LOG_TYPE_FTICKS)
                debug_syslogfacility = LOG_DAEMON;
            else if (log_type == LOG_TYPE_FTICKS)
                fticks_syslogfacility = 0;
        }
        return 1;
    }
    debug(DBG_ERR, "Unknown log destination, exiting %s", dest);
    exit(1);
}

void debug_reopen_log(void) {
    if (debug_syslogfacility) {
        active_syslogfacility = debug_syslogfacility;
        openlog(debug_ident, LOG_PID, active_syslogfacility);
        return;
    }
    if (!debug_filepath)
        return;

    if (debug_file != stderr)
        fclose(debug_file);

    debug_file = fopen(debug_filepath, "a");
    if (!debug_file) {
        debug_file = stderr;
        debug(DBG_ERR, "Failed to open logfile %s, using stderr\n%s",
              debug_filepath, strerror(errno));
    }
    setvbuf(debug_file, NULL, _IONBF, 0);
}

void debug_logit(uint8_t level, const char *format, va_list ap) {
    struct timeval now;
    char *timebuf = NULL, *tidbuf, *tmp = NULL, *tmp2 = NULL;
    int priority;
    size_t malloc_size;

    if (debug_tid) {
#ifdef __linux__
        pid_t tid = syscall(SYS_gettid);
        tidbuf = malloc(3 * sizeof(tid) + 1);
        sprintf(tidbuf, "%u", tid);
#else
        pthread_t tid = pthread_self();
        uint8_t *ptid = (uint8_t *)&tid;
        int i;

        tidbuf = malloc((2 * sizeof(tid) + 1));
        tmp = tidbuf;
        for (i = sizeof(tid) - 1; i >= 0; i--) {
            tmp += sprintf(tmp, "%02x", ptid[i]);
        }
#endif
        tmp = malloc(strlen(tidbuf) + strlen(format) + 4);
        sprintf(tmp, "(%s) %s", tidbuf, format);
        format = tmp;
        free(tidbuf);
    }

    if (active_syslogfacility) {
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
        if (debug_timestamp && (timebuf = malloc(26 + 1))) {
            gettimeofday(&now, NULL);
            ctime_r(&now.tv_sec, timebuf);
            /*ctime_r writes exactly 24 bytes + "\n\0" */
            strncpy(timebuf + 24, ": ", 3);
        }
        malloc_size = strlen(format) + (timebuf ? strlen(timebuf) : 0) + 2 * sizeof(char);
        tmp2 = malloc(malloc_size);
        if (tmp2) {
            snprintf(tmp2, malloc_size, "%s%s\n", timebuf ? timebuf : "", format);
            format = tmp2;
        }
        vfprintf(debug_file, format, ap);
    }
    free(tmp);
    free(tmp2);
    free(timebuf);
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
        va_start(ap, format);
        if (strerror_r(err, tmp + len, 1024))
            debug_logit(level, format, ap);
        else
            debug_logit(level, tmp, ap);
        va_end(ap);
        free(tmp);
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

void fticks_debug(const char *format, ...) {
    int priority;
    va_list ap;
    va_start(ap, format);
    if (!active_syslogfacility && !fticks_syslogfacility)
        debug_logit(0xff, format, ap);
    else {
        priority = LOG_DEBUG | fticks_syslogfacility;
        vsyslog(priority, format, ap);
    }
    va_end(ap);
}
/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
