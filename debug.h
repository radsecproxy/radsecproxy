/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifndef SYS_SOLARIS9
#include <stdint.h>
#endif

#define DBG_DBG 8
#define DBG_INFO 16
#define DBG_NOTICE 32
#define DBG_WARN 64
#define DBG_ERR 128

#define LOG_TYPE_DEBUG 0
#define LOG_TYPE_FTICKS 1

void debug_init(char *ident);
void debug_set_level(uint8_t level);
void debug_timestamp_on();
uint8_t debug_get_level();
void debug(uint8_t level, char *format, ...);
void debugx(int status, uint8_t level, char *format, ...);
void debugerrno(int err, uint8_t level, char *format, ...);
void debugerrnox(int err, uint8_t level, char *format, ...);
int debug_set_destination(char *dest, int log_type);
void debug_reopen_log();
#if defined(WANT_FTICKS)
void fticks_debug(const char *format, ...);
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
