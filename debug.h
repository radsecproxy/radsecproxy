/*
 * Copyright (C) 2007 Stig Venaas <venaas@uninett.no>
 * Copyright (C) 2010 NORDUnet A/S
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#ifndef SYS_SOLARIS9
#include <stdint.h>
#endif

#define DBG_DBG 8
#define DBG_INFO 16
#define DBG_NOTICE 32
#define DBG_WARN 64
#define DBG_ERR 128

#define DEBUG_LOG 0
#define FTICKS_LOG 1

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
