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
#include <errno.h>
#include <stdarg.h>
#include "debug.h"

static uint8_t debug_level = 0;

void debug(uint8_t level, char *format, ...) {
    extern int errno;
    
    if (level >= debug_level) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errno) {
	    fprintf(stderr, ": ");
	    perror(NULL);
	    fprintf(stderr, "errno=%d\n", errno);
	} else
	    fprintf(stderr, "\n");
    }
    if (level >= DBG_ERR)
	exit(1);
}
