AUTOMAKE_OPTIONS = foreign
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)
AM_CFLAGS = -Wall -Werror -g

TESTS = test-udp

check_PROGRAMS = test-udp udp-server

test_udp_SOURCES = test-udp.c udp.c udp.h
test_udp_LDADD = ../libradsec.la -lcunit -lm

udp_server_SOURCES = udp-server.c udp.c udp.h
