AUTOMAKE_OPTIONS = foreign
INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -g

TESTS = test-udp

check_PROGRAMS = test-udp udp-server

test_udp_SOURCES = test-udp.c udp.c
test_udp_LDADD = ../libradsec.la -lcgreen -lm

udp_server_SOURCES = udp-server.c udp.c
