AUTOMAKE_OPTIONS = foreign
INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -Werror -g

TESTS = test-udp

check_PROGRAMS = test-udp udp-server tls-server

test_udp_SOURCES = test-udp.c udp.c
test_udp_LDADD = ../libradsec.la -lcgreen -lm

udp_server_SOURCES = udp-server.c udp.c

tls_server_SOURCES = server.c
tls_server_LDADD = ../libradsec.la

