AUTOMAKE_OPTS = foreign
bin_PROGRAMS = ssltrace
EXTRA_DIST= ssltrace.vcproj
ssltrace_SOURCES = ssltrace.c ssltrace.h utils.c
ssltrace_LDADD = ../src/libdssl.la -lpcap -lcrypto -lssl -lz 
INCLUDES = -I../src

