AUTOMAKE_OPTS = foreign
check_PROGRAMS = dssl_test
TESTS = $(check_PROGRAMS)

EXTRA_DIST= ssltrace.vcproj ssl-test-data test-data 
dssl_test_SOURCES = CuTest.c ssl_test_data.c t_capenv.c t_packet.c t_session_table.c \
t_sessionkey_table.c t_ssl_autokey_decode.c t_ssl_decode.c t_stream.c t_stream_utils.c \
t_tls_ticket_table.c t_udp.c testmain.c utils.c

dssl_test_LDADD = ../src/libdssl.la -lpcap -lcrypto -lssl -lz 
INCLUDES = -I../src

