AM_CFLAGS="-fPIC"

lib_LTLIBRARIES = libdssl.la

libdssl_la_SOURCES = capture_env.c ciphersuites.c decoder.c \
        decoder_stack.c fnv_hash.c decode.c \
        log.c packet.c pcap_decode.c session.c \
        session_table.c ssl_ctx.c ssl_decode.c \
        ssl_decode_hs.c ssl_mac.c ssl_session.c \
        ssl_sessionkey_table.c ssl_utils.c stream.c \
        compression.c ssl2_decode.c ssl2_decode_hs.c \
		tls_ticket_table.c

pkginclude_HEADERS = sslcap.h ptypes.h dssl_defs.h log.h \
        errors.h capenv.h session_table.h session.h \
        stream.h packet.h ssl_ctx.h netdefs.h

noinst_HEADERS = stdinc.h ciphersuites.h decoder_stack.h ssl_utils.h \
	decode.h ssl_mac.h ssl_decode.h ssl_sessionkey_table.h \
	ssl_decode_hs.h decoder.h fnv_hash.h ptypes.h ssl_session.h \
	compression.h ssl2_decode.h ssl2_decode_hs.h decode.h tls_ticket_table.h

