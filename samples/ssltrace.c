/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#ifdef _WIN32
  #define _CRT_SECURE_NO_WARNINGS 
#endif

#include <string.h>
#include <openssl/ssl.h>
#include <pcap.h>
#ifdef _WIN32
        #include "../win32/include/netinet/ip.h"
        #include "../win32/include/netinet/tcp.h"
#elif __linux
        #include <arpa/inet.h>
        #include <netinet/ip.h>
        #include <netinet/tcp.h>
#endif
#include <sslcap.h>
#include "ssltrace.h"

/* Global variables */
char ErrBuffer[2048];

int main( int argc, char** argv )
{
	SSTRACE_ARGS args; int rc = 0;

	memset( &args, 0, sizeof( args ) );
	ErrBuffer[0] = 0;

	if( argc < 3 )
	{
		print_usage();
		return 0;
	}

	if( load_args( argc, argv, &args ) != 0 )
	{
		if( strlen( ErrBuffer ) ) 
		{
			fprintf( stderr, ErrBuffer );
		}
		else
		{
			print_usage();
		}

		return 1;
	}

	/* Initialize OpenSSL library before using DSSL! */
	SSL_library_init();	
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	rc = proceed( &args );
	if( rc != 0 )
	{
		if( strlen( ErrBuffer ) ) fprintf( stderr, ErrBuffer );
	}

	/* Cleanup OpenSSL */
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	return rc;
}


/* Open libpcap (WinPcap) adapter */
pcap_t* open_adapter( const SSTRACE_ARGS* args )
{
	pcap_t* retval = NULL;

	if( !args ) 
	{
		sprintf( ErrBuffer, "Internal error at %s, line %d", __FILE__, __LINE__ );
		return NULL;
	}

	switch( args->src_type )
	{
	case SRCTYPE_FILE:
		retval = pcap_open_offline( args->src, ErrBuffer );
		break;

	case SCRTYPE_LIVE:
		retval = pcap_open_live( args->src, 65535, 0, PCAP_CAPTURE_TIMEOUT, ErrBuffer );
		break;

	default:
		sprintf( ErrBuffer, "Internal error at %s, line %d", __FILE__, __LINE__ );
		return NULL;
	}

	return retval;
}


/* data callback routine that simply dumps the decoded data on the screen */
static void data_callback_proc( NM_PacketDir dir, void* user_data, u_char* pkt_payload,
							  uint32_t pkt_size, DSSL_Pkt* last_packet )
{
	last_packet;
	switch(dir)
	{
	case ePacketDirFromClient:
		printf( "\nC->S:\n" );
		break;
	case ePacketDirFromServer:
		printf( "\nS->C:\n" );
		break;
	default:
		printf( "\nUnknown packet direction!" );
		return;
	}

	DumpData( pkt_payload, pkt_size );
}

static int missing_packet_callback(NM_PacketDir dir, void* user_data, uint32_t pkt_seq, uint32_t pkt_size)
{
	printf("\n Missing packet(s) detected; missing segment size %u", pkt_size);
	return 1; /* skip and continue */
}

/* error callback routine; prints the error on the screen */
static void error_callback_proc( void* user_data, int error_code )
{
	TcpSession* sess = (TcpSession*) user_data;
	char buff[512];
	SessionToString(sess, buff);
	printf( "\nERROR: Session: %s, error code: %d", buff, error_code );
}


#define MISSING_PACKET_COUNT	100
#define MISSING_PACKET_TIMEOUT	10

/* session event callback routine: traces opening / closing sessions; sets the callbacks */
static void session_event_handler( CapEnv* env, TcpSession* sess, char event )
{
	char buff[512];
	switch( event )
	{
	case DSSL_EVENT_NEW_SESSION:
		SessionToString(sess, buff);
		printf( "\n=> New Session: %s", buff );
		SessionSetCallback( sess, data_callback_proc, error_callback_proc, sess );
		SessionSetMissingPacketCallback( sess, missing_packet_callback, MISSING_PACKET_COUNT, 
			MISSING_PACKET_TIMEOUT );
		break;

	case DSSL_EVENT_SESSION_CLOSING:
		SessionToString(sess, buff);
		printf( "\n<= Session closing: %s", buff );
		break;

	default:
		fprintf( stderr, "ERROR: Unknown session event code (%d)", (int)event );
		break;
	}
}


/* the main processing function: opens pcap_t interface, creates and initializes 
the CapEnv instance, starts the data processing and handles deinitialization sequence */
int proceed( const SSTRACE_ARGS* args )
{
	pcap_t* p = NULL;
	CapEnv* env = NULL;
	int rc = 0;

	/* First, open the pcap adapter */
	p = open_adapter( args );
	if( !p ) return -1;

	/* Create and initialize the CapEnv structure */
	env = CapEnvCreate( p, 100, 0, 0 );

	if( args->keyfile[0] != 0 ) {
		rc = CapEnvSetSSL_ServerInfo( env, &args->server_ip, args->port, 
			args->keyfile, args->pwd );
	}

	if (rc == 0 ) CapEnvSetSessionCallback( env, session_event_handler, NULL );

	if( rc == 0 ) 
	{
		rc = CapEnvCapture( env );
		if( rc != 0 )
		{
			sprintf( ErrBuffer, "CapEnvCapture failed. Pcap error message:%s", pcap_geterr(p) );
		}
	}

	if( env ) 
	{
		CapEnvDestroy( env );
		env = NULL;
	}

	if( p )
	{
		pcap_close( p );
		p = NULL;
	}

	return rc;
}
