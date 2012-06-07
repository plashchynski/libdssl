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


void print_usage( void )
{
	printf( "ssltrace: a command-line SSL/TLS analyzer utility.\nCopyright (c) 2005-2009 Atomic Labs, Inc.\nAll rights reserved.\n" );
	printf( "\nUsage: ssltrace -i <interface> || -r <file> -key <file> -ip <server IP> -port <server port> [-pwd <password>]" );
	printf( "\nInput parameters:" );
	printf( "\n\t-i <interface>: capture and decrypt data from network link <interface>" );
	printf( "\n\t-r <file>: decrypt data from pcap capture file" );
	printf( "\nSSL server parameters:" );
	printf( "\n\t-key: server's private key file path" );
	printf( "\n\t-pwd: (optional) server's private key file password, if the file is encrypted" );
	printf( "\n\t-ip: server IP address" );
	printf( "\n\t-port: (optional) server port number. Port 443 is used if not specified directly\n" );
}


/* Format and dump the data on the screen */
void DumpData( u_char* data, uint32_t sz )
{
	uint32_t i;

	for( i = 0; i < sz; i++ )
	{
		if( isprint(data[i]) || data[i] == '\n' || data[i] == '\t' || data[i] == '\r' ) 
			putc( data[i], stdout );
		else
			putc( '.', stdout );
	}
}


/* Command line argument processing functions and data */

/* Command line parameter enumeration */
typedef enum ssltrace_arg_token
{
	eInvalid = -1,
	eInputFile = 0,
	eInterface,
	eKeyfile,
	eKeyfilePassword,
	eServerAddress,
	ePort
} SSLTRACE_ARG_TOKEN;

#define ARG_TOKEN_COUNT (ePort - eInputFile + 1)

/* Command line parameters */
static const char* ArgTokens[] = { "-r", "-i", "-key", "-pwd", "-ip", "-port" };

/* Parse a command line parameter and return the corresponding SSLTRACE_ARG_TOKEN enum */
static SSLTRACE_ARG_TOKEN GetToken( const char* arg )
{
	int i;
	for( i = 0; i < sizeof( ArgTokens ) / sizeof( ArgTokens[0] ); i++ )
	{
		if( strcmp( arg, ArgTokens[i] ) == 0 ) return i;
	}

	return eInvalid;
}

/* Process the command line parameters */
int load_args( int argc, char** argv, SSTRACE_ARGS* Args )
{
	int i = 0;
	char token_checks[ARG_TOKEN_COUNT];

	memset( token_checks, 0, sizeof( token_checks ) );

	memset(Args, 0, sizeof(*Args) );

	for( i = 1; i < argc; i+=2 )
	{
		SSLTRACE_ARG_TOKEN token = GetToken( argv[i] );

		if( token == eInvalid )
		{
			sprintf( ErrBuffer, "Invalid command line option specified: %s.", argv[i] );
			return -1;
		}

		if( i+1 >= argc )
		{
			sprintf( ErrBuffer, "Unexpected end of command line: %s key must have a value", argv[i] );
			return -1;
		}
		
		if( token == eInputFile || token == eInterface || token == eKeyfile )
		{
			if( strlen( argv[i+1] ) >= MAX_PATH_LEN )
			{
				sprintf( ErrBuffer, "File path or interface name length exceeds the maximum length expected." );
				return -1;
			}
		}

		if( token >= sizeof(token_checks)/sizeof(token_checks[0]) )
		{
			sprintf( ErrBuffer, "Internal error at %s, line %d", __FILE__, __LINE__ );
			return -1;
		}

		if( token_checks[token] )
		{
			sprintf( ErrBuffer, "Parameter %s specified more than once", argv[i] );
			return -1;
		}

		token_checks[token] = 1;

		switch( token )
		{
		case eInputFile:
			strcpy( Args->src, argv[i+1] );
			Args->src_type = SRCTYPE_FILE;
			break;

		case eInterface:
			strcpy( Args->src, argv[i+1] );
			Args->src_type = SCRTYPE_LIVE;
			break;

		case eKeyfile:
			strcpy( Args->keyfile, argv[i+1] );
			break;

		case eKeyfilePassword:
			if( strlen( argv[i+1] ) >= MAX_PWD_LEN )
			{
				sprintf( ErrBuffer, "Password length exceeds the maximum length expected." );
				return -1;
			}

			strcpy( Args->pwd, argv[i+1] );
			break;

		case eServerAddress:
			Args->server_ip.s_addr = inet_addr( argv[i+1] );
			if( INADDR_NONE == Args->server_ip.s_addr )
			{
				sprintf( ErrBuffer, "Invalid IP address format '%s'", argv[i+1] );
				return -1;
			}
			break;

		case ePort:
			{
				int port = atoi( argv[i+1] );
				if ( port < 0 || port > 0xffff ) 
				{
					sprintf( ErrBuffer, "Invalid TCP port value '%s'", argv[i+1] );
					return -1;
				}
				Args->port = (uint16_t) port;
			}
			break;
		}
	}

	if( token_checks[eInputFile] && token_checks[eInterface] )
	{
		sprintf( ErrBuffer, "Either -i or -r parameter expected, not both" );
		return -1;
	}

	if( !(token_checks[eInputFile] || token_checks[eInterface]) )
	{
		sprintf( ErrBuffer, "Either -i or -r parameter must be specified." );
		return -1;
	}

	if( token_checks[eServerAddress] != token_checks[eKeyfile] )
	{
		if(!token_checks[eServerAddress]) {
			sprintf( ErrBuffer, "If you specify -key parameter, you also need to specify -ip parameter." );
		} else {
			sprintf( ErrBuffer, "If you specify -ip parameter, you also need to specify -key parameter." );
		}

		return -1;
	}


	if( !token_checks[ePort] )
	{
		Args->port = DEFAULT_PORT_NUMBER;
	}

	return 0;
}
