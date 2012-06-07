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
#ifndef __SSL_TRACE_H__
#define __SSL_TRACE_H__

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 
#define WIN32_LEAN_AND_MEAN
  #ifdef _DEBUG
    #define _CRTDBG_MAP_ALLOC
    #include <stdlib.h>
    #include <crtdbg.h>
  #endif
#endif

#define MAX_PATH_LEN	1024
#define MAX_PWD_LEN		256

#define DEFAULT_PORT_NUMBER		443

/* Screen width used by DumpData function */
#define CHAR_PER_LINE			80

/* SSTRACE_ARGS src_type constants */
#define SRCTYPE_FILE	1
#define SCRTYPE_LIVE	2

#define PCAP_CAPTURE_TIMEOUT	10

/* A structure to place parsed command line argument */
typedef struct ssltrace_args
{
	char			keyfile[MAX_PATH_LEN];	/* SSL server's private key file path */
	char			pwd[MAX_PWD_LEN];		/*Keyfile password, if present; NULL otherwise */
	char			src[MAX_PATH_LEN];		/* Input source - a capture file in tcpdump format or a network interface name */
	int				src_type;				/* Input source type - SRCTYPE_FILE or SCRTYPE_LIVE */
	struct in_addr	server_ip;				/* SSL server's IP address */
	uint16_t		port;					/* SSL server's port */
} SSTRACE_ARGS;

extern char ErrBuffer[2048];

/* the main processing function: opens pcap_t interface, creates and 
initializes the CapEnv instance, starts the data processing,
and handles deinitialization sequence */
int proceed( const SSTRACE_ARGS* args );


/* ********************* Utility routines ***************** */

/* Process the command line parameters */
int load_args( int argc, char** argv, SSTRACE_ARGS* Args );

/* Format and dump the data on the screen */
void DumpData( u_char* data, uint32_t pkt_size );

/* print program's command line parameters help */
void print_usage( void );

#endif
