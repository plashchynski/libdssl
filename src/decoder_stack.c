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
#include <string.h>
#include "stdinc.h"
#include "decoder_stack.h"
#include "ssl_session.h"
#include "ssl_decode.h"
#include "ssl_decode_hs.h"
#include "compression.h"
#include "ssl2_decode.h"
#include "ssl2_decode_hs.h"

void dssl_decoder_stack_init( dssl_decoder_stack* stack )
{
	memset( stack, 0, sizeof(stack) );
	stack->state = SS_Initial;
}


void dssl_decoder_stack_deinit( dssl_decoder_stack* stack )
{
	dssl_decoder_deinit( &stack->dalert );
	dssl_decoder_deinit( &stack->dappdata );
	dssl_decoder_deinit( &stack->dcss );
	dssl_decoder_deinit( &stack->dhandshake );
	dssl_decoder_deinit( &stack->drecord );

	if( stack->cipher )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher );
		free( stack->cipher );
		stack->cipher = NULL;
	}

	if( stack->cipher_new )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher_new );
		free( stack->cipher_new );
		stack->cipher_new = NULL;
	}

	if( stack->compression_method != 0 )
	{
		dssl_compr_deinit( stack->compression_method, stack->compression_data );
	}

	if( stack->compression_method_new != 0 )
	{
		dssl_compr_deinit( stack->compression_method_new, stack->compression_data_new );
	}

	stack->md = stack->md_new = NULL;
}


int sslc_is_decoder_stack_set( dssl_decoder_stack* s)
{
	return s->sess != NULL;
}


int dssl_decoder_stack_set( dssl_decoder_stack* d, DSSL_Session* sess, uint16_t version, 
						   int is_client )
{
	int rc = DSSL_RC_OK;
	int supported =	1;

	d->sess = NULL;

	switch( version )
	{
	case SSL3_VERSION:
		DEBUG_TRACE0("dssl_decoder_stack_set - SSL 3.0\n");
	case TLS1_VERSION:
		DEBUG_TRACE0("dssl_decoder_stack_set - TLS version 1.0\n");
		dssl_decoder_init( &d->drecord, ssl3_record_layer_decoder, d );
		dssl_decoder_init( &d->dhandshake, ssl3_decode_handshake_record, d );
		dssl_decoder_init( &d->dcss, ssl3_change_cipher_spec_decoder, d );
		dssl_decoder_init( &d->dappdata, ssl_application_data_decoder, d );
		dssl_decoder_init( &d->dalert, ssl3_alert_decoder, d );
		break;
	case SSL2_VERSION:
		DEBUG_TRACE0("dssl_decoder_stack_set - SSL 2.0\n");
		dssl_decoder_init( &d->drecord, ssl2_record_layer_decoder, d );
		dssl_decoder_init( &d->dhandshake, ssl2_handshake_record_decode_wrapper, d );
		dssl_decoder_init( &d->dappdata, ssl_application_data_decoder, d );
		break;
	case TLS1_1_VERSION:
		DEBUG_TRACE0("dssl_decoder_stack_set - TLS version 1.1\n");
		supported = 0;
		break;
	case TLS1_2_VERSION:
		DEBUG_TRACE0("dssl_decoder_stack_set - TLS version 1.2\n");
		supported = 0;
		break;
	default:
		DEBUG_TRACE0("dssl_decoder_stack_set - Unknown version\n");
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
		supported = 0;
		break;
	}

	if (!supported)
	{
		DEBUG_TRACE1("dssl_decoder_stack_set - version is: 0x%02X\n", version);

		// Although TLS is 1.1 there is a message with 1.2 that should 
		// not be voided
		if (version > 300)
		{
			DEBUG_TRACE0("dssl_decoder_stack_set - adding support\n");
			dssl_decoder_init( &d->drecord, ssl3_record_layer_decoder, d );
			dssl_decoder_init( &d->dhandshake, ssl3_decode_handshake_record, d );
			dssl_decoder_init( &d->dcss, ssl3_change_cipher_spec_decoder, d );
			dssl_decoder_init( &d->dappdata, ssl_application_data_decoder, d );
			dssl_decoder_init( &d->dalert, ssl3_alert_decoder, d );
		}
		else
		{
			DEBUG_TRACE0("dssl_decoder_stack_set - Unknown version (not identified TLS 1.x\n");
			rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
		}
	}

	if( rc == DSSL_RC_OK ) { d->sess = sess; }

	return rc;
}

int dssl_decoder_stack_process( dssl_decoder_stack* stack, NM_PacketDir dir, u_char* data, uint32_t len )
{
	return dssl_decoder_process( &stack->drecord, dir, data, len );
}


int dssl_decoder_stack_flip_cipher( dssl_decoder_stack* stack )
{
	DEBUG_TRACE0("dssl_decoder_stack_flip_cipher - start\n");

	/* deinitialize old compression state and cipher, if any */
	if( stack->compression_method != 0 )
	{
		dssl_compr_deinit( stack->compression_method, stack->compression_data );
	}

	if( stack->cipher )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher );
		free( stack->cipher );
		stack->cipher = NULL;
	}

	/* set new compression */
	stack->compression_method = stack->compression_method_new;
	stack->compression_method_new = 0;

	stack->compression_data = stack->compression_data_new;
	stack->compression_data_new = NULL;

	/* set new cypher */
	stack->cipher = stack->cipher_new;

	DEBUG_TRACE1("dssl_decoder_stack_flip_cipher - stack->cipher key len: %d\n", stack->cipher->key_len);

	if(  stack->md_new != NULL && stack->sess && 
		(stack->sess->version == SSL3_VERSION || stack->sess->version == TLS1_VERSION) )
	{
		// TODO: TLS_1_1_VERSION TLS_1_2_VERSION
		memcpy( stack->mac_key, stack->mac_key_new, EVP_MD_size( stack->md_new ) );
	}
	else if(  stack->md_new != NULL && stack->sess )
	{
		// Trying same code for TLS 1.x
		memcpy( stack->mac_key, stack->mac_key_new, EVP_MD_size( stack->md_new ) );
	}

	DEBUG_TRACE1("dssl_decoder_stack_flip_cipher - cipher is: %d\n", stack->md);
	stack->md = stack->md_new;

	stack->cipher_new = NULL;
	stack->md_new = NULL;

	DEBUG_TRACE1("dssl_decoder_stack_flip_cipher - end. new is: %d\n", stack->md);

	return DSSL_RC_OK;
}
