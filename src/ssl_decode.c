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
#include "ssl_session.h"
#include "ssl_decode_hs.h"
#include "ssl_decode.h"
#include "session.h"
#include "decoder_stack.h"
#include "compression.h"

int ssl3_change_cipher_spec_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	dssl_decoder_stack* stack = (dssl_decoder_stack*) decoder_stack;

	/* unused parameters */
	dir;

	/* check packet data to comply to CSS protocol */
	if( len != 1 ) return NM_ERROR( NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ) );
	if(data[0] != 1 ) return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );

	*processed = 1;

	return dssl_decoder_stack_flip_cipher( stack );
}


int ssl_application_data_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	dssl_decoder_stack* stack = (dssl_decoder_stack*) decoder_stack;
	DSSL_Session* sess;
	
	sess = stack->sess;
	if ( sess->data_callback )
	{
		sess->data_callback( dir, sess->user_data, data, len, sess->last_packet);
	}

	*processed = len;
	return DSSL_RC_OK;
}


int ssl3_alert_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	dssl_decoder_stack* stack = (dssl_decoder_stack*) decoder_stack;

	UNUSED_PARAM(dir);

	if( len != 2 ) return NM_ERROR( NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ) );

	if( data[0] == 2 )
	{
		stack->state = SS_FatalAlert;
	}

	/* Close notify? */
	if( data[1] == 0 )
	{
		stack->state = SS_SeenCloseNotify;
	}

#ifdef NM_TRACE_SSL_RECORD
	DEBUG_TRACE2( "\nAlert received: %s (%d)", 
			( (stack->state == SS_FatalAlert) ? "fatal alert" : 
			((stack->state == SS_SeenCloseNotify) ? "close_notify alert" : "unknown alert")), 
			(int) MAKE_UINT16( data[0], data[1] ) );
#endif

		(*processed) = len;
	return DSSL_RC_OK;
}


static int ssl_decrypt_record( dssl_decoder_stack* stack, u_char* data, uint32_t len, 
					  u_char** out, uint32_t* out_len, int *buffer_aquired )
{
	u_char* buf = NULL;
	uint32_t buf_len = len;
	int rc = DSSL_RC_OK;
	int block_size;
	const EVP_CIPHER* c = NULL;


	_ASSERT( stack );
	_ASSERT( stack->sess );
	_ASSERT( stack->cipher );

	rc = ssls_get_decrypt_buffer( stack->sess, &buf, buf_len );
	if( rc != DSSL_RC_OK ) return rc;

	*buffer_aquired = 1;

	c = EVP_CIPHER_CTX_cipher( stack->cipher );
	block_size = EVP_CIPHER_block_size( c );

	if( block_size != 1 )
	{
		if( len == 0 || (len % block_size) != 0 )
		{
			return NM_ERROR( DSSL_E_SSL_DECRYPTION_ERROR );
		}
	}

	EVP_Cipher(stack->cipher, buf, data, len );

	buf_len = len;
	/* strip the padding */
	if( block_size != 1 )
	{
		if( buf[len-1] >= buf_len - 1 ) return NM_ERROR( DSSL_E_SSL_DECRYPTION_ERROR );
		buf_len -= buf[len-1] + 1;
	}

	*out = buf;
	*out_len = buf_len;

	return DSSL_RC_OK;
}

static int ssl_decompress_record( dssl_decoder_stack* stack, u_char* data, uint32_t len, 
					  u_char** out, uint32_t* out_len, int *buffer_aquired )
{
	int rc = DSSL_RC_OK;
	u_char* buf = NULL;
	/* always require the maximum decompressed record size possible */
	uint32_t buf_len = DSSL_MAX_RECORD_LENGTH;

	_ASSERT( stack );
	_ASSERT( stack->sess );

	rc = ssls_get_decompress_buffer( stack->sess, &buf, buf_len );
	if( rc != DSSL_RC_OK ) return rc;

	*buffer_aquired = 1;

	rc = dssl_decompress( stack->compression_method, stack->compression_data,
			data, len, buf, &buf_len );

	if( rc == DSSL_RC_OK ) 
	{
		*out = buf;
		*out_len = buf_len;
	}

	return rc;
}


int ssl3_record_layer_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_E_UNSPECIFIED_ERROR;
	uint32_t recLen = 0, totalRecLen = 0;
	uint8_t record_type = 0;
	dssl_decoder_stack* stack = (dssl_decoder_stack*) decoder_stack;
	dssl_decoder* next_decoder = NULL;
	int decrypt_buffer_aquired = 0;
	int decompress_buffer_aquired = 0;

	_ASSERT( stack );
	_ASSERT( processed );
	_ASSERT( stack->sess );

	if( stack->state > SS_Established )
	{
#ifdef NM_TRACE_SSL_RECORD
		DEBUG_TRACE1( "[!]Unexpected SSL record after %s", 
			( (stack->state == SS_FatalAlert) ? "fatal alert" : "close_notify alert") );
#endif
		return NM_ERROR( DSSL_E_SSL_UNEXPECTED_TRANSMISSION );
	}

	/* special case for a first client hello */
	if( stack->sess->version == 0 )
	{
		_ASSERT( dir == ePacketDirFromClient );
		rc = ssl_decode_first_client_hello( stack->sess, data, len, processed );
		return rc;
	}

	if( len < SSL3_HEADER_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	if( data[1] != 3) return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );

	/* Decode record type */
	record_type = data[0];
	totalRecLen = recLen = MAKE_UINT16( data[3], data[4] );

	data += SSL3_HEADER_LEN;
	len -= SSL3_HEADER_LEN;

#ifdef NM_TRACE_SSL_RECORD
	DEBUG_TRACE2( "\n==>Decoding SSL v3 Record, type: %d, len: %d\n{\n", (int) record_type, (int) recLen );
#endif

	rc = DSSL_RC_OK;
	if( len < recLen ) { rc = DSSL_RC_WOULD_BLOCK; }

	if( rc == DSSL_RC_OK && stack->cipher )
	{
		rc = ssl_decrypt_record( stack, data, recLen, &data, &recLen, &decrypt_buffer_aquired );
	}

	/* check if the record length is still within bounds (failed decryption, etc) */
	if( rc == DSSL_RC_OK && (recLen > RFC_2246_MAX_COMPRESSED_LENGTH || 
		recLen > len || (stack->md && recLen < EVP_MD_size(stack->md))) )
	{
		rc = NM_ERROR(DSSL_E_SSL_INVALID_RECORD_LENGTH);
	}

	if( rc == DSSL_RC_OK && stack->md )
	{
		u_char mac[EVP_MAX_MD_SIZE];
		u_char* rec_mac = NULL;
		
		recLen -= EVP_MD_size( stack->md );
		rec_mac = data+recLen;

		memset(mac, 0, sizeof(mac) );
		rc = stack->sess->caclulate_mac_proc( stack, record_type, data, recLen, mac );

		if( rc == DSSL_RC_OK )
		{
			rc = memcmp( mac, rec_mac, EVP_MD_size(stack->md) ) == 0 ? DSSL_RC_OK : NM_ERROR( DSSL_E_SSL_INVALID_MAC );
		}
	}

	if( rc == DSSL_RC_OK && stack->compression_method != 0 )
	{
		rc = ssl_decompress_record( stack, data, recLen, &data, &recLen, &decompress_buffer_aquired );
	}

	if( rc == DSSL_RC_OK )
	{
		switch( record_type )
		{
			case SSL3_RT_HANDSHAKE:
				next_decoder = &stack->dhandshake;
				break;

			case SSL3_RT_CHANGE_CIPHER_SPEC:
				next_decoder = &stack->dcss;
				break;

			case SSL3_RT_APPLICATION_DATA:
				next_decoder = &stack->dappdata;
				break;
			case SSL3_RT_ALERT:
				next_decoder = &stack->dalert;
				break;

			default:
				rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		}
	}

	if( rc == DSSL_RC_OK )
	{
		_ASSERT( next_decoder != NULL );
		rc = dssl_decoder_process( next_decoder, dir, data, recLen );
	}

	if( rc == DSSL_RC_OK )
	{
		*processed = totalRecLen + SSL3_HEADER_LEN;
	}

	if( decrypt_buffer_aquired )
	{
		ssls_release_decrypt_buffer( stack->sess );
	}

	if( decompress_buffer_aquired )
	{
		ssls_release_decompress_buffer( stack->sess );
	}

#ifdef NM_TRACE_SSL_RECORD
	DEBUG_TRACE1( "\n} rc: %d\n", (int) rc);
#endif

	if( stack->state == SS_SeenCloseNotify )
	{
		stack->sess->flags |= SSF_CLOSE_NOTIFY_RECEIVED;
	} else if ( stack->state == SS_FatalAlert )
	{
		stack->sess->flags |= SSF_FATAL_ALERT_RECEIVED;
	}

	return rc;
}
