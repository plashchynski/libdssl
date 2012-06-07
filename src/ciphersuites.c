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
#include "stdinc.h"
#include "ciphersuites.h"

static DSSL_CipherSuite ssl3suites[] = 
{
	{ 0x01, SSL3_VERSION, SSL_KEX_RSA, 0, "NULL", "MD5" },
	{ 0x02, SSL3_VERSION, SSL_KEX_RSA, 0, "NULL", "SHA1" },
	{ 0x03, SSL3_VERSION, SSL_KEX_RSA,	40, "RC4", "MD5" },
	{ 0x04, SSL3_VERSION, SSL_KEX_RSA, 0, "RC4", "MD5" },
	{ 0x05, SSL3_VERSION, SSL_KEX_RSA, 0, "RC4", "SHA1" },
	{ 0x06, SSL3_VERSION, SSL_KEX_RSA, 40, "RC2", "MD5" },
	{ 0x07, SSL3_VERSION, SSL_KEX_RSA, 0, "IDEA", "SHA1" },
	{ 0x08, SSL3_VERSION, SSL_KEX_RSA, 40, "DES", "SHA1" },
	{ 0x09, SSL3_VERSION, SSL_KEX_RSA, 0, "DES", "SHA1" },
	{ 0x0A, SSL3_VERSION, SSL_KEX_RSA, 0, "DES3", "SHA1" },
	{ 0x2F, TLS1_VERSION, SSL_KEX_RSA, 0, SN_aes_128_cbc, "SHA1" },
	{ 0x35, TLS1_VERSION, SSL_KEX_RSA,	0, SN_aes_256_cbc, "SHA1" }
};

static int compare_cipher_suites( const void* key, const void* elem )
{
	uint16_t id = *((uint16_t*)key);
	DSSL_CipherSuite* cs = (DSSL_CipherSuite*) elem;

	return id - cs->id;
}

DSSL_CipherSuite* DSSL_GetSSL3CipherSuite( uint16_t id )
{
	return (DSSL_CipherSuite*) bsearch( &id, ssl3suites, 
			sizeof(ssl3suites)/sizeof(ssl3suites[0]), sizeof(ssl3suites[0]),
			compare_cipher_suites );
}

static DSSL_CipherSuite ssl2suites[] = 
{
	{ 0x01, SSL2_VERSION, SSL_KEX_RSA, 0, "RC4", "MD5" },
	{ 0x02, SSL2_VERSION, SSL_KEX_RSA, 40, "RC4", "MD5" },
	{ 0x03, SSL2_VERSION, SSL_KEX_RSA, 0, "RC2", "MD5" },
	{ 0x04, SSL2_VERSION, SSL_KEX_RSA, 40, "RC2", "MD5" },
	{ 0x05, SSL2_VERSION, SSL_KEX_RSA, 0, "IDEA", "MD5" },
	{ 0x06, SSL2_VERSION, SSL_KEX_RSA, 0, "DES", "MD5" },
	{ 0x07, SSL2_VERSION, SSL_KEX_RSA, 0, SN_des_ede3_cbc, "MD5" }
};


int DSSL_ConvertSSL2CipherSuite( u_char cs[3], uint16_t* pcs )
{
	_ASSERT( pcs );

	if(cs[0] > 0x07 ) return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND );
	if(cs[1] != 0 ) return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND );
	switch(cs[2])
	{
	case 0x80: if( cs[0] > 0x05 ) { return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	case 0x40: if( cs[0] != 0x06 ) { return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	case 0xC0: if( cs[0] != 0x07 ) { return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	default: return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND );
	}

	_ASSERT( cs[0] <= sizeof(ssl2suites)/sizeof(ssl2suites[0]) );

	*pcs = cs[0];

	return DSSL_RC_OK;
}


DSSL_CipherSuite* DSSL_GetSSL2CipherSuite( uint16_t id )
{
	if( id == 0 || id > sizeof(ssl2suites)/sizeof(ssl2suites[0]) )
	{
		_ASSERT( FALSE );
		return NULL;
	}

	return &ssl2suites[id-1];
}


int DSSL_CipherSuiteExportable( DSSL_CipherSuite* ss )
{
	return ss->export_key_bits != 0;
}
