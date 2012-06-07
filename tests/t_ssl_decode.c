#include "stdinc.h"
#include "alltests.h"
#include "t_stream_utils.h"
#include "ssl_test_data.h"


void TestSSLDecode( CuTest* tc, const char* file, 
				   const char* c_to_s, const char* s_to_c,
				   int c_to_s_ack, int c_to_s_data, int c_to_s_retrans,
				   int s_to_c_ack, int s_to_c_data, int s_to_c_retrans,
				   int expected_rc, SSL_ServerParams* Params )
{
	SessionCaptureData bl_data;

	InitSessionCaptureData( &bl_data );

	bl_data.rc = expected_rc;
	
	bl_data.client.data = (u_char*) strdup(c_to_s);
	bl_data.client.len = (int)strlen( c_to_s );
	bl_data.client.stats.ack_pkt_count = c_to_s_ack;
	bl_data.client.stats.data_pkt_count = c_to_s_data;
	bl_data.client.stats.retrans_pkt_count = c_to_s_retrans;
	
	bl_data.server.data = (u_char*) strdup(s_to_c);
	bl_data.server.len = (int)strlen( s_to_c );
	bl_data.server.stats.ack_pkt_count = s_to_c_ack;
	bl_data.server.stats.data_pkt_count = s_to_c_data;
	bl_data.server.stats.retrans_pkt_count = s_to_c_retrans;

	TestCaptureFile( tc, file, &bl_data, Params );

	DestroySessionCaptureData( &bl_data );
}


void TestTLS_RSA_EXPORT_WITH_RC4_40_MD5( CuTest* tc )
{
	TestSSLDecode( tc, "./ssl-test-data/TLS_RSA_EXPORT_WITH_RC4_40_MD5[0x0003].cap",
			"123""\xA""789\xA", "456""\xA""101112\xA", 
			5, 4,0, 3, 4, 0, 0, &SSL_ServerParam3 );
}


void TestSSL3_EXP_RC2_CBC_MD5( CuTest* tc )
{
	TestSSLDecode( tc, "./ssl-test-data/SSL3_EXP_RC2_CBC_MD5[0x0006].cap",
				"1234567890\xA", "", 3,4,0, 3,2,0, 0, &SSL_ServerParam3 );
}


void TestSSL3_RSA_WITH_RC4_128_MD5( CuTest* tc )
{
	TestSSLDecode( tc, "./ssl-test-data/SSL3_RSA_WITH_RC4_128_MD5[0x0004].cap",
				"1234567890\xA", "", 2,4,0, 2,2,0, 0, &SSL_ServerParam3 );
}

void TestSSLSessionCache( CuTest* tc )
{
	TestSSLDecode( tc, "./ssl-test-data/TLS_session_reuse.cap",
				"1\xA", "2\xA", 3,4,0, 4,2,0, 0, &SSL_ServerParam3 );
}

