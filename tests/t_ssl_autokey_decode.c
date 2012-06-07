#include "stdinc.h"
#include "alltests.h"
#include "t_stream_utils.h"
#include "ssl_test_data.h"

#ifndef _ASSERT
	/* this appears to get redefined somewhere after stdinc.h */
	#define _ASSERT(a) ((void)0)
#endif

#define BUFF_SIZE	1024
#define PATH_LEN	255

#define MISSING_PACKET_COUNT	100
#define MISSING_PACKET_TIMEOUT	10


/* Format and dump the data on the screen */
void DumpData( FILE*f, u_char* data, uint32_t sz )
{
	uint32_t i;

	for( i = 0; i < sz; i++ )
	{
		if( isprint(data[i]) || data[i] == '\n' || data[i] == '\t' || data[i] == '\r' ) 
			putc( data[i], f );
		else
			putc( '.', f );
	}
}

static int missing_packet_callback(NM_PacketDir dir, void* user_data, uint32_t pkt_seq, uint32_t pkt_size)
{
	TcpSession* sess = (TcpSession*) user_data;
	FILE* f = (FILE*) CapEnvGetUserData(sess->env);
	fprintf(f, "\n Missing packet(s) detected; dir = %d, seq=%u, size=%u", dir, pkt_seq, pkt_size);
	return 1; /* skip and continue */
}

/* data callback routine that simply dumps the decoded data on the screen */
static void data_callback_proc( NM_PacketDir dir, void* user_data, u_char* pkt_payload,
							  uint32_t pkt_size, DSSL_Pkt* last_packet )
{
	TcpSession* sess = (TcpSession*) user_data;
	FILE* f = (FILE*) CapEnvGetUserData(sess->env);

	last_packet;
	
	switch(dir)
	{
	case ePacketDirFromClient:
		fprintf( f, "\nC->S:\n" );
		break;
	case ePacketDirFromServer:
		fprintf( f, "\nS->C:\n" );
		break;
	default:
		fprintf( f, "\nUnknown packet direction!" );
		return;
	}

	DumpData( f, pkt_payload, pkt_size );
}

/* error callback routine; prints the error on the screen */
static void error_callback_proc( void* user_data, int error_code )
{
	TcpSession* sess = (TcpSession*) user_data;
	FILE* f = (FILE*) CapEnvGetUserData(sess->env);
	char buff[512];
	SessionToString( sess, buff );
	fprintf( f, "\nERROR: Session: %s, error code: %d", buff, error_code );
}

static void event_callback( void* user_data, int event_code, const void* event_data)
{
	TcpSession* sess = (TcpSession*) user_data;
	FILE* f = (FILE*) CapEnvGetUserData(sess->env);
	char* event_str = "";
	char event_buf[512];
	char session_buff[512];

	switch( event_code )
	{
	case eSslMappedKeyFailed: 
	case eSslMappingDiscovered: 
	case eSslMissingServerKey: 
		{
			const DSSL_ServerInfo* si = (const DSSL_ServerInfo*) event_data;
			if( si )
			{
				AddressToString( INADDR_IP(si->server_ip), si->port, event_buf);
			}
			else
			{
				_ASSERT( si != NULL );
				sprintf( event_buf, "NULL DSSL_ServerInfo pointer passed to the event");
			}
		} 
		break;
	default:
		event_buf[0]=0;
		break;
	}

	switch( event_code )
	{
	case eSslMappedKeyFailed: 
			event_str = "Automatically mapped SSL key failed";
		break;
	case eSslMappingDiscovered: 
			event_str = "SSL server discovered";
		break;
	case eSslMissingServerKey: 
			event_str = "No key found for SSL server"; 
		break;
	case eSslHandshakeComplete: 
		return; /* not reporting this event */
	default: event_str = "Unknown event code"; 
		break;
	}

	SessionToString( sess, session_buff );
	fprintf( f, "\n>>%s [%s] Session: %s", event_str, event_buf, session_buff);
}

/* session event callback routine: traces opening / closing sessions; sets the callbacks */
static void session_event_handler( CapEnv* env, TcpSession* sess, char event )
{
	FILE* f = (FILE*) CapEnvGetUserData(env);

	char session_buff[512];
	switch( event )
	{
	case DSSL_EVENT_NEW_SESSION:
		SessionToString( sess, session_buff );
		fprintf( f, "\n=> New Session: %s", session_buff );
		SessionSetCallback( sess, data_callback_proc, error_callback_proc, sess );
		SessionSetMissingPacketCallback( sess, missing_packet_callback, MISSING_PACKET_COUNT, 
			MISSING_PACKET_TIMEOUT );
		SessionSetEventCallback( sess, event_callback );
		break;

	case DSSL_EVENT_SESSION_CLOSING:
		SessionToString( sess, session_buff );
		fprintf( f, "\n<= Session closing: %s", session_buff );
		break;

	default:
		fprintf( f, "ERROR: Unknown session event code (%d)", (int)event );
		break;
	}
}


/* simple password callback function to use with openssl certificate / private key API */
static int password_cb_direct( char *buf, int size, int rwflag, void *userdata )
{
	char* pwd = (char*) userdata;
	int len = (int) strlen( pwd );

	rwflag;

	strncpy( buf, pwd, size );
	return len;
}

static void LoadPrivateKey( CuTest* tc, EVP_PKEY **pkey, const char *keyfile, const char *pwd )
{
	FILE* f = NULL;

	f = fopen( keyfile, "r" );
	if( !f ) {CuFail(tc, "Failed to open key file");}

	if( PEM_read_PrivateKey( f, pkey, password_cb_direct, pwd ) == NULL )
	{
		CuFail(tc, "Failed to load RSA key");
	}

	fclose( f );
}

static int CompareFiles( CuTest* tc, const char* fn1, const char* fn2)
{
	char b1[BUFF_SIZE];
	char b2[BUFF_SIZE];

	FILE* f1 = NULL;
	FILE* f2 = NULL;
	int c1 = 0;
	int c2 = 0;
	
	int rc = 0;

	f1 = fopen( fn1, "rb");
	CuAssert(tc, "fopen should succeed", f1 != NULL);

	f2 = fopen(fn2, "rb");
	CuAssert(tc, "fopen should succeed", f2 != NULL);

	do
	{
		c1 = (int) fread(b1, 1, BUFF_SIZE-1, f1);
		c2 = (int) fread(b2, 1, BUFF_SIZE-1, f2);

		rc = c1 - c2;
		if(rc) break;

		rc = memcmp(b1, b2, c1);
		if(rc) break;
	} while( c1 && c2 );

	fclose(f1);
	fclose(f2);

	return rc;
}


void TestSSLAutoKeyDecode( CuTest* tc, const char* cap_file, const char* key_files[], int key_count)
{
	pcap_t* p;
	CapEnv* env;
	int rc = 0;
	int i = 0;
	FILE* f;
	char out_file_name[PATH_LEN];
	char ref_file_name[PATH_LEN];
	char buff[BUFF_SIZE];

	CuAssertPtrNotNull(tc, cap_file);

	/* build output and known good file names*/
	strcpy(out_file_name, cap_file);
	strcat(out_file_name, ".out");

	strcpy(ref_file_name, cap_file);
	strcat(ref_file_name, ".good");

	f = fopen(out_file_name, "wb");
	CuAssert(tc, "Output file opened", f != NULL);

	/* set up CapEnv object */
	p = pcap_open_offline( cap_file, buff );
	if( !p ) { CuFail( tc, buff ); }

	env = CapEnvCreate( p, 100, 0, 0 );
	CuAssert( tc, "CapEnvCreate should succeed", env != NULL );
	
	for(i = 0; i < key_count; i++)
	{
		EVP_PKEY* pkey = NULL; 
		LoadPrivateKey(tc, &pkey, key_files[i], NULL);
		CuAssert(tc, "Check a key is loaded", pkey != NULL);
		CuAssert(tc, "Check CapEnvAddSSLKey succeeds", CapEnvAddSSLKey(env, pkey) == DSSL_RC_OK );
	}

	CapEnvSetSessionCallback(env, session_event_handler, f);
	rc = CapEnvCapture( env );

	env->sessions->RemoveAll(env->sessions);
	CuAssert( tc, "check the session reassembly packet count is 0", env->sessions->packet_cache_count == 0);
	CuAssert( tc, "check the session reassembly packet size is 0", env->sessions->packet_cache_mem == 0);

	CapEnvDestroy( env );
	fclose(f);
	pcap_close( p );

	CuAssert(tc, "Compare output to the baseline", CompareFiles(tc, out_file_name, ref_file_name) == 0 );
}

static char* ssl_keys[] = {
	"./ssl-test-data/test1.pem",
	"./ssl-test-data/test2.pem",
	"./ssl-test-data/test3.pem",
	"./ssl-test-data/test4.pem",
	"./ssl-test-data/test5.pem" };
static const int ssk_key_count = sizeof(ssl_keys)/sizeof(ssl_keys[0]);

void Test_AutoSSLKey1( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test1.cap", ssl_keys, ssk_key_count); 
}

void Test_AutoSSLKey2( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test2.cap", ssl_keys, ssk_key_count); 
}

void Test_AutoSSLKey3( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test3.cap", ssl_keys, ssk_key_count); 
}

void Test_AutoSSLKey4( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test4.cap", ssl_keys, ssk_key_count); 
}

void Test_AutoSSLKey5( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test5.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2AutoSSLKey1( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2test1.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2AutoSSLKey2( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2test2.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2AutoSSLKey3( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2test3.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2AutoSSLKey4( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2test4.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2AutoSSLKey5( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2test5.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2_RC2_reuse_AutoSSLKey( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2_rc2_reuse.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2_DES_reuse_AutoSSLKey( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2_des_cbc_md5.cap", ssl_keys, ssk_key_count); 
}

void Test_SSL2_exp_RC2_reuse_AutoSSLKey( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/ssl2_exp_rc2_cbc_md5.cap", ssl_keys, ssk_key_count); 
}

void TestSSLMissingKeyServerList( CuTest* tc )
{
	char* ssl_keys2_5[] = {
		"./ssl-test-data/test2.pem",
		"./ssl-test-data/test3.pem",
		"./ssl-test-data/test4.pem",
		"./ssl-test-data/test5.pem" };
	const int ssk_key_count_2_5 = sizeof(ssl_keys2_5)/sizeof(ssl_keys2_5[0]);

	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test_missing_server_key.cap", ssl_keys2_5, ssk_key_count_2_5); 
}

void TestSSL2MissingKeyServerList( CuTest* tc )
{
	char* ssl_keys2_5[] = {
		"./ssl-test-data/test2.pem",
		"./ssl-test-data/test3.pem",
		"./ssl-test-data/test4.pem",
		"./ssl-test-data/test5.pem" };
	const int ssk_key_count_2_5 = sizeof(ssl_keys2_5)/sizeof(ssl_keys2_5[0]);

	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test_ssl2_missing_server_key.cap", ssl_keys2_5, ssk_key_count_2_5); 
}
void TestSSL2MissingKeyEmptyServerList( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test_ssl2_empty_server_key.cap", NULL, 0); 
}

void TestSSLMissingKeyEmptyServerList( CuTest* tc )
{
	TestSSLAutoKeyDecode( tc, "./ssl-test-data/test_empty_server_key.cap", NULL, 0); 
}
