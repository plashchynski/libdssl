#include "stdinc.h"
#include "t_stream_utils.h"

void InitSessionCaptureData( SessionCaptureData* cd )
{
	memset( cd, 0, sizeof( *cd ) );
}

void DestroySessionCaptureData( SessionCaptureData* cd )
{
	if( !cd ) return;

	if( cd->client.data != NULL ) free( cd->client.data );
	if( cd->server.data != NULL ) free( cd->server.data );

	InitSessionCaptureData( cd );
}

static int CompareCaptureData( const CaptureData* d1, const CaptureData* d2 )
{
	if( d1 == NULL && d2 == NULL ) return 0;
	if( d1 == NULL && d2 != NULL ) return 1;
	if( d2 == NULL && d1 != NULL ) return -1;

	if( d2->len != d1->len ) return d1->len - d2->len;

	if( d1->stats.ack_pkt_count != d2->stats.ack_pkt_count )
		return d1->stats.ack_pkt_count != d2->stats.ack_pkt_count;

	if( d1->stats.data_pkt_count != d2->stats.data_pkt_count )
		return d1->stats.data_pkt_count != d2->stats.data_pkt_count;

	if( d1->stats.retrans_pkt_count != d2->stats.retrans_pkt_count )
		return d1->stats.retrans_pkt_count != d2->stats.retrans_pkt_count;

	return memcmp( d1->data, d2->data, d1->len );
}


static void PrintCaptureDataDiff( const CaptureData* d1, const CaptureData* d2, char* buff )
{
	int i, sz;
	if( d1 == NULL || d2 == NULL ) 
	{
		sprintf( buff, "one or both arguments are null" );
		return;
	}

	if( (d1->len == 0 || d2->len == 0) && d1->len != d2->len )
	{
		sprintf( buff, "one of the arguments have zero length" );
		return;
	}

	sz = d1->len < d2->len ? d1->len : d2->len;

	for( i = 0; i < sz; i++ )
	{
		if( d1->data[i] != d2->data[i] )
		{
			sprintf( buff, "difference at index %d: %c - %c", i, d1->data[i], d2->data[i] );
			return;
		}
	}
	
	sprintf( buff, "no difference" );
}


void CaptureDataPacketHandler( NM_PacketDir dir, void* user_data, u_char* pkt_payload,
							  uint32_t pkt_size, DSSL_Pkt* last_packet )
{
	SessionCaptureData * scapdata = (SessionCaptureData*) user_data;
	CaptureData* data = NULL;

	last_packet; /* to make the compiler happy */
	if( dir == ePacketDirFromClient )
		data = &scapdata->client;
	else if( dir == ePacketDirFromServer )
		data = &scapdata->server;
	else
	{
		return;
	}

	data->data = realloc( data->data, data->len + pkt_size );
	memcpy( data->data + data->len, pkt_payload, pkt_size );
	data->len += pkt_size;
}


static void CaptureDataErrorCallback( void* user_data, int error_code )
{
	SessionCaptureData * scapdata = (SessionCaptureData*) user_data;

	scapdata->rc = error_code;
}

static int MissingPacketCallback( NM_PacketDir dir, void* user_data, uint32_t seq, uint32_t len )
{
	SessionCaptureData * scapdata = (SessionCaptureData*) user_data;

	dir; len; seq;

	++scapdata->missing_count;
	return scapdata->missing_response;
}

static void CaptureDataEventHandler( void* user_data, int event_code, const void* event_data )
{
	SessionCaptureData * scapdata = (SessionCaptureData*) user_data;
	if(event_code == eSslHandshakeComplete )
	{
		scapdata->handshake_time = *((const struct timeval*) event_data);
	}
	else
	{
		scapdata->rc = NM_ERROR(DSSL_E_NOT_IMPL); /*unknown event code - add unit test support */
	}
}

static void OnNewSessionHandler( CapEnv* env, TcpSession* sess, char event )
{
	SessionCaptureData * scapdata = (SessionCaptureData*) CapEnvGetUserData( env );
	if( event == DSSL_EVENT_NEW_SESSION )
	{
		SessionSetCallback( sess, CaptureDataPacketHandler, CaptureDataErrorCallback, CapEnvGetUserData( env ) );
		SessionSetEventCallback( sess, CaptureDataEventHandler );
		SessionSetMissingPacketCallback( sess, MissingPacketCallback,
			scapdata->session_missing_count, scapdata->session_missing_timeout);
	} else if( event == DSSL_EVENT_SESSION_CLOSING )
	{
		scapdata->client.stats = sess->clientStream.stats;
		scapdata->server.stats = sess->serverStream.stats;
	}
}

static NM_SessionType TestReassembler_ForReassemble( struct CapEnv_* env, struct DSSL_Pkt_* pkt )
{
	pkt; env;
	return eSessionTypeTcp;
}


int CaptureStreamsFromFile( CuTest* tc, const char* file, SessionCaptureData* cd, 
						   SSL_ServerParams* ssl_params )
{
	char buff[1024];
	pcap_t* p;
	CapEnv* env;
	int rc = 0;

	p = pcap_open_offline( file, buff );
	if( !p ) 
	{
		CuFail( tc, buff );
		return -1;
	}

	env = CapEnvCreate( p, 100, 0, 0 );


	if( ssl_params != NULL ) 
	{
		rc = CapEnvSetSSL_ServerInfo( env, &ssl_params->server_ip,
			ssl_params->port, ssl_params->server_key_file, ssl_params->key_file_password );
		CuAssert( tc, "CapEnvSetSSL_ServerInfo failed", rc == DSSL_RC_OK );
	}
	else
	{
		env->ForReassemble = TestReassembler_ForReassemble;
	}

	CuAssert( tc, "CapEnvCreate should succeed", env != NULL );

	CapEnvSetSessionCallback( env, OnNewSessionHandler, cd );
	
	rc = CapEnvCapture( env );

	env->sessions->RemoveAll(env->sessions);
	CuAssert( tc, "check the session reassembly packet count is 0", env->sessions->packet_cache_count == 0);
	CuAssert( tc, "check the session reassembly packet size is 0", env->sessions->packet_cache_mem == 0);

	CapEnvDestroy( env );
	pcap_close( p );

	return rc;
}


void TestStreamReassembler( CuTest* tc, const char* baseline_file, 
							const char** altered_files, int altered_file_cnt,
							SSL_ServerParams* ssl_params )
{
	int i;
	char buff[1024];
	SessionCaptureData capdata;
	SessionCaptureData baseline;

	InitSessionCaptureData( &capdata );
	InitSessionCaptureData( &baseline );

	if ( CaptureStreamsFromFile( tc, baseline_file, &baseline, ssl_params ) )
	{
		CuFail( tc, "TestStreamReassembler: Failed to capture baseline file" );
	}

	if( baseline.client.len == 0 && baseline.server.len == 0 )
	{
		CuFail( tc, "TestStreamReassembler: No baseline data captured" );
	}

	for( i=0; i < altered_file_cnt; i++)
	{
		if( CaptureStreamsFromFile( tc, altered_files[i], &capdata, ssl_params ) )
		{
			CuFail( tc, "TestStreamReassembler: Failed to capture test file" );
		}

		if( baseline.rc != capdata.rc )
		{
			sprintf( buff, "TestStreamReassembler: unexpected error code: %d", capdata.rc );
			CuFail( tc, buff );
		}

		if( CompareCaptureData( &baseline.server, &capdata.server ) != 0 )
		{
			sprintf( buff, "TestStreamReassembler: server stream different, file=%s", altered_files[i] );
			CuFail( tc, buff );
		}

		if( CompareCaptureData( &baseline.client, &capdata.client ) != 0 )
		{
			sprintf( buff, "TestStreamReassembler: client stream different, file=%s", altered_files[i] );
			CuFail( tc, buff );
		}

		DestroySessionCaptureData( &capdata );
	}

	DestroySessionCaptureData( &baseline );
}


void TestCaptureFile( CuTest* tc, const char* file, const SessionCaptureData* baseline_data, 
					 SSL_ServerParams* ssl_params )
{
	char buff[1024];
	SessionCaptureData capdata;
	
	InitSessionCaptureData( &capdata );

	if ( CaptureStreamsFromFile( tc, file, &capdata, ssl_params ) )
	{
		CuFail( tc, "TestCaptureFile: capture failed" );
	}

	if( baseline_data->rc != capdata.rc )
	{
		sprintf( buff, "TestStreamReassembler: unexpected error code: %d", capdata.rc );
		CuFail( tc, buff );
	}

	if( CompareCaptureData( &baseline_data->client, &capdata.client ) != 0 )
	{
		printf("baseline->data: %s\n", baseline_data->client.data );
		printf("captured->data: %s\n", capdata.client.data );
		printf("baseline->len: %d\n", baseline_data->client.len );
		printf("captured->len: %d\n", capdata.client.len );
		printf("baseline->ack_pkt_count: %d\n", baseline_data->client.stats.ack_pkt_count );
		printf("captured->ack_pkt_count: %d\n", capdata.client.stats.ack_pkt_count );
		printf("baseline->data_pkt_count: %d\n", baseline_data->client.stats.data_pkt_count );
		printf("captured->data_pkt_count: %d\n", capdata.client.stats.data_pkt_count );
		printf("baseline->retrans_pkt_count: %d\n", baseline_data->client.stats.retrans_pkt_count );
		printf("captured->retrans_pkt_count: %d\n", capdata.client.stats.retrans_pkt_count );
		CuFail( tc, "TestCaptureFile: client stream different" );
	}

	if( CompareCaptureData( &baseline_data->server, &capdata.server ) != 0 )
	{
		printf("baseline->data: %s\n", baseline_data->server.data );
		printf("captured->data: %s\n", capdata.server.data );
		printf("baseline->len: %d\n", baseline_data->server.len );
		printf("captured->len: %d\n", capdata.server.len );
		printf("baseline->ack_pkt_count: %d\n", baseline_data->server.stats.ack_pkt_count );
		printf("captured->ack_pkt_count: %d\n", capdata.server.stats.ack_pkt_count );
		printf("baseline->data_pkt_count: %d\n", baseline_data->server.stats.data_pkt_count );
		printf("captured->data_pkt_count: %d\n", capdata.server.stats.data_pkt_count );
		printf("baseline->retrans_pkt_count: %d\n", baseline_data->server.stats.retrans_pkt_count );
		printf("captured->retrans_pkt_count: %d\n", capdata.server.stats.retrans_pkt_count );
		CuFail( tc, "TestCaptureFile: server stream different\n" );
	}

	DestroySessionCaptureData( &capdata );
}


void CompareCaptureFiles(  CuTest* tc, const char* file1,  SSL_ServerParams* ssl_params1,
		const char* file2,  SSL_ServerParams* ssl_params2 )
{
	char buff[1024];
	SessionCaptureData capdata1, capdata2;
	
	/* Run the first file */
	InitSessionCaptureData( &capdata1 );

	if ( CaptureStreamsFromFile( tc, file1, &capdata1, ssl_params1 ) )
	{
		CuFail( tc, "CompareCaptureFiles: first file capture failed" );
	}

	if( capdata1.rc != DSSL_RC_OK )
	{
		sprintf( buff, "CompareCaptureFiles: unexpected error code: %d", capdata1.rc );
		CuFail( tc, buff );
	}

	/* Run the second file */
	InitSessionCaptureData( &capdata2 );

	if ( CaptureStreamsFromFile( tc, file2, &capdata2, ssl_params2 ) )
	{
		CuFail( tc, "CompareCaptureFiles: second file capture failed" );
	}

	if( capdata2.rc != DSSL_RC_OK )
	{
		sprintf( buff, "CompareCaptureFiles: unexpected error code: %d", capdata2.rc );
		CuFail( tc, buff );
	}

	/* Compare */
	if( CompareCaptureData( &capdata1.client, &capdata2.client ) != 0 )
	{
		PrintCaptureDataDiff( &capdata1.client, &capdata2.client, buff );
		CuFail( tc, buff );
	}

	if( CompareCaptureData( &capdata1.server, &capdata2.server ) != 0 )
	{
		PrintCaptureDataDiff( &capdata1.server, &capdata2.server, buff );
		CuFail( tc, buff );
	}
	
	DestroySessionCaptureData( &capdata1 );
	DestroySessionCaptureData( &capdata2 );
}
