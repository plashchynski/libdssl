#ifndef __T_STREAM_UTILS_H__
#define __T_STREAM_UTILS_H__

typedef struct _CaptureData
{
	u_char* data;
	int len;
	TcpStreamStats	stats;
} CaptureData;

typedef struct _SessionCaptureData
{
	CaptureData server;
	CaptureData client;
	int rc;
	int missing_count;
	int missing_response;

	int session_missing_timeout;
	int	session_missing_count;
	struct timeval handshake_time;
} SessionCaptureData;

typedef struct _SSL_ServerParams
{
	struct in_addr	server_ip;
	uint16_t		port;
	const char*		server_key_file;
	const char*		key_file_password;
} SSL_ServerParams;


void TestStreamReassembler( CuTest* tc, const char* baseline_file, 
							const char** altered_files, int altered_file_cnt,
							SSL_ServerParams* param /* can be NULL */ );

void TestCaptureFile( CuTest* tc, const char* file, const SessionCaptureData* baseline_data, 
					 SSL_ServerParams* ssl_params );

void CompareCaptureFiles(  CuTest* tc, const char* file1,  SSL_ServerParams* ssl_params1,
		const char* file2,  SSL_ServerParams* ssl_params2 );

int CaptureStreamsFromFile( CuTest* tc, const char* file, SessionCaptureData* cd, 
						   SSL_ServerParams* ssl_params );

void InitSessionCaptureData( SessionCaptureData* cd );
void DestroySessionCaptureData( SessionCaptureData* cd );

#endif

