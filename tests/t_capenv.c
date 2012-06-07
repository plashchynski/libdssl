#include "stdinc.h"
#include "alltests.h"
#include "ssl_test_data.h"

void CreateCaptureEnvAndTestAdapter( CuTest* tc, CapEnv** ppEnv, pcap_t** ppAdapter )
{
	CuAssertTrue( tc, ppAdapter != NULL );
	CuAssertTrue( tc, ppEnv != NULL );

	(*ppAdapter) = OpenTestAdapter();
	CuAssertTrue( tc, (*ppAdapter) != NULL );

	(*ppEnv) = CapEnvCreate( *ppAdapter, 1024, 0, 0 );
	CuAssertTrue( tc, (*ppEnv) != NULL );
}


void TestCapEnvCreateDestroy( CuTest* tc )
{
	pcap_t* adapter;
	CapEnv* env;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );

	CapEnvDestroy( env );
	pcap_close( adapter );
}

void TestCapEnvBasicCapture( CuTest* tc )
{
	pcap_t* adapter;
	CapEnv* env;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );

	CapEnvCapture( env );

	CapEnvDestroy( env );
	pcap_close( adapter );
}


void TestCapEnvSetSSL_ServerInfo( CuTest* tc )
{
	pcap_t* adapter;
	CapEnv* env;
	struct in_addr server_ip = { 127, 0, 0, 1 };
	uint16_t port = 443;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );

	CapEnvSetSSL_ServerInfo( env, &server_ip, port, server_keyfile, NULL );
	
	CuAssertTrue( tc, env->ssl_env != NULL );
	CuAssertTrue( tc, env->ssl_env->servers != NULL );
	CuAssertTrue( tc, env->ssl_env->server_count == 1 );
	CuAssertTrue( tc, DSSL_EnvFindServerInfo( env->ssl_env, server_ip, port ) != NULL );

	// adding another server
	CapEnvSetSSL_ServerInfo( env, &SSL_ServerParam2.server_ip, SSL_ServerParam2.port, SSL_ServerParam2.server_key_file, NULL );

	CuAssertTrue( tc, env->ssl_env != NULL );
	CuAssertTrue( tc, env->ssl_env->servers != NULL );
	CuAssertTrue( tc, env->ssl_env->server_count == 2 );
	CuAssertTrue( tc, DSSL_EnvFindServerInfo( env->ssl_env, 
			SSL_ServerParam2.server_ip, SSL_ServerParam2.port ) != NULL );
	
	CapEnvDestroy( env );
	pcap_close( adapter );
}


void TestDSSL_MoveServerToMissingKeyListNull( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue(tc, DSSL_MoveServerToMissingKeyList(env->ssl_env, NULL ) == 0 ); 

	CapEnvDestroy( env );
	pcap_close( adapter );
}


void TestDSSL_RemoveNonExistingServerKey( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	struct in_addr server_ip = { 127, 0, 0, 1 };
	uint16_t port = 443;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip, port, server_keyfile, NULL ) == DSSL_RC_OK);
	CuAssertTrue(tc, env->ssl_env->server_count == 1 ); 
	
	CuAssertTrue(tc, DSSL_MoveServerToMissingKeyList(env->ssl_env, NULL ) == 0 ); 
	
	CuAssertTrue(tc, env->ssl_env->server_count == 1 ); 

	CapEnvDestroy( env );
	pcap_close( adapter );
}

void TestDSSL_RemoveSingleServerKey( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	struct in_addr server_ip = { 127, 0, 0, 1 };
	uint16_t port = 443;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip, port, server_keyfile, NULL ) == DSSL_RC_OK);
	CuAssertTrue(tc, env->ssl_env->server_count == 1 ); 
	
	CuAssertTrue(tc, DSSL_MoveServerToMissingKeyList(env->ssl_env, env->ssl_env->servers[0] ) == 1 ); 
	
	CuAssertTrue(tc, env->ssl_env->server_count == 0 ); 
	CuAssertTrue(tc, env->ssl_env->servers == NULL ); 

	CuAssertTrue(tc, env->ssl_env->missing_key_server_count == 1 ); 
	CuAssertTrue(tc, env->ssl_env->missing_key_servers != NULL ); 

	CapEnvDestroy( env );
	pcap_close( adapter );
}

void TestDSSL_RemoveLastServerKey( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	struct in_addr server_ip1 = { 127, 0, 0, 1 };
	struct in_addr server_ip2 = { 10, 0, 0, 10 };
	uint16_t port = 443;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip1, port, server_keyfile, NULL ) == DSSL_RC_OK);
	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip2, port, server_keyfile, NULL ) == DSSL_RC_OK);

	CuAssertTrue(tc, env->ssl_env->server_count == 2 ); 
	
	CuAssertTrue(tc, env->ssl_env->missing_key_server_count == 0 ); 
	CuAssertTrue(tc, env->ssl_env->missing_key_servers == NULL );

	CuAssertTrue(tc, DSSL_MoveServerToMissingKeyList(env->ssl_env, env->ssl_env->servers[1] ) == 1 ); 
	
	CuAssertTrue(tc, env->ssl_env->server_count == 1 ); 
	CuAssertTrue(tc, env->ssl_env->servers != NULL ); 

	CuAssertTrue(tc, env->ssl_env->missing_key_server_count == 1 ); 
	CuAssertTrue(tc, env->ssl_env->missing_key_servers != NULL );

	CapEnvDestroy( env );
	pcap_close( adapter );
}

void TestDSSL_RemoveFirstServerKey( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	struct in_addr server_ip1 = { 127, 0, 0, 1 };
	struct in_addr server_ip2 = { 10, 0, 0, 10 };
	uint16_t port = 443;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip1, port, server_keyfile, NULL ) == DSSL_RC_OK);
	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip2, port, server_keyfile, NULL ) == DSSL_RC_OK);

	CuAssertTrue(tc, env->ssl_env->server_count == 2 ); 
	
	CuAssertTrue(tc, env->ssl_env->missing_key_server_count == 0 ); 
	CuAssertTrue(tc, env->ssl_env->missing_key_servers == NULL ); 

	CuAssertTrue(tc, DSSL_MoveServerToMissingKeyList(env->ssl_env, env->ssl_env->servers[0] ) == 1 ); 
	
	CuAssertTrue(tc, env->ssl_env->server_count == 1 ); 
	CuAssertTrue(tc, env->ssl_env->servers != NULL ); 

	CuAssertTrue(tc, env->ssl_env->missing_key_server_count == 1 ); 
	CuAssertTrue(tc, env->ssl_env->missing_key_servers != NULL ); 

	CapEnvDestroy( env );
	pcap_close( adapter );
}

void TestDSSL_RemoveNonExistingServerKey2( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	struct in_addr server_ip1 = { 127, 0, 0, 1 };
	struct in_addr server_ip2 = { 10, 0, 0, 10 };
	uint16_t port = 443;

	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip1, port, server_keyfile, NULL ) == DSSL_RC_OK);
	CuAssertTrue(tc, CapEnvSetSSL_ServerInfo( env, &server_ip2, port, server_keyfile, NULL ) == DSSL_RC_OK);

	CuAssertTrue(tc, env->ssl_env->server_count == 2 ); 
	
	CuAssertTrue(tc, DSSL_MoveServerToMissingKeyList(env->ssl_env, NULL ) == 0 ); 
	
	CuAssertTrue(tc, env->ssl_env->server_count == 2 ); 
	CuAssertTrue(tc, env->ssl_env->servers != NULL ); 

	CapEnvDestroy( env );
	pcap_close( adapter );
}

void TestDSSL_EnvAddMissingKeyServer( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	struct in_addr server_ip1 = { 127, 0, 0, 1 };
	struct in_addr server_ip2 = { 10, 0, 0, 10 };
	uint16_t port = 443;

	/* check initial conditions */
	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );
	CuAssertTrue( tc, env->ssl_env != NULL );

	CuAssertTrue( tc, env->ssl_env->missing_key_servers == NULL );
	CuAssertTrue( tc, env->ssl_env->missing_key_server_count == 0 );

	/* check that DSSL_EnvIsMissingKeyServer is working against an empty list */
	CuAssertTrue( tc, DSSL_EnvIsMissingKeyServer( env->ssl_env, server_ip1, port ) == 0 );
	CuAssertTrue( tc, DSSL_EnvIsMissingKeyServer( env->ssl_env, server_ip2, port ) == 0 );

	/* add a server */
	CuAssertTrue( tc, DSSL_EnvAddMissingKeyServer( env->ssl_env, server_ip1, port ) == DSSL_RC_OK );

	CuAssertTrue( tc, env->ssl_env->missing_key_server_count == 1 );
	CuAssertPtrNotNull( tc, env->ssl_env->missing_key_servers );
	CuAssertPtrNotNull( tc, env->ssl_env->missing_key_servers[0] );

	CuAssertTrue(tc, INADDR_IP(env->ssl_env->missing_key_servers[0]->server_ip) == INADDR_IP(server_ip1));
	CuAssertTrue(tc, env->ssl_env->missing_key_servers[0]->port == port );

	/* check that DSSL_EnvIsMissingKeyServer reports the added server back */
	CuAssertTrue( tc, DSSL_EnvIsMissingKeyServer( env->ssl_env, server_ip1, port ) != NULL );
	/* but nothing else */
	CuAssertTrue( tc, DSSL_EnvIsMissingKeyServer( env->ssl_env, server_ip2, port ) == 0 );

	/* now add the second server */
	CuAssertTrue( tc, DSSL_EnvAddMissingKeyServer( env->ssl_env, server_ip2, port ) == DSSL_RC_OK );

	CuAssertTrue( tc, env->ssl_env->missing_key_server_count == 2 );
	CuAssertPtrNotNull( tc, env->ssl_env->missing_key_servers );
	CuAssertPtrNotNull( tc, env->ssl_env->missing_key_servers[0] );
	CuAssertPtrNotNull( tc, env->ssl_env->missing_key_servers[1] );

	/* check that the first server is still there */
	CuAssertTrue(tc, INADDR_IP(env->ssl_env->missing_key_servers[0]->server_ip) == INADDR_IP(server_ip1));
	CuAssertTrue(tc, env->ssl_env->missing_key_servers[0]->port == port );

	/* as well as the second one */
	CuAssertTrue(tc, INADDR_IP(env->ssl_env->missing_key_servers[1]->server_ip) == INADDR_IP(server_ip2));
	CuAssertTrue(tc, env->ssl_env->missing_key_servers[1]->port == port );

	/* check that DSSL_EnvIsMissingKeyServer reports both servers */
	CuAssertTrue( tc, DSSL_EnvIsMissingKeyServer( env->ssl_env, server_ip1, port ) != NULL );
	CuAssertTrue( tc, DSSL_EnvIsMissingKeyServer( env->ssl_env, server_ip2, port ) != NULL );

	CapEnvDestroy( env );
	pcap_close( adapter );
}

static char max_session_count_event = -1;
static void max_session_count_error_callback_proc( struct CapEnv_* env, TcpSession* sess, char e )
{
	env; sess; /*unused*/
	max_session_count_event = e;
}

void TestMaxSessionCount( CuTest* tc )
{
	pcap_t* adapter = NULL;
	CapEnv* env = NULL;
	TcpSession* sess = NULL;

	max_session_count_event = -1;
	/* check initial conditions */
	CreateCaptureEnvAndTestAdapter( tc, &env, &adapter );

	CuAssertPtrNotNull(tc, env);
	CuAssertTrue(tc, CapEnvGetMaxSessionCount(env) == 0);

	CapEnvSetMaxSessionCount(env, 1);
	CuAssert(tc, "Check that CapEnvGetMaxSessionCount returns previously set value", CapEnvGetMaxSessionCount(env) == 1);

	CapEnvSetSessionCallback(env, max_session_count_error_callback_proc, NULL );

	/* create first session, should succeed */
	sess = env->sessions->CreateSession( env->sessions, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess != NULL );
	CuAssert(tc, "Check that new session event was received", max_session_count_event == DSSL_EVENT_NEW_SESSION);

	/* create second session, should get an error */
	sess = env->sessions->CreateSession( env->sessions, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess == NULL );
	CuAssert(tc, "Check that session limit reached event was received", max_session_count_event == DSSL_EVENT_SESSION_LIMIT);

	/* cleanup */
	CapEnvDestroy(env);
}