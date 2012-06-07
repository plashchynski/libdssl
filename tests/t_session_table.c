#include "stdinc.h"
#include "alltests.h"

/* dummy capenv object to initialize the session tables with*/
static CapEnv g_env;

void TestSessionTableCreateDestroy( CuTest* tc )
{
	dssl_SessionTable* tbl;

	tbl = CreateSessionTable( 100, 10 );
	
	CuAssertTrue( tc, tbl != NULL );
	CuAssert( tc, "hash table should be initialized", tbl->table != NULL );
	CuAssert( tc, "all functions must be set", tbl->CreateSession != NULL );
	CuAssert( tc, "all functions must be set", tbl->DestroySession != NULL );
	CuAssert( tc, "all functions must be set", tbl->FindSession != NULL );
	CuAssert( tc, "all functions must be set", tbl->RemoveAll != NULL );
	CuAssert( tc, "there should be no sessions yet", tbl->sessionCount == 0 );

	DestroySessionTable( tbl );
}

void TestSessionTableAPI( CuTest* tc )
{
	dssl_SessionTable* tbl;
	TcpSession* sess, *sess2, *s2;

	tbl = CreateSessionTable( 100, 10 );
	CuAssertTrue( tc, tbl != NULL );
	tbl->env = &g_env;

	sess = tbl->CreateSession( tbl, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess != NULL );

	s2 = tbl->FindSession( tbl, GetTestPacket() );
	CuAssert( tc, "must find the same session we just added!", s2 == sess );

	sess2 = tbl->CreateSession( tbl, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess2 != NULL );

	tbl->DestroySession( tbl, sess );

	s2 = tbl->FindSession( tbl, GetTestPacket() );
	CuAssert( tc, "the second session should be found!", s2 == sess2 );

	tbl->DestroySession( tbl, sess2 );

	s2 = tbl->FindSession( tbl, GetTestPacket() );
	CuAssert( tc, "the session should not be there anymore!", s2 == NULL );

	CuAssert( tc, "check the session reassembly packet count is 0", tbl->packet_cache_count == 0);
	CuAssert( tc, "check the session reassembly packet size is 0", tbl->packet_cache_mem == 0);

	DestroySessionTable( tbl );
}

void TestSessionTableAPI2( CuTest* tc )
{
	dssl_SessionTable* tbl;
	TcpSession* sess, *sess2, *s2;

	tbl = CreateSessionTable( 100, 10 );
	CuAssertTrue( tc, tbl != NULL );
	tbl->env = &g_env;

	sess = tbl->CreateSession( tbl, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess != NULL );

	s2 = tbl->FindSession( tbl, GetTestPacket() );
	CuAssert( tc, "must find the same session we just added!", s2 == sess );

	sess2 = tbl->CreateSession( tbl, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess2 != NULL );

	tbl->DestroySession( tbl, sess2 );

	s2 = tbl->FindSession( tbl, GetTestPacket() );
	CuAssert( tc, "the first session should be found!", s2 == sess );

	tbl->DestroySession( tbl, sess );

	s2 = tbl->FindSession( tbl, GetTestPacket() );
	CuAssert( tc, "the session should not be there anymore!", s2 == NULL );

	CuAssert( tc, "check the session reassembly packet count is 0", tbl->packet_cache_count == 0);
	CuAssert( tc, "check the session reassembly packet size is 0", tbl->packet_cache_mem == 0);

	DestroySessionTable( tbl );
}

void TestSessionTableCleanup( CuTest* tc )
{
	dssl_SessionTable* tbl;
	TcpSession* sess;
	int timeout = 1; /* 1 sec */

	/* create session table */
	tbl = CreateSessionTable( 100, timeout );
	CuAssertTrue( tc, tbl != NULL );
	tbl->env = &g_env;

	/* create session */
	sess = tbl->CreateSession( tbl, GetTestPacket(), eSessionTypeTcp );
	CuAssertTrue( tc, sess != NULL );

	/* make sure the session is found */
	CuAssert( tc, "session is not found!", tbl->FindSession(tbl, GetTestPacket()) == sess );

	/* sleep past timeout */
	ThreadSleep( timeout*2*1000);

	/* call cleanup */
	tbl->Cleanup( tbl );

	CuAssert( tc, "session is still there!", tbl->FindSession(tbl, GetTestPacket()) == NULL );

	CuAssert( tc, "check the session reassembly packet count is 0", tbl->packet_cache_count == 0);
	CuAssert( tc, "check the session reassembly packet size is 0", tbl->packet_cache_mem == 0);

	DestroySessionTable( tbl );
}
