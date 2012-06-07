#include "stdinc.h"
#include "../src/ssl_sessionkey_table.h"
#include "../src/ssl_session.h"
#include "alltests.h"

#define TEST_CACHE_TIMEOUT 1

void TestSessionKeyTableAPI( CuTest* tc )
{
	dssl_SessionKeyTable* tbl = NULL;
	DSSL_Session* sess = NULL;
	DSSL_SessionKeyData* kd = NULL;

	tbl = dssl_SessionKT_Create( 100, TEST_CACHE_TIMEOUT );
	CuAssert( tc, "SessionKeyTable object should be not NULL", tbl != NULL );

	sess = (DSSL_Session*) malloc( sizeof( DSSL_Session ) );
	CuAssert( tc, "DSSL_Session object should be not NULL", sess != NULL );
	
	memset( sess, 0, sizeof(*sess) );

	dssl_SessionKT_Add( tbl, sess );
	CuAssertTrue( tc, tbl->count == 1 );

	kd = dssl_SessionKT_Find( tbl, sess->session_id );
	CuAssertTrue( tc, kd != NULL );

	CuAssertTrue( tc, kd->refcount == 1 );
	CuAssertTrue( tc, kd->released_time == 0 );

	kd = NULL; 
	dssl_SessionKT_Release( tbl, sess->session_id );

	ThreadSleep( (TEST_CACHE_TIMEOUT+1)*1000 );

	dssl_SessionKT_CleanSessionCache( tbl );
	CuAssertTrue( tc, tbl->count == 0 );

	free( sess );
	dssl_SessionKT_Destroy( tbl );
}

