#include "stdinc.h"
#include "alltests.h"
#include "../src/tls_ticket_table.h"
#include "../src/ssl_session.h"

void TestTlsSessionTicketTableCreateDestroy( CuTest* tc )
{
	DSSL_SessionTicketTable* tbl = dssl_SessionTicketTable_Create( 100, 1 );
	CuAssertPtrNotNull(tc, tbl);

	CuAssert(tc, "check initial entry count (0)", tbl->count == 0);
	CuAssert(tc, "check timeout interval", tbl->timeout_interval == 1);

	dssl_SessionTicketTable_Destroy(tbl);
}

void TestTlsSessionTicketTableAddRemove( CuTest* tc )
{
	DSSL_Session* sess = NULL;
	DSSL_SessionTicketData* data = NULL;
	DSSL_SessionTicketTable* tbl = dssl_SessionTicketTable_Create( 100, 1 );
	const u_char * test_ticket = (const u_char*)"test ticket"; /* actual ticket content is not important*/
	int rc = DSSL_RC_OK;

	CuAssertPtrNotNull(tc, tbl);

	sess = (DSSL_Session*) malloc( sizeof( DSSL_Session ) );
	CuAssert( tc, "DSSL_Session object should be not NULL", sess != NULL );
	
	memset( sess, 0, sizeof(*sess) );

	rc = dssl_SessionTicketTable_Add( tbl, sess, test_ticket, (uint32_t) strlen(test_ticket));
	CuAssert(tc, "check dssl_SessionTicketTable_Add return value", rc == DSSL_RC_OK);
	CuAssert(tc, "check session ticket count to be 1", tbl->count == 1);

	data = dssl_SessionTicketTable_Find( tbl, test_ticket, (uint32_t) strlen(test_ticket) );
	CuAssert(tc, "check session ticket is found", data != NULL);

	dssl_SessionTicketTable_Remove( tbl, test_ticket, (uint32_t) strlen(test_ticket) );
	CuAssert(tc, "check the table is empty after deletion", tbl->count == 0);

	data = dssl_SessionTicketTable_Find( tbl, test_ticket, (uint32_t) strlen(test_ticket) );
	CuAssert(tc, "check session ticket is not there anymore", data == NULL);

	free(sess);
	dssl_SessionTicketTable_Destroy(tbl);
}

void TestTlsSessionTicketTableRemoveAll( CuTest* tc )
{
	DSSL_Session* sess = NULL;
	DSSL_SessionTicketTable* tbl = dssl_SessionTicketTable_Create( 100, 1 );
	const u_char * test_ticket = (const u_char*)"test ticket"; /* actual ticket content is not important*/
	int rc = DSSL_RC_OK;

	CuAssertPtrNotNull(tc, tbl);

	sess = (DSSL_Session*) malloc( sizeof( DSSL_Session ) );
	CuAssert( tc, "DSSL_Session object should be not NULL", sess != NULL );
	
	memset( sess, 0, sizeof(*sess) );

	rc = dssl_SessionTicketTable_Add( tbl, sess, test_ticket, (uint32_t) strlen(test_ticket));
	CuAssert(tc, "check dssl_SessionTicketTable_Add return value", rc == DSSL_RC_OK);
	CuAssert(tc, "check session ticket count to be 1", tbl->count == 1);


	dssl_SessionTicketTable_RemoveAll(tbl);
	CuAssert(tc, "check session ticket count to be 0 after removing everything", tbl->count == 0);

	free(sess);
	dssl_SessionTicketTable_Destroy(tbl);
}

void TestTlsSessionTicketTableCleanup( CuTest* tc )
{
	DSSL_Session* sess = NULL;
	DSSL_SessionTicketTable* tbl = dssl_SessionTicketTable_Create( 100, 1 );
	const u_char* test_ticket = (const u_char*)"test ticket"; /* actual ticket content is not important*/
	const u_char* test_ticket2 = (const u_char*)"another ticket";
	int rc = DSSL_RC_OK;

	CuAssertPtrNotNull(tc, tbl);

	sess = (DSSL_Session*) malloc( sizeof( DSSL_Session ) );
	CuAssert( tc, "DSSL_Session object should be not NULL", sess != NULL );
	
	memset( sess, 0, sizeof(*sess) );

	rc = dssl_SessionTicketTable_Add( tbl, sess, test_ticket, (uint32_t) strlen(test_ticket));
	CuAssert(tc, "check dssl_SessionTicketTable_Add return value", rc == DSSL_RC_OK);
	CuAssert(tc, "check session ticket count to be 1", tbl->count == 1);

	ThreadSleep( 2000 ); /* sleep for more than a second to time out the ticket data */
	tbl->last_cleanup_time = time(NULL) - DSSL_CACHE_CLEANUP_INTERVAL - 1; /* pretend that cache cleanup interval expired*/
	dssl_SessionTicketTable_Add(tbl, sess, test_ticket2, (uint32_t) strlen(test_ticket2));
	CuAssert(tc, "check session ticket count to be 1 after cleanup", tbl->count == 1);

	CuAssertPtrNotNull(tc, 	dssl_SessionTicketTable_Find( tbl, test_ticket2, (uint32_t) strlen(test_ticket2)) );

	free(sess);
	dssl_SessionTicketTable_Destroy(tbl);
}

