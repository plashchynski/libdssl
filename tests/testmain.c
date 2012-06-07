#include <stdio.h>

#include "CuTest.h"
#include "alltests.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#ifdef _WIN32
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>
#endif

void AddTests( CuSuite* suite )
{

	SUITE_ADD_TEST( suite, TestPktClone );
	SUITE_ADD_TEST( suite, TestPktCloneChunk );
	SUITE_ADD_TEST( suite, TestPktCloneChunkArg );

	SUITE_ADD_TEST( suite, TestSSLMissingKeyEmptyServerList );
	SUITE_ADD_TEST( suite, TestSSL2MissingKeyEmptyServerList );
	SUITE_ADD_TEST( suite, TestSSL2MissingKeyServerList );
	SUITE_ADD_TEST( suite, TestSSLMissingKeyServerList );
	SUITE_ADD_TEST( suite, TestDSSL_EnvAddMissingKeyServer );

	SUITE_ADD_TEST( suite, Test_SSL2_DES_reuse_AutoSSLKey );
	SUITE_ADD_TEST( suite, Test_SSL2_RC2_reuse_AutoSSLKey );
	SUITE_ADD_TEST( suite, Test_SSL2_exp_RC2_reuse_AutoSSLKey );

	SUITE_ADD_TEST( suite, Test_SSL2AutoSSLKey1 );
	SUITE_ADD_TEST( suite, Test_SSL2AutoSSLKey2 );
	SUITE_ADD_TEST( suite, Test_SSL2AutoSSLKey3 );
	SUITE_ADD_TEST( suite, Test_SSL2AutoSSLKey4 );
	SUITE_ADD_TEST( suite, Test_SSL2AutoSSLKey5 );

	SUITE_ADD_TEST( suite, TestDSSL_MoveServerToMissingKeyListNull );
	SUITE_ADD_TEST( suite, TestDSSL_RemoveNonExistingServerKey );
	SUITE_ADD_TEST( suite, TestDSSL_RemoveSingleServerKey );
	SUITE_ADD_TEST( suite, TestDSSL_RemoveLastServerKey );
	SUITE_ADD_TEST( suite, TestDSSL_RemoveFirstServerKey );
	SUITE_ADD_TEST( suite, TestDSSL_RemoveNonExistingServerKey2 );

	SUITE_ADD_TEST( suite, Test_AutoSSLKey1 );
	SUITE_ADD_TEST( suite, Test_AutoSSLKey2 );
	SUITE_ADD_TEST( suite, Test_AutoSSLKey3 );
	SUITE_ADD_TEST( suite, Test_AutoSSLKey4 );
	SUITE_ADD_TEST( suite, Test_AutoSSLKey5 );

	SUITE_ADD_TEST( suite, TestSessionTableCreateDestroy );
	SUITE_ADD_TEST( suite, TestSessionTableAPI );
	SUITE_ADD_TEST( suite, TestSessionTableAPI2 );
	SUITE_ADD_TEST( suite, TestSessionTableCleanup );

	SUITE_ADD_TEST( suite, TestCapEnvCreateDestroy );
	SUITE_ADD_TEST( suite, TestCapEnvBasicCapture );

	SUITE_ADD_TEST( suite, TestSessionKeyTableAPI );

	SUITE_ADD_TEST( suite, TestReassemblerSMB);
	SUITE_ADD_TEST( suite, TestReassembler1 );
	SUITE_ADD_TEST( suite, TestReassembler10 );
	SUITE_ADD_TEST( suite, TestMissingPacketCallback );


	SUITE_ADD_TEST( suite, TestSSLSessionCache );
	SUITE_ADD_TEST( suite, TestSSL3_EXP_RC2_CBC_MD5 );
	SUITE_ADD_TEST( suite, TestSSL3_RSA_WITH_RC4_128_MD5 );
	SUITE_ADD_TEST( suite, TestTLS_RSA_EXPORT_WITH_RC4_40_MD5 );

	SUITE_ADD_TEST( suite, TestUdp );
	
	SUITE_ADD_TEST( suite, TestTlsSessionTicketTableCreateDestroy );
	SUITE_ADD_TEST( suite, TestTlsSessionTicketTableAddRemove );
	SUITE_ADD_TEST( suite, TestTlsSessionTicketTableRemoveAll );
	SUITE_ADD_TEST( suite, TestTlsSessionTicketTableCleanup );

	SUITE_ADD_TEST( suite, TestMaxSessionCount );
}

int RunTests()
{
	CuString *output = CuStringNew();
	CuSuite* suite = CuSuiteNew();
	int tests_failed;
	
	AddTests( suite );

	CuSuiteRun(suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	printf("%s\n", output->buffer);
	tests_failed = (suite->failCount > 0);
	
	CuSuiteDestroy( suite );
	CuStringDestroy( output );
	
	return tests_failed;
}

int main(void)
{
	int tests_failed;

	SSL_library_init();	
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	
	tests_failed = RunTests();

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return tests_failed;
}
