
void TestPktClone(CuTest* cu);
void TestPktCloneChunk(CuTest* cu);
void TestPktCloneChunkArg(CuTest* cu);

void TestSessionTableCreateDestroy( CuTest* tc );
void TestSessionTableAPI( CuTest* tc );
void TestSessionTableAPI2( CuTest* tc );
void TestSessionTableCleanup( CuTest* tc );

void TestCapEnvCreateDestroy( CuTest* tc );
void TestCapEnvBasicCapture( CuTest* tc );
void TestCapEnvSetSSL_ServerInfo( CuTest* tc );

void TestSessionKeyTableAPI( CuTest* tc );

void TestReassembler1( CuTest* tc );
void TestReassembler10( CuTest* tc );
void TestReassemblerSMB( CuTest* tc );
void TestMissingPacketCallback( CuTest* tc );

void TestTLS_RSA_EXPORT_WITH_RC4_40_MD5( CuTest* tc );
void TestSSL3_EXP_RC2_CBC_MD5( CuTest* tc );
void TestSSL3_RSA_WITH_RC4_128_MD5( CuTest* tc );
void TestSSLSessionCache( CuTest* tc );

void TestUdp( CuTest* tc );

void Test_AutoSSLKey1( CuTest* tc );
void Test_AutoSSLKey2( CuTest* tc );
void Test_AutoSSLKey3( CuTest* tc );
void Test_AutoSSLKey4( CuTest* tc );
void Test_AutoSSLKey5( CuTest* tc );

void TestDSSL_MoveServerToMissingKeyListNull( CuTest* tc );
void TestDSSL_RemoveNonExistingServerKey( CuTest* tc );
void TestDSSL_RemoveSingleServerKey( CuTest* tc );
void TestDSSL_RemoveLastServerKey( CuTest* tc );
void TestDSSL_RemoveFirstServerKey( CuTest* tc );
void TestDSSL_RemoveNonExistingServerKey2( CuTest* tc );

void Test_SSL2AutoSSLKey1( CuTest* tc );
void Test_SSL2AutoSSLKey2( CuTest* tc );
void Test_SSL2AutoSSLKey3( CuTest* tc );
void Test_SSL2AutoSSLKey4( CuTest* tc );
void Test_SSL2AutoSSLKey5( CuTest* tc );

void Test_SSL2_RC2_reuse_AutoSSLKey( CuTest* tc );
void Test_SSL2_DES_reuse_AutoSSLKey( CuTest* tc );
void Test_SSL2_exp_RC2_reuse_AutoSSLKey( CuTest* tc );

void TestDSSL_EnvAddMissingKeyServer( CuTest* tc );

void TestSSLMissingKeyServerList( CuTest* tc );
void TestSSL2MissingKeyServerList( CuTest* tc );
void TestSSL2MissingKeyEmptyServerList( CuTest* tc );
void TestSSLMissingKeyEmptyServerList( CuTest* tc );

void TestTlsSessionTicketTableCreateDestroy( CuTest* tc );
void TestTlsSessionTicketTableAddRemove( CuTest* tc );
void TestTlsSessionTicketTableRemoveAll( CuTest* tc );
void TestTlsSessionTicketTableCleanup( CuTest* tc );

void TestMaxSessionCount( CuTest* tc );
