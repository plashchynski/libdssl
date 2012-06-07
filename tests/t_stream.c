#include "stdinc.h"
#include "alltests.h"
#include "t_stream_utils.h"

void TestReassembler1( CuTest* tc )
{
	const char* alt_files[] = { "./test-data/test1-1.cap" };
	const char* baseline_file = "./test-data/test1.cap";

	TestStreamReassembler( tc, baseline_file, alt_files, 
		sizeof(alt_files)/sizeof(alt_files[0]), NULL );
}


void TestReassemblerSMB( CuTest* tc )
{
	const char* alt_files[] = { "./test-data/smbtorture-t.cap" };
	const char* baseline_file = "./test-data/smbtorture-b.cap";

	TestStreamReassembler( tc, baseline_file, alt_files, 
		sizeof(alt_files)/sizeof(alt_files[0]), NULL );
}


void TestReassembler10( CuTest* tc )
{
	const char* alt_files[] = { 
		"./test-data/10-6.cap", "./test-data/10-5.cap",
		"./test-data/10-4.cap", 
		"./test-data/10-3.cap"
		, "./test-data/10-2.cap", "./test-data/10-1.cap" 
	};

	const char* baseline_file = "./test-data/10.cap";

	TestStreamReassembler( tc, baseline_file, alt_files,
			sizeof(alt_files)/sizeof(alt_files[0]), NULL );
}

void TestMissingPacketCallback( CuTest* tc )
{
	SessionCaptureData capdata;

	/* test timeout-based response */
	InitSessionCaptureData( &capdata );
	capdata.missing_response = 0;
	capdata.session_missing_timeout = 1;

	if ( CaptureStreamsFromFile( tc, "./test-data/10-m-to.pcap", &capdata, NULL ) )
	{
		CuFail( tc, "TestMissingPacketCallback: failed to capture stream" );
	}

	CuAssertTrue( tc, capdata.missing_count == 1);
	CuAssertTrue( tc, capdata.rc == DSSL_E_TCP_MISSING_PACKET_DETECTED);

	/* test packet count-based response */
	InitSessionCaptureData( &capdata );
	capdata.missing_response = 0;
	capdata.session_missing_count = 2;

	if ( CaptureStreamsFromFile( tc, "./test-data/10-m-cnt.pcap", &capdata, NULL ) )
	{
		CuFail( tc, "TestMissingPacketCallback: failed to capture stream" );
	}

	CuAssertTrue( tc, capdata.missing_count == 1);
	CuAssertTrue( tc, capdata.rc == DSSL_E_TCP_MISSING_PACKET_DETECTED);
	DestroySessionCaptureData( &capdata );

	/* test timeout-based response with recovery */
	InitSessionCaptureData( &capdata );
	capdata.missing_response = 1;
	capdata.session_missing_timeout = 1;

	if ( CaptureStreamsFromFile( tc, "./test-data/10-m-to.pcap", &capdata, NULL ) )
	{
		CuFail( tc, "TestMissingPacketCallback: failed to capture stream" );
	}

	CuAssertTrue( tc, capdata.missing_count == 1);
	CuAssertTrue( tc, capdata.client.len == 10 );
	CuAssertTrue( tc, strncmp((const char*)&capdata.client.data[0], "1235678910", 10) == 0);
	CuAssertTrue( tc, capdata.rc == DSSL_RC_OK);
	DestroySessionCaptureData( &capdata );

	/* test packet count-based response with recovery */
	InitSessionCaptureData( &capdata );
	capdata.missing_response = 1;
	capdata.session_missing_count = 2;

	if ( CaptureStreamsFromFile( tc, "./test-data/10-m-cnt.pcap", &capdata, NULL ) )
	{
		CuFail( tc, "TestMissingPacketCallback: failed to capture stream" );
	}

	CuAssertTrue( tc, capdata.missing_count == 1);
	CuAssertTrue( tc, capdata.client.len == 9 );
	CuAssertTrue( tc, strncmp((const char*)&capdata.client.data[0], "123678910", 9) == 0);
	CuAssertTrue( tc, capdata.rc == DSSL_RC_OK);

	DestroySessionCaptureData( &capdata );
}
