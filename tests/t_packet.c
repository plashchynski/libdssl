#include "stdinc.h"
#include "alltests.h"

static uint8_t test_packet_data[] = 
{
	/* ethernet header */
	'e', 't', 'h', 's', 'r', 'c',
	'e', 't', 'h', 'd', 's', 't',
	0x08, 0x00, 
	/*ip header */
	0x45, 0x00, 0x00, 0x28, 0x3c, 0x6f, 0x40, 0x00, 
	0x80, IPPROTO_TCP, 0xb0, 0x67, 
	0x0a, 0x32, 0x05, 0x70, /* src ip */
	0xd8, 0xfe, 0x25, 0x68, /* dst ip */
	/*tcp hdr*/
	0x04, 0x99, /*src port 1177*/
	0x00, 0x50, /*dst port 80*/
	0x8e, 0x14, 0xde, 0x2e, /*seq 724*/
	0x5c, 0x87, 0xdd, 0x77, /*ack 324*/
	0x50, 0x10, 
	0xfd, 0x52, /*window size*/
	0x90, 0x5c, /*checksum*/
	0x00, 0x00,
	/*data*/
	'0','1','2','3'
};

static DSSL_Pkt _pkt = 
{ 
	&test_packet_data[0],
	{ {0}, sizeof(test_packet_data), sizeof(test_packet_data) },
	DLT_EN10MB, /* data_link*/
	(struct ether_header*)&test_packet_data[0], 
	(struct ip*) &test_packet_data[14], 
	(struct tcphdr*) &test_packet_data[34],
	NULL, /*UDP hdr */
	NULL, NULL, NULL, /*next. prev, session */
	{2345,6789}, /* ack_time */
	4,0 /*data_len, flags */
};

DSSL_Pkt* GetTestPacket()
{
	return &_pkt;
}


pcap_t* OpenTestAdapter()
{
	char buff[1024];
	pcap_t* rc;

	buff[0]=0;
	rc = pcap_open_offline( "./test-data/test1.cap", buff );

	if( rc == NULL )
	{
		nmLogMessage( LG_SEVERITY_ERROR | LG_CATEGORY_CAPTURE, buff );
	}
	return rc;
}

void TestPktClone(CuTest* cu)
{
	DSSL_Pkt* p = GetTestPacket();
	DSSL_Pkt* p2 = PktClone(p);

	CuAssertTrue(cu, p->data_len == p2->data_len);
	CuAssertTrue(cu, p2->data_len == 4);
	CuAssertTrue(cu, p->link_type == p2->link_type);
	CuAssertTrue(cu, p->flags == p2->flags);
	CuAssertTrue(cu, p->session == p2->session);
	CuAssertTrue(cu, p->ack_time.tv_sec == p2->ack_time.tv_sec);
	CuAssertTrue(cu, p->ack_time.tv_usec == p2->ack_time.tv_usec);

	CuAssertTrue(cu, p2->next == NULL);
	CuAssertTrue(cu, p2->prev == NULL);
	CuAssertTrue(cu, memcmp(p->ether_header, p2->ether_header, sizeof(struct ether_header)) == 0);
	CuAssertTrue(cu, memcmp(p->ip_header, p2->ip_header, sizeof(struct ip)) == 0);
	CuAssertTrue(cu, memcmp(p->tcp_header, p2->tcp_header, sizeof(struct tcphdr)) == 0);

	PktFree(p2);
	p2 = NULL;
}

void TestPktCloneChunk(CuTest* cu)
{
	DSSL_Pkt* p = GetTestPacket();
	DSSL_Pkt* p2 = NULL; 
	u_char* pld = NULL;

	CuAssertTrue(cu, PktCloneChunk(p, 3, &p2) == DSSL_RC_OK);
	CuAssertTrue(cu, p2->data_len == 3);
	CuAssertTrue(cu, PktNextTcpSeqExpected(p2) == PktNextTcpSeqExpected(p));
	pld = PKT_TCP_PAYLOAD(p2);
	CuAssertTrue(cu, pld[0] == '1');
	CuAssertTrue(cu, pld[1] == '2');
	CuAssertTrue(cu, pld[2] == '3');

	CuAssertTrue(cu, p->link_type == p2->link_type);
	CuAssertTrue(cu, p->flags == p2->flags);
	CuAssertTrue(cu, p->session == p2->session);
	CuAssertTrue(cu, p->ack_time.tv_sec == p2->ack_time.tv_sec);
	CuAssertTrue(cu, p->ack_time.tv_usec == p2->ack_time.tv_usec);
	CuAssertTrue(cu, p2->next == NULL);
	CuAssertTrue(cu, p2->prev == NULL);
	PktFree(p2);
}

void TestPktCloneChunkArg(CuTest* cu)
{
	DSSL_Pkt* p = GetTestPacket();
	DSSL_Pkt* p2 = NULL;
	
	CuAssertTrue(cu, PktCloneChunk(p, -1, &p2) == DSSL_E_INVALID_PARAMETER);
	CuAssertTrue(cu, PktCloneChunk(p, 0,&p2) == DSSL_E_INVALID_PARAMETER);
	CuAssertTrue(cu, PktCloneChunk(p, p->data_len + 1, &p2) == DSSL_E_INVALID_PARAMETER);

}
