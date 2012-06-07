#include "stdinc.h"
#include "alltests.h"

struct UdpStats
{
	int			pkt_cnt;
	uint32_t	total_len;
};


static void UdpPacketCallback( struct CapEnv_* env, const u_char* data, uint32_t len, DSSL_Pkt* pkt )
{
	struct UdpStats* stats = env->env_user_data;

	stats->total_len += len;
	++stats->pkt_cnt;

	/* unused */
	pkt; data;
}

void TestUdp( CuTest* tc )
{
	char buff[1024];
	pcap_t* p;
	CapEnv* env;
	int rc = 0;
	const char file[] = "./test-data/smbtorture-udp.cap";
	struct UdpStats stats;

	memset(&stats, 0, sizeof(stats));

	p = pcap_open_offline( file, buff );
	if( !p ) 
	{
		CuFail( tc, buff );
		return;
	}

	env = CapEnvCreate( p, 100, 0, 0 );
	CuAssert( tc, "CapEnvCreate should succeed", env != NULL );

	env->env_user_data = &stats;

	CapEnvSetDatagramCallback( env, UdpPacketCallback );

	rc = CapEnvCapture( env );

	CapEnvDestroy( env );
	pcap_close( p );

	CuAssert( tc, "Checking UPD packet count", stats.pkt_cnt == 49 );
	CuAssert( tc, "Checking total length", stats.total_len == 6260 );
}
