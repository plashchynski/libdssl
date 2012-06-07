/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#include "stdinc.h"
#include "decode.h"

void DecodeTcpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int tcp_hdr_len;

	/* Check the packet length */
	if( len < sizeof(struct tcphdr) )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than minimal TCP header size", len );
		return;
	}

	pkt->tcp_header = (struct tcphdr*) data;

	tcp_hdr_len = NM_TCP_HDR_LEN( pkt->tcp_header );

	if( len < tcp_hdr_len )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than TCP header size specified (%d)", 
			len, tcp_hdr_len );
		return;
	}

	pkt->data_len = (uint16_t)( len - tcp_hdr_len );

	CapEnvProcessPacket( env, pkt );
}


void DecodeUdpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int hdr_len = sizeof(struct udphdr);

	/* Check the packet length */
	if( len < hdr_len )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than minimal UDP header size", len );
		return;
	}

	pkt->udp_header = (struct udphdr*) data;

	pkt->data_len = (uint16_t)( len - hdr_len );

	CapEnvProcessDatagram( env, data + hdr_len, pkt->data_len, pkt );
}


void DecodeIpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int ip_len, ip_hdrlen;

	pkt->ip_header = (struct ip*) data;

	if( len < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Invalid IP header length!" );
		return;
	}

	if( IP_V(pkt->ip_header) != 4 )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Unsupported IP version: %d",
				(int)IP_V(pkt->ip_header) );
		return;
	}

	/*TODO: reassemble fragmented packets*/

	ip_len = ntohs(pkt->ip_header->ip_len);
	ip_hdrlen = IP_HL(pkt->ip_header) << 2;

	if( ip_hdrlen < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Bogus IP header!" );
		return;
	}

	if( pkt->ip_header->ip_p == IPPROTO_TCP )
	{
		DecodeTcpPacket( env, pkt, data + ip_hdrlen, ip_len - ip_hdrlen );
	}
	else if( pkt->ip_header->ip_p == IPPROTO_UDP && env->datagram_callback != NULL )
	{
		DecodeUdpPacket( env, pkt, data + ip_hdrlen, ip_len - ip_hdrlen );
	}
}
