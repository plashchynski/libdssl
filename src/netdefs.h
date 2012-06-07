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
#ifndef __DSSL_NETDEFS_H__
#define __DSSL_NETDEFS_H__

#if defined( _WIN32)
  #include "win32/include/netinet/ether.h"
  #include "win32/include/netinet/ethertype.h"
  #include "win32/include/netinet/ip.h"
  #include "win32/include/netinet/tcp.h"
  #include "win32/include/netinet/udp.h"

#elif defined(__linux)
  #include <features.h>
  #define __FAVOR_BSD
  #include <netinet/ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
  #define ETHER_HDRLEN  14
  #define TH_ECNECHO    0x40  /* ECN Echo */
  #define TH_CWR        0x80  /* ECN Cwnd Reduced */

#elif defined(__FreeBSD__) || defined(__APPLE__)
  #include <netinet/in_systm.h>
  #include <netinet/in.h>
  #include <net/ethernet.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
  #define ETHER_HDRLEN  14
  #define TH_ECNECHO    0x40    /* ECN Echo */
  #define TH_CWR        0x80    /* ECN Cwnd Reduced */

#else
  #include <netinet/ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
#endif

#define MAKE_IP( b1, b2, b3, b4 ) ((uint32_t)(b1 | ((uint32_t)b2 << 8) | ((uint32_t)b3 << 16) | ((uint32_t)b4 << 24 )))

#if defined (__linux)
  #define INADDR_IP( _inaddr ) ((_inaddr).s_addr)
  #define NM_TCP_HDR_LEN( hdr ) (((u_char)(hdr)->th_off ) << 2 )
  #define IP_V(ip ) ((ip)->ip_v)
  #define IP_HL(ip) ((ip)->ip_hl)
#elif defined(__FreeBSD__) || defined(__APPLE__)
  #define INADDR_IP( _inaddr ) ((_inaddr).s_addr)
  #define NM_TCP_HDR_LEN( hdr ) (((u_char)(hdr)->th_off ) << 2 )
  #define IP_V(ip ) ((ip)->ip_v)
  #define IP_HL(ip) ((ip)->ip_hl)
#elif defined(_WIN32)
  #define INADDR_IP( _inaddr ) ((_inaddr).S_un.S_addr)
  #define NM_TCP_HDR_LEN( hdr ) (((hdr)->th_offx2 & 0xF0 ) >> 2 )
#endif

#endif
