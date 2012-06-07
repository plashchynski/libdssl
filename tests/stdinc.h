#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #ifdef _DEBUG
    #define _CRTDBG_MAP_ALLOC
    #include <stdlib.h>
    #include <crtdbg.h>
  #endif
#endif


#ifdef _WIN32
#pragma warning(push, 3)
#include <pcap.h>
#pragma warning(pop)
#else
#include <pcap.h>
#endif

#include <openssl/ssl.h>

/*
#define NM_TRACE_TCP_STATE
*/
#include "../src/netdefs.h"
#include "../src/sslcap.h"

#include "CuTest.h"
#include "t_packet.h"
#include "utils.h"
