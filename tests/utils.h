#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef _WIN32
  #define ThreadSleep Sleep

#elif __linux
void ThreadSleep( uint32_t  millisec );

#elif __FreeBSD__
void ThreadSleep( uint32_t  millisec );

#endif

#endif
