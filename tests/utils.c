#include "stdinc.h"
#include "utils.h"

#ifdef _WIN32

#elif defined(__linux) || defined(__FreeBSD__) || defined(__APPLE__)

#include <sys/time.h>
void ThreadSleep( uint32_t millisec )
{
  struct timeval tv;
  
  tv.tv_sec = millisec / 1000;
  tv.tv_usec = millisec % 1000;
  select( 0, 0, 0, 0, &tv );
}

#else
#error "ThreadSleep is not implemented for this platform!"

#endif
