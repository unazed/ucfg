#include "platform.h"

#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__) \
  || defined(__CYGWIN__)
# include <Windows.h>
  void*
  platform_load_library (const char* name)
  {
    return LoadLibraryA (name); 
  }
#endif