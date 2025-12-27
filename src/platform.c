#include "platform.h"

#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__) \
  || defined(__CYGWIN__)
# include <Windows.h>
  void*
  platform_load_library (const char* name)
  {
    return LoadLibraryA (name); 
  }

  void*
  platform_get_procedure (void* module, const char* procname)
  {
    return GetProcAddress (module, procname);
  }

  void
  platform_free_library (void* module)
  {
    FreeLibrary (module);
  }
#endif