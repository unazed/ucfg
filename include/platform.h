#pragma once

void* platform_load_library (const char* name);
void platform_free_library (void* module);
void* platform_get_procedure (void* module, const char* procname);
void* platform_readgs (void);