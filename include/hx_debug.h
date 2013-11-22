#ifndef HX_DEBUG_H
#define HX_DEBUG_H
#include <stdio.h>
#define hxdbg(...) do {printf(__VA_ARGS__);} while(0)
#endif
