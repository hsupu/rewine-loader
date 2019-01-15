#pragma once

#include <stdlib.h>
#include <string.h>

#define MALLOC(type, n) ((type *)malloc(sizeof(type) * (n)))
#define MEMSET(address, type, n, c) ((type *)memset(address, c, sizeof(type) * (n)))

#define MALLOC_S(type, n) MEMSET(MALLOC(type, n), type, n, 0)
