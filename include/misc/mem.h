#pragma once

#include <stdlib.h>

#define MALLOC(type, n) ((type *)malloc(sizeof(type) * (n)))
