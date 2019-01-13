#pragma once
#include "misc/raii.h"

void __cleanup_fd(int *fd);
#define RAII_FD RAII(__cleanup_fd)
