#pragma once

#include "wintypes/string.h"

PCSTR copy_dirname(PCSTR fullname);
PCWSTR copy_dirname_w(PCWSTR fullname);
PCSTR copy_basename(PCSTR fullname);
PCWSTR copy_basename_w(PCWSTR fullname);
