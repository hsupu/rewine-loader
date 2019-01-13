#pragma once

#include "wintypes/string.h"

PCSTR get_dirname(PCSTR fullname);

PCWSTR get_dirname_w(PCWSTR fullname);

PCSTR get_basename(PCSTR fullname);

PCWSTR get_basename_w(PCWSTR fullname);
