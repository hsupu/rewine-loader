#pragma once

#define RAII(fn) __attribute((cleanup(fn)))
