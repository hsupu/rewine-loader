#pragma once

#include "types/linkedlist.h"
#include "types/pe-image.h"

extern size_t nb_loaded_image;
extern ll_t *loaded_image_ll;

image_info_t * find_loaded_dll_by_filename(PBSTR name);
image_info_t * find_loaded_dll_by_exportname(PBSTR name);

void add_loaded_dll(image_info_t *image);
void remove_loaded_dll(image_info_t *image);
