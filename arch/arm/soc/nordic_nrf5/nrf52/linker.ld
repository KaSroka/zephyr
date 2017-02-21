/* linker.ld - Linker command/script file */

/*
 * Copyright (c) 2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arch/arm/cortex_m/scripts/linker.ld>

 SECTIONS
 {
    top_of_image_ram (NOLOAD):
    {
        __top_of_image_ram_start__ = .;
        *(.top_of_image_ram)
        *(".top_of_image_ram.*")
        __top_of_image_ram_end__ = .;
    } > SRAM
 };
