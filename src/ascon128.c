#include "headers/ascon128.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

uint64_t *generateIV(uint8_t r, uint8_t a, uint8_t b)
{
    uint64_t *buffer = (uint64_t *)calloc(1, sizeof(uint64_t)); // 64 bit buffer

    // Generate IV
    *buffer = (((((((*buffer << 8) | 128) << 8) | r) << 8) | a) << 8 | b) << 32;
    return buffer;
}
