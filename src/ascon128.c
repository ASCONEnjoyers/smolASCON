#include "headers/ascon128.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

uint64_t *generateIV(uint8_t r, uint8_t a, uint8_t b)
{
    uint64_t *buffer = (uint64_t *)calloc(1, sizeof(uint64_t)); // 64 bit buffer

    // Generate IV
    *buffer = ((((((*buffer | 128) << 8) | r) << 8) | a) << 8 | b) << 32;
    return buffer;
}

uint64_t *generateFirstState(uint64_t *K, uint64_t *N)
{
    uint64_t *state = (uint64_t *)calloc(5, sizeof(uint64_t)); // 320 bit state

    //*state = (((*state | *generateIV(BLOCK_SIZE, A, B) << 64) | *K) << 128) | *N;
    state[0] = *generateIV(BLOCK_SIZE, A, B);
    state[1] = K[0];
    state[2] = K[1];
    state[3] = N[0];
    state[4] = N[1]; 
    return state;
}
