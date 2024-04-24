#include "headers/ascon128.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EXTRACT_BIT(bit, pos, shift) (((state[bit] >> pos) & 0x1) << shift)

uint8_t constants[] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};                                                                                                    // adding constants
uint8_t sbox[] = {0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2, 0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c, 0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18, 0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17}; // 5bit sbox

uint64_t *generateIV(uint8_t r, uint8_t a, uint8_t b)
{
    uint64_t *buffer = (uint64_t *)calloc(1, sizeof(uint64_t)); // 64 bit buffer

    // Generate IV
    *buffer = ((((((*buffer | 128) << 8) | r) << 8) | a) << 8 | b) << 32; //  k || r || a || b || 0^{160-k}
    return buffer;
}

uint64_t *generateEntranceState(uint64_t *K, uint64_t *N) // 128 bit key, 128 bit nonce
{
    uint64_t *state = (uint64_t *)calloc(5, sizeof(uint64_t)); // 320 bit state

    state[0] = *generateIV(BLOCK_SIZE, A, B); // first 64 bits of IV
    state[1] = K[0];                          // first 64 bits of key
    state[2] = K[1];                          // last 64 bits of key
    state[3] = N[0];                          // first 64 bits of nonce
    state[4] = N[1];                          // last 64 bits of nonce
    // S = IV || K || N
    return state; // and that's it
}

uint64_t *doPermutation(uint64_t *state, uint8_t roundNumber, uint8_t type)
{
    uint8_t state5bit; // 5 bit from the state. used to perform sbox operation
    // 64 bit mask to take a precise bit from the state
    // uint64_t mask=~0ULL;
    // int max=63;

    if (type == 0)                                                      // a-type round
        state[2] = state[2] ^ (uint64_t)constants[roundNumber];         // add round constant to key
    else                                                                // b-type round
        state[2] = state[2] ^ (uint64_t)constants[roundNumber + A - B]; // add round constant to key

    // Substitution layer
    // Here, i'm building the 5 bit state from the 64 bit state, this has to be done for each 64 5 bit groups

    // state5bit = 0;
    //  state5bit = ((((state5bit | (state[0] >> 63 & 0x1) << 1) | (state[0] >> 62 & 0x1) << 1) | (state[0] >> 61 & 0x1) << 1) | (state[0] >> 60 & 0x1) << 1) | (state[0] >> 59 & 0x1);
    //  I want to cry
    //  printf("aiuto %x\n", state5bit);

    for (int i = 63; i >= 0; i--)
    {
        state5bit = 0;

        // extract 5 bit column from state
        state5bit = EXTRACT_BIT(0, i, 4) | EXTRACT_BIT(1, i, 3) | EXTRACT_BIT(2, i, 2) | EXTRACT_BIT(3, i, 1) | EXTRACT_BIT(4, i, 0);

        printf("column %x\n", state5bit);
        printf("x0 %lx\n", EXTRACT_BIT(0, i, 4));
        printf("x1 %lx\n", EXTRACT_BIT(1, i, 3));
        printf("x2 %lx\n", EXTRACT_BIT(2, i, 2));
        printf("x3 %lx\n", EXTRACT_BIT(3, i, 1));
        printf("x4 %lx\n", EXTRACT_BIT(4, i, 0));

        state5bit = sbox[state5bit]; // apply sbox
        printf("sbox %x\n", state5bit);
        uint64_t state64bit = state5bit;
        printf("state64bit %lx\n", state64bit);
        // rebuild 64 bit state
        state[0] = (state[0] & ~(1ULL << i)) | ((state64bit & 0x1) << i);
        state[1] = (state[1] & ~(1ULL << i)) | (((state64bit >> 1) & 0x1) << i);
        state[2] = (state[2] & ~(1ULL << i)) | (((state64bit >> 2) & 0x1) << i);
        state[3] = (state[3] & ~(1ULL << i)) | (((state64bit >> 3) & 0x1) << i);
        state[4] = (state[4] & ~(1ULL << i)) | (((state64bit >> 4) & 0x1) << i);
    }

    // tutto ciò in un for che da 6

    // Permutation layer
    state[0] = state[0] ^ (state[0] >> 19) ^ (state[1] >> 28);
    state[1] = state[1] ^ (state[1] >> 61) ^ (state[0] >> 39);
    state[2] = state[2] ^ (state[2] >> 1) ^ (state[1] >> 6);
    state[3] = state[3] ^ (state[3] >> 10) ^ (state[2] >> 17);
    state[4] = state[4] ^ (state[4] >> 7) ^ (state[3] >> 41);

    return state;
}

uint64_t *pbox(uint64_t *state, uint8_t roundNumber, uint8_t type)
{
    for (int i = 0; i < roundNumber; i++)
    {
        state = doPermutation(state, roundNumber, type);
    }
    return state;
}

uint64_t *splitDataIn64bitBlock(char *data)
{
    uint16_t len = strlen(data);
    uint16_t num_blocks = (len + sizeof(uint64_t) - 1) / sizeof(uint64_t); // round up
    uint64_t *blocks = calloc(num_blocks, sizeof(uint64_t));

    printf("blocs %d\n", num_blocks);

    for (uint16_t i = 0; i < num_blocks - 1; i++)
    {
        memcpy(&blocks[i], data + (i * 8), sizeof(char) * 8);
        printf("%lx\n", blocks[i]);
    }
    if (!(len % 8))
    {
        memcpy(&blocks[num_blocks - 1], data + ((num_blocks - 1) * 8), sizeof(char) * 8);
    }
    else
    {
        memcpy(&blocks[num_blocks - 1], data + ((num_blocks - 1) * 8), sizeof(char) * (len % 8));
        // + padding
        blocks[num_blocks - 1] |= (1ULL << (len * 8 % BLOCK_SIZE));
    }
    printf("%16lx\n", blocks[num_blocks - 1]);

    return blocks;
}