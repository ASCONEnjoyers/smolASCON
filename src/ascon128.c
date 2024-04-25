#include "headers/ascon128.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROTATE(state, l) ((state >> l) ^ (state << (64 - l))) // rotate right

uint8_t constants[] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}; // adding constants
uint64_t temp[5] = {0};                                                                         // to build the sbox

void printState(uint64_t *state)
{
    for (int i = 0; i < 5; i++)
    {
        printf("x%d> %16lx\n", i, state[i]);
    }
    printf("\n");
}

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
    if (type == 0)                                            // a-type round
        state[2] ^= (uint64_t)constants[roundNumber];         // add round constant to key
    else                                                      // b-type round
        state[2] ^= (uint64_t)constants[roundNumber + A - B]; // add round constant to key

    // Substitution layer
    // Here, i'm building the 5 bit state from the 64 bit state, this has to be done for each 64 5 bit groups
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];
    temp[0] = state[0];
    temp[1] = state[1];
    temp[2] = state[2];
    temp[3] = state[3];
    temp[4] = state[4];
    temp[0] = ~temp[0];
    temp[1] = ~temp[1];
    temp[2] = ~temp[2];
    temp[3] = ~temp[3];
    temp[4] = ~temp[4];
    temp[0] &= state[1];
    temp[1] &= state[2];
    temp[2] &= state[3];
    temp[3] &= state[4];
    temp[4] &= state[0];
    state[0] ^= temp[1];
    state[1] ^= temp[2];
    state[2] ^= temp[3];
    state[3] ^= temp[4];
    state[4] ^= temp[0];
    state[1] ^= state[0];
    state[0] ^= state[4];
    state[3] ^= state[2];
    state[2] = ~state[2];

    // Permutation layer
    state[0] ^= ROTATE(state[0], 19) ^ ROTATE(state[0], 28);
    state[1] ^= ROTATE(state[1], 61) ^ ROTATE(state[1], 39);
    state[2] ^= ROTATE(state[2], 1) ^ ROTATE(state[2], 6);
    state[3] ^= ROTATE(state[3], 10) ^ ROTATE(state[3], 17);
    state[4] ^= ROTATE(state[4], 7) ^ ROTATE(state[4], 41);

    return state;
}

uint64_t *pbox(uint64_t *state, uint8_t roundNumber, uint8_t type)
{
    for (int i = 0; i < roundNumber; i++)
    {
        state = doPermutation(state, i, type);
    }
    return state;
}

uint64_t *splitDataIn64bitBlock(char *data) // split data in 64 bit blocks and add padding
{
    uint16_t len = strlen(data);
    uint16_t num_blocks = (len + sizeof(uint64_t) - 1) / sizeof(uint64_t); // round up
    uint64_t *blocks = calloc(num_blocks, sizeof(uint64_t));

    for (uint16_t i = 0; i < num_blocks - 1; i++)
    {
        memcpy(&blocks[i], data + (i * 8), sizeof(char) * 8);
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

    return blocks;
}

uint64_t *initialization(uint64_t *key, uint64_t *nonce) // initialization phase in cipher diagram
{
    uint64_t *state = generateEntranceState(key, nonce);
    printf("Entrance state: \n");
    printState(state);

    state = pbox(state, A, 0);
    state[3] ^= key[0];
    state[4] ^= key[1];

    return state;
}

uint64_t *processAssociated(char *associated, uint64_t *state)
{
    uint64_t *blockAssociated = splitDataIn64bitBlock(associated);
    uint16_t numBlocks = (strlen(associated) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    if (numBlocks == 1) // if there is only one associated data block
    {
        // printf("only associated data block 0\n");
        state[0] ^= blockAssociated[0];
        pbox(state, B, 1); // pboxing, as the diagram shows
        // printState(state);
    }
    else
    {
        for (uint16_t i = 0; i < numBlocks; i++)
        { // for each generated associated data block
            // printf("Associated data block %d\n", i);
            state[0] ^= blockAssociated[i]; // xoring the associated date
            pbox(state, B, 1);              // pboxing, as the diagram shows
            // printState(state);
        }
    }
    state[4] ^= 1ULL; // final xor with 0*||1
    return state;
}

char *encrypt(char *plaintext, char *associated, char *key, char *nonce)
{
    char *ciphertext;
    uint64_t *blockKey = splitDataIn64bitBlock(key);
    uint64_t *blockNonce = splitDataIn64bitBlock(nonce);

    // INITIALIZATION
    uint64_t *state = initialization(blockKey, blockNonce);

    // ASSOCIATED DATA MANAGEMENT
    if (strlen(associated))
    { // if there is any associated date
        // printf("Associated!\n");
        state = processAssociated(associated, state);
    }

    printState(state);

    // ENCRYPTION AND FINALIZATION
    // RebelNightmare's task here>

    return ciphertext;
}