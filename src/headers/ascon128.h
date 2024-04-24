#include <stdint.h>

#define KEY_SIZE 128
#define NONCE_SIZE 64
#define BLOCK_SIZE 64
#define A 12
#define B 6

uint64_t *generateEntranceState(uint64_t *K, uint64_t *N);
uint64_t *doPermutation(uint64_t *state, uint8_t roundNumber, uint8_t type);
uint64_t *splitDataIn64bitBlock(char *data);