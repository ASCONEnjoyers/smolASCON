#include <stdint.h>

#define KEY_SIZE 128
#define NONCE_SIZE 64
#define BLOCK_SIZE 64
#define A 12
#define B 6

uint64_t *generateFirstState(uint64_t *K, uint64_t *N);
