#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void printState(uint64_t *state);
uint16_t getNumBlocks(char *data, uint8_t base);
uint64_t *splitDataIn64bitBlock(char *data, uint16_t dataLength);
char *getStringFrom64bitBlocks(uint64_t *blocks, uint16_t strLength);

char *base64_encode(const unsigned char *data, uint64_t input_length);
char *base64_decode(const char *encoded);
uint64_t *divideKeyIntoBlocks(char *key);