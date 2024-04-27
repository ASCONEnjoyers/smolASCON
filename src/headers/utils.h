#include "ascon128.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void printState(uint64_t *state);
uint16_t getNumBlocks(char *data);
uint64_t *splitDataIn64bitBlock(char *data);
char *getStringFrom64bitBlocks(uint64_t *blocks, uint16_t strLength);

char *base64_encode(const unsigned char *data, uint64_t input_length);
char *base64_decode(const char *encoded);