#include "headers/utils.h"
#include "headers/ascon128.h"

#define RROTATE(state, l) ((state >> l) ^ (state << (64 - l))) // ROTATE right

uint8_t constants[] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}; // adding constants

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
    uint64_t temp[5] = {0};                                   // temporary state to build the sbox
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
    state[0] ^= RROTATE(state[0], 19) ^ RROTATE(state[0], 28);
    state[1] ^= RROTATE(state[1], 61) ^ RROTATE(state[1], 39);
    state[2] ^= RROTATE(state[2], 1) ^ RROTATE(state[2], 6);
    state[3] ^= RROTATE(state[3], 10) ^ RROTATE(state[3], 17);
    state[4] ^= RROTATE(state[4], 7) ^ RROTATE(state[4], 41);

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

uint64_t *initialization(uint64_t *key, uint64_t *nonce) // initialization phase in cipher diagram
{
    uint64_t *state = generateEntranceState(key, nonce);

    state = pbox(state, A, 0);
    state[3] ^= key[0];
    state[4] ^= key[1];

    return state;
}

uint64_t *processAssociated(char *associated, uint64_t *state)
{
    uint16_t associatedLength = strlen(associated);
    uint64_t *blockAssociated = splitDataIn64bitBlock(associated, associatedLength);
    uint16_t numBlocks = (associatedLength + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    if (numBlocks == 1) // if there is only one associated data block
    {
        state[0] ^= blockAssociated[0];
        pbox(state, B, 1); // pboxing, as the diagram shows
    }
    else
    {
        for (uint16_t i = 0; i < numBlocks; i++)
        {                                   // for each generated associated data block
            state[0] ^= blockAssociated[i]; // xoring the associated date
            pbox(state, B, 1);              // pboxing, as the diagram shows
        }
    }
    state[4] ^= 1ULL; // final xor with 0*||1
    return state;
}

uint64_t *finalize(uint64_t *state, char *key){
    uint64_t *key_into_blocks = divideKeyIntoBlocks(key);

    for (int i = 0; i < 3; i++)
    {
        state[i + 1] ^= key_into_blocks[i]; // updating state
    }

    pbox(state, A, 0);

    uint64_t *tag_in_blocks = malloc(2 * sizeof(uint64_t));
    tag_in_blocks[0] = state[3] ^ key_into_blocks[0]; // last 128 bits of state are xored with 128 bit key
    tag_in_blocks[1] = state[4] ^ key_into_blocks[1];

    return tag_in_blocks;
}

ascon_t *encrypt(char *plaintext, char *associated, char *key, char *nonce)
{
    uint64_t *blockKey = splitDataIn64bitBlock(key, KEY_SIZE / 8);
    uint64_t *blockNonce = splitDataIn64bitBlock(nonce, NONCE_SIZE / 8);

    // INITIALIZATION
    uint64_t *state = initialization(blockKey, blockNonce);

    // ASSOCIATED DATA MANAGEMENT
    if (strlen(associated))
    { // if there is any associated date
        state = processAssociated(associated, state);
    }

    // ENCRYPTION
    uint16_t plaintextLength = strlen(plaintext);
    uint64_t *plaintextInBlocks = splitDataIn64bitBlock(plaintext, plaintextLength);

    uint16_t plaintext_numblocks = getNumBlocks(plaintext, 10);
    printf("plaintext blocks: %d\n", plaintext_numblocks);
    uint64_t *ciphertextInBlocks = (uint64_t *)calloc(plaintext_numblocks, sizeof(uint64_t));

    for (int i = 0; i < plaintext_numblocks; i++)
    {                                                            // as many rounds as the number of blocks
        ciphertextInBlocks[i] = plaintextInBlocks[i] ^ state[0]; // xoring plaintext and first block of state
        state[0] = ciphertextInBlocks[i];                        // state is updated
        if (i < plaintext_numblocks - 1)
        {                      // process after last block is different
            pbox(state, B, 1); // state goes through the p-box
        }
    }

    // FINALIZATION

    /*
    uint64_t *key_into_blocks = divideKeyIntoBlocks(key);
    for (int i = 0; i < 3; i++)
    {
        state[i + 1] ^= key_into_blocks[i]; // updating state
    }

    pbox(state, A, 0);
    
    uint64_t *tag_in_blocks = malloc(2 * sizeof(uint64_t));

    char *tag = (char *)calloc(2, sizeof(uint64_t));

    tag_in_blocks[0] = state[3] ^ key_into_blocks[0]; // last 128 bits of state are xored with 128 bit key
    tag_in_blocks[1] = state[4] ^ key_into_blocks[1];

    memcpy(tag, tag_in_blocks, 2 * sizeof(uint64_t));
    */

    uint64_t *tag_in_blocks = malloc(2 * sizeof(uint64_t));
    tag_in_blocks = finalize(state,key);

    ascon_t *ascon = (ascon_t *)calloc(1, sizeof(ascon_t));

    ascon->ciphertext = ciphertextInBlocks;
    ascon->tag = tag_in_blocks;
    ascon->originalLength = plaintextLength;

    return ascon;
}

char *decrypt(ascon_t *ascon, char *associated, char *key, char *nonce)
{

    char *plaintext;
    uint64_t *blockKey = splitDataIn64bitBlock(key, KEY_SIZE / 8);
    uint64_t *blockNonce = splitDataIn64bitBlock(nonce, NONCE_SIZE / 8);

    // INITIALIZATION
    uint64_t *state = initialization(blockKey, blockNonce);

    // ASSOCIATED DATA MANAGEMENT
    if (strlen(associated))
    { // if there is any associated date
        state = processAssociated(associated, state);
    }

    // DECRYPTION
    printf("original length: %d\n", ascon->originalLength);
    uint16_t ciphertext_numblocks = (ascon->originalLength + sizeof(uint64_t) - 1) / sizeof(uint64_t); // round up
    printf("ciphertext blocks: %d\n", ciphertext_numblocks);
    uint64_t *ciphertextInBlocks = ascon->ciphertext;
    uint64_t *plaintextInBlocks = (uint64_t *)calloc(ciphertext_numblocks, sizeof(uint64_t));
    for (int i = 0; i < ciphertext_numblocks; i++)
    {                                                            // as many rounds as the number of blocks
        plaintextInBlocks[i] = ciphertextInBlocks[i] ^ state[0]; // xoring plaintext and first block of state
        state[0] = ciphertextInBlocks[i];                        // state is updated
        if (i < ciphertext_numblocks - 1)
        {                      // process after last block is different
            pbox(state, B, 1); // state goes through the p-box
        }
    }

    plaintext = getStringFrom64bitBlocks(plaintextInBlocks, ascon->originalLength);

    // FINALIZATION
    
    uint64_t *tag_in_blocks = malloc(2 * sizeof(uint64_t));
    tag_in_blocks = finalize(state,key);

    if(tag_in_blocks[0] == ascon->tag[0] && tag_in_blocks[1] == ascon->tag[1]){     // if tag is the same
        return plaintext;
    } else {
        return "the tag is not the same!";
    }
    
}

void incrementNonce(char *nonce)
{
    /**((uint64_t *)nonce + 1) += 1;
    if (*((uint64_t *)nonce + 1) == 0)
        *((uint64_t *)nonce) += 1;*/
    for(int i = 15; i >= 0; i--){
        nonce[i]--;
        if(nonce[i] != 0){
            break;
        }
    }
}


char *getPrintableText(uint64_t *blocks, uint16_t length)
{
    char *res = base64_encode((const unsigned char *)getStringFrom64bitBlocks(blocks, length), length);
    return res;
}