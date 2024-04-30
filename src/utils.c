#include "headers/utils.h"
#include "headers/ascon128.h"

void printState(uint64_t *state)
{
    for (int i = 0; i < 5; i++)
    {
        printf("x%d> %16lx\n", i, state[i]);
    }
    printf("\n");
}

uint16_t getNumBlocks(char *data)
{
    uint16_t numblocks = (strlen(data) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    return numblocks;
}

uint64_t *splitDataIn64bitBlock(char *data) // split data in 64 bit blocks and add padding
{
    uint16_t len = strlen(data);
    uint16_t num_blocks = (len + sizeof(uint64_t) - 1) / sizeof(uint64_t); // round up
    uint64_t *blocks = calloc(num_blocks, sizeof(uint64_t));

    memcpy(blocks, data, len);
    if (len % 8)
    {
        blocks[num_blocks - 1] |= (1ULL << (len * 8 % BLOCK_SIZE));
    }

    return blocks;
}

uint64_t *divideKeyIntoBlocks(char *key)
{
    uint16_t len = strlen(key);
    uint64_t *key_into_blocks = calloc(4,sizeof(uint64_t));

    memcpy(key_into_blocks,key,len);    // copying key value, the rest is 0 thanks to calloc
    return key_into_blocks;
}

char *getStringFrom64bitBlocks(uint64_t *blocks, uint16_t strLength)
{
    char *res = (char *)calloc(strLength + 1, sizeof(char));
    // copy elements from ciphertextInBlocks to ciphertext
    
    memcpy(res, blocks, strLength);
    res[strLength] = '\0';

    return res;
}

int cceil(double x)
{
    int int_part = (int)x; // Extract the integer part

    if (x == (double)int_part)
    {             // If x is already an integer
        return x; // Return x
    }
    else if (x < 0)
    {                    // If x is negative
        return int_part; // Return the integer part
    }
    else
    {                        // If x is positive
        return int_part + 1; // Return the integer part + 1
    }
}

uint16_t stringLengthFromB64(const char *base64_str)
{
    int base64_len = strlen(base64_str);
    int padding = 0;

    // Check for padding characters at the end of the Base64 string
    if (base64_str[base64_len - 1] == '=')
    {
        padding++;
        if (base64_str[base64_len - 2] == '=')
        {
            padding++;
        }
    }

    // Calculate the number of bytes represented by the Base64 string
    uint64_t num_bytes = (int)cceil((6.0 * base64_len) / 8.0) - padding;

    return num_bytes;
}

char *base64_encode(const unsigned char *data, size_t input_length)
{
    const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    uint64_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL)
        return NULL;

    for (uint64_t i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = base64_table[triple & 0x3F];
    }

    for (uint64_t i = 0; i < (3 - (input_length % 3)) % 3; i++)
    {
        encoded_data[output_length - 1 - i] = '=';
    }

    encoded_data[output_length] = '\0';
    return encoded_data;
}

char *base64_decode(const char *data)
{
    uint16_t in_len = strlen(data);
    uint16_t out_len = stringLengthFromB64(data);
    char *decoded_data = malloc(out_len + 1); // +1 for the null-terminator
    if (!decoded_data)
        return NULL;

    static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j;
    for (i = 0, j = 0; i < in_len; i += 4, j += 3)
    {
        uint16_t idx[4];
        for (uint16_t k = 0; k < 4; k++)
        {
            idx[k] = strchr(b64_table, data[i + k]) - b64_table;
        }

        decoded_data[j] = ((idx[0] << 2) & 0xFC) | ((idx[1] >> 4) & 0x03);
        if (j + 1 < out_len)
            decoded_data[j + 1] = ((idx[1] << 4) & 0xF0) | ((idx[2] >> 2) & 0x0F);
        if (j + 2 < out_len)
            decoded_data[j + 2] = ((idx[2] << 6) & 0xC0) | (idx[3] & 0x3F);
    }

    decoded_data[out_len] = '\0';
    return decoded_data;
}