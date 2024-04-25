#include <stdio.h>
#include <stdlib.h>
#include "headers/ascon128.h"

int main()
{

    char plaintext[500] = {0};
    char associated[500] = {0};

    while (1)
    {
        char key[16] = {0};
        char nonce[16] = {0};

        char *ciphertext = encrypt(plaintext, associated, key, nonce);

        return 0;
    }
}