#include <stdio.h>
#include <stdlib.h>
#include "headers/ascon128.h"

int main()
{

    char plaintext[500];
    char associated[500];

    while (1)
    {
        scanf("%s", plaintext);
        scanf("%s", associated);
        

        char *key = "aaaaaaaabbbbbbbb";
        char *nonce = "ccccccccdddddddd";

        char *ciphertext = encrypt(plaintext, associated, key, nonce);

        return 0;
    }
}