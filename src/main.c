#include <stdio.h>
#include <stdlib.h>
#include "headers/ascon128.h"

int main()
{

    char plaintext[500];
    char associated[500] = {0};

    while (1)
    {
        char key[16] = {0};
        char nonce[16] = {0};

        scanf("%s", plaintext);

        char *ciphertext = encrypt(plaintext, associated, key, nonce);
        printf("Ciphertext> %s\n", ciphertext);

        char *m = decrypt(ciphertext, associated, key, nonce);

        printf("Plaintext> %s\n\n", m);
    }

    return 0;
}